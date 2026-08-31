using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.PayPal;
using Emby.Sso.Licensing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The wire, over the real routes. Program.BuildApp is what Main runs, so
    /// these exercise the same wiring rather than a copy of it.
    ///
    /// What is checked here and nowhere else is the SHAPE of the answers: the
    /// plugin was written from contract.md by somebody else, against these exact
    /// field names and these exact machine codes, and neither half can see the
    /// other's code.
    /// </summary>
    public class EndpointTests : IAsyncLifetime
    {
        private const string ServerA = "c5bc6e91458540caa295c4efdda1a58a";

        private TestService _service;
        private PayPalTestCertificate _certificate;
        private WebApplication _app;
        private HttpClient _client;

        public async Task InitializeAsync()
        {
            _service = new TestService(options =>
            {
                options.PayPal.ClientId = null;
                options.PayPal.ClientSecret = null;
            });

            _certificate = new PayPalTestCertificate();

            _app = Program.BuildApp(_service.Options, _service.Key, builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Services.AddSingleton<IPayPalCertificateSource>(new FakeCertificateSource(_certificate));
            });

            await _app.StartAsync();

            _client = _app.GetTestClient();
        }

        public async Task DisposeAsync()
        {
            _client?.Dispose();

            if (_app != null)
            {
                await _app.StopAsync();
                await _app.DisposeAsync();
            }

            _certificate?.Dispose();
            _service?.Dispose();
        }

        [Fact]
        public async Task A_successful_activation_answers_exactly_the_fields_the_contract_names()
        {
            var code = _service.GiveOutACode();

            var response = await Activate(code, ServerA);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

            var root = body.RootElement;

            Assert.True(root.TryGetProperty("licence", out var licence));
            Assert.True(root.TryGetProperty("expiresUtc", out var expires));
            Assert.Equal(1, root.GetProperty("activationsUsed").GetInt32());
            Assert.Equal(3, root.GetProperty("activationsAllowed").GetInt32());

            // The licence is a JWT, and expiresUtc is the format the rest of this
            // system uses everywhere.
            Assert.Equal(3, licence.GetString().Split('.').Length);
            Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", expires.GetString());
        }

        [Fact]
        public async Task An_unknown_code_answers_invalid_code()
        {
            var response = await Activate(RedemptionCode.Format(RedemptionCode.Generate()), ServerA);

            await AssertError(response, HttpStatusCode.BadRequest, "invalid_code");
        }

        [Fact]
        public async Task A_body_that_is_not_JSON_answers_malformed_request_rather_than_the_frameworks_problem_json()
        {
            using var content = new StringContent("this is not json", Encoding.UTF8, "application/json");

            var response = await _client.PostAsync("/v1/activate", content);

            await AssertError(response, HttpStatusCode.BadRequest, "malformed_request");
        }

        [Fact]
        public async Task An_empty_body_answers_malformed_request()
        {
            using var content = new StringContent("{}", Encoding.UTF8, "application/json");

            var response = await _client.PostAsync("/v1/activate", content);

            await AssertError(response, HttpStatusCode.BadRequest, "malformed_request");
        }

        [Fact]
        public async Task An_exhausted_code_answers_code_exhausted()
        {
            var code = _service.GiveOutACode(activationsAllowed: 1);

            await Activate(code, ServerA);

            var response = await Activate(code, "aaaa1111bbbb2222cccc3333dddd4444");

            await AssertError(response, HttpStatusCode.Conflict, "code_exhausted");
        }

        [Fact]
        public async Task Rate_limiting_answers_429_with_a_Retry_After_header()
        {
            // The suite's default limits are effectively off, so this one asks
            // for a real limit and then trips it.
            using var service = new TestService(options =>
            {
                options.RateLimit.PerClientBurst = 1;
                options.RateLimit.PerClientPerMinute = 1;
                options.PayPal.ClientId = null;
            });

            var app = Program.BuildApp(service.Options, service.Key, builder => builder.WebHost.UseTestServer());

            try
            {
                await app.StartAsync();

                using var client = app.GetTestClient();
                var code = service.GiveOutACode();

                await Post(client, code, ServerA);

                var response = await Post(client, code, ServerA);

                await AssertError(response, HttpStatusCode.TooManyRequests, "rate_limited");

                Assert.True(response.Headers.Contains("Retry-After"), "429 must carry Retry-After");
                Assert.True(int.Parse(
                    string.Join(string.Empty, response.Headers.GetValues("Retry-After")),
                    CultureInfo.InvariantCulture) >= 1);
            }
            finally
            {
                await app.StopAsync();
                await app.DisposeAsync();
            }
        }

        [Fact]
        public async Task An_unsigned_webhook_answers_401_and_nothing_else()
        {
            using var content = new StringContent("{\"id\":\"WH-1\"}", Encoding.UTF8, "application/json");

            var response = await _client.PostAsync("/paypal/webhook", content);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            // No hint about why. Somebody scanning for this endpoint learns
            // nothing from the answer.
            Assert.Empty(await response.Content.ReadAsByteArrayAsync());
            Assert.False(File.Exists(_service.Options.OutboxPath));
        }

        [Fact]
        public async Task A_signed_webhook_creates_a_code_that_then_activates()
        {
            var body = Encoding.UTF8.GetBytes(
                "{\"id\":\"WH-END-1\",\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\",\"resource\":{"
                + "\"id\":\"CAPTURE-END-1\",\"amount\":{\"value\":\"19.00\",\"currency_code\":\"GBP\"},"
                + "\"payer\":{\"email_address\":\"buyer@example.com\"}}}");

            using var content = new ByteArrayContent(body);

            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            const string TransmissionId = "TX-END-1";
            const string TransmissionTime = "2026-01-05T12:00:00Z";

            var message = PayPalTestCertificate.Message(
                TransmissionId,
                TransmissionTime,
                _service.Options.PayPal.WebhookId,
                body);

            using var request = new HttpRequestMessage(HttpMethod.Post, "/paypal/webhook") { Content = content };

            request.Headers.Add(PayPalWebhookVerifier.TransmissionIdHeader, TransmissionId);
            request.Headers.Add(PayPalWebhookVerifier.TransmissionTimeHeader, TransmissionTime);
            request.Headers.Add(PayPalWebhookVerifier.TransmissionSignatureHeader, _certificate.Sign(message));
            request.Headers.Add(
                PayPalWebhookVerifier.CertificateUrlHeader,
                "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-1");
            request.Headers.Add(PayPalWebhookVerifier.AuthAlgorithmHeader, PayPalWebhookVerifier.RequiredAuthAlgorithm);

            var response = await _client.SendAsync(request);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            using var outbox = JsonDocument.Parse(File.ReadAllLines(_service.Options.OutboxPath)[0]);

            var activation = await Activate(outbox.RootElement.GetProperty("code").GetString(), ServerA);

            Assert.Equal(HttpStatusCode.OK, activation.StatusCode);
        }

        [Fact]
        public async Task Health_says_which_key_is_loaded_without_saying_anything_secret()
        {
            var response = await _client.GetAsync("/healthz");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var text = await response.Content.ReadAsStringAsync();

            using var body = JsonDocument.Parse(text);

            Assert.Equal("ok", body.RootElement.GetProperty("status").GetString());
            Assert.Equal(_service.Key.Thumbprint, body.RootElement.GetProperty("signingKey").GetString());
            Assert.Equal("sandbox", body.RootElement.GetProperty("paypal").GetString());

            // Nothing from the private half, and nothing from the environment.
            Assert.DoesNotContain(_service.Key.Key.D, text, StringComparison.Ordinal);
            Assert.DoesNotContain(_service.KeyPath, text, StringComparison.Ordinal);
        }

        private Task<HttpResponseMessage> Activate(string code, string serverId)
        {
            return Post(_client, code, serverId);
        }

        private static Task<HttpResponseMessage> Post(HttpClient client, string code, string serverId)
        {
            return client.PostAsJsonAsync(
                "/v1/activate",
                new { code, serverId, pluginVersion = "1.4.0" });
        }

        private static async Task AssertError(HttpResponseMessage response, HttpStatusCode status, string error)
        {
            Assert.Equal(status, response.StatusCode);

            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

            Assert.Equal(error, body.RootElement.GetProperty("error").GetString());

            var message = body.RootElement.GetProperty("message").GetString();

            Assert.False(string.IsNullOrWhiteSpace(message), "every error carries one sentence for a human");
        }
    }
}

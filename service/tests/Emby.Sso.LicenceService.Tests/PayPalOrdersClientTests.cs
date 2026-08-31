using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.PayPal;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The checkout client, tested as far as it can be without PayPal.
    ///
    /// **THE LIVE PATH IS UNVERIFIED.** These tests prove the requests are built
    /// the way PayPal's documentation says to build them and that the response is
    /// read correctly. They cannot prove PayPal accepts them - no credentials, no
    /// route - so what they buy is that a mistake in the shape of the request is
    /// caught here rather than in the vendor's first sandbox run. The sandbox run
    /// is still required: docs/paypal-sandbox-checklist.md.
    /// </summary>
    public class PayPalOrdersClientTests
    {
        [Fact]
        public async Task The_token_request_is_client_credentials_with_basic_auth()
        {
            var transport = new RecordingTransport();
            var client = new PayPalOrdersClient(new HttpClient(transport), Options());

            await client.CreateOrderAsync(null, CancellationToken.None);

            var token = transport.Requests[0];

            Assert.Equal("https://api-m.sandbox.paypal.com/v1/oauth2/token", token.Url);
            Assert.Equal("Basic", token.AuthorizationScheme);
            Assert.Equal(
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("client-id:client-secret")),
                token.AuthorizationParameter);
            Assert.Contains("grant_type=client_credentials", token.Body, StringComparison.Ordinal);

            // The secret is in the header and nowhere else - not in the URL, not
            // in the body, because both of those are the things that end up in
            // logs.
            Assert.DoesNotContain("client-secret", token.Url, StringComparison.Ordinal);
            Assert.DoesNotContain("client-secret", token.Body, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_order_carries_the_configured_price_and_currency()
        {
            var transport = new RecordingTransport();
            var client = new PayPalOrdersClient(new HttpClient(transport), Options());

            await client.CreateOrderAsync(null, CancellationToken.None);

            var order = transport.Requests[1];

            Assert.Equal("https://api-m.sandbox.paypal.com/v2/checkout/orders", order.Url);
            Assert.Equal("Bearer", order.AuthorizationScheme);
            Assert.Equal("test-access-token", order.AuthorizationParameter);

            using var document = JsonDocument.Parse(order.Body);

            var amount = document.RootElement
                .GetProperty("purchase_units")[0]
                .GetProperty("amount");

            Assert.Equal("CAPTURE", document.RootElement.GetProperty("intent").GetString());
            Assert.Equal("19.00", amount.GetProperty("value").GetString());
            Assert.Equal("GBP", amount.GetProperty("currency_code").GetString());
        }

        [Fact]
        public async Task The_live_environment_uses_the_live_host()
        {
            var transport = new RecordingTransport();
            var options = Options();

            options.Environment = PayPalOptions.Live;

            var client = new PayPalOrdersClient(new HttpClient(transport), options);

            await client.CreateOrderAsync(null, CancellationToken.None);

            Assert.StartsWith("https://api-m.paypal.com/", transport.Requests[0].Url, StringComparison.Ordinal);
            Assert.StartsWith("https://api-m.paypal.com/", transport.Requests[1].Url, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_originating_server_id_travels_as_custom_id_and_is_omitted_when_absent()
        {
            var withServer = new RecordingTransport();

            await new PayPalOrdersClient(new HttpClient(withServer), Options())
                .CreateOrderAsync("c5bc6e91458540caa295c4efdda1a58a", CancellationToken.None);

            using (var document = JsonDocument.Parse(withServer.Requests[1].Body))
            {
                Assert.Equal(
                    "c5bc6e91458540caa295c4efdda1a58a",
                    document.RootElement.GetProperty("purchase_units")[0].GetProperty("custom_id").GetString());
            }

            var without = new RecordingTransport();

            await new PayPalOrdersClient(new HttpClient(without), Options())
                .CreateOrderAsync(null, CancellationToken.None);

            using (var document = JsonDocument.Parse(without.Requests[1].Body))
            {
                Assert.False(document.RootElement.GetProperty("purchase_units")[0].TryGetProperty("custom_id", out _));
            }
        }

        [Fact]
        public void The_approval_link_is_picked_out_of_the_response()
        {
            var order = PayPalOrdersClient.ReadOrder(
                "{\"id\":\"5O190127TN364715T\",\"links\":["
                + "{\"rel\":\"self\",\"href\":\"https://api-m.sandbox.paypal.com/v2/checkout/orders/5O1\"},"
                + "{\"rel\":\"approve\",\"href\":\"https://www.sandbox.paypal.com/checkoutnow?token=5O1\"}]}");

            Assert.Equal("5O190127TN364715T", order.OrderId);
            Assert.Equal("https://www.sandbox.paypal.com/checkoutnow?token=5O1", order.ApproveUrl);
        }

        [Fact]
        public void The_newer_payer_action_relation_is_understood_too()
        {
            var order = PayPalOrdersClient.ReadOrder(
                "{\"id\":\"5O1\",\"links\":[{\"rel\":\"payer-action\",\"href\":\"https://www.paypal.com/x\"}]}");

            Assert.Equal("https://www.paypal.com/x", order.ApproveUrl);
        }

        [Fact]
        public void A_response_with_no_approval_link_is_an_error_and_not_a_half_built_order()
        {
            Assert.Throws<PayPalApiException>(() => PayPalOrdersClient.ReadOrder("{\"id\":\"5O1\",\"links\":[]}"));
            Assert.Throws<PayPalApiException>(() => PayPalOrdersClient.ReadOrder("{}"));
        }

        [Fact]
        public async Task Refused_credentials_are_an_error_that_does_not_repeat_PayPals_body()
        {
            var transport = new RecordingTransport
            {
                TokenStatus = HttpStatusCode.Unauthorized,
                TokenBody = "{\"error\":\"invalid_client\",\"error_description\":\"account 4XZ is restricted\"}",
            };

            var client = new PayPalOrdersClient(new HttpClient(transport), Options());

            var ex = await Assert.ThrowsAsync<PayPalApiException>(
                () => client.CreateOrderAsync(null, CancellationToken.None));

            Assert.Contains("401", ex.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("account 4XZ", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Checkout_without_credentials_refuses_before_it_makes_a_request()
        {
            var transport = new RecordingTransport();
            var options = Options();

            options.ClientSecret = null;

            var client = new PayPalOrdersClient(new HttpClient(transport), options);

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.CreateOrderAsync(null, CancellationToken.None));

            Assert.Empty(transport.Requests);
        }

        private static PayPalOptions Options()
        {
            return new PayPalOptions
            {
                Environment = PayPalOptions.Sandbox,
                ClientId = "client-id",
                ClientSecret = "client-secret",
                WebhookId = "WH-1",
                Currency = "GBP",
                Price = "19.00",
                MinimumAmount = "19.00",
                ProductName = "Emby SSO plugin licence",
                ReturnUrl = "https://licence.example.com/buy/complete",
                CancelUrl = "https://licence.example.com/buy/cancelled",
            };
        }

        private sealed class RecordedRequest
        {
            public string Url { get; set; }

            public string Body { get; set; }

            public string AuthorizationScheme { get; set; }

            public string AuthorizationParameter { get; set; }
        }

        /// <summary>
        /// Stands in for PayPal. It answers the two calls the client makes and
        /// records exactly what was sent, which is the only part of this that can
        /// be checked without them.
        /// </summary>
        private sealed class RecordingTransport : HttpMessageHandler
        {
            public List<RecordedRequest> Requests { get; } = new List<RecordedRequest>();

            public HttpStatusCode TokenStatus { get; set; } = HttpStatusCode.OK;

            public string TokenBody { get; set; } = "{\"access_token\":\"test-access-token\",\"expires_in\":32400}";

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                Requests.Add(new RecordedRequest
                {
                    Url = request.RequestUri.ToString(),
                    Body = request.Content == null
                        ? null
                        : await request.Content.ReadAsStringAsync(cancellationToken),
                    AuthorizationScheme = request.Headers.Authorization?.Scheme,
                    AuthorizationParameter = request.Headers.Authorization?.Parameter,
                });

                if (request.RequestUri.AbsolutePath.EndsWith("/oauth2/token", StringComparison.Ordinal))
                {
                    return new HttpResponseMessage(TokenStatus)
                    {
                        Content = new StringContent(TokenBody, System.Text.Encoding.UTF8, "application/json"),
                    };
                }

                return new HttpResponseMessage(HttpStatusCode.Created)
                {
                    Content = new StringContent(
                        "{\"id\":\"5O190127TN364715T\",\"links\":["
                        + "{\"rel\":\"approve\",\"href\":\"https://www.sandbox.paypal.com/checkoutnow?token=5O1\"}]}",
                        System.Text.Encoding.UTF8,
                        "application/json"),
                };
            }
        }
    }
}

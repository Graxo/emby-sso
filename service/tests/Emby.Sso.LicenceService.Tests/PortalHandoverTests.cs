using System;
using System.Collections.Generic;
using System.Net;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// LICENCE_PORTAL_URL: once the shop lives in the portal, this service must
    /// not sell, and must say where the shop went rather than 404.
    /// </summary>
    public sealed class PortalHandoverTests : IAsyncLifetime
    {
        private const string Portal = "https://portal.example.com/emby-licence";

        private TestService _service;
        private WebApplication _app;
        private HttpClient _client;

        public Task InitializeAsync()
        {
            return StartAsync(Portal);
        }

        public async Task DisposeAsync()
        {
            _client?.Dispose();

            if (_app != null)
            {
                await _app.StopAsync();
                await _app.DisposeAsync();
            }

            _service?.Dispose();
        }

        private async Task StartAsync(string portalUrl, Action<ServiceOptions> tweak = null, Action<WebApplicationBuilder> configure = null)
        {
            _service = new TestService(o =>
            {
                o.PortalUrl = portalUrl;
                tweak?.Invoke(o);
            });

            _app = Program.BuildApp(_service.Options, builder =>
            {
                builder.WebHost.UseTestServer();
                configure?.Invoke(builder);
            });

            await _app.StartAsync();

            _client = _app.GetTestClient();
        }

        [Theory]
        [InlineData("/")]
        [InlineData("/buy")]
        [InlineData("/buy?serverId=c5bc6e91458540caa295c4efdda1a58a")]
        [InlineData("/buy/complete")]
        [InlineData("/buy/cancelled")]
        [InlineData("/buy/start")]
        [InlineData("/buy/anything/else")]
        public async Task The_shop_pages_are_a_permanent_redirect_to_the_portal(string path)
        {
            var response = await _client.GetAsync(path);

            Assert.Equal(HttpStatusCode.MovedPermanently, response.StatusCode);
            Assert.Equal(Portal, response.Headers.Location.ToString());
        }

        [Fact]
        public async Task Starting_a_payment_is_gone()
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>());

            Assert.Equal(HttpStatusCode.Gone, (await _client.PostAsync("/buy/start", form)).StatusCode);
            Assert.Equal(HttpStatusCode.Gone, (await _client.PostAsync("/v1/checkout", new StringContent("{}"))).StatusCode);
        }

        [Fact]
        public async Task The_routes_the_plugin_uses_are_untouched()
        {
            Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/healthz")).StatusCode);

            // Reaches the activation handler (which refuses a body that is not
            // JSON) rather than a redirect or a 410.
            var activate = await _client.PostAsync("/v1/activate", new StringContent("not json"));

            Assert.Equal(HttpStatusCode.BadRequest, activate.StatusCode);
        }

        [Fact]
        public async Task Without_a_portal_url_the_service_still_sells_for_itself()
        {
            await DisposeAsync();
            _app = null;
            await StartAsync(null);

            var root = await _client.GetAsync("/");

            Assert.Equal(HttpStatusCode.Found, root.StatusCode);
            Assert.Equal("/buy", root.Headers.Location.ToString());
            Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/buy")).StatusCode);
        }

        [Fact]
        public async Task The_paypal_webhook_is_not_mapped_in_portal_mode()
        {
            var response = await _client.PostAsync("/paypal/webhook", new StringContent("{}"));

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }

        [Fact]
        public async Task The_paypal_webhook_is_still_mapped_without_a_portal_url()
        {
            await DisposeAsync();
            _app = null;
            await StartAsync(null);

            var response = await _client.PostAsync("/paypal/webhook", new StringContent("{}"));

            Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
        }

        [Fact]
        public async Task Portal_mode_starts_with_no_paypal_configuration_at_all()
        {
            await DisposeAsync();
            _app = null;

            await StartAsync(Portal, o =>
            {
                o.PayPal.WebhookId = null;
                o.PayPal.ClientId = null;
                o.PayPal.ClientSecret = null;
                o.PayPal.Price = null;
                o.PayPal.MinimumAmount = null;
            });

            Assert.Empty(_service.Options.Problems());
            Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/healthz")).StatusCode);
        }

        [Fact]
        public void Without_a_portal_url_missing_paypal_configuration_is_still_a_problem()
        {
            Assert.Contains(Read(null, withPayPal: false).Problems(), p => p.Contains("PAYPAL_WEBHOOK_ID"));
            Assert.Empty(Read(Portal, withPayPal: false).Problems());
        }

        [Fact]
        public async Task Paypal_settings_in_portal_mode_are_ignored_with_one_startup_warning()
        {
            await DisposeAsync();
            _app = null;

            var log = new RecordingLogger<object>();

            // TestService already sets a webhook id, so PayPal is "set anyway".
            await StartAsync(Portal, null, b => b.Logging.AddProvider(new Provider(log)));

            var warnings = log.At(LogLevel.Warning).Where(l => l.Rendered.Contains("PAYPAL_")).ToList();

            Assert.Single(warnings);
            Assert.Equal(HttpStatusCode.NotFound, (await _client.PostAsync("/paypal/webhook", new StringContent("{}"))).StatusCode);

            await DisposeAsync();
            _app = null;

            var quiet = new RecordingLogger<object>();

            await StartAsync(Portal, o => o.PayPal.WebhookId = null, b => b.Logging.AddProvider(new Provider(quiet)));

            Assert.DoesNotContain(quiet.At(LogLevel.Warning), l => l.Rendered.Contains("PAYPAL_"));
        }

        private sealed class Provider : ILoggerProvider
        {
            private readonly RecordingLogger<object> _log;

            public Provider(RecordingLogger<object> log)
            {
                _log = log;
            }

            public ILogger CreateLogger(string categoryName)
            {
                return categoryName == "Emby.Sso.LicenceService" ? _log : NullLogger.Instance;
            }

            public void Dispose()
            {
            }
        }

        [Fact]
        public void The_variable_is_read_and_must_be_an_https_url()
        {
            Assert.Equal(Portal, Read(Portal).PortalUrl);
            Assert.Null(Read(null).PortalUrl);
            Assert.DoesNotContain(Read(Portal).Problems(), p => p.Contains("LICENCE_PORTAL_URL"));
            Assert.Contains(Read("http://portal.example.com").Problems(), p => p.Contains("LICENCE_PORTAL_URL"));
            Assert.Contains(Read("not a url").Problems(), p => p.Contains("LICENCE_PORTAL_URL"));
        }

        private static ServiceOptions Read(string portalUrl, bool withPayPal = true)
        {
            var env = new Dictionary<string, string>
            {
                ["LICENCE_PUBLIC_KEYS"] = "{\"kty\":\"RSA\",\"n\":\"" + new string('A', 342) + "\",\"e\":\"AQAB\"}",
                ["PAYPAL_WEBHOOK_ID"] = withPayPal ? "WH-1" : null,
                ["LICENCE_PORTAL_URL"] = portalUrl,
            };

            return ServiceOptions.FromEnvironment(name => env.TryGetValue(name, out var v) ? v : null);
        }
    }
}

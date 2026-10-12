using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
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

        private async Task StartAsync(string portalUrl)
        {
            _service = new TestService(o => o.PortalUrl = portalUrl);
            _app = Program.BuildApp(_service.Options, builder => builder.WebHost.UseTestServer());

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
        public void The_variable_is_read_and_must_be_an_https_url()
        {
            Assert.Equal(Portal, Read(Portal).PortalUrl);
            Assert.Null(Read(null).PortalUrl);
            Assert.DoesNotContain(Read(Portal).Problems(), p => p.Contains("LICENCE_PORTAL_URL"));
            Assert.Contains(Read("http://portal.example.com").Problems(), p => p.Contains("LICENCE_PORTAL_URL"));
            Assert.Contains(Read("not a url").Problems(), p => p.Contains("LICENCE_PORTAL_URL"));
        }

        private static ServiceOptions Read(string portalUrl)
        {
            var env = new Dictionary<string, string>
            {
                ["LICENCE_PUBLIC_KEYS"] = "{\"kty\":\"RSA\",\"n\":\"" + new string('A', 342) + "\",\"e\":\"AQAB\"}",
                ["PAYPAL_WEBHOOK_ID"] = "WH-1",
                ["LICENCE_PORTAL_URL"] = portalUrl,
            };

            return ServiceOptions.FromEnvironment(name => env.TryGetValue(name, out var v) ? v : null);
        }
    }
}

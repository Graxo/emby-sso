using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// GET /buy - the link the plugin's configuration page renders into an Emby
    /// administrator's browser.
    ///
    /// The serverId on that link is a query parameter, which means it is written
    /// by whoever sends the link. It is echoed back to the page, so the tests
    /// that matter most here are the ones about escaping it.
    /// </summary>
    public class BuyPageTests : IAsyncLifetime
    {
        private TestService _service;
        private WebApplication _app;
        private HttpClient _client;

        public async Task InitializeAsync()
        {
            _service = new TestService(options =>
            {
                options.PayPal.ClientId = "client-id";
                options.PayPal.ClientSecret = "client-secret";
                options.PayPal.Price = "19.00";
            });

            _app = Program.BuildApp(_service.Options, builder => builder.WebHost.UseTestServer());

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

            _service?.Dispose();
        }

        /// <summary>
        /// The regression that broke checkout entirely. `form-action` is checked
        /// against every hop a form submission takes, and POST /buy/start
        /// answers 303 to PayPal - so a policy of `form-action 'self'` had the
        /// browser refuse the submission and name /buy/start as the violation,
        /// which is 'self' and looked impossible. The buyer saw a Pay button
        /// that did nothing.
        /// </summary>
        [Fact]
        public async Task The_buy_page_may_hand_a_form_to_paypal()
        {
            var response = await _client.GetAsync("/buy?serverId=c5bc6e91458540caa295c4efdda1a58a");

            var policy = response.Headers.GetValues("Content-Security-Policy").ToArray()[0];

            Assert.Contains(
                "form-action 'self' https://www.sandbox.paypal.com",
                policy,
                StringComparison.Ordinal);
        }

        /// <summary>
        /// A live deployment must not let a form be posted to the sandbox, and
        /// the PayPal allowance must not leak onto any other page - least of all
        /// the admin pages, where form-action 'self' is what stops an injected
        /// form posting the operator's session somewhere else.
        /// </summary>
        [Fact]
        public async Task Only_the_buy_pages_may_reach_paypal_and_only_the_configured_one()
        {
            Assert.Contains(
                "form-action 'self' https://www.paypal.com;",
                Http.SecurityHeaders.BuyPolicy(live: true),
                StringComparison.Ordinal);

            Assert.DoesNotContain(
                "sandbox",
                Http.SecurityHeaders.BuyPolicy(live: true),
                StringComparison.Ordinal);

            Assert.DoesNotContain("paypal", Http.SecurityHeaders.PagePolicy, StringComparison.Ordinal);
            Assert.DoesNotContain("paypal", Http.SecurityHeaders.ApiPolicy, StringComparison.Ordinal);

            var admin = await _client.GetAsync("/admin");

            Assert.DoesNotContain(
                "paypal",
                admin.Headers.GetValues("Content-Security-Policy").ToArray()[0],
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task It_answers_HTML_and_says_what_is_being_bought()
        {
            var response = await _client.GetAsync("/buy?serverId=c5bc6e91458540caa295c4efdda1a58a");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("text/html", response.Content.Headers.ContentType.MediaType);

            var html = await response.Content.ReadAsStringAsync();

            Assert.Contains("19.00", html, StringComparison.Ordinal);
            Assert.Contains("GBP", html, StringComparison.Ordinal);
            Assert.Contains("365 days", html, StringComparison.Ordinal);
            Assert.Contains("3 Emby servers", html, StringComparison.Ordinal);
            Assert.Contains("Pay with PayPal", html, StringComparison.Ordinal);
        }

        [Fact]
        public async Task It_works_with_no_server_id_at_all()
        {
            var response = await _client.GetAsync("/buy");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("Pay with PayPal", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("<script>alert(1)</script>")]
        [InlineData("\"><script>alert(1)</script>")]
        [InlineData("' onmouseover='alert(1)")]
        [InlineData("javascript:alert(1)")]
        public async Task A_server_id_that_is_an_attack_never_reaches_the_page(string serverId)
        {
            var response = await _client
                .GetAsync("/buy?serverId=" + Uri.EscapeDataString(serverId));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var html = await response.Content.ReadAsStringAsync();

            // Two defences, and this asserts both: it is not a plausible server
            // id so it is dropped entirely, and anything that did reach the page
            // would be HTML-encoded.
            Assert.DoesNotContain("<script>", html, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("onmouseover", html, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("javascript:", html, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task A_plausible_server_id_is_shown_back_and_the_page_says_it_binds_nothing()
        {
            var response = await _client.GetAsync("/buy?serverId=c5bc6e91458540caa295c4efdda1a58a");

            var html = await response.Content.ReadAsStringAsync();

            Assert.Contains("c5bc6e91458540caa295c4efdda1a58a", html, StringComparison.Ordinal);
            Assert.Contains("not tied to it yet", html, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_button_is_a_form_post_so_that_nothing_creates_an_order_by_loading_the_page()
        {
            var html = await _client.GetStringAsync("/buy");

            Assert.Contains("<form method=\"post\" action=\"/buy/start\">", html, StringComparison.Ordinal);

            // No script at all: a checkout that needs JavaScript is a checkout
            // that fails silently for somebody.
            Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task The_completed_page_never_shows_a_code_and_says_the_tab_does_not_matter()
        {
            var html = await _client.GetStringAsync("/buy/complete");

            Assert.Contains("Thank you", html, StringComparison.Ordinal);
            Assert.Contains("Closing it now loses nothing", html, StringComparison.Ordinal);
            Assert.Contains("email address on your PayPal payment", html, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_cancelled_page_says_nothing_was_charged()
        {
            var html = await _client.GetStringAsync("/buy/cancelled");

            Assert.Contains("Nothing was charged", html, StringComparison.Ordinal);
        }

        [Fact]
        public async Task With_PayPal_unconfigured_the_page_says_so_instead_of_showing_a_button_that_cannot_work()
        {
            using var unconfigured = new TestService(options =>
            {
                options.PayPal.ClientId = null;
                options.PayPal.ClientSecret = null;
            });

            var app = Program.BuildApp(unconfigured.Options, builder => builder.WebHost.UseTestServer());

            try
            {
                await app.StartAsync();

                using var client = app.GetTestClient();

                var html = await client.GetStringAsync("/buy");

                Assert.Contains("not set up to take payments yet", html, StringComparison.Ordinal);
                Assert.DoesNotContain("Pay with PayPal", html, StringComparison.Ordinal);

                using var content = new FormUrlEncodedContent(Array.Empty<System.Collections.Generic.KeyValuePair<string, string>>());

                var response = await client.PostAsync("/buy/start", content);

                Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            }
            finally
            {
                await app.StopAsync();
                await app.DisposeAsync();
            }
        }

        [Fact]
        public async Task Starting_a_purchase_is_rate_limited_like_everything_else_unauthenticated()
        {
            using var throttled = new TestService(options =>
            {
                options.PayPal.ClientId = "client-id";
                options.PayPal.ClientSecret = "client-secret";
                options.RateLimit.PerClientBurst = 1;
                options.RateLimit.PerClientPerMinute = 1;
            });

            var app = Program.BuildApp(throttled.Options, builder => builder.WebHost.UseTestServer());

            try
            {
                await app.StartAsync();

                using var client = app.GetTestClient();
                var empty = Array.Empty<System.Collections.Generic.KeyValuePair<string, string>>();

                // The first attempt reaches PayPal, which is unreachable from
                // here, so it fails with 502 - which is fine: what is under test
                // is that the SECOND attempt does not get that far.
                using (var first = new FormUrlEncodedContent(empty))
                {
                    await client.PostAsync("/buy/start", first);
                }

                using var second = new FormUrlEncodedContent(empty);

                var response = await client.PostAsync("/buy/start", second);

                Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
                Assert.True(response.Headers.Contains("Retry-After"));
            }
            finally
            {
                await app.StopAsync();
                await app.DisposeAsync();
            }
        }
    }
}

using System;
using System.Net;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Admin;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The door itself: whether it exists, what opens it, what it hands back,
    /// and what happens to the things that open it afterwards.
    ///
    /// These are the security properties, not the happy path. Each one is
    /// written so that removing the guard it names makes it fail.
    /// </summary>
    public class AdminEndpointTests
    {
        private const string ServerA = "c5bc6e91458540caa295c4efdda1a58a";

        // ------------------------------------------- the page that is absent

        /// <summary>
        /// The first requirement, and the one a warning banner would fail: with
        /// no password configured there is no page. Not a login form, not a 401,
        /// not a default password - the routes are never mapped, so /admin
        /// answers what any other unrouted path answers.
        /// </summary>
        [Fact]
        public async Task With_no_password_configured_there_is_no_admin_page_at_all()
        {
            await using var host = await AdminTestHost.StartAsync(options =>
            {
                options.Admin.PasswordHash = null;
                options.Admin.Password = null;
            });

            foreach (var path in new[] { "/admin", "/admin/codes", "/admin/issue", "/admin/outbox", "/admin/audit" })
            {
                using var response = await host.GetAsync(path);

                Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            }

            using var login = await host.PostAsync("/admin/login", ("password", AdminTestHost.Password));

            Assert.Equal(HttpStatusCode.NotFound, login.StatusCode);

            // And nothing anywhere hints that one is a configuration change away.
            using var health = await host.GetAsync("/healthz");

            Assert.DoesNotContain("admin", await health.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task An_unconfigured_service_still_serves_everything_else()
        {
            await using var host = await AdminTestHost.StartAsync(options =>
            {
                options.Admin.PasswordHash = null;
            });

            using var buy = await host.GetAsync("/buy");

            Assert.Equal(HttpStatusCode.OK, buy.StatusCode);
        }

        // ------------------------------------------------------------- login

        [Fact]
        public async Task The_login_page_is_a_form_and_nothing_else()
        {
            await using var host = await AdminTestHost.StartAsync();

            using var response = await host.GetAsync("/admin");
            var html = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("name=\"password\"", html, StringComparison.Ordinal);
            Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
            Assert.Null(response.SetCookieOf());
        }

        [Fact]
        public async Task A_wrong_password_is_refused_and_hands_out_no_session()
        {
            await using var host = await AdminTestHost.StartAsync();

            using var response = await host.PostAsync("/admin/login", ("password", "not the password"));

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(response.SetCookieOf());
            Assert.Contains(AdminAudit.LoginFailed, host.AuditFile(), StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_empty_password_is_refused()
        {
            await using var host = await AdminTestHost.StartAsync();

            using var response = await host.PostAsync("/admin/login", ("password", string.Empty));

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(response.SetCookieOf());
        }

        [Fact]
        public async Task A_login_with_no_form_at_all_is_refused()
        {
            await using var host = await AdminTestHost.StartAsync();

            using var response = await host.PostAsync("/admin/login");

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(response.SetCookieOf());
        }

        /// <summary>
        /// Every attribute the brief asks for, checked on the header as it goes
        /// out. The `__Host-` prefix is checked too: a browser refuses such a
        /// cookie unless it is Secure, has no Domain and has Path=/, so the name
        /// is a second enforcement of the same three properties.
        /// </summary>
        [Fact]
        public async Task The_session_cookie_carries_every_attribute_that_protects_it()
        {
            await using var host = await AdminTestHost.StartAsync();

            var header = await host.LoginAsync();

            Assert.NotNull(header);
            Assert.StartsWith("__Host-", header, StringComparison.Ordinal);
            Assert.Contains("httponly", header, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("secure", header, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("samesite=strict", header, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("path=/", header, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("domain=", header, StringComparison.OrdinalIgnoreCase);

            // A session cookie: nothing written to the disk of whatever machine
            // the operator happened to sign in from.
            Assert.DoesNotContain("expires=", header, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("max-age=", header, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task A_correct_password_lands_on_the_codes_page_and_is_audited()
        {
            await using var host = await AdminTestHost.StartAsync();

            using var response = await host.PostAsync("/admin/login", ("password", AdminTestHost.Password));

            Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
            Assert.Equal("/admin/codes", response.LocationOf());
            Assert.Contains("\"event\":\"" + AdminAudit.LoggedIn + "\"", host.AuditFile(), StringComparison.Ordinal);
        }

        /// <summary>
        /// The password never reaches the audit trail, whatever it was. This
        /// fails if a future edit records "tried: &lt;submitted&gt;".
        /// </summary>
        [Fact]
        public async Task No_submitted_password_reaches_the_audit_trail()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.PostAsync("/admin/login", ("password", "a-distinctive-wrong-password-4718"));
            await host.LoginAsync();

            var audit = host.AuditFile();

            Assert.DoesNotContain("a-distinctive-wrong-password-4718", audit, StringComparison.Ordinal);
            Assert.DoesNotContain(AdminTestHost.Password, audit, StringComparison.Ordinal);
        }

        // ---------------------------------------------------- rate limiting

        [Fact]
        public async Task Wrong_passwords_buy_an_increasing_wait_rather_than_a_lockout()
        {
            await using var host = await AdminTestHost.StartAsync();

            using (var first = await host.PostAsync("/admin/login", ("password", "wrong")))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);
            }

            using (var second = await host.PostAsync("/admin/login", ("password", "wrong")))
            {
                Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
                Assert.NotNull(second.HeaderOf("Retry-After"));
            }

            // Even the RIGHT password is refused while the wait runs: the check
            // happens before the password is looked at, so guessing cannot make
            // this service spend PBKDF2 time.
            using (var during = await host.PostAsync("/admin/login", ("password", AdminTestHost.Password)))
            {
                Assert.Equal(HttpStatusCode.TooManyRequests, during.StatusCode);
            }

            host.Clock.Advance(TimeSpan.FromMinutes(5));

            var header = await host.LoginAsync();

            Assert.NotNull(header);
        }

        /// <summary>
        /// The login's budget is its own. A caller who has spent every
        /// activation attempt they have can still sign in, and vice versa - the
        /// property the brief asks for, checked over the wire.
        /// </summary>
        [Fact]
        public async Task The_login_budget_is_not_the_activation_endpoints_budget()
        {
            await using var host = await AdminTestHost.StartAsync(options =>
            {
                options.RateLimit.PerClientBurst = 2;
                options.RateLimit.PerClientPerMinute = 2;
            });

            for (var i = 0; i < 6; i++)
            {
                using var spend = await host.PostAsync("/v1/activate");

                _ = spend;
            }

            var header = await host.LoginAsync();

            Assert.NotNull(header);
        }

        // ------------------------------------------------- what needs a session

        [Theory]
        [InlineData("/admin/codes")]
        [InlineData("/admin/issue")]
        [InlineData("/admin/outbox")]
        [InlineData("/admin/audit")]
        [InlineData("/admin/issued")]
        [InlineData("/admin/code/0123456789ab")]
        public async Task Every_page_behind_the_door_needs_a_session(string path)
        {
            await using var host = await AdminTestHost.StartAsync();

            using var response = await host.GetAsync(path);

            Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
            Assert.Equal("/admin", response.LocationOf());
        }

        [Fact]
        public async Task A_cookie_nobody_issued_authorises_nothing()
        {
            await using var host = await AdminTestHost.StartAsync
                ();

            host.Cookie = AdminSessions.CookieName + "=this-is-not-a-session-id";

            using var response = await host.GetAsync("/admin/codes");

            Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
            Assert.Equal("/admin", response.LocationOf());
        }

        // ---------------------------------------------------------- sessions

        [Fact]
        public async Task A_session_left_alone_past_the_idle_timeout_stops_working()
        {
            await using var host = await AdminTestHost.StartAsync(options => options.Admin.IdleMinutes = 30);

            await host.LoginAsync();

            using (var live = await host.GetAsync("/admin/codes"))
            {
                Assert.Equal(HttpStatusCode.OK, live.StatusCode);
            }

            host.Clock.Advance(TimeSpan.FromMinutes(31));

            using var expired = await host.GetAsync("/admin/codes");

            Assert.Equal(HttpStatusCode.SeeOther, expired.StatusCode);
            Assert.Equal("/admin", expired.LocationOf());
        }

        [Fact]
        public async Task No_amount_of_activity_gets_a_session_past_the_absolute_timeout()
        {
            await using var host = await AdminTestHost.StartAsync(options =>
            {
                options.Admin.IdleMinutes = 30;
                options.Admin.AbsoluteMinutes = 120;
            });

            await host.LoginAsync();

            for (var i = 0; i < 5; i++)
            {
                host.Clock.Advance(TimeSpan.FromMinutes(20));

                using var beat = await host.GetAsync("/admin/codes");

                _ = beat;
            }

            host.Clock.Advance(TimeSpan.FromMinutes(21));

            using var response = await host.GetAsync("/admin/codes");

            Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        }

        /// <summary>
        /// Logout has to destroy the state on the server, not merely clear the
        /// cookie: the same cookie value, replayed by something that kept a copy
        /// of it, must be worth nothing. This test deliberately keeps the cookie
        /// after signing out and sends it again.
        /// </summary>
        [Fact]
        public async Task Logging_out_destroys_the_session_on_the_server()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var page = await host.BodyOfAsync("/admin/codes");
            var stolen = host.Cookie;

            using (var logout = await host.PostAsync("/admin/logout", ("csrf", AdminTestHost.CsrfIn(page))))
            {
                Assert.Equal(HttpStatusCode.SeeOther, logout.StatusCode);
            }

            host.Cookie = stolen;

            using var replayed = await host.GetAsync("/admin/codes");

            Assert.Equal(HttpStatusCode.SeeOther, replayed.StatusCode);
            Assert.Equal("/admin", replayed.LocationOf());
            Assert.Contains("\"event\":\"" + AdminAudit.LoggedOut + "\"", host.AuditFile(), StringComparison.Ordinal);
        }

        // -------------------------------------------------------------- CSRF

        [Fact]
        public async Task A_state_changing_post_with_no_csrf_token_is_refused()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = host.Service.GiveOutACode();
            var tag = RedemptionCode.LogTag(RedemptionCode.Hash(Normalise(code)));

            using var response = await host.PostAsync("/admin/void", ("tag", tag), ("reason", "csrf test"));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.NotEqual("void", host.Service.Store.FindCodeByHash(HashOf(code)).Status);
            Assert.Contains(AdminAudit.CsrfRefused, host.AuditFile(), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_csrf_token_from_somebody_elses_session_is_refused()
        {
            await using var host = await AdminTestHost.StartAsync();

            // One browser signs in, reads its token, and keeps it.
            await host.LoginAsync();

            var foreign = AdminTestHost.CsrfIn(await host.BodyOfAsync("/admin/codes"));

            // A second sign-in is a second session with a token of its own.
            host.Cookie = null;

            await host.LoginAsync();

            var code = host.Service.GiveOutACode();
            var tag = RedemptionCode.LogTag(HashOf(code));

            using var response = await host.PostAsync(
                "/admin/void",
                ("csrf", foreign),
                ("tag", tag),
                ("reason", "csrf test"));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.NotEqual("void", host.Service.Store.FindCodeByHash(HashOf(code)).Status);
        }

        [Fact]
        public async Task An_empty_csrf_token_is_refused()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var page = await host.BodyOfAsync("/admin/codes");

            _ = page;

            using var response = await host.PostAsync("/admin/void", ("csrf", string.Empty), ("tag", "0123456789ab"));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task Logging_out_without_the_token_leaves_the_session_alone()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            using (var refused = await host.PostAsync("/admin/logout"))
            {
                Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            }

            using var still = await host.GetAsync("/admin/codes");

            Assert.Equal(HttpStatusCode.OK, still.StatusCode);
        }

        // ----------------------------------------------------------- headers

        [Fact]
        public async Task Every_admin_response_says_do_not_store_this()
        {
            await using var host = await AdminTestHost.StartAsync();

            using (var anonymous = await host.GetAsync("/admin"))
            {
                AssertHeaders(anonymous, mustBeNoStore: true);
            }

            await host.LoginAsync();

            using (var page = await host.GetAsync("/admin/codes"))
            {
                AssertHeaders(page, mustBeNoStore: true);
            }

            using (var redirect = await host.GetAsync("/admin"))
            {
                Assert.Equal(HttpStatusCode.SeeOther, redirect.StatusCode);
                AssertHeaders(redirect, mustBeNoStore: true);
            }
        }

        [Fact]
        public async Task The_buy_page_carries_the_headers_too()
        {
            await using var host = await AdminTestHost.StartAsync();

            using var response = await host.GetAsync("/buy");

            AssertHeaders(response, mustBeNoStore: false);
        }

        private static void AssertHeaders(System.Net.Http.HttpResponseMessage response, bool mustBeNoStore)
        {
            Assert.Equal("nosniff", response.HeaderOf("X-Content-Type-Options"));
            Assert.Equal("DENY", response.HeaderOf("X-Frame-Options"));
            Assert.Equal("no-referrer", response.HeaderOf("Referrer-Policy"));

            var policy = response.HeaderOf("Content-Security-Policy");

            Assert.NotNull(policy);
            Assert.Contains("default-src 'none'", policy, StringComparison.Ordinal);
            Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);

            if (mustBeNoStore)
            {
                Assert.Contains("no-store", response.HeaderOf("Cache-Control"), StringComparison.Ordinal);
                Assert.Contains("form-action 'self'", policy, StringComparison.Ordinal);
            }
        }

        // ------------------------------------------------------------ helpers

        private static string Normalise(string code)
        {
            RedemptionCode.TryNormalise(code, out var normalised);

            return normalised;
        }

        private static string HashOf(string code)
        {
            return RedemptionCode.Hash(Normalise(code));
        }
    }
}

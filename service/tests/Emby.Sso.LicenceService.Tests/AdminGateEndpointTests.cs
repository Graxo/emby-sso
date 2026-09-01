using System;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The gate as a request actually meets it: over HTTP, in front of every
    /// /admin route, before the login form is even rendered.
    ///
    /// The refusal is a 404, and these tests hold it to that. A 403 would tell
    /// somebody scanning for admin panels that there is one here and it is worth
    /// coming back to from a different address; a 404 tells them what every
    /// unmapped path tells them.
    /// </summary>
    public class AdminGateEndpointTests
    {
        [Fact]
        public async Task A_caller_outside_the_allowed_networks_finds_no_admin_page_at_all()
        {
            await using var host = await AdminTestHost.StartAsync(options =>
                options.Admin.AllowedNetworks = "203.0.113.0/24");

            // The TestServer's client has no remote address, which is exactly
            // the "cannot tell" case the gate must refuse.
            Assert.Equal(HttpStatusCode.NotFound, (await host.GetAsync("/admin")).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await host.GetAsync("/admin/codes")).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await host.GetAsync("/admin/signing")).StatusCode);
        }

        [Fact]
        public async Task The_refusal_happens_before_the_login_form_and_before_any_password_work()
        {
            await using var host = await AdminTestHost.StartAsync(options =>
                options.Admin.AllowedNetworks = "203.0.113.0/24");

            var response = await host.PostAsync("/admin/login", ("password", "anything-at-all"));

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

            // And no login attempt was recorded, because none reached the page:
            // the audit trail is for things that happened at the door, not for
            // traffic that never found it.
            Assert.DoesNotContain("login_failed", await AuditText(host), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_required_header_gates_the_page_and_the_right_value_opens_it()
        {
            await using var host = await AdminTestHost.StartAsync(options =>
            {
                options.Admin.RequiredHeaderName = "X-From-The-Proxy";
                options.Admin.RequiredHeaderValue = "a-long-shared-secret-value";
            });

            Assert.Equal(HttpStatusCode.NotFound, (await host.GetAsync("/admin")).StatusCode);

            var admitted = await host.GetWithHeaderAsync("/admin", "X-From-The-Proxy", "a-long-shared-secret-value");

            Assert.Equal(HttpStatusCode.OK, admitted.StatusCode);
            Assert.Contains("Password", await admitted.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_wrong_header_value_is_refused()
        {
            await using var host = await AdminTestHost.StartAsync(options =>
            {
                options.Admin.RequiredHeaderName = "X-From-The-Proxy";
                options.Admin.RequiredHeaderValue = "a-long-shared-secret-value";
            });

            var refused = await host.GetWithHeaderAsync("/admin", "X-From-The-Proxy", "not-the-secret-value-here");

            Assert.Equal(HttpStatusCode.NotFound, refused.StatusCode);
        }

        [Fact]
        public async Task Nothing_outside_admin_is_affected_by_the_gate()
        {
            await using var host = await AdminTestHost.StartAsync(options =>
                options.Admin.AllowedNetworks = "203.0.113.0/24");

            // The gate is a guard on one page, not a firewall on the service. A
            // customer activating a licence must be unaffected by it.
            Assert.Equal(HttpStatusCode.OK, (await host.GetAsync("/healthz")).StatusCode);
        }

        [Fact]
        public async Task With_no_restriction_configured_the_page_is_reachable_as_before()
        {
            await using var host = await AdminTestHost.StartAsync();

            Assert.Equal(HttpStatusCode.OK, (await host.GetAsync("/admin")).StatusCode);
        }

        private static async Task<string> AuditText(AdminTestHost host)
        {
            var path = host.Options.AdminAuditPath;

            return System.IO.File.Exists(path)
                ? await System.IO.File.ReadAllTextAsync(path)
                : string.Empty;
        }
    }
}

using System;
using System.Net;
using Emby.Sso.LicenceService.Admin;
using Emby.Sso.LicenceService.Configuration;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// What stands in front of the admin password.
    ///
    /// Both guards are off by default, and both must FAIL CLOSED when on: the
    /// direction of every test here is that anything unexpected - no address, a
    /// short forwarded chain, a missing header, an address family that does not
    /// match - is a refusal rather than a pass. A defence-in-depth layer that
    /// falls open under an odd input is not a layer.
    /// </summary>
    public class AdminAccessGateTests
    {
        [Fact]
        public void With_nothing_configured_the_gate_is_open_and_the_password_is_on_its_own()
        {
            var gate = new AdminAccessGate(new AdminOptions(), 0);

            Assert.True(gate.IsOpen);
            Assert.True(gate.Admits(IPAddress.Parse("198.51.100.7"), null, null));
        }

        [Theory]
        [InlineData("203.0.113.4", "203.0.113.4", true)]
        [InlineData("203.0.113.4", "203.0.113.5", false)]
        [InlineData("203.0.113.0/24", "203.0.113.200", true)]
        [InlineData("203.0.113.0/24", "203.0.114.1", false)]
        [InlineData("10.0.0.0/8", "10.44.7.9", true)]
        [InlineData("10.0.0.0/8", "11.0.0.1", false)]
        [InlineData("192.168.1.0/28", "192.168.1.15", true)]
        [InlineData("192.168.1.0/28", "192.168.1.16", false)]
        [InlineData("::1/128", "::1", true)]
        [InlineData("2001:db8::/32", "2001:db8:1234::9", true)]
        [InlineData("2001:db8::/32", "2001:db9::1", false)]
        public void An_address_is_admitted_only_if_a_named_network_contains_it(string allowed, string caller, bool admitted)
        {
            var gate = Gate(allowed);

            Assert.Equal(admitted, gate.Admits(IPAddress.Parse(caller), null, null));
        }

        [Fact]
        public void A_bare_address_means_that_host_and_not_its_network()
        {
            var gate = Gate("203.0.113.4");

            Assert.True(gate.Admits(IPAddress.Parse("203.0.113.4"), null, null));
            Assert.False(gate.Admits(IPAddress.Parse("203.0.113.3"), null, null));
        }

        [Fact]
        public void An_ipv4_range_does_not_contain_an_ipv6_address()
        {
            var gate = Gate("0.0.0.0/0");

            Assert.True(gate.Admits(IPAddress.Parse("8.8.8.8"), null, null));
            Assert.False(gate.Admits(IPAddress.Parse("2001:db8::1"), null, null));
        }

        [Fact]
        public void An_ipv4_mapped_ipv6_address_is_the_ipv4_address()
        {
            // Kestrel on a dual-stack socket reports ::ffff:203.0.113.4 for a
            // plain IPv4 client. An operator who allowed 203.0.113.4 means that
            // host, and finding it refused for a reason invisible from outside
            // is how a working restriction gets turned off in frustration.
            var gate = Gate("203.0.113.4");

            Assert.True(gate.Admits(IPAddress.Parse("::ffff:203.0.113.4"), null, null));
        }

        [Fact]
        public void With_no_address_at_all_the_request_is_refused()
        {
            // A check that cannot be made has not passed.
            Assert.False(Gate("203.0.113.4").Admits(null, null, null));
        }

        [Fact]
        public void Without_a_trusted_proxy_the_forwarded_header_is_ignored()
        {
            // The dangerous direction. With LICENCE_TRUSTED_PROXY_HOPS at its
            // default of 0, a caller who sends X-Forwarded-For must not be able
            // to choose the address they are judged by.
            var gate = Gate("203.0.113.4", hops: 0);

            Assert.False(gate.Admits(IPAddress.Parse("198.51.100.9"), "203.0.113.4", null));
        }

        [Fact]
        public void With_one_trusted_proxy_the_last_entry_is_the_client()
        {
            var gate = Gate("203.0.113.4", hops: 1);

            Assert.True(gate.Admits(IPAddress.Parse("10.0.0.1"), "203.0.113.4", null));

            // And a caller prepending their own value cannot reach past the hop
            // the proxy wrote, because the chain is read from the right.
            Assert.True(gate.Admits(IPAddress.Parse("10.0.0.1"), "203.0.113.99, 203.0.113.4", null));
            Assert.False(gate.Admits(IPAddress.Parse("10.0.0.1"), "203.0.113.4, 203.0.113.99", null));
        }

        [Fact]
        public void A_forwarded_chain_shorter_than_the_configured_hops_falls_back_to_the_peer()
        {
            // Which for a request that really came through the proxy is the
            // proxy's own address, and is therefore refused unless that address
            // was allowed. Fail closed.
            var gate = Gate("203.0.113.4", hops: 2);

            Assert.False(gate.Admits(IPAddress.Parse("10.0.0.1"), "203.0.113.4", null));
        }

        [Fact]
        public void A_forwarded_entry_that_is_not_an_address_is_refused()
        {
            Assert.False(Gate("203.0.113.4", hops: 1).Admits(IPAddress.Parse("10.0.0.1"), "not-an-address", null));
        }

        [Fact]
        public void A_required_header_must_be_present_and_exact()
        {
            var gate = new AdminAccessGate(
                new AdminOptions
                {
                    RequiredHeaderName = "X-From-The-Proxy",
                    RequiredHeaderValue = "a-long-shared-secret-value",
                },
                0);

            Assert.False(gate.IsOpen);
            Assert.Equal("X-From-The-Proxy", gate.HeaderName);

            Assert.True(gate.Admits(IPAddress.Parse("198.51.100.7"), null, "a-long-shared-secret-value"));
            Assert.False(gate.Admits(IPAddress.Parse("198.51.100.7"), null, null));
            Assert.False(gate.Admits(IPAddress.Parse("198.51.100.7"), null, string.Empty));
            Assert.False(gate.Admits(IPAddress.Parse("198.51.100.7"), null, "a-long-shared-secret-valu"));
            Assert.False(gate.Admits(IPAddress.Parse("198.51.100.7"), null, "A-LONG-SHARED-SECRET-VALUE"));
        }

        [Fact]
        public void Both_guards_must_pass_when_both_are_configured()
        {
            var gate = new AdminAccessGate(
                new AdminOptions
                {
                    AllowedNetworks = "203.0.113.0/24",
                    RequiredHeaderName = "X-From-The-Proxy",
                    RequiredHeaderValue = "a-long-shared-secret-value",
                },
                0);

            Assert.True(gate.Admits(IPAddress.Parse("203.0.113.9"), null, "a-long-shared-secret-value"));
            Assert.False(gate.Admits(IPAddress.Parse("198.51.100.9"), null, "a-long-shared-secret-value"));
            Assert.False(gate.Admits(IPAddress.Parse("203.0.113.9"), null, "wrong"));
        }

        [Fact]
        public void An_empty_header_value_is_refused_at_construction_rather_than_admitting_everything()
        {
            Assert.Throws<ArgumentException>(() => new AdminAccessGate(
                new AdminOptions { RequiredHeaderName = "X-From-The-Proxy", RequiredHeaderValue = string.Empty },
                0));
        }

        [Theory]
        [InlineData("not-an-address")]
        [InlineData("203.0.113.4/33")]
        [InlineData("203.0.113.4/-1")]
        [InlineData("2001:db8::/129")]
        [InlineData(" , ")]
        public void A_list_that_cannot_be_parsed_is_refused_by_name(string value)
        {
            Assert.False(AdminAccessGate.TryParseNetworks(value, out _, out var problem));
            Assert.False(string.IsNullOrWhiteSpace(problem));
        }

        [Fact]
        public void Whitespace_and_empty_entries_are_tolerated()
        {
            Assert.True(AdminAccessGate.TryParseNetworks(" 10.0.0.0/8 ,, 203.0.113.4 ", out var networks, out _));
            Assert.Equal(2, networks.Count);
        }

        [Fact]
        public void The_configuration_refuses_to_start_on_an_unusable_list()
        {
            var admin = new AdminOptions { Password = "a-long-enough-admin-password", AllowedNetworks = "nonsense" };

            Assert.Contains(admin.Problems(), p => p.Contains("ADMIN_ALLOWED_CIDRS", StringComparison.Ordinal));
        }

        [Fact]
        public void The_configuration_refuses_a_header_check_with_no_value_or_a_short_one()
        {
            var empty = new AdminOptions
            {
                Password = "a-long-enough-admin-password",
                RequiredHeaderName = "X-From-The-Proxy",
                RequiredHeaderValue = string.Empty,
            };

            Assert.Contains(empty.Problems(), p => p.Contains("ADMIN_REQUIRED_HEADER_VALUE", StringComparison.Ordinal));

            var brief = new AdminOptions
            {
                Password = "a-long-enough-admin-password",
                RequiredHeaderName = "X-From-The-Proxy",
                RequiredHeaderValue = "short",
            };

            Assert.Contains(brief.Problems(), p => p.Contains("ADMIN_REQUIRED_HEADER_VALUE", StringComparison.Ordinal));
        }

        [Fact]
        public void The_startup_line_says_when_the_password_is_the_only_thing_guarding_the_page()
        {
            var alone = new AdminOptions { Password = "a-long-enough-admin-password" };

            Assert.Contains("PASSWORD ONLY", alone.Describe(), StringComparison.Ordinal);

            var guarded = new AdminOptions
            {
                Password = "a-long-enough-admin-password",
                AllowedNetworks = "10.0.0.0/8",
            };

            Assert.DoesNotContain("PASSWORD ONLY", guarded.Describe(), StringComparison.Ordinal);

            // And never the password itself, however it is configured.
            Assert.DoesNotContain("a-long-enough-admin-password", guarded.Describe(), StringComparison.Ordinal);
        }

        private static AdminAccessGate Gate(string allowed, int hops = 0)
        {
            return new AdminAccessGate(new AdminOptions { AllowedNetworks = allowed }, hops);
        }
    }
}

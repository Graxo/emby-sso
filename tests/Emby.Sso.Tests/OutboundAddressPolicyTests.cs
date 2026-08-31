using System;
using System.Net;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class OutboundAddressPolicyTests
    {
        public class ClassifyTests
        {
            [Theory]
            [InlineData("127.0.0.1")]
            [InlineData("127.255.255.254")]
            [InlineData("::1")]
            public void Loopback_addresses_are_recognised(string address)
            {
                Assert.Equal(
                    OutboundAddressOutcome.Loopback,
                    OutboundAddressPolicy.Classify(IPAddress.Parse(address)));
            }

            [Theory]
            [InlineData("10.0.0.1")]
            [InlineData("10.255.255.255")]
            [InlineData("172.16.0.1")]
            [InlineData("172.31.255.254")]
            [InlineData("192.168.1.1")]
            [InlineData("fc00::1")]
            [InlineData("fd12:3456:789a::1")]
            [InlineData("fec0::1")]
            public void Private_addresses_are_recognised(string address)
            {
                Assert.Equal(
                    OutboundAddressOutcome.PrivateNetwork,
                    OutboundAddressPolicy.Classify(IPAddress.Parse(address)));
            }

            [Theory]
            [InlineData("169.254.0.1")]
            [InlineData("169.254.169.254")]
            [InlineData("fe80::1")]
            public void Link_local_addresses_are_recognised(string address)
            {
                Assert.Equal(
                    OutboundAddressOutcome.LinkLocal,
                    OutboundAddressPolicy.Classify(IPAddress.Parse(address)));
            }

            [Theory]
            [InlineData("100.64.0.1")]
            [InlineData("100.127.255.254")]
            public void Carrier_grade_nat_is_recognised(string address)
            {
                Assert.Equal(
                    OutboundAddressOutcome.SharedAddressSpace,
                    OutboundAddressPolicy.Classify(IPAddress.Parse(address)));
            }

            [Theory]
            [InlineData("0.0.0.0")]
            [InlineData("::")]
            public void The_unspecified_address_is_recognised(string address)
            {
                Assert.Equal(
                    OutboundAddressOutcome.Unspecified,
                    OutboundAddressPolicy.Classify(IPAddress.Parse(address)));
            }

            [Theory]
            [InlineData("224.0.0.1")]
            [InlineData("239.255.255.250")]
            [InlineData("ff02::1")]
            public void Multicast_addresses_are_recognised(string address)
            {
                Assert.Equal(
                    OutboundAddressOutcome.Multicast,
                    OutboundAddressPolicy.Classify(IPAddress.Parse(address)));
            }

            [Theory]
            [InlineData("192.0.2.1")]
            [InlineData("198.18.0.1")]
            [InlineData("198.51.100.1")]
            [InlineData("203.0.113.1")]
            [InlineData("240.0.0.1")]
            [InlineData("255.255.255.255")]
            public void Reserved_ranges_are_recognised(string address)
            {
                Assert.Equal(
                    OutboundAddressOutcome.Reserved,
                    OutboundAddressPolicy.Classify(IPAddress.Parse(address)));
            }

            [Theory]
            [InlineData("8.8.8.8")]
            [InlineData("1.1.1.1")]
            [InlineData("172.15.0.1")]
            [InlineData("172.32.0.1")]
            [InlineData("192.167.1.1")]
            [InlineData("192.169.1.1")]
            [InlineData("100.63.255.255")]
            [InlineData("100.128.0.1")]
            [InlineData("2606:4700:4700::1111")]
            public void Public_addresses_are_permitted(string address)
            {
                Assert.Equal(
                    OutboundAddressOutcome.Permitted,
                    OutboundAddressPolicy.Classify(IPAddress.Parse(address)));
            }

            /// <summary>
            /// An IPv6 address can spell an IPv4 one several ways, and each of
            /// them is a way past a check that only looked at the outer address.
            ///
            /// The expected outcome travels as a name rather than as the enum
            /// itself, here and below: the enum is internal, and a public
            /// [Theory] parameter cannot be.
            /// </summary>
            [Theory]
            [InlineData("::ffff:127.0.0.1", "Loopback")]
            [InlineData("::ffff:169.254.169.254", "LinkLocal")]
            [InlineData("::ffff:10.0.0.1", "PrivateNetwork")]
            [InlineData("::ffff:8.8.8.8", "Permitted")]
            [InlineData("2002:a00:1::", "PrivateNetwork")]
            [InlineData("2002:a9fe:a9fe::", "LinkLocal")]
            [InlineData("64:ff9b::7f00:1", "Loopback")]
            public void An_ipv4_address_wrapped_in_an_ipv6_one_is_classified_as_what_it_is(
                string address,
                string expected)
            {
                Assert.Equal(
                    (OutboundAddressOutcome)Enum.Parse(typeof(OutboundAddressOutcome), expected),
                    OutboundAddressPolicy.Classify(IPAddress.Parse(address)));
            }

            [Fact]
            public void A_teredo_address_is_unwrapped_too()
            {
                // 2001:0::/32; the embedded IPv4 lives in the last four bytes,
                // stored inverted. ~10.0.0.1 is 245.255.255.254.
                Assert.Equal(
                    OutboundAddressOutcome.PrivateNetwork,
                    OutboundAddressPolicy.Classify(IPAddress.Parse("2001:0:0:0:0:0:f5ff:fffe")));
            }

            [Fact]
            public void A_null_address_is_refused_rather_than_waved_through()
            {
                Assert.Equal(
                    OutboundAddressOutcome.UnknownFamily,
                    OutboundAddressPolicy.Classify(null));
                Assert.False(OutboundAddressPolicy.Permits(OutboundAddressOutcome.UnknownFamily, true));
            }
        }

        public class PermitsTests
        {
            [Fact]
            public void A_public_address_needs_no_allowance()
            {
                Assert.True(OutboundAddressPolicy.Permits(OutboundAddressOutcome.Permitted, false));
            }

            [Theory]
            [InlineData("Loopback")]
            [InlineData("PrivateNetwork")]
            [InlineData("SharedAddressSpace")]
            public void The_home_lab_ranges_are_refused_by_default_and_permitted_by_the_setting(
                string outcomeName)
            {
                var outcome = (OutboundAddressOutcome)Enum.Parse(typeof(OutboundAddressOutcome), outcomeName);

                Assert.False(OutboundAddressPolicy.Permits(outcome, false));
                Assert.True(OutboundAddressPolicy.Permits(outcome, true));
                Assert.True(OutboundAddressPolicy.IsOverridable(outcome));
            }

            /// <summary>
            /// Nobody runs an identity provider on the cloud metadata service,
            /// so the allowance deliberately does not stretch that far.
            /// </summary>
            [Theory]
            [InlineData("LinkLocal")]
            [InlineData("Multicast")]
            [InlineData("Unspecified")]
            [InlineData("Reserved")]
            [InlineData("UnknownFamily")]
            public void The_setting_does_not_reach_the_ranges_no_provider_lives_in(
                string outcomeName)
            {
                var outcome = (OutboundAddressOutcome)Enum.Parse(typeof(OutboundAddressOutcome), outcomeName);

                Assert.False(OutboundAddressPolicy.Permits(outcome, false));
                Assert.False(OutboundAddressPolicy.Permits(outcome, true));
                Assert.False(OutboundAddressPolicy.IsOverridable(outcome));
            }
        }

        public class ExplainTests
        {
            [Fact]
            public void A_refusal_names_the_address_the_rule_and_the_setting()
            {
                var message = OutboundAddressPolicy.Explain(
                    "https://idp.example.com/.well-known/openid-configuration",
                    IPAddress.Parse("10.1.2.3"),
                    OutboundAddressOutcome.PrivateNetwork);

                Assert.Contains("https://idp.example.com/.well-known/openid-configuration", message);
                Assert.Contains("10.1.2.3", message);
                Assert.Contains("10.0.0.0/8", message);
                Assert.Contains(OutboundAddressPolicy.AllowanceSettingName, message);
            }

            [Fact]
            public void A_refusal_no_setting_can_lift_says_so_instead_of_naming_one()
            {
                var message = OutboundAddressPolicy.Explain(
                    "https://idp.example.com/",
                    IPAddress.Parse("169.254.169.254"),
                    OutboundAddressOutcome.LinkLocal);

                Assert.Contains("169.254.169.254", message);
                Assert.Contains("169.254.0.0/16", message);
                Assert.DoesNotContain(OutboundAddressPolicy.AllowanceSettingName, message);
                Assert.Contains("No setting permits this address.", message);
            }

            [Fact]
            public void A_hostile_url_cannot_forge_extra_log_lines()
            {
                var message = OutboundAddressPolicy.Explain(
                    "https://idp.example.com/\r\nInfo Something else entirely",
                    IPAddress.Parse("127.0.0.1"),
                    OutboundAddressOutcome.Loopback);

                Assert.DoesNotContain("\r", message);
                Assert.DoesNotContain("\n", message);
            }
        }
    }
}

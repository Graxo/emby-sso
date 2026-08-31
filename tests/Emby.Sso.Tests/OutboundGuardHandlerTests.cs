using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The guard in front of every provider fetch. The inner handler here
    /// records what it was asked to send, so "refused" can be distinguished
    /// from "sent and then complained about" - the whole point of the guard is
    /// that the request never leaves.
    /// </summary>
    public class OutboundGuardHandlerTests
    {
        private const string Metadata = "https://idp.test/application/o/emby/.well-known/openid-configuration";

        /// <summary>Records every request and answers from a script.</summary>
        private sealed class RecordingHandler : HttpMessageHandler
        {
            public List<HttpRequestMessage> Requests { get; } = new List<HttpRequestMessage>();

            public Queue<HttpResponseMessage> Responses { get; } = new Queue<HttpResponseMessage>();

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Requests.Add(request);

                return Task.FromResult(
                    Responses.Count > 0
                        ? Responses.Dequeue()
                        : new HttpResponseMessage(HttpStatusCode.OK));
            }
        }

        private static HttpResponseMessage Redirect(HttpStatusCode status, string location)
        {
            var response = new HttpResponseMessage(status);

            if (location != null)
            {
                response.Headers.TryAddWithoutValidation("Location", location);
            }

            return response;
        }

        private static Func<string, Task<IPAddress[]>> Resolves(params string[] addresses)
        {
            var parsed = new IPAddress[addresses.Length];

            for (var i = 0; i < addresses.Length; i++)
            {
                parsed[i] = IPAddress.Parse(addresses[i]);
            }

            return _ => Task.FromResult(parsed);
        }

        private static async Task<Exception> SendAndCatchAsync(
            RecordingHandler inner,
            HttpRequestMessage request,
            bool allowPrivateNetworks,
            Func<string, Task<IPAddress[]>> resolver)
        {
            var guard = new OutboundGuardHandler(inner, () => allowPrivateNetworks, resolver);

            using (var invoker = new HttpMessageInvoker(guard))
            {
                return await Record.ExceptionAsync(() => invoker.SendAsync(request, CancellationToken.None));
            }
        }

        private static Task<HttpResponseMessage> SendAsync(
            RecordingHandler inner,
            HttpRequestMessage request,
            bool allowPrivateNetworks,
            Func<string, Task<IPAddress[]>> resolver)
        {
            var guard = new OutboundGuardHandler(inner, () => allowPrivateNetworks, resolver);
            var invoker = new HttpMessageInvoker(guard);

            return invoker.SendAsync(request, CancellationToken.None);
        }

        public class BlockedRanges
        {
            [Theory]
            [InlineData("127.0.0.1", "loopback")]
            [InlineData("10.1.2.3", "private")]
            [InlineData("172.16.5.5", "private")]
            [InlineData("192.168.1.1", "private")]
            [InlineData("169.254.169.254", "link-local")]
            [InlineData("100.64.1.1", "carrier-grade NAT")]
            [InlineData("0.0.0.0", "unspecified")]
            [InlineData("224.0.0.1", "multicast")]
            [InlineData("198.51.100.7", "reserved")]
            [InlineData("::1", "loopback")]
            [InlineData("fd00::1", "private")]
            [InlineData("fe80::1", "link-local")]
            public async Task Each_blocked_range_is_refused_before_the_request_is_sent(
                string address,
                string ruleWording)
            {
                var inner = new RecordingHandler();

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves(address));

                var refused = Assert.IsType<OutboundRefusedException>(error);
                Assert.Empty(inner.Requests);
                Assert.Contains(address, refused.Message);
                Assert.Contains(ruleWording, refused.Message);
            }

            /// <summary>
            /// The case a URL-shaped check cannot catch: the name looks like an
            /// ordinary public one and DNS is what points it inwards.
            /// </summary>
            [Fact]
            public async Task A_public_name_that_resolves_to_a_private_address_is_refused()
            {
                var inner = new RecordingHandler();

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, "https://totally-normal.example.com/.well-known/openid-configuration"),
                    allowPrivateNetworks: false,
                    resolver: Resolves("192.168.7.7"));

                var refused = Assert.IsType<OutboundRefusedException>(error);
                Assert.Empty(inner.Requests);
                Assert.Contains("192.168.7.7", refused.Message);
            }

            [Fact]
            public async Task A_name_that_answers_with_one_good_and_one_bad_address_is_refused()
            {
                var inner = new RecordingHandler();

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34", "127.0.0.1"));

                Assert.IsType<OutboundRefusedException>(error);
                Assert.Empty(inner.Requests);
            }

            [Fact]
            public async Task An_address_literal_is_checked_without_asking_dns()
            {
                var inner = new RecordingHandler();
                var resolverCalled = false;

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, "https://169.254.169.254/latest/meta-data/"),
                    allowPrivateNetworks: false,
                    resolver: _ =>
                    {
                        resolverCalled = true;
                        return Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
                    });

                Assert.IsType<OutboundRefusedException>(error);
                Assert.False(resolverCalled);
                Assert.Empty(inner.Requests);
            }

            [Fact]
            public async Task A_public_address_is_sent_without_any_setting()
            {
                var inner = new RecordingHandler();

                using (var response = await SendAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34")))
                {
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    Assert.Single(inner.Requests);
                }
            }

            [Fact]
            public async Task A_url_that_is_not_http_is_refused()
            {
                var inner = new RecordingHandler();

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, "file:///etc/shadow"),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34"));

                Assert.IsType<OutboundRefusedException>(error);
                Assert.Empty(inner.Requests);
            }

            /// <summary>
            /// A name that cannot be looked up is a provider this server could
            /// not reach, not a destination it refused - and the two must not
            /// arrive at the caller as the same thing, because only one of them
            /// means "no credential was tested".
            /// </summary>
            [Fact]
            public async Task A_failed_lookup_is_left_as_a_transport_failure()
            {
                var inner = new RecordingHandler();

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: _ => throw new SocketException(11001));

                Assert.IsType<SocketException>(error);
                Assert.Null(OutboundRefusedException.Find(error));
                Assert.Empty(inner.Requests);
            }
        }

        public class TheOperatorAllowance
        {
            [Theory]
            [InlineData("127.0.0.1")]
            [InlineData("10.1.2.3")]
            [InlineData("192.168.1.1")]
            [InlineData("100.64.1.1")]
            [InlineData("fd00::1")]
            public async Task A_home_lab_provider_is_permitted_once_the_setting_is_on(string address)
            {
                var inner = new RecordingHandler();

                using (var response = await SendAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: true,
                    resolver: Resolves(address)))
                {
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    Assert.Single(inner.Requests);
                }
            }

            [Theory]
            [InlineData("169.254.169.254")]
            [InlineData("fe80::1")]
            [InlineData("224.0.0.1")]
            public async Task The_setting_does_not_open_the_cloud_metadata_range(string address)
            {
                var inner = new RecordingHandler();

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: true,
                    resolver: Resolves(address));

                var refused = Assert.IsType<OutboundRefusedException>(error);
                Assert.Empty(inner.Requests);
                Assert.Contains("No setting permits this address.", refused.Message);
            }

            [Fact]
            public async Task The_refusal_tells_the_operator_which_setting_would_permit_it()
            {
                var inner = new RecordingHandler();

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("10.10.140.5"));

                var refused = Assert.IsType<OutboundRefusedException>(error);
                Assert.Contains(OutboundAddressPolicy.AllowanceSettingName, refused.Message);
                Assert.Contains("10.10.140.5", refused.Message);
                Assert.Contains(Metadata, refused.Message);
            }
        }

        public class Redirects
        {
            [Fact]
            public async Task A_same_origin_redirect_is_followed()
            {
                var inner = new RecordingHandler();
                inner.Responses.Enqueue(Redirect(HttpStatusCode.Found, "https://idp.test/application/o/emby/openid-configuration"));
                inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.OK));

                using (var response = await SendAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34")))
                {
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    Assert.Equal(2, inner.Requests.Count);
                    Assert.Equal(
                        "https://idp.test/application/o/emby/openid-configuration",
                        inner.Requests[1].RequestUri.ToString());
                }
            }

            [Fact]
            public async Task A_relative_location_is_resolved_against_the_current_url()
            {
                var inner = new RecordingHandler();
                inner.Responses.Enqueue(Redirect(HttpStatusCode.MovedPermanently, "/application/o/emby/config"));
                inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.OK));

                using (var response = await SendAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34")))
                {
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    Assert.Equal(
                        "https://idp.test/application/o/emby/config",
                        inner.Requests[1].RequestUri.ToString());
                }
            }

            [Fact]
            public async Task A_redirect_that_downgrades_to_plain_http_is_refused()
            {
                var inner = new RecordingHandler();
                inner.Responses.Enqueue(Redirect(HttpStatusCode.Found, "http://idp.test/application/o/emby/.well-known/openid-configuration"));

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34"));

                var refused = Assert.IsType<OutboundRefusedException>(error);
                Assert.Single(inner.Requests);
                Assert.Contains("may not change the scheme", refused.Message);
            }

            [Fact]
            public async Task A_redirect_to_another_host_is_refused()
            {
                var inner = new RecordingHandler();
                inner.Responses.Enqueue(Redirect(HttpStatusCode.Found, "https://attacker.test/.well-known/openid-configuration"));

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34"));

                var refused = Assert.IsType<OutboundRefusedException>(error);
                Assert.Single(inner.Requests);
                Assert.Contains("may not leave the origin", refused.Message);
                Assert.Contains("attacker.test", refused.Message);
            }

            [Fact]
            public async Task A_redirect_to_another_port_on_the_same_host_is_refused()
            {
                var inner = new RecordingHandler();
                inner.Responses.Enqueue(Redirect(HttpStatusCode.Found, "https://idp.test:8443/.well-known/openid-configuration"));

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34"));

                Assert.IsType<OutboundRefusedException>(error);
                Assert.Single(inner.Requests);
            }

            [Fact]
            public async Task A_chain_cannot_walk_away_one_same_origin_step_at_a_time()
            {
                var inner = new RecordingHandler();
                inner.Responses.Enqueue(Redirect(HttpStatusCode.Found, "https://idp.test/second"));
                inner.Responses.Enqueue(Redirect(HttpStatusCode.Found, "https://elsewhere.test/third"));

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34"));

                Assert.IsType<OutboundRefusedException>(error);
                Assert.Equal(2, inner.Requests.Count);
            }

            [Fact]
            public async Task A_redirect_to_a_non_http_scheme_is_refused()
            {
                var inner = new RecordingHandler();
                inner.Responses.Enqueue(Redirect(HttpStatusCode.Found, "file:///etc/shadow"));

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34"));

                Assert.IsType<OutboundRefusedException>(error);
                Assert.Single(inner.Requests);
            }

            [Fact]
            public async Task A_redirect_with_no_location_is_refused()
            {
                var inner = new RecordingHandler();
                inner.Responses.Enqueue(Redirect(HttpStatusCode.Found, null));

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34"));

                var refused = Assert.IsType<OutboundRefusedException>(error);
                Assert.Contains("Location header is missing", refused.Message);
            }

            /// <summary>
            /// The token request carries an authorization code or, on the
            /// native path, a user's real password. A 307 or 308 would have the
            /// stack re-send that body to whatever the Location header names.
            /// </summary>
            [Theory]
            [InlineData(307)]
            [InlineData(302)]
            public async Task A_redirect_returned_for_a_credential_carrying_post_is_never_followed(int status)
            {
                var inner = new RecordingHandler();
                inner.Responses.Enqueue(Redirect((HttpStatusCode)status, "https://idp.test/token-2"));

                var request = new HttpRequestMessage(HttpMethod.Post, "https://idp.test/application/o/token/")
                {
                    Content = new StringContent("grant_type=password&password=hunter2"),
                };

                var error = await SendAndCatchAsync(
                    inner,
                    request,
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34"));

                var refused = Assert.IsType<OutboundRefusedException>(error);
                Assert.Single(inner.Requests);
                Assert.Contains("carries a credential", refused.Message);
            }

            [Fact]
            public async Task A_redirect_loop_is_abandoned_rather_than_followed_forever()
            {
                var inner = new RecordingHandler();

                for (var i = 0; i < OutboundRedirectPolicy.MaxRedirects + 2; i++)
                {
                    inner.Responses.Enqueue(Redirect(HttpStatusCode.Found, Metadata));
                }

                var error = await SendAndCatchAsync(
                    inner,
                    new HttpRequestMessage(HttpMethod.Get, Metadata),
                    allowPrivateNetworks: false,
                    resolver: Resolves("93.184.216.34"));

                var refused = Assert.IsType<OutboundRefusedException>(error);
                Assert.Contains("more than " + OutboundRedirectPolicy.MaxRedirects, refused.Message);
                Assert.Equal(OutboundRedirectPolicy.MaxRedirects + 1, inner.Requests.Count);
            }
        }
    }
}

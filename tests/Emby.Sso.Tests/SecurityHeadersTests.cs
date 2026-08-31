using System;
using System.Collections.Generic;
using System.Linq;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// Finding F4. What can be tested here is the policy itself: which headers
    /// exist, what they say, and that a page cannot end up with a policy that
    /// allows the inline script the escaping exists to prevent.
    ///
    /// What CANNOT be tested here, and is stated rather than implied: that Emby
    /// puts these on the wire. The Api/ layer that hands them to
    /// <c>IHttpResultFactory</c> and <c>IResponse.AddHeader</c> references
    /// <c>MediaBrowser.*</c> and is not compiled into this project, and the
    /// plugin runs on no reachable server, so no header below has been observed
    /// on a response.
    /// </summary>
    public class SecurityHeadersTests
    {
        private static readonly string[] EveryHeaderSet = { "scripted", "static", "redirect" };

        private static IDictionary<string, string> Headers(string kind, string nonce)
        {
            switch (kind)
            {
                case "scripted": return SecurityHeaders.ForScriptedPage(nonce);
                case "static": return SecurityHeaders.ForStaticPage(nonce);
                default: return SecurityHeaders.ForRedirect();
            }
        }

        [Fact]
        public void Every_response_this_plugin_produces_carries_the_same_four_hardening_headers()
        {
            // Including the redirect and, through Error(), every failure path.
            // A header set only on the successful response is the classic way
            // this control is missed.
            foreach (var kind in EveryHeaderSet)
            {
                var headers = Headers(kind, SecurityHeaders.NewNonce());

                Assert.Equal("DENY", headers["X-Frame-Options"]);
                Assert.Equal("nosniff", headers["X-Content-Type-Options"]);
                Assert.Equal("no-referrer", headers["Referrer-Policy"]);
                Assert.Contains("frame-ancestors 'none'", headers["Content-Security-Policy"]);
            }
        }

        [Fact]
        public void The_no_store_headers_the_pages_already_had_are_still_there()
        {
            // The completion page holds a live handoff secret; a cached copy of
            // it is a credential on disk.
            foreach (var kind in EveryHeaderSet)
            {
                var headers = Headers(kind, SecurityHeaders.NewNonce());

                Assert.Contains("no-store", headers["Cache-Control"]);
                Assert.Equal("no-cache", headers["Pragma"]);
            }
        }

        [Fact]
        public void No_policy_ever_allows_inline_script()
        {
            // The whole point of the nonce. 'unsafe-inline' or 'unsafe-eval'
            // anywhere in here would make the escaping in PageText decorative.
            foreach (var kind in EveryHeaderSet)
            {
                var policy = Headers(kind, SecurityHeaders.NewNonce())["Content-Security-Policy"];

                Assert.DoesNotContain("unsafe-inline", policy);
                Assert.DoesNotContain("unsafe-eval", policy);
                Assert.DoesNotContain("unsafe-hashes", policy);
                Assert.StartsWith("default-src 'none'", policy);
            }
        }

        [Fact]
        public void The_completion_page_may_run_its_own_script_and_talk_to_this_server_only()
        {
            var nonce = SecurityHeaders.NewNonce();
            var policy = SecurityHeaders.ScriptedPagePolicy(nonce);

            Assert.Contains("script-src 'nonce-" + nonce + "'", policy);
            Assert.Contains("style-src 'nonce-" + nonce + "'", policy);

            // It posts the handoff secret to this same server and reads
            // /emby/System/Info back. Nothing else.
            Assert.Contains("connect-src 'self'", policy);
        }

        [Fact]
        public void The_error_page_may_not_run_script_at_all()
        {
            var nonce = SecurityHeaders.NewNonce();
            var policy = SecurityHeaders.StaticPagePolicy(nonce);

            Assert.Contains("script-src 'none'", policy);
            Assert.Contains("style-src 'nonce-" + nonce + "'", policy);
            Assert.DoesNotContain("connect-src", policy);
        }

        [Fact]
        public void A_nonce_is_fresh_for_every_response()
        {
            // A nonce reused across responses is a nonce an attacker can read
            // off one page and reuse to authorise script on the next.
            var nonces = Enumerable.Range(0, 100).Select(_ => SecurityHeaders.NewNonce()).ToArray();

            Assert.Equal(nonces.Length, nonces.Distinct(StringComparer.Ordinal).Count());
            Assert.All(nonces, nonce => Assert.True(SecurityHeaders.IsValidNonce(nonce)));
        }

        [Theory]
        [InlineData("abc'; script-src *")]
        [InlineData("abc\r\nX-Injected: yes")]
        [InlineData("abc def")]
        [InlineData("abc\"")]
        [InlineData("")]
        [InlineData(null)]
        public void A_nonce_that_is_not_base64url_is_refused_rather_than_emitted(string nonce)
        {
            // SecureRandom cannot produce any of these, so this is the guard
            // against a future caller supplying the value from somewhere else.
            // The failure direction matters: the source becomes 'none', so the
            // page's own script stops working - a visible break - rather than
            // the header carrying a quote, a newline, or a second directive.
            Assert.False(SecurityHeaders.IsValidNonce(nonce));

            var policy = SecurityHeaders.ScriptedPagePolicy(nonce);

            Assert.Contains("script-src 'none'", policy);
            Assert.DoesNotContain("unsafe-inline", policy);

            if (!string.IsNullOrEmpty(nonce))
            {
                Assert.DoesNotContain(nonce, policy);
            }
        }

        [Fact]
        public void No_header_name_or_value_can_split_a_response()
        {
            foreach (var kind in EveryHeaderSet)
            {
                foreach (var header in Headers(kind, SecurityHeaders.NewNonce()))
                {
                    Assert.DoesNotContain('\r', header.Key);
                    Assert.DoesNotContain('\n', header.Key);
                    Assert.DoesNotContain('\r', header.Value);
                    Assert.DoesNotContain('\n', header.Value);
                }
            }
        }
    }
}

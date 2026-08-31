using System;
using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The response headers every page this plugin serves must carry, and the
    /// content security policies that go with them (assessment finding F4).
    ///
    /// WHY THIS MATTERS MOST FOR THE COMPLETION PAGE. That page holds a live
    /// one-time handoff secret as a JavaScript string and posts it to
    /// <c>/emby/Users/AuthenticateByName</c>, then writes the resulting Emby
    /// access token into <c>localStorage</c>. A page that does that must not be
    /// framable by anyone: framed, it is a click away from being driven by a
    /// site the user did not choose, and any injected script sharing its origin
    /// would be reading a session token. <c>X-Frame-Options: DENY</c> and
    /// <c>frame-ancestors 'none'</c> say the same thing twice on purpose - the
    /// former is understood by everything, the latter is the one still being
    /// specified.
    ///
    /// WHY A NONCE RATHER THAN <c>'unsafe-inline'</c>. Both pages are built
    /// here, in this process, from a fixed template plus values that have been
    /// through <c>PageText.Html</c> or <c>PageText.JsString</c> - so the exact
    /// inline blocks that need to run are known when the header is written, and
    /// a fresh per-response nonce names them without opening the door to any
    /// other inline script. <c>'unsafe-inline'</c> would have allowed precisely
    /// the injected script the escaping exists to prevent, which would make the
    /// policy decorative.
    ///
    /// EVERY response, not just the successful one. The error page is the one a
    /// stranger can reach most easily, and a header set only on the happy path
    /// is the classic way this control is missed. There are three shapes of
    /// response this plugin produces - the scripted completion page, the static
    /// error page, and the redirect to the identity provider - and all three
    /// have a policy here.
    ///
    /// UNVERIFIED: that Emby emits these headers as given. The dictionary route
    /// is the one <c>IHttpResultFactory.GetResult</c> already carries
    /// <c>Cache-Control</c> and <c>Pragma</c> over on this server, and
    /// <c>IResponse.AddHeader</c> is the documented way to add one to a response
    /// with no dictionary (both read from MediaBrowser.Model 4.9.1.90 by
    /// reflection), but the plugin runs on no reachable server, so no header
    /// below has been observed on the wire from this build.
    ///
    /// No <c>MediaBrowser.*</c> type appears here, so it lives in Protocol/
    /// where the test project can reach it.
    /// </summary>
    internal static class SecurityHeaders
    {
        /// <summary>
        /// Belt to <c>frame-ancestors</c>'s braces, and the half that every
        /// browser in service understands.
        /// </summary>
        public const string FrameOptions = "DENY";

        /// <summary>
        /// Stops a browser from deciding for itself that our
        /// <c>text/html</c> is something else. Cheap, and the pages carry a
        /// secret, so nothing about their type should be up for negotiation.
        /// </summary>
        public const string ContentTypeOptions = "nosniff";

        /// <summary>
        /// A real header rather than only the <c>&lt;meta name='referrer'&gt;</c>
        /// the pages already carry: the meta tag is honoured only once the
        /// document has been parsed, and it does nothing at all for the redirect
        /// to the identity provider, which has no document.
        /// </summary>
        public const string ReferrerPolicy = "no-referrer";

        /// <summary>
        /// The completion page holds a live credential and the error page must
        /// not be re-shown from a back button as though it were current.
        /// </summary>
        public const string CacheControl = "no-store, no-cache, must-revalidate";

        /// <summary>For the HTTP/1.0 caches that predate Cache-Control.</summary>
        public const string Pragma = "no-cache";

        /// <summary>
        /// Bytes of randomness behind a nonce. Sixteen (128 bits) is far beyond
        /// what guessing within the life of a single response could reach, and a
        /// nonce is worthless to an attacker who cannot read the response
        /// anyway - the point is that it is fresh per response, so a value
        /// scraped from one page cannot authorise script on the next.
        /// </summary>
        private const int NonceBytes = 16;

        /// <summary>
        /// The base part every policy starts from: nothing loads, nothing frames
        /// us, no base tag can re-point a relative URL, and no form may be
        /// submitted anywhere. Each page then adds back only what it actually
        /// uses.
        /// </summary>
        private const string Base =
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'none'";

        /// <summary>A fresh nonce for one response. Never reuse one across responses.</summary>
        public static string NewNonce()
        {
            return SecureRandom.CreateToken(NonceBytes);
        }

        /// <summary>
        /// Whether a nonce is safe to put in a header and in an attribute.
        /// <see cref="SecureRandom"/> only ever produces base64url, so a false
        /// answer means something else supplied the value - and the policies
        /// below then leave the nonce source OUT rather than emitting a header
        /// that could be malformed or, worse, split. A page whose script is
        /// refused is a visible failure; a policy that quietly allows anything
        /// is not.
        /// </summary>
        public static bool IsValidNonce(string nonce)
        {
            if (string.IsNullOrEmpty(nonce))
            {
                return false;
            }

            foreach (var character in nonce)
            {
                var ok = (character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '-'
                    || character == '_';

                if (!ok)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// The policy for a page that carries one inline script and one inline
        /// style block - the sign-in completion page.
        ///
        /// <c>connect-src 'self'</c> is what that script needs and all it needs:
        /// it posts the handoff secret to this same server and reads
        /// <c>/emby/System/Info</c> back. Nothing else on the page fetches
        /// anything.
        /// </summary>
        public static string ScriptedPagePolicy(string nonce)
        {
            var source = NonceSource(nonce);

            return Base
                + "; script-src " + source
                + "; style-src " + source
                + "; connect-src 'self'";
        }

        /// <summary>
        /// The policy for a page with an inline style block and no script at all
        /// - the error page. It says <c>script-src 'none'</c> explicitly rather
        /// than leaning on <c>default-src</c>, so that adding a script to that
        /// page later is a visible break rather than a silent one.
        /// </summary>
        public static string StaticPagePolicy(string nonce)
        {
            return Base
                + "; script-src 'none'"
                + "; style-src " + NonceSource(nonce);
        }

        /// <summary>
        /// The policy for a response with no document of its own - the 302 to
        /// the identity provider. There is nothing to protect inside it, but a
        /// header that is only present on some responses is one a reviewer has
        /// to reason about, so this one is stated too.
        /// </summary>
        public static string RedirectPolicy()
        {
            return Base + "; script-src 'none'; style-src 'none'";
        }

        /// <summary>Headers for the sign-in completion page.</summary>
        public static IDictionary<string, string> ForScriptedPage(string nonce)
        {
            return Build(ScriptedPagePolicy(nonce));
        }

        /// <summary>Headers for the error page.</summary>
        public static IDictionary<string, string> ForStaticPage(string nonce)
        {
            return Build(StaticPagePolicy(nonce));
        }

        /// <summary>Headers for the redirect to the identity provider.</summary>
        public static IDictionary<string, string> ForRedirect()
        {
            return Build(RedirectPolicy());
        }

        /// <summary>
        /// <c>'nonce-...'</c> for a nonce that is safe to emit, and
        /// <c>'none'</c> for one that is not - see <see cref="IsValidNonce"/>
        /// for why the failure direction is "refuse the inline block" rather
        /// than "allow inline".
        /// </summary>
        private static string NonceSource(string nonce)
        {
            return IsValidNonce(nonce) ? "'nonce-" + nonce + "'" : "'none'";
        }

        private static IDictionary<string, string> Build(string contentSecurityPolicy)
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Cache-Control"] = CacheControl,
                ["Pragma"] = Pragma,
                ["X-Frame-Options"] = FrameOptions,
                ["X-Content-Type-Options"] = ContentTypeOptions,
                ["Referrer-Policy"] = ReferrerPolicy,
                ["Content-Security-Policy"] = contentSecurityPolicy,
            };
        }
    }
}

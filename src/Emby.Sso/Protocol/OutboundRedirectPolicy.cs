using System;

namespace Emby.Sso.Protocol
{
    /// <summary>What <see cref="OutboundRedirectPolicy.Classify"/> made of one hop.</summary>
    internal enum OutboundRedirectOutcome
    {
        Permitted = 0,

        /// <summary>The Location header was missing, relative to nothing, or unparseable.</summary>
        Unusable = 1,

        /// <summary>https -&gt; http, or either -&gt; anything else.</summary>
        SchemeChanged = 2,

        /// <summary>Same scheme, different host or port.</summary>
        DifferentOrigin = 3,

        /// <summary>Not an http(s) URL at all.</summary>
        UnsupportedScheme = 4,
    }

    /// <summary>
    /// Decides whether one HTTP redirect may be followed.
    ///
    /// The plugin fetches the discovery document and the JWKS from an address an
    /// administrator configured, and the HTTP stack will follow redirects from
    /// there without asking anybody. That turns one trusted address into an
    /// arbitrary one: a provider - or anything that can answer for it - replies
    /// 302 and the next fetch goes wherever the Location header says, including
    /// back down to plain HTTP, where the JWKS that decides who may sign in
    /// travels over a channel any network device can rewrite.
    ///
    /// So a redirect is followed only when it stays on the same scheme, host and
    /// port as the address that was actually configured. Both halves matter and
    /// neither implies the other: same-origin catches the jump to another host,
    /// and the scheme test exists to give a downgrade its own name in the log,
    /// because "your provider redirected sign-in to plain HTTP" is a different
    /// thing for an operator to read than "it redirected somewhere else".
    ///
    /// The origin compared against is the origin of the request the chain
    /// STARTED from, not the previous hop, so a chain cannot walk away from the
    /// configured address one same-origin step at a time.
    ///
    /// This is deliberately stricter than a browser, and the cost is understood:
    /// a provider fronted by a redirect from example.com to auth.example.com
    /// will be refused, and the operator's fix is to configure the address the
    /// provider actually serves from. The refusal says so.
    /// </summary>
    internal static class OutboundRedirectPolicy
    {
        /// <summary>
        /// How many redirects may be followed before the chain is abandoned.
        /// Every hop is same-origin by the rule above, so a chain longer than
        /// this is a loop or a stall, not a provider that needs more room.
        /// </summary>
        public const int MaxRedirects = 5;

        public static OutboundRedirectOutcome Classify(Uri origin, Uri target)
        {
            if (origin == null || target == null || !target.IsAbsoluteUri)
            {
                return OutboundRedirectOutcome.Unusable;
            }

            if (!IsHttpScheme(target))
            {
                return OutboundRedirectOutcome.UnsupportedScheme;
            }

            if (!string.Equals(origin.Scheme, target.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                return OutboundRedirectOutcome.SchemeChanged;
            }

            if (!string.Equals(origin.Host, target.Host, StringComparison.OrdinalIgnoreCase)
                || origin.Port != target.Port)
            {
                return OutboundRedirectOutcome.DifferentOrigin;
            }

            return OutboundRedirectOutcome.Permitted;
        }

        /// <summary>
        /// The refusal, naming the rule and what an operator can do about it.
        /// Goes to the server log, never to the browser.
        /// </summary>
        public static string Explain(Uri origin, string location, OutboundRedirectOutcome outcome)
        {
            var from = LogSafeText.Flatten(origin == null ? "the configured address" : origin.ToString());
            var to = LogSafeText.Flatten(string.IsNullOrEmpty(location) ? "(no Location header)" : location);

            switch (outcome)
            {
                case OutboundRedirectOutcome.SchemeChanged:
                    return "refusing to follow a redirect from " + from + " to " + to
                        + ": a redirect may not change the scheme, and this one leaves "
                        + "the scheme the issuer was configured with.";
                case OutboundRedirectOutcome.UnsupportedScheme:
                    return "refusing to follow a redirect from " + from + " to " + to
                        + ": only http and https redirects are followed.";
                case OutboundRedirectOutcome.Unusable:
                    return "refusing to follow a redirect from " + from + " to " + to
                        + ": the Location header is missing or is not a usable URL.";
                default:
                    return "refusing to follow a redirect from " + from + " to " + to
                        + ": a redirect may not leave the origin (scheme, host and port) of the "
                        + "configured issuer URL. If the provider really lives at the redirect "
                        + "target, configure that address as the issuer URL instead.";
            }
        }

        private static bool IsHttpScheme(Uri uri)
        {
            return string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase)
                || string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase);
        }
    }
}

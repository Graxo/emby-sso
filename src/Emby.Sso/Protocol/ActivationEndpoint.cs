using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Where the vendor's activation service lives, and how the two URLs the
    /// plugin builds from it are made.
    ///
    /// HTTPS ONLY, and that refusal is here rather than in the HTTP stack so it
    /// is a decision under test. The redemption code is a bearer secret and
    /// goes in the request body; a plain-HTTP base would put it on the wire in
    /// cleartext for anybody on the path to spend.
    ///
    /// AN OVERRIDE IS SAFE. <see cref="PluginConfigurationOverrideNote"/> spells
    /// out why: the licence that comes back is verified against the public key
    /// compiled into THIS build and against THIS server's id before it is
    /// stored (<see cref="ActivationClient"/>), so pointing this at a hostile
    /// server gains an attacker nothing beyond a refusal. The override exists
    /// so the vendor can test the service before it is live.
    /// </summary>
    internal static class ActivationEndpoint
    {
        /// <summary>
        /// The vendor's service, compiled in.
        ///
        /// HOW TO CHANGE THIS. Edit it here and rebuild - it is deliberately a
        /// build-time constant, like <see cref="LicencePublicKey.Jwk"/>, so that
        /// the shipped plugin has a home to phone even on a fresh install with
        /// an empty configuration.
        ///
        /// Getting it wrong costs an activation attempt and nothing else. It is
        /// NOT a trust boundary: see the class comment.
        /// </summary>
        public const string DefaultServiceBase = "https://licence.koper.cloud";

        /// <summary>The activation endpoint's path, fixed by the API contract.</summary>
        public const string ActivatePath = "/v1/activate";

        /// <summary>The purchase page's path. Prefilled with the server id so the shop does not have to ask for it.</summary>
        public const string BuyPath = "/buy";

        /// <summary>
        /// Referenced from the class comment above so the reason an override is
        /// safe cannot drift away from the override itself.
        /// </summary>
        public const string PluginConfigurationOverrideNote =
            "the licence returned by any service, vendor's or not, is verified against this build's "
            + "embedded public key and this server's own id before it is stored";

        /// <summary>
        /// The base to use: the operator's override when they set one, the
        /// compiled-in vendor address otherwise. Whitespace is not an override.
        /// </summary>
        public static string Resolve(string configuredOverride)
        {
            return string.IsNullOrWhiteSpace(configuredOverride)
                ? DefaultServiceBase
                : configuredOverride.Trim();
        }

        /// <summary>
        /// Builds <c>{base}/v1/activate</c>, or explains why the base is not
        /// usable. False leaves <paramref name="url"/> null, so a caller that
        /// ignores the return value still has nothing to send to.
        /// </summary>
        public static bool TryBuildActivateUrl(string serviceBase, out string url, out string refusal)
        {
            return TryBuild(serviceBase, ActivatePath, null, out url, out refusal);
        }

        /// <summary>
        /// The purchase link shown on the configuration page, carrying this
        /// server's id so the shop can prefill it. Null when the base is not
        /// usable or the server id is not known - the page then shows no link
        /// at all rather than a broken one.
        /// </summary>
        public static string BuildBuyUrl(string serviceBase, string serverId)
        {
            if (string.IsNullOrWhiteSpace(serverId))
            {
                return null;
            }

            var query = "serverId=" + Uri.EscapeDataString(serverId.Trim());

            return TryBuild(serviceBase, BuyPath, query, out var url, out _) ? url : null;
        }

        private static bool TryBuild(string serviceBase, string path, string query, out string url, out string refusal)
        {
            url = null;

            if (string.IsNullOrWhiteSpace(serviceBase))
            {
                refusal = "no licensing service address is configured";
                return false;
            }

            if (!Uri.TryCreate(serviceBase.Trim(), UriKind.Absolute, out var parsed))
            {
                refusal = "the licensing service address is not a valid absolute URL";
                return false;
            }

            // Ordinal, case-insensitive: Uri lower-cases the scheme already, but
            // this must not depend on that, and it must never be a culture
            // comparison - see the Turkish-I problem.
            if (!string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                refusal = "the licensing service address must be https:// - a redemption code is a secret "
                    + "and will not be sent over plain HTTP";
                return false;
            }

            if (string.IsNullOrEmpty(parsed.Host))
            {
                refusal = "the licensing service address has no host";
                return false;
            }

            // A base carrying credentials, a query or a fragment is ambiguous
            // once a path and a query of our own are appended to it, and no
            // legitimate configuration needs one. Refuse rather than guess.
            if (!string.IsNullOrEmpty(parsed.UserInfo))
            {
                refusal = "the licensing service address must not carry a username or password";
                return false;
            }

            if (!string.IsNullOrEmpty(parsed.Query) || !string.IsNullOrEmpty(parsed.Fragment))
            {
                refusal = "the licensing service address must not carry a query string or a fragment";
                return false;
            }

            // GetLeftPart(Path) rather than the original string: it is the
            // normalised absolute URL, so a base with a trailing slash, a
            // default port or mixed-case host all produce the same result.
            var trimmed = parsed.GetLeftPart(UriPartial.Path).TrimEnd('/');

            url = trimmed + path + (string.IsNullOrEmpty(query) ? string.Empty : "?" + query);
            refusal = null;

            return true;
        }
    }
}

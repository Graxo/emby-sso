using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    internal sealed class OidcIdentity
    {
        public OidcIdentity(string subject, string username, string displayName,
            IReadOnlyList<string> groups, bool hasGroupsClaim, bool? emailVerified = null)
        {
            Subject = subject;
            Username = username;
            DisplayName = displayName;
            Groups = groups ?? new string[0];
            HasGroupsClaim = hasGroupsClaim;
            EmailVerified = emailVerified;
        }

        /// <summary>
        /// The identity provider's subject identifier - the one claim OpenID
        /// Connect guarantees is stable and unique for this principal, and the
        /// only thing here a user cannot change about themselves.
        ///
        /// <see cref="SubjectBindingStore"/> is what reads it, and every sign-in
        /// goes through that. It was parsed and read by nothing at all until
        /// then, which is what made the plugin authenticate whoever presented a
        /// matching username string (assessment finding F1).
        /// </summary>
        public string Subject { get; }

        public string Username { get; }

        public string DisplayName { get; }

        /// <summary>Never null. Empty when the claim was absent or carried no values.</summary>
        public IReadOnlyList<string> Groups { get; }

        /// <summary>
        /// Whether the token carried the groups claim at all. An absent claim
        /// usually means the provider was not configured to emit groups, which
        /// is a different operator problem from a user simply lacking a group.
        /// </summary>
        public bool HasGroupsClaim { get; }

        /// <summary>
        /// The token's <c>email_verified</c>, or null when it carried none.
        /// Null is NOT "verified": see <see cref="UsernameClaimPolicy"/>, which
        /// refuses both null and false when the configured username claim is
        /// <c>email</c>.
        /// </summary>
        public bool? EmailVerified { get; }
    }
}

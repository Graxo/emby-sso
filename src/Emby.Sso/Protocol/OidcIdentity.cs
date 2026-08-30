using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    public sealed class OidcIdentity
    {
        public OidcIdentity(string subject, string username, string displayName,
            IReadOnlyList<string> groups, bool hasGroupsClaim)
        {
            Subject = subject;
            Username = username;
            DisplayName = displayName;
            Groups = groups ?? new string[0];
            HasGroupsClaim = hasGroupsClaim;
        }

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
    }
}

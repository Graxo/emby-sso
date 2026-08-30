using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Decides whether a claim value names a given Emby user. Ordinal
    /// case-insensitive after trimming: no culture-sensitive comparison, because
    /// culture-dependent casing rules have produced authentication bypasses.
    /// </summary>
    public static class UsernameMatcher
    {
        /// <summary>
        /// The one comparison that decides whether two spellings are the same
        /// person. Exposed so that anything keyed BY username - the per-username
        /// buckets in <see cref="ProvisioningThrottle"/>, today - uses this
        /// comparer rather than a second one of its own. A key comparer that was
        /// stricter than <see cref="Matches"/> would let "Alice" and "alice"
        /// carry separate failure budgets while the rest of the plugin treats
        /// them as one account.
        /// </summary>
        public static readonly StringComparer Comparer = StringComparer.OrdinalIgnoreCase;

        /// <summary>
        /// The trimming half of that comparison, split out for the same reason.
        /// Null becomes the empty string so this is safe to use as a dictionary
        /// key; it never says two names match - <see cref="Matches"/> rejects
        /// empty and whitespace names before it compares.
        /// </summary>
        public static string NormalizeKey(string username)
        {
            return username == null ? string.Empty : username.Trim();
        }

        public static bool Matches(string claimValue, string embyUsername)
        {
            if (string.IsNullOrWhiteSpace(claimValue) || string.IsNullOrWhiteSpace(embyUsername))
            {
                return false;
            }

            return Comparer.Equals(NormalizeKey(claimValue), NormalizeKey(embyUsername));
        }
    }
}

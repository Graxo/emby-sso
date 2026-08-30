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
        public static bool Matches(string claimValue, string embyUsername)
        {
            if (string.IsNullOrWhiteSpace(claimValue) || string.IsNullOrWhiteSpace(embyUsername))
            {
                return false;
            }

            return string.Equals(claimValue.Trim(), embyUsername.Trim(), StringComparison.OrdinalIgnoreCase);
        }
    }
}

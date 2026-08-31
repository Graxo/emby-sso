using System;

namespace Emby.Sso.Protocol
{
    internal enum GroupGateOutcome
    {
        /// <summary>The gate is unusable: no required group is configured, or there is no identity.</summary>
        NotConfigured = 0,

        /// <summary>The token carried no groups claim at all — usually a misconfigured provider.</summary>
        GroupsClaimMissing = 1,

        /// <summary>The identity is real and the claim was present, but the group is not among them.</summary>
        GroupNotHeld = 2,

        Allowed = 3,
    }

    /// <summary>
    /// Decides whether a verified identity holds the group an operator requires.
    /// Knows nothing about Emby and performs no verification of its own — the
    /// caller must already have validated the identity.
    /// </summary>
    internal static class GroupGate
    {
        public static GroupGateOutcome Evaluate(OidcIdentity identity, string requiredGroup)
        {
            if (identity == null || string.IsNullOrWhiteSpace(requiredGroup))
            {
                return GroupGateOutcome.NotConfigured;
            }

            if (!identity.HasGroupsClaim)
            {
                return GroupGateOutcome.GroupsClaimMissing;
            }

            var wanted = requiredGroup.Trim();

            foreach (var group in identity.Groups)
            {
                if (group != null &&
                    string.Equals(group.Trim(), wanted, StringComparison.OrdinalIgnoreCase))
                {
                    return GroupGateOutcome.Allowed;
                }
            }

            return GroupGateOutcome.GroupNotHeld;
        }
    }
}

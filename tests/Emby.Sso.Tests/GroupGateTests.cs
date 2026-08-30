using System.Collections.Generic;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class GroupGateTests
    {
        private static OidcIdentity Identity(IReadOnlyList<string> groups, bool hasClaim = true) =>
            new OidcIdentity("sub-1", "alice", "Alice", groups, hasClaim);

        [Fact]
        public void A_held_group_is_allowed()
        {
            Assert.Equal(GroupGateOutcome.Allowed,
                GroupGate.Evaluate(Identity(new[] { "emby-users" }), "emby-users"));
        }

        [Theory]
        [InlineData("EMBY-USERS")]
        [InlineData("  emby-users  ")]
        public void Group_matching_is_ordinal_case_insensitive_and_trimmed(string held)
        {
            Assert.Equal(GroupGateOutcome.Allowed,
                GroupGate.Evaluate(Identity(new[] { held }), "emby-users"));
        }

        [Fact]
        public void The_group_is_found_among_several()
        {
            Assert.Equal(GroupGateOutcome.Allowed,
                GroupGate.Evaluate(Identity(new[] { "staff", "emby-users", "other" }), "emby-users"));
        }

        [Fact]
        public void A_missing_group_is_refused()
        {
            Assert.Equal(GroupGateOutcome.GroupNotHeld,
                GroupGate.Evaluate(Identity(new[] { "staff" }), "emby-users"));
        }

        [Fact]
        public void An_empty_group_list_is_refused_as_not_held()
        {
            Assert.Equal(GroupGateOutcome.GroupNotHeld,
                GroupGate.Evaluate(Identity(new string[0]), "emby-users"));
        }

        [Fact]
        public void An_absent_claim_is_reported_separately_from_a_missing_group()
        {
            Assert.Equal(GroupGateOutcome.GroupsClaimMissing,
                GroupGate.Evaluate(Identity(new string[0], hasClaim: false), "emby-users"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void An_unconfigured_required_group_refuses(string required)
        {
            Assert.Equal(GroupGateOutcome.NotConfigured,
                GroupGate.Evaluate(Identity(new[] { "emby-users" }), required));
        }

        [Fact]
        public void A_null_identity_refuses()
        {
            Assert.Equal(GroupGateOutcome.NotConfigured, GroupGate.Evaluate(null, "emby-users"));
        }
    }
}

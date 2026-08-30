using System;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class UsernameClaimPolicyTests
    {
        [Theory]
        [InlineData("preferred_username")]
        [InlineData("sub")]
        [InlineData("upn")]
        public void ANonEmailClaimIsAcceptedWhateverTheTokenSaysAboutEmail(string claim)
        {
            // This guard is about the `email` claim specifically. It must not
            // start refusing perfectly good providers that simply do not emit
            // email_verified.
            Assert.Equal(UsernameClaimOutcome.Accepted, UsernameClaimPolicy.Evaluate(claim, null));
            Assert.Equal(UsernameClaimOutcome.Accepted, UsernameClaimPolicy.Evaluate(claim, false));
            Assert.Equal(UsernameClaimOutcome.Accepted, UsernameClaimPolicy.Evaluate(claim, true));
        }

        [Fact]
        public void AVerifiedEmailClaimIsAccepted()
        {
            Assert.Equal(UsernameClaimOutcome.Accepted, UsernameClaimPolicy.Evaluate("email", true));
        }

        [Fact]
        public void AnUnverifiedEmailClaimIsRefused()
        {
            var outcome = UsernameClaimPolicy.Evaluate("email", false);

            Assert.Equal(UsernameClaimOutcome.EmailNotVerified, outcome);
            Assert.False(UsernameClaimPolicy.Permits(outcome));
        }

        [Fact]
        public void AnEmailClaimWithNoVerificationAtAllIsRefused()
        {
            // Silence is not verification. A provider that never says the
            // address was checked has not checked it.
            var outcome = UsernameClaimPolicy.Evaluate("email", null);

            Assert.Equal(UsernameClaimOutcome.EmailVerificationUnknown, outcome);
            Assert.False(UsernameClaimPolicy.Permits(outcome));
        }

        [Theory]
        [InlineData("Email")]
        [InlineData("EMAIL")]
        [InlineData("  email  ")]
        public void TheEmailClaimIsRecognisedWhateverTheOperatorTyped(string claim)
        {
            // An operator-typed setting. "Email " must not slip past a guard
            // that "email" would have caught.
            Assert.True(UsernameClaimPolicy.IsEmailClaim(claim));
            Assert.Equal(UsernameClaimOutcome.EmailVerificationUnknown, UsernameClaimPolicy.Evaluate(claim, null));
        }

        [Theory]
        [InlineData("email_address")]
        [InlineData("mail")]
        [InlineData("preferred_username")]
        [InlineData(null)]
        public void OtherClaimNamesAreNotTheEmailClaim(string claim)
        {
            Assert.False(UsernameClaimPolicy.IsEmailClaim(claim));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void NoConfiguredClaimIsARefusal(string claim)
        {
            Assert.Equal(UsernameClaimOutcome.Refused, UsernameClaimPolicy.Evaluate(claim, true));
        }

        [Fact]
        public void ZeroIsARefusalAndOnlyOneOutcomePermits()
        {
            Assert.Equal(UsernameClaimOutcome.Refused, default(UsernameClaimOutcome));

            foreach (UsernameClaimOutcome outcome in Enum.GetValues(typeof(UsernameClaimOutcome)))
            {
                Assert.Equal(outcome == UsernameClaimOutcome.Accepted, UsernameClaimPolicy.Permits(outcome));
            }
        }
    }
}

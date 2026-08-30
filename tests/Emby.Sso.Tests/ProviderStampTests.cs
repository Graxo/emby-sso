using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The decision half of S1a. The Emby-facing half - reading
    /// Policy.AuthenticationProviderId off a resolved user and refusing the
    /// sign-in - lives in Auth/ and Api/, which this project cannot compile, so
    /// it is NOT covered here. What is covered is the rule those two call sites
    /// share, so they cannot disagree about which accounts are ours.
    /// </summary>
    public class ProviderStampTests
    {
        private const string Ours = "Emby.Sso.Auth.SsoAuthenticationProvider";
        private const string Emby = "Emby.Server.Implementations.Library.DefaultAuthenticationProvider";

        [Fact]
        public void AccountStampedToThisPluginIsPermitted()
        {
            var outcome = ProviderStamp.Evaluate(Ours, Ours);

            Assert.Equal(ProviderStampOutcome.StampedToThisPlugin, outcome);
            Assert.True(ProviderStamp.Permits(outcome));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void AccountWithNoProviderAssignedIsRefused(string providerId)
        {
            // The takeover this closes: Emby offers an account with an empty
            // AuthenticationProviderId to EVERY enabled provider, so a
            // never-signed-in administrator would otherwise be reachable through
            // SSO by whoever can present its name.
            var outcome = ProviderStamp.Evaluate(providerId, Ours);

            Assert.Equal(ProviderStampOutcome.Unstamped, outcome);
            Assert.False(ProviderStamp.Permits(outcome));
        }

        [Fact]
        public void AccountBelongingToAnotherProviderIsRefused()
        {
            var outcome = ProviderStamp.Evaluate(Emby, Ours);

            Assert.Equal(ProviderStampOutcome.StampedToAnotherProvider, outcome);
            Assert.False(ProviderStamp.Permits(outcome));
        }

        [Fact]
        public void ComparisonIsOrdinalAndCaseSensitive()
        {
            // Emby compares the stored type name with ordinal equality, so a
            // differently cased spelling names an account Emby does not actually
            // route to this plugin. Admitting it here would sign in an account
            // this plugin was never given.
            Assert.Equal(
                ProviderStampOutcome.StampedToAnotherProvider,
                ProviderStamp.Evaluate(Ours.ToLowerInvariant(), Ours));
        }

        [Fact]
        public void SurroundingWhitespaceDoesNotBreakAMatch()
        {
            Assert.Equal(ProviderStampOutcome.StampedToThisPlugin, ProviderStamp.Evaluate("  " + Ours + "\t", Ours));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void AnUnknownOwnProviderIdRefusesEverything(string thisProviderId)
        {
            // If the caller cannot name this plugin, nothing can legitimately
            // match. Guessing is not an option on an authentication decision.
            Assert.Equal(ProviderStampOutcome.Refused, ProviderStamp.Evaluate(Ours, thisProviderId));
            Assert.Equal(ProviderStampOutcome.Refused, ProviderStamp.Evaluate(null, thisProviderId));
        }

        [Fact]
        public void ZeroIsARefusal()
        {
            // A default-initialised outcome, or one produced by a future enum
            // member nobody updated the callers for, must not admit anyone.
            Assert.Equal(ProviderStampOutcome.Refused, default(ProviderStampOutcome));
            Assert.False(ProviderStamp.Permits(default(ProviderStampOutcome)));
        }

        [Fact]
        public void OnlyOneOutcomeEverPermits()
        {
            foreach (ProviderStampOutcome outcome in System.Enum.GetValues(typeof(ProviderStampOutcome)))
            {
                Assert.Equal(outcome == ProviderStampOutcome.StampedToThisPlugin, ProviderStamp.Permits(outcome));
            }
        }
    }
}

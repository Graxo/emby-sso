using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// Where the activation request is allowed to go. The refusals here are the
    /// ones that stop a redemption code - a bearer secret - from leaving over a
    /// channel that does not protect it, and they are decisions rather than
    /// transport behaviour precisely so they can be tested.
    /// </summary>
    public class ActivationEndpointTests
    {
        [Fact]
        public void UsesTheCompiledInVendorAddressWhenNothingIsConfigured()
        {
            Assert.Equal(ActivationEndpoint.DefaultServiceBase, ActivationEndpoint.Resolve(null));
            Assert.Equal(ActivationEndpoint.DefaultServiceBase, ActivationEndpoint.Resolve(string.Empty));
            Assert.Equal(ActivationEndpoint.DefaultServiceBase, ActivationEndpoint.Resolve("   "));
        }

        [Fact]
        public void TheCompiledInVendorAddressIsItselfUsable()
        {
            // A shipped build whose own default cannot be turned into a URL
            // would refuse every activation, and nobody would find out until an
            // operator tried to buy one.
            Assert.True(ActivationEndpoint.TryBuildActivateUrl(ActivationEndpoint.DefaultServiceBase, out var url, out _));
            Assert.EndsWith("/v1/activate", url);
            Assert.StartsWith("https://", url);
        }

        [Fact]
        public void AnOverrideWins()
        {
            Assert.Equal("https://staging.test", ActivationEndpoint.Resolve("  https://staging.test  "));
        }

        [Theory]
        [InlineData("https://licence.test", "https://licence.test/v1/activate")]
        [InlineData("https://licence.test/", "https://licence.test/v1/activate")]
        [InlineData("https://licence.test///", "https://licence.test/v1/activate")]
        [InlineData("https://licence.test/vendor", "https://licence.test/vendor/v1/activate")]
        [InlineData("https://licence.test/vendor/", "https://licence.test/vendor/v1/activate")]
        [InlineData("https://licence.test:8443", "https://licence.test:8443/v1/activate")]
        public void BuildsTheContractPath(string serviceBase, string expected)
        {
            Assert.True(ActivationEndpoint.TryBuildActivateUrl(serviceBase, out var url, out var refusal));
            Assert.Equal(expected, url);
            Assert.Null(refusal);
        }

        [Theory]
        [InlineData("http://licence.test")]
        [InlineData("HTTP://licence.test")]
        [InlineData("ftp://licence.test")]
        [InlineData("file:///etc/passwd")]
        public void RefusesAnythingThatIsNotHttps(string serviceBase)
        {
            Assert.False(ActivationEndpoint.TryBuildActivateUrl(serviceBase, out var url, out var refusal));
            Assert.Null(url);
            Assert.Contains("https", refusal);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("licence.test")]
        [InlineData("/v1/activate")]
        [InlineData("https://user:secret@licence.test")]
        [InlineData("https://licence.test?tenant=1")]
        [InlineData("https://licence.test#fragment")]
        public void RefusesAnAddressItCannotUseUnambiguously(string serviceBase)
        {
            Assert.False(ActivationEndpoint.TryBuildActivateUrl(serviceBase, out var url, out var refusal));
            Assert.Null(url);
            Assert.False(string.IsNullOrWhiteSpace(refusal));
        }

        [Fact]
        public void TheBuyLinkCarriesTheServerId()
        {
            var url = ActivationEndpoint.BuildBuyUrl("https://licence.test", "c5bc6e91458540caa295c4efdda1a58a");

            Assert.Equal("https://licence.test/buy?serverId=c5bc6e91458540caa295c4efdda1a58a", url);
        }

        [Fact]
        public void TheBuyLinkEscapesTheServerId()
        {
            // A server id is a hex string in practice. It is escaped anyway,
            // because the page renders this into an href and nothing here gets
            // to assume what a future Emby puts in SystemId.
            var url = ActivationEndpoint.BuildBuyUrl("https://licence.test", "a b&c=d#e");

            Assert.Equal("https://licence.test/buy?serverId=a%20b%26c%3Dd%23e", url);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("  ")]
        public void ThereIsNoBuyLinkWithoutAServerId(string serverId)
        {
            // The page shows nothing rather than a link that would buy a licence
            // for no server in particular.
            Assert.Null(ActivationEndpoint.BuildBuyUrl("https://licence.test", serverId));
        }

        [Fact]
        public void ThereIsNoBuyLinkForAnUnusableAddress()
        {
            Assert.Null(ActivationEndpoint.BuildBuyUrl("http://licence.test", "server-1"));
        }
    }
}

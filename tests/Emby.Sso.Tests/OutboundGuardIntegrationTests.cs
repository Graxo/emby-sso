using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The guard as OidcClient actually meets it: wrapped around the transport
    /// the client was handed, several frames below anything that knows a
    /// browser is waiting. What matters here is not that the fetch is refused -
    /// OutboundGuardHandlerTests covers that - but what the refusal turns into
    /// by the time a caller sees it.
    /// </summary>
    public class OutboundGuardIntegrationTests
    {
        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();

        private OidcClient CreateGuardedClient(string resolvesTo, bool allowPrivateNetworks)
        {
            var guard = new OutboundGuardHandler(
                _idp,
                () => allowPrivateNetworks,
                _ => Task.FromResult(new[] { IPAddress.Parse(resolvesTo) }));

            var options = new OidcOptions
            {
                IssuerUrl = FakeIdentityProvider.Issuer,
                ClientId = FakeIdentityProvider.ClientId,
                ClientSecret = FakeIdentityProvider.ClientSecret,
                Scopes = "openid profile email",
                RedirectUri = "https://emby.test/emby/Sso/Callback",
                UsernameClaim = "preferred_username",
            };

            return new OidcClient(new HttpClient(guard), options);
        }

        [Fact]
        public async Task A_refused_destination_reaches_the_caller_naming_the_rule_and_the_setting()
        {
            var client = CreateGuardedClient("169.254.169.254", allowPrivateNetworks: false);
            var store = new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => client.BuildAuthorizationUrlAsync(store.Create(), CancellationToken.None));

            Assert.Contains("169.254.169.254", error.Message);
            Assert.Contains("link-local", error.Message);
        }

        /// <summary>
        /// A destination this plugin refused is NOT an unreachable provider.
        /// Nothing was sent, so the provider had no part in it - and the
        /// unreachable flag exempts a failure from the provisioning throttle,
        /// which a refusal an attacker can trigger for free must never do.
        /// </summary>
        [Fact]
        public async Task A_refusal_is_not_marked_as_an_unreachable_provider()
        {
            var client = CreateGuardedClient("127.0.0.1", allowPrivateNetworks: false);
            var store = new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => client.BuildAuthorizationUrlAsync(store.Create(), CancellationToken.None));

            Assert.False(error.ProviderUnreachable);
            Assert.Equal(SsoErrors.NotConfigured, error.UserSafeReason);
        }

        [Fact]
        public async Task The_same_provider_works_once_the_operator_permits_its_address()
        {
            var client = CreateGuardedClient("10.0.0.5", allowPrivateNetworks: true);
            var store = new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

            var url = await client.BuildAuthorizationUrlAsync(store.Create(), CancellationToken.None);

            Assert.StartsWith(FakeIdentityProvider.Issuer + "authorize/", url, StringComparison.Ordinal);
        }
    }
}

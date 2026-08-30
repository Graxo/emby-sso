using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class OidcClientDiscoveryTests
    {
        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();

        private OidcClient CreateClient()
        {
            var options = new OidcOptions
            {
                IssuerUrl = FakeIdentityProvider.Issuer,
                ClientId = FakeIdentityProvider.ClientId,
                ClientSecret = FakeIdentityProvider.ClientSecret,
                Scopes = "openid profile email",
                RedirectUri = "https://emby.test/emby/Sso/Callback",
                UsernameClaim = "preferred_username",
            };

            return new OidcClient(new HttpClient(_idp), options);
        }

        [Fact]
        public async Task The_authorization_url_carries_every_required_parameter()
        {
            var store = new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
            var login = store.Create();

            var url = await CreateClient().BuildAuthorizationUrlAsync(login, CancellationToken.None);

            var uri = new Uri(url);
            var query = HttpUtility.ParseQueryString(uri.Query);

            Assert.Equal(FakeIdentityProvider.Issuer + "authorize/", uri.GetLeftPart(UriPartial.Path));
            Assert.Equal("code", query["response_type"]);
            Assert.Equal(FakeIdentityProvider.ClientId, query["client_id"]);
            Assert.Equal("https://emby.test/emby/Sso/Callback", query["redirect_uri"]);
            Assert.Equal("openid profile email", query["scope"]);
            Assert.Equal(login.State, query["state"]);
            Assert.Equal(login.Nonce, query["nonce"]);
            Assert.Equal(login.CodeChallenge, query["code_challenge"]);
            Assert.Equal("S256", query["code_challenge_method"]);
        }

        [Fact]
        public async Task The_authorization_url_never_contains_the_code_verifier_or_client_secret()
        {
            var store = new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
            var login = store.Create();

            var url = await CreateClient().BuildAuthorizationUrlAsync(login, CancellationToken.None);

            Assert.DoesNotContain(login.CodeVerifier, url, StringComparison.Ordinal);
            Assert.DoesNotContain(FakeIdentityProvider.ClientSecret, url, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Discovery_is_fetched_once_and_reused()
        {
            var client = CreateClient();
            var store = new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

            await client.BuildAuthorizationUrlAsync(store.Create(), CancellationToken.None);
            await client.BuildAuthorizationUrlAsync(store.Create(), CancellationToken.None);
            await client.BuildAuthorizationUrlAsync(store.Create(), CancellationToken.None);

            Assert.Equal(1, _idp.DiscoveryRequestCount);
        }
    }
}

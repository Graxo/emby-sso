using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class OidcClientDirectGrantTests
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
        public async Task Correct_credentials_yield_the_identity()
        {
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "alice"));

            var identity = await CreateClient().DirectGrantAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal("alice", identity.Username);
        }

        [Fact]
        public async Task The_request_uses_the_password_grant_and_carries_the_credentials()
        {
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "alice"));

            await CreateClient().DirectGrantAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal("password", _idp.LastTokenRequestForm["grant_type"]);
            Assert.Equal("alice", _idp.LastTokenRequestForm["username"]);
            Assert.Equal("correct horse", _idp.LastTokenRequestForm["password"]);
            Assert.Equal("openid profile email", _idp.LastTokenRequestForm["scope"]);
        }

        [Fact]
        public async Task Wrong_credentials_surface_as_a_provider_rejection()
        {
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().DirectGrantAsync("alice", "wrong", CancellationToken.None));

            Assert.Equal(SsoErrors.ProviderRejected, error.UserSafeReason);
        }

        [Fact]
        public async Task An_empty_password_is_rejected_without_contacting_the_provider()
        {
            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().DirectGrantAsync("alice", string.Empty, CancellationToken.None));

            Assert.Equal(SsoErrors.ProviderRejected, error.UserSafeReason);
            Assert.Null(_idp.LastTokenRequestForm);
        }

        [Fact]
        public async Task A_direct_grant_token_is_still_fully_validated()
        {
            var otherIdp = new FakeIdentityProvider();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(otherIdp.CreateIdToken(username: "alice"));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().DirectGrantAsync("alice", "correct horse", CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task Failures_never_leak_the_password()
        {
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;

            // The response body echoes the submitted password back, so this only
            // proves anything if the implementation is redacting the body rather
            // than simply never having concatenated a secret it never touched.
            _idp.TokenResponseJson =
                "{\"error\":\"invalid_grant\",\"error_description\":\"invalid password: hunter2\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().DirectGrantAsync("alice", "hunter2", CancellationToken.None));

            Assert.DoesNotContain("hunter2", error.ToString(), StringComparison.Ordinal);
        }
    }
}

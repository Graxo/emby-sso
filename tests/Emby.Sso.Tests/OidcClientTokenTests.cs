using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class OidcClientTokenTests
    {
        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();
        private readonly PendingLoginStore _logins =
            new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

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
        public async Task A_valid_code_exchange_yields_the_identity()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(username: "alice", displayName: "Alice Example", nonce: login.Nonce));

            var identity = await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.Equal("alice", identity.Username);
            Assert.Equal("Alice Example", identity.DisplayName);
            Assert.Equal("sub-1", identity.Subject);
        }

        [Fact]
        public async Task The_token_request_sends_the_pkce_verifier_and_authenticates_the_client()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(nonce: login.Nonce));

            await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.Equal("authorization_code", _idp.LastTokenRequestForm["grant_type"]);
            Assert.Equal("the-code", _idp.LastTokenRequestForm["code"]);
            Assert.Equal(login.CodeVerifier, _idp.LastTokenRequestForm["code_verifier"]);
            Assert.Equal("https://emby.test/emby/Sso/Callback", _idp.LastTokenRequestForm["redirect_uri"]);

            Assert.Equal("Basic", _idp.LastTokenRequestAuthorization.Scheme);
            var decoded = Encoding.UTF8.GetString(
                Convert.FromBase64String(_idp.LastTokenRequestAuthorization.Parameter));
            Assert.Equal(
                FakeIdentityProvider.ClientId + ":" + FakeIdentityProvider.ClientSecret,
                decoded);

            Assert.False(_idp.LastTokenRequestForm.ContainsKey("client_secret"));
        }

        [Fact]
        public async Task A_token_signed_by_the_wrong_key_is_rejected()
        {
            var otherIdp = new FakeIdentityProvider();
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(otherIdp.CreateIdToken(nonce: login.Nonce));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task An_expired_token_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(
                nonce: login.Nonce,
                notBefore: DateTime.UtcNow.AddHours(-2),
                expires: DateTime.UtcNow.AddHours(-1)));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_for_a_different_audience_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: login.Nonce, audience: "some-other-client"));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_from_a_different_issuer_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: login.Nonce, issuer: "https://evil.test/"));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_with_the_wrong_nonce_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: "a-different-nonce"));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_with_no_nonce_at_all_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(nonce: null));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_missing_the_username_claim_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(username: null, nonce: login.Nonce));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_rejected_code_surfaces_as_a_provider_rejection()
        {
            var login = _logins.Create();
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.ProviderRejected, error.UserSafeReason);
        }

        [Fact]
        public async Task A_response_without_an_id_token_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = "{\"access_token\":\"a\",\"token_type\":\"Bearer\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task Failures_never_leak_the_client_secret_or_the_token()
        {
            var login = _logins.Create();
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            var text = error.ToString();
            Assert.DoesNotContain(FakeIdentityProvider.ClientSecret, text, StringComparison.Ordinal);
            Assert.DoesNotContain(login.CodeVerifier, text, StringComparison.Ordinal);
        }
    }
}

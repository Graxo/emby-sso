using System;
using System.Collections.Generic;
using System.IO;
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

        private static OidcOptions CreateOptions()
        {
            return new OidcOptions
            {
                IssuerUrl = FakeIdentityProvider.Issuer,
                ClientId = FakeIdentityProvider.ClientId,
                ClientSecret = FakeIdentityProvider.ClientSecret,
                Scopes = "openid profile email",
                RedirectUri = "https://emby.test/emby/Sso/Callback",
                UsernameClaim = "preferred_username",
            };
        }

        private OidcClient CreateClient()
        {
            return CreateClient(options => { });
        }

        private OidcClient CreateClient(Action<OidcOptions> configure)
        {
            var options = CreateOptions();
            configure(options);
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

            // The response body itself carries the secret and code verifier, so this only proves
            // anything if the implementation is redacting the body rather than
            // simply never having had a secret to leak in the first place.
            _idp.TokenResponseJson =
                "{\"error\":\"invalid_grant\",\"error_description\":\"invalid client secret: "
                + FakeIdentityProvider.ClientSecret + ", code verifier: " + login.CodeVerifier + "\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            var text = error.ToString();
            Assert.DoesNotContain(FakeIdentityProvider.ClientSecret, text, StringComparison.Ordinal);
            Assert.DoesNotContain(login.CodeVerifier, text, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Failures_never_leak_the_id_token_on_a_validation_failure()
        {
            // The path that actually attaches an inner exception (and so is the one
            // that could leak into SsoException.ToString()) is JWT validation, not
            // the HTTP-rejection path above.
            var otherIdp = new FakeIdentityProvider();
            var login = _logins.Create();
            var idToken = otherIdp.CreateIdToken(nonce: login.Nonce);
            _idp.TokenResponseJson = _idp.CreateTokenResponse(idToken);

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
            Assert.DoesNotContain(idToken, error.ToString(), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_pending_login_with_no_nonce_is_rejected_before_contacting_the_provider()
        {
            // A pending login should always carry a nonce (PendingLoginStore.Create
            // always mints one). This constructs one directly, bypassing the store,
            // to prove the code-exchange path fails closed rather than treating a
            // missing nonce as "nonce checking is optional here".
            var login = new PendingLogin(
                "state-1",
                nonce: null,
                SecureRandom.CreateCodeVerifier(),
                DateTimeOffset.UtcNow.AddMinutes(5),
                SecureRandom.CreateToken(32));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
            Assert.Null(_idp.LastTokenRequestForm);
        }

        [Fact]
        public async Task A_null_pending_login_is_rejected_as_session_expired_before_contacting_the_provider()
        {
            // PendingLoginStore.Consume returns null for an expired, unknown, or
            // replayed state - the realistic caller is the callback handler doing
            // _logins.Consume(state). ExchangeCodeAsync must fail closed with
            // SessionExpired rather than dereferencing a null login.
            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", null, CancellationToken.None));

            Assert.Equal(SsoErrors.SessionExpired, error.UserSafeReason);
            Assert.Null(_idp.LastTokenRequestForm);
        }

        [Fact]
        public async Task An_unreachable_provider_surfaces_as_provider_unreachable()
        {
            var login = _logins.Create();
            var client = new OidcClient(new HttpClient(new ThrowingHandler()), CreateOptions());

            var error = await Assert.ThrowsAsync<SsoException>(
                () => client.ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.ProviderUnreachable, error.UserSafeReason);
            Assert.DoesNotContain(FakeIdentityProvider.Issuer, error.UserSafeReason, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_failure_reading_the_token_response_surfaces_as_provider_unreachable()
        {
            var login = _logins.Create();
            var client = new OidcClient(new HttpClient(new TokenReadFailureHandler(_idp)), CreateOptions());

            var error = await Assert.ThrowsAsync<SsoException>(
                () => client.ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.ProviderUnreachable, error.UserSafeReason);
        }

        [Fact]
        public async Task A_provider_error_containing_newlines_is_flattened_and_capped_in_the_exception_message()
        {
            // A hostile or compromised token endpoint controls this field. If it
            // reached the log verbatim it could forge additional log lines -
            // including a fake successful-authentication record.
            var login = _logins.Create();
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;

            var forged = "invalid_grant\n2026-08-30 00:00:00 Info AuthentikSso: SSO: issued a sign-in handoff for embyadmin"
                + new string('X', 250);
            _idp.TokenResponseJson = new Newtonsoft.Json.Linq.JObject { ["error"] = forged }.ToString();

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.ProviderRejected, error.UserSafeReason);
            Assert.DoesNotContain("\n", error.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("\r", error.Message, StringComparison.Ordinal);

            // Capped the same way SsoService.ForLog caps a provider-supplied
            // string: 200 characters, well short of the 280-character forged
            // value above.
            Assert.True(error.Message.Length < forged.Length, "the flattened message should be capped, not merely control-character-stripped");
        }

        [Fact]
        public async Task A_public_client_sends_client_id_in_the_form_and_no_authorization_header()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(nonce: login.Nonce));

            var options = CreateOptions();
            options.ClientSecret = string.Empty;

            await new OidcClient(new HttpClient(_idp), options)
                .ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.Equal(FakeIdentityProvider.ClientId, _idp.LastTokenRequestForm["client_id"]);
            Assert.Null(_idp.LastTokenRequestAuthorization);
        }

        [Fact]
        public async Task The_token_request_form_urlencodes_the_client_secret_before_basic_auth()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(nonce: login.Nonce));

            var options = CreateOptions();
            options.ClientSecret = "p@ss:w rd+%";

            await new OidcClient(new HttpClient(_idp), options)
                .ExchangeCodeAsync("the-code", login, CancellationToken.None);

            var decoded = Encoding.UTF8.GetString(
                Convert.FromBase64String(_idp.LastTokenRequestAuthorization.Parameter));

            // RFC 6749 §2.3.1: form-urlencoded, not raw concatenation. ':' -> %3A,
            // '@' -> %40, ' ' -> '+', '+' -> %2B, '%' -> %25.
            Assert.Equal(FakeIdentityProvider.ClientId + ":p%40ss%3Aw+rd%2B%25", decoded);
        }

        [Fact]
        public async Task Groups_are_read_from_the_token()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: login.Nonce, groups: new[] { "emby-users", "staff" }));

            var identity = await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.True(identity.HasGroupsClaim);
            Assert.Equal(new[] { "emby-users", "staff" }, identity.Groups);
        }

        [Fact]
        public async Task An_absent_groups_claim_is_distinguishable_from_an_empty_one()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(nonce: login.Nonce));

            var identity = await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.False(identity.HasGroupsClaim);
            Assert.Empty(identity.Groups);
        }

        [Fact]
        public async Task An_empty_groups_claim_is_present_but_empty()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: login.Nonce, groups: new string[0]));

            var identity = await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.True(identity.HasGroupsClaim);
            Assert.Empty(identity.Groups);
        }

        [Fact]
        public async Task The_groups_claim_name_is_configurable()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(
                nonce: login.Nonce,
                extraClaims: new Dictionary<string, object> { ["roles"] = new[] { "emby-users" } }));

            var client = CreateClient(options => options.GroupsClaim = "roles");
            var identity = await client.ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.Equal(new[] { "emby-users" }, identity.Groups);
        }

        /// <summary>Every request fails, as if the provider (or DNS, or the network) were down.</summary>
        private sealed class ThrowingHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                throw new HttpRequestException("simulated network failure reaching " + request.RequestUri);
            }
        }

        /// <summary>
        /// Discovery and JWKS succeed normally (forwarded to a real fake provider),
        /// but the token endpoint returns a response whose body throws when read -
        /// a mid-response transport failure rather than a connect failure.
        /// </summary>
        private sealed class TokenReadFailureHandler : HttpMessageHandler
        {
            private readonly HttpMessageInvoker _inner;

            public TokenReadFailureHandler(HttpMessageHandler inner)
            {
                _inner = new HttpMessageInvoker(inner, disposeHandler: false);
            }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (request.RequestUri.AbsoluteUri.EndsWith("/token/", StringComparison.Ordinal))
                {
                    return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ThrowingContent() };
                }

                return await _inner.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }

            private sealed class ThrowingContent : HttpContent
            {
                protected override Task SerializeToStreamAsync(Stream stream, TransportContext context)
                {
                    throw new IOException("simulated failure reading the token response body");
                }

                protected override bool TryComputeLength(out long length)
                {
                    length = 0;
                    return false;
                }
            }
        }
    }
}

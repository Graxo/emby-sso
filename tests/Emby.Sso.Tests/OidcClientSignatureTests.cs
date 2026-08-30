using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The signature and algorithm half of id_token validation - the token the
    /// group claim, and therefore the whole authorisation decision, is read out
    /// of.
    ///
    /// These tests exist because a mutation run found three surviving mutants
    /// here and nowhere else: <c>RequireSignedTokens = false</c>, deleting the
    /// <c>ValidAlgorithms</c> pin, and making the pin's fallback return an empty
    /// list (which the token handler reads as "no restriction"). Every one of
    /// them could be applied to the shipped source without a single test
    /// noticing. Each test below was confirmed to FAIL against the mutation it
    /// names - not merely to pass against the correct code.
    ///
    /// The JWKS in these tests deliberately omits the optional <c>alg</c> member
    /// (RFC 7517 §4.4), so that key resolution cannot be what rejects a
    /// wrongly-signed token and <c>ValidAlgorithms</c> is the only thing left
    /// holding the line. A JWKS that pins <c>alg</c> would make these tests pass
    /// for a reason that has nothing to do with the code under test.
    /// </summary>
    public class OidcClientSignatureTests
    {
        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();
        private readonly PendingLoginStore _logins =
            new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

        private OidcClient CreateClient()
        {
            return new OidcClient(
                new HttpClient(_idp),
                new OidcOptions
                {
                    IssuerUrl = FakeIdentityProvider.Issuer,
                    ClientId = FakeIdentityProvider.ClientId,
                    ClientSecret = FakeIdentityProvider.ClientSecret,
                    Scopes = "openid profile email",
                    RedirectUri = "https://emby.test/emby/Sso/Callback",
                    UsernameClaim = "preferred_username",
                });
        }

        [Fact]
        public async Task An_unsigned_token_is_rejected()
        {
            // "alg": "none" with an empty signature. Everything else about the
            // token is correct - right issuer, right audience, right nonce, in
            // date - so the only thing that can refuse it is
            // RequireSignedTokens. Kills the RequireSignedTokens = false mutant.
            var login = _logins.Create();
            var idToken = _idp.CreateIdToken(nonce: login.Nonce, signed: false);

            Assert.Equal(string.Empty, idToken.Split('.')[2]);

            _idp.TokenResponseJson = _idp.CreateTokenResponse(idToken);

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task An_unsigned_token_is_rejected_on_the_direct_grant_path_too()
        {
            // The native path validates with requireNonce: false, which is a
            // second set of TokenValidationParameters' worth of behaviour to get
            // wrong. It is also the path that reaches an id_token without a
            // browser ever being involved.
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(signed: false));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().DirectGrantAsync("alice", "hunter2", CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_signed_with_an_algorithm_the_provider_does_not_advertise_is_rejected()
        {
            // The discovery document advertises RS256 alone, as Authentik's
            // does. The token is signed RS512 with the provider's own real key,
            // so its signature verifies - only the algorithm pin refuses it.
            // Kills both the "delete ValidAlgorithms" mutant and the "return an
            // empty list" mutant.
            _idp.JwksAlgorithm = null;
            _idp.AdvertisedSigningAlgorithms = new[] { "RS256" };

            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: login.Nonce, signingAlgorithm: SecurityAlgorithms.RsaSha512));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task An_algorithm_the_provider_does_advertise_is_accepted()
        {
            // The other half of the pin: it must admit what the document
            // advertises, or the test above would pass just as well against a
            // pin that refuses everything.
            _idp.JwksAlgorithm = null;
            _idp.AdvertisedSigningAlgorithms = new[] { "RS256", "RS512" };

            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: login.Nonce, signingAlgorithm: SecurityAlgorithms.RsaSha512));

            var identity = await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.Equal("alice", identity.Username);
        }

        [Fact]
        public async Task A_document_advertising_no_recognised_rsa_algorithm_still_pins_rs256()
        {
            // The fallback in AllowedRsaAlgorithms. An empty ValidAlgorithms is
            // read by the token handler as NO restriction, so a document that
            // advertises nothing this client recognises must fall back to RS256
            // alone rather than producing an empty list. Under the "return an
            // empty list" mutant this RS512 token is accepted.
            _idp.JwksAlgorithm = null;
            _idp.AdvertisedSigningAlgorithms = new[] { "HS256", "ES256" };

            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: login.Nonce, signingAlgorithm: SecurityAlgorithms.RsaSha512));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_document_advertising_no_recognised_rsa_algorithm_still_accepts_rs256()
        {
            // The fallback must be RS256 specifically, not "refuse everything":
            // a provider whose document is missing or unhelpful still has to be
            // able to sign in with the one algorithm every OIDC provider
            // supports.
            _idp.JwksAlgorithm = null;
            _idp.AdvertisedSigningAlgorithms = new string[0];

            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(nonce: login.Nonce));

            var identity = await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.Equal("alice", identity.Username);
        }

        [Fact]
        public async Task A_token_signed_with_an_unadvertised_algorithm_is_rejected_on_the_direct_grant_path_too()
        {
            _idp.JwksAlgorithm = null;
            _idp.AdvertisedSigningAlgorithms = new[] { "RS256" };
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(signingAlgorithm: SecurityAlgorithms.RsaSha512));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().DirectGrantAsync("alice", "hunter2", CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }
    }
}

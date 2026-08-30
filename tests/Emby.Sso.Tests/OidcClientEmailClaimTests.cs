using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// S1c end to end through real token validation: an operator who configures
    /// the `email` claim gets it only on tokens that positively assert
    /// email_verified. Signed by the in-process provider, so these exercise the
    /// same path a live sign-in does.
    /// </summary>
    public class OidcClientEmailClaimTests
    {
        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();
        private readonly PendingLoginStore _logins =
            new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

        private OidcClient CreateClient(string usernameClaim)
        {
            return new OidcClient(new HttpClient(_idp), new OidcOptions
            {
                IssuerUrl = FakeIdentityProvider.Issuer,
                ClientId = FakeIdentityProvider.ClientId,
                ClientSecret = FakeIdentityProvider.ClientSecret,
                Scopes = "openid profile email",
                RedirectUri = "https://emby.test/emby/Sso/Callback",
                UsernameClaim = usernameClaim,
            });
        }

        private PendingLogin ArrangeToken(IDictionary<string, object> extraClaims)
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: login.Nonce, extraClaims: extraClaims));
            return login;
        }

        [Fact]
        public async Task An_email_claim_with_a_verified_address_is_accepted()
        {
            var login = ArrangeToken(new Dictionary<string, object>
            {
                ["email"] = "alice@example.test",
                ["email_verified"] = true,
            });

            var identity = await CreateClient("email").ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.Equal("alice@example.test", identity.Username);
            Assert.True(identity.EmailVerified);
        }

        [Fact]
        public async Task An_email_claim_with_an_unverified_address_is_refused()
        {
            // The takeover shape: a user who can set their own email address in
            // the identity provider naming somebody else's Emby account.
            var login = ArrangeToken(new Dictionary<string, object>
            {
                ["email"] = "victim@example.test",
                ["email_verified"] = false,
            });

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient("email").ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task An_email_claim_with_no_email_verified_at_all_is_refused()
        {
            var login = ArrangeToken(new Dictionary<string, object>
            {
                ["email"] = "victim@example.test",
            });

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient("email").ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_string_valued_email_verified_is_read_the_same_way()
        {
            // Providers do emit "email_verified": "true" as a string. Both
            // directions must be read, and only those two.
            var accepted = await CreateClient("email").ExchangeCodeAsync(
                "the-code",
                ArrangeToken(new Dictionary<string, object>
                {
                    ["email"] = "alice@example.test",
                    ["email_verified"] = "true",
                }),
                CancellationToken.None);

            Assert.Equal("alice@example.test", accepted.Username);

            var refusal = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient("email").ExchangeCodeAsync(
                    "the-code",
                    ArrangeToken(new Dictionary<string, object>
                    {
                        ["email"] = "victim@example.test",
                        ["email_verified"] = "false",
                    }),
                    CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, refusal.UserSafeReason);
        }

        [Theory]
        [InlineData("yes")]
        [InlineData("1")]
        [InlineData(1)]
        public async Task An_unrecognised_email_verified_value_is_not_a_true(object value)
        {
            // Anything this code cannot read as a boolean reads as "the token
            // does not say", which refuses. A hostile or merely eccentric
            // provider must not be able to spell its way past the guard.
            var login = ArrangeToken(new Dictionary<string, object>
            {
                ["email"] = "victim@example.test",
                ["email_verified"] = value,
            });

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient("email").ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task The_default_username_claim_is_unaffected_by_a_missing_email_verified()
        {
            // The guard applies to the `email` claim only; a provider that emits
            // no email_verified must keep working on preferred_username.
            var login = ArrangeToken(null);

            var identity = await CreateClient("preferred_username")
                .ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.Equal("alice", identity.Username);
            Assert.Null(identity.EmailVerified);
        }
    }
}

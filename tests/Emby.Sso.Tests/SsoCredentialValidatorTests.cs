using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class SsoCredentialValidatorTests
    {
        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();
        private readonly HandoffSecretStore _handoff =
            new HandoffSecretStore(() => DateTimeOffset.UtcNow, TimeSpan.FromSeconds(30));

        private bool _directGrantEnabled = true;
        private bool _configured = true;

        private OidcClient Client()
        {
            if (!_configured)
            {
                return null;
            }

            return new OidcClient(new HttpClient(_idp), new OidcOptions
            {
                IssuerUrl = FakeIdentityProvider.Issuer,
                ClientId = FakeIdentityProvider.ClientId,
                ClientSecret = FakeIdentityProvider.ClientSecret,
                Scopes = "openid profile email",
                RedirectUri = "https://emby.test/emby/Sso/Callback",
                UsernameClaim = "preferred_username",
            });
        }

        private SsoCredentialValidator CreateValidator() =>
            new SsoCredentialValidator(_handoff, Client, () => _directGrantEnabled);

        [Fact]
        public async Task A_valid_handoff_secret_is_accepted_without_contacting_the_provider()
        {
            var secret = _handoff.Issue("alice");

            var result = await CreateValidator().ValidateAsync("alice", secret, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.HandoffAccepted, result.Outcome);
            Assert.Null(_idp.LastTokenRequestForm);
        }

        [Fact]
        public async Task A_handoff_secret_works_only_once()
        {
            var secret = _handoff.Issue("alice");
            var validator = CreateValidator();

            await validator.ValidateAsync("alice", secret, CancellationToken.None);
            _directGrantEnabled = false;

            var second = await validator.ValidateAsync("alice", secret, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, second.Outcome);
        }

        [Fact]
        public async Task A_real_password_is_checked_by_direct_grant()
        {
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "alice"));

            var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.DirectGrantAccepted, result.Outcome);
            Assert.Equal("password", _idp.LastTokenRequestForm["grant_type"]);
        }

        [Fact]
        public async Task A_password_is_rejected_when_direct_grant_is_disabled()
        {
            _directGrantEnabled = false;

            var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Equal(SsoErrors.DirectGrantDisabled, result.Reason);
            Assert.Null(_idp.LastTokenRequestForm);
        }

        [Fact]
        public async Task A_handoff_secret_is_accepted_even_when_direct_grant_is_disabled()
        {
            _directGrantEnabled = false;
            var secret = _handoff.Issue("alice");

            var result = await CreateValidator().ValidateAsync("alice", secret, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.HandoffAccepted, result.Outcome);
        }

        [Fact]
        public async Task Wrong_credentials_are_rejected()
        {
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var result = await CreateValidator().ValidateAsync("alice", "wrong", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Equal(SsoErrors.ProviderRejected, result.Reason);
        }

        [Fact]
        public async Task A_provider_identity_for_a_different_user_is_rejected()
        {
            // The provider authenticated someone, but not the account being signed into.
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "mallory"));

            var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Equal(SsoErrors.UnknownUser, result.Reason);
        }

        [Fact]
        public async Task An_unconfigured_plugin_rejects_everything()
        {
            _configured = false;

            var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Equal(SsoErrors.NotConfigured, result.Reason);
        }

        [Fact]
        public async Task An_unconfigured_plugin_takes_precedence_over_direct_grant_disabled()
        {
            // Both checks would reject this call on their own, so on their own
            // they can't prove the validator checks configuration before checking
            // whether direct grant is enabled. Swapping that order would only
            // surface via an incidental null reference from the unconfigured
            // client factory. Pin the precedence directly by asserting the reason.
            _configured = false;
            _directGrantEnabled = false;

            var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Equal(SsoErrors.NotConfigured, result.Reason);
        }

        [Fact]
        public async Task An_empty_username_or_password_is_rejected()
        {
            var validator = CreateValidator();

            var noUsername = await validator.ValidateAsync(null, "x", CancellationToken.None);
            var noPassword = await validator.ValidateAsync("alice", null, CancellationToken.None);
            var emptyPassword = await validator.ValidateAsync("alice", "", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, noUsername.Outcome);
            Assert.Equal(SsoCredentialOutcome.Rejected, noPassword.Outcome);
            Assert.Equal(SsoCredentialOutcome.Rejected, emptyPassword.Outcome);

            // Its own reason, not a borrowed one: nothing here was rejected by
            // the provider, so ProviderRejected would misdescribe why in both
            // the log and the response.
            Assert.Equal(SsoErrors.EmptyCredential, noUsername.Reason);
            Assert.Equal(SsoErrors.EmptyCredential, noPassword.Reason);
            Assert.Equal(SsoErrors.EmptyCredential, emptyPassword.Reason);
        }
    }
}

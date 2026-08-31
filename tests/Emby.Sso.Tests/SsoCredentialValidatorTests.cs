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

        private readonly SignInPinStore _pins =
            new SignInPinStore(() => DateTimeOffset.UtcNow, SignInPinStore.DefaultTtl);

        private bool _directGrantEnabled = true;
        private bool _pinSignInEnabled = true;
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
            new SsoCredentialValidator(_handoff, _pins, Client, () => _directGrantEnabled, () => _pinSignInEnabled);

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

        [Fact]
        public async Task A_direct_grant_result_carries_the_verified_identity()
        {
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(username: "alice", groups: new[] { "emby-users" }));

            var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.DirectGrantAccepted, result.Outcome);
            Assert.NotNull(result.Identity);
            Assert.Equal("alice", result.Identity.Username);
            Assert.Equal(new[] { "emby-users" }, result.Identity.Groups);
        }

        [Fact]
        public async Task A_rejection_carries_no_identity()
        {
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var result = await CreateValidator().ValidateAsync("alice", "wrong", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Null(result.Identity);
        }

        [Fact]
        public async Task A_handoff_result_carries_no_identity()
        {
            var secret = _handoff.Issue("alice");

            var result = await CreateValidator().ValidateAsync("alice", secret, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.HandoffAccepted, result.Outcome);
            Assert.Null(result.Identity);
        }

        // ------------------------------------------------------------------
        // The third credential shape: a one-time sign-in PIN.
        //
        // The rules being pinned here are that a PIN never reaches the identity
        // provider, that it is refused when the operator has not enabled it,
        // and - the one that matters - that a value which is not somebody's
        // live PIN falls through to the remaining shapes exactly as it did
        // before PINs existed, so nothing about a refusal says which shape was
        // attempted.
        // ------------------------------------------------------------------

        [Fact]
        public async Task A_live_pin_is_accepted_without_contacting_the_provider()
        {
            var pin = _pins.Issue("alice");

            var result = await CreateValidator().ValidateAsync("alice", pin, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.PinAccepted, result.Outcome);
            Assert.Null(_idp.LastTokenRequestForm);
        }

        [Fact]
        public async Task A_pin_result_carries_no_identity()
        {
            var pin = _pins.Issue("alice");

            var result = await CreateValidator().ValidateAsync("alice", pin, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.PinAccepted, result.Outcome);
            Assert.Null(result.Identity);
        }

        [Fact]
        public async Task A_pin_works_only_once()
        {
            var pin = _pins.Issue("alice");
            var validator = CreateValidator();

            await validator.ValidateAsync("alice", pin, CancellationToken.None);
            _directGrantEnabled = false;

            var second = await validator.ValidateAsync("alice", pin, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, second.Outcome);
        }

        [Fact]
        public async Task A_pin_is_refused_while_pin_sign_in_is_disabled()
        {
            var pin = _pins.Issue("alice");
            _pinSignInEnabled = false;
            _directGrantEnabled = false;

            var result = await CreateValidator().ValidateAsync("alice", pin, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
        }

        /// <summary>
        /// And it is not consumed on the way past, either: turning the setting
        /// off must not silently destroy the PINs of everyone who was holding
        /// one when it happened.
        /// </summary>
        [Fact]
        public async Task Disabling_pin_sign_in_does_not_spend_the_pins_already_issued()
        {
            var pin = _pins.Issue("alice");
            _pinSignInEnabled = false;
            _directGrantEnabled = false;

            await CreateValidator().ValidateAsync("alice", pin, CancellationToken.None);

            _pinSignInEnabled = true;

            var result = await CreateValidator().ValidateAsync("alice", pin, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.PinAccepted, result.Outcome);
        }

        /// <summary>
        /// A PIN belongs to one account. Presented with another username it is
        /// simply not a PIN at all, and falls through to the direct grant like
        /// any other password - where the identity provider refuses it.
        /// </summary>
        [Fact]
        public async Task A_pin_presented_with_another_username_is_not_accepted()
        {
            var pin = _pins.Issue("alice");
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var result = await CreateValidator().ValidateAsync("bob", pin, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
        }

        /// <summary>
        /// The no-leak rule. A wrong PIN and a wrong password produce the same
        /// outcome and the same sentence, so a caller cannot use the refusal to
        /// discover which shape they were attempting - or whether the account
        /// had a live PIN at all.
        /// </summary>
        [Fact]
        public async Task A_wrong_pin_is_refused_exactly_as_a_wrong_password_is()
        {
            _pins.Issue("alice");
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var wrongPin = await CreateValidator().ValidateAsync("alice", "ABCD-EFGH", CancellationToken.None);
            var wrongPassword = await CreateValidator().ValidateAsync("carol", "not my password", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, wrongPin.Outcome);
            Assert.Equal(wrongPassword.Outcome, wrongPin.Outcome);
            Assert.Equal(wrongPassword.Reason, wrongPin.Reason);
        }

        /// <summary>
        /// The fall-through, from the other direction: a user whose account has
        /// a live PIN can still sign in with their real password, and doing so
        /// does not cost them the PIN.
        /// </summary>
        [Fact]
        public async Task A_password_still_works_for_a_user_who_is_holding_a_live_pin()
        {
            var pin = _pins.Issue("alice");
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "alice"));

            var byPassword = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.DirectGrantAccepted, byPassword.Outcome);

            var byPin = await CreateValidator().ValidateAsync("alice", pin, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.PinAccepted, byPin.Outcome);
        }

        /// <summary>
        /// And a handoff secret still works for such a user too - the three
        /// shapes are independent, and none of them can spend another's.
        /// </summary>
        [Fact]
        public async Task A_handoff_secret_still_works_for_a_user_who_is_holding_a_live_pin()
        {
            var pin = _pins.Issue("alice");
            var secret = _handoff.Issue("alice");

            var byHandoff = await CreateValidator().ValidateAsync("alice", secret, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.HandoffAccepted, byHandoff.Outcome);

            var byPin = await CreateValidator().ValidateAsync("alice", pin, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.PinAccepted, byPin.Outcome);
        }

        /// <summary>
        /// A PIN must never be forwarded to the identity provider as though it
        /// were a password. It is answered from memory, above the round trip.
        /// </summary>
        [Fact]
        public async Task A_pin_is_answered_before_the_direct_grant_is_even_permitted()
        {
            var pin = _pins.Issue("alice");
            _directGrantEnabled = false;

            var result = await CreateValidator().ValidateAsync("alice", pin, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.PinAccepted, result.Outcome);
            Assert.Null(_idp.LastTokenRequestForm);
        }
    }
}

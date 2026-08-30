using System;
using System.Threading;
using System.Threading.Tasks;

namespace Emby.Sso.Protocol
{
    public enum SsoCredentialOutcome
    {
        Rejected = 0,
        HandoffAccepted = 1,
        DirectGrantAccepted = 2,
    }

    public sealed class SsoCredentialResult
    {
        private SsoCredentialResult(SsoCredentialOutcome outcome, string displayName, string reason)
        {
            Outcome = outcome;
            DisplayName = displayName;
            Reason = reason;
        }

        public SsoCredentialOutcome Outcome { get; }

        public string DisplayName { get; }

        public string Reason { get; }

        public static SsoCredentialResult Handoff(string displayName) =>
            new SsoCredentialResult(SsoCredentialOutcome.HandoffAccepted, displayName, null);

        public static SsoCredentialResult DirectGrant(string displayName) =>
            new SsoCredentialResult(SsoCredentialOutcome.DirectGrantAccepted, displayName, null);

        public static SsoCredentialResult Reject(string reason) =>
            new SsoCredentialResult(SsoCredentialOutcome.Rejected, null, reason);
    }

    /// <summary>
    /// The single decision an Emby sign-in funnels into: is this password a live
    /// browser handoff secret, or a real password the identity provider should
    /// check?
    ///
    /// This class does NOT and CANNOT verify that the Emby account exists. It
    /// stays free of <c>MediaBrowser.*</c> types by design, so it has no way to
    /// ask Emby whether the username it was given resolved to a real user.
    /// Emby hands its authentication providers a null resolved user for an
    /// unknown username, and if a provider returns success for that call, Emby
    /// auto-creates the account. The caller - the Emby-facing authentication
    /// provider - MUST check Emby's resolved user itself and refuse the sign-in
    /// when it is null, before ever consulting this validator's result. Do not
    /// treat a <see cref="SsoCredentialOutcome.HandoffAccepted"/> or
    /// <see cref="SsoCredentialOutcome.DirectGrantAccepted"/> result from
    /// <see cref="ValidateAsync"/> as proof the account already exists.
    /// </summary>
    public sealed class SsoCredentialValidator
    {
        private readonly HandoffSecretStore _handoff;
        private readonly Func<OidcClient> _clientFactory;
        private readonly Func<bool> _directGrantEnabled;

        public SsoCredentialValidator(
            HandoffSecretStore handoff,
            Func<OidcClient> clientFactory,
            Func<bool> directGrantEnabled)
        {
            _handoff = handoff ?? throw new ArgumentNullException(nameof(handoff));
            _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
            _directGrantEnabled = directGrantEnabled ?? throw new ArgumentNullException(nameof(directGrantEnabled));
        }

        public async Task<SsoCredentialResult> ValidateAsync(string embyUsername, string password, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(embyUsername) || string.IsNullOrEmpty(password))
            {
                return SsoCredentialResult.Reject(SsoErrors.ProviderRejected);
            }

            if (_handoff.TryConsume(embyUsername, password))
            {
                return SsoCredentialResult.Handoff(embyUsername);
            }

            var client = _clientFactory();

            if (client == null)
            {
                return SsoCredentialResult.Reject(SsoErrors.NotConfigured);
            }

            if (!_directGrantEnabled())
            {
                return SsoCredentialResult.Reject(SsoErrors.DirectGrantDisabled);
            }

            OidcIdentity identity;

            try
            {
                identity = await client.DirectGrantAsync(embyUsername, password, cancellationToken).ConfigureAwait(false);
            }
            catch (SsoException ex)
            {
                return SsoCredentialResult.Reject(ex.UserSafeReason);
            }

            if (!UsernameMatcher.Matches(identity.Username, embyUsername))
            {
                return SsoCredentialResult.Reject(SsoErrors.UnknownUser);
            }

            return SsoCredentialResult.DirectGrant(identity.DisplayName);
        }
    }
}

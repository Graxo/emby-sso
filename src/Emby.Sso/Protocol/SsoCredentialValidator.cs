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
        private SsoCredentialResult(
            SsoCredentialOutcome outcome,
            string displayName,
            string reason,
            OidcIdentity identity,
            bool providerUnreachable)
        {
            Outcome = outcome;
            DisplayName = displayName;
            Reason = reason;
            Identity = identity;
            ProviderUnreachable = providerUnreachable;
        }

        public SsoCredentialOutcome Outcome { get; }

        public string DisplayName { get; }

        public string Reason { get; }

        /// <summary>
        /// The verified identity, on the direct-grant path only. Null on rejection,
        /// and null for a handoff secret — that path proves the browser flow already
        /// ran and applied the gate, so no identity is carried here.
        /// </summary>
        public OidcIdentity Identity { get; }

        /// <summary>
        /// This refusal is a transport failure: the identity provider was never
        /// reached, so no credential was tested and the result reflects the
        /// network, not the caller.
        ///
        /// It is a property of the result rather than a fourth
        /// <see cref="SsoCredentialOutcome"/> member on purpose. Nothing in this
        /// codebase switches exhaustively on that enum - callers ask
        /// `== Rejected` or `!= DirectGrantAccepted` - so a new member would be
        /// read as "not a rejection" by whichever of those a future reader
        /// forgot to visit, and on an authorisation decision that direction is
        /// fail-open. As a flag on a result that is still
        /// <see cref="SsoCredentialOutcome.Rejected"/>, every existing caller
        /// keeps refusing exactly as it did, and only code that deliberately
        /// asks the question sees any difference.
        ///
        /// It is false on every other result, including refusals that also never
        /// reached the provider (an empty credential, an unconfigured plugin,
        /// direct grant switched off). That is deliberate and must stay so: this
        /// flag says "the provider could not be reached", NOT "cheap to
        /// produce". Those refusals ARE free for an attacker to generate, so
        /// <see cref="ProvisioningThrottle"/> must keep counting them.
        ///
        /// The one and only thing this changes is whether the provisioning
        /// throttle counts the failure. It must never become something a caller
        /// can see: the refusal an unreachable provider produces is the same
        /// outcome and the same sentence it has always been.
        /// </summary>
        public bool ProviderUnreachable { get; }

        public static SsoCredentialResult Handoff(string displayName) =>
            new SsoCredentialResult(SsoCredentialOutcome.HandoffAccepted, displayName, null, null, false);

        public static SsoCredentialResult DirectGrant(OidcIdentity identity) =>
            new SsoCredentialResult(SsoCredentialOutcome.DirectGrantAccepted, identity.DisplayName, null, identity, false);

        /// <summary>
        /// The ordinary refusal. Not unreachable: every reason that reaches here
        /// is either the provider's own verdict or one this process decided, and
        /// both are things a caller can produce at will, so both must cost
        /// budget.
        /// </summary>
        public static SsoCredentialResult Reject(string reason) =>
            new SsoCredentialResult(SsoCredentialOutcome.Rejected, null, reason, null, false);

        /// <summary>
        /// A refusal caused by not reaching the identity provider at all. Takes
        /// no reason, so it cannot say anything other than what an unreachable
        /// provider has always said, and it is
        /// <see cref="SsoCredentialOutcome.Rejected"/> like any other refusal,
        /// so no caller that does not ask about
        /// <see cref="ProviderUnreachable"/> can tell the two apart.
        ///
        /// The only correct source of this is an <see cref="SsoException"/>
        /// whose <see cref="SsoException.ProviderUnreachable"/> is set. Do not
        /// call it for a failure the provider actually judged - that would hand
        /// an attacker failures that cost nothing.
        /// </summary>
        public static SsoCredentialResult Unreachable() =>
            new SsoCredentialResult(SsoCredentialOutcome.Rejected, null, SsoErrors.ProviderUnreachable, null, true);
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
                return SsoCredentialResult.Reject(SsoErrors.EmptyCredential);
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
                // The exception's flag, never its text, decides this. An
                // unreachable provider tested no password, so the failure is
                // carried through as one the provisioning throttle will not
                // charge to the caller - and as nothing else: same outcome, same
                // sentence, since ex.UserSafeReason for an unreachable failure is
                // the very constant Unreachable() carries.
                //
                // Everything else, the provider's own rejection of the credential
                // included, is an ordinary refusal and is counted.
                return ex.ProviderUnreachable
                    ? SsoCredentialResult.Unreachable()
                    : SsoCredentialResult.Reject(ex.UserSafeReason);
            }

            if (!UsernameMatcher.Matches(identity.Username, embyUsername))
            {
                return SsoCredentialResult.Reject(SsoErrors.UnknownUser);
            }

            return SsoCredentialResult.DirectGrant(identity);
        }
    }
}

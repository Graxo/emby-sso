using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Why the provisioning branch may not forward a credential, or that it may.
    ///
    /// The zero member is a refusal, like <see cref="GroupGateOutcome"/>'s, so
    /// that a default-initialised value fails closed; and the only member that
    /// admits anything is <see cref="MayContactProvider"/>, which callers must
    /// test for explicitly rather than testing for the refusals they happen to
    /// know about.
    /// </summary>
    public enum ProvisioningPreconditionOutcome
    {
        /// <summary>Auto-create is off. Indistinguishable to the caller from the account not existing.</summary>
        AutoCreateDisabled = 0,

        /// <summary>No template user is configured, so there is no policy to create an account with.</summary>
        TemplateNotConfigured = 1,

        /// <summary>Native password sign-in is switched off.</summary>
        DirectGrantDisabled = 2,

        /// <summary>
        /// No required group is configured, so the gate this branch ends in
        /// cannot admit anyone. Decided from configuration alone.
        /// </summary>
        RequiredGroupNotConfigured = 3,

        /// <summary>The brute-force brake is closed for this username or globally.</summary>
        Throttled = 4,

        /// <summary>Every precondition passed; the credential may now be forwarded.</summary>
        MayContactProvider = 5,
    }

    /// <summary>
    /// The settings the provisioning branch's preconditions are decided from.
    /// A plain carrier so <see cref="ProvisioningPreconditions"/> can live in
    /// Protocol/, which never references <c>MediaBrowser.*</c> or the plugin's
    /// own configuration type - and so the whole ordered chain is reachable
    /// from the test project.
    /// </summary>
    public sealed class ProvisioningSettings
    {
        public bool EnableAutoCreate { get; set; }

        public string TemplateUserName { get; set; }

        public bool EnableDirectGrant { get; set; }

        public string RequiredGroup { get; set; }
    }

    /// <summary>
    /// Everything the provisioning branch decides BEFORE it forwards a password
    /// to the identity provider, in the order it decides it.
    ///
    /// The order is the security argument of that branch, and it is here rather
    /// than inline in <c>SsoAuthenticationProvider.ProvisionOrRefuse</c> so that
    /// it can be asserted by a test instead of only described in a comment. Two
    /// properties are load-bearing and are what the tests pin:
    ///
    /// - <b>Every configuration refusal is decided before the throttle is
    ///   consulted, and before anything is sent anywhere.</b> These refusals are
    ///   an operator's omission, not a credential attempt. If one of them were
    ///   decided after the throttle check, or worse after the credential was
    ///   forwarded, it would be charged to the throttle's global bucket - and a
    ///   hundred such refusals, spread over a hundred DIFFERENT usernames on a
    ///   mass first sign-in, close the branch for fifteen minutes for everybody,
    ///   including for the fifteen minutes AFTER the operator fixes the setting.
    ///   That is the self-inflicted outage this ordering exists to prevent.
    /// - <b>This function itself records nothing.</b> It reads the throttle and
    ///   never writes to it, so no refusal it returns can consume budget. The
    ///   counted failures all live below it, at the exits that reflect the
    ///   credential itself.
    ///
    /// A future reader must not reorder these to "fail faster" on the cheap
    /// checks, and must not move a configuration check below the throttle read.
    /// </summary>
    public static class ProvisioningPreconditions
    {
        public static ProvisioningPreconditionOutcome Evaluate(
            ProvisioningSettings settings,
            string username,
            ProvisioningThrottle throttle,
            DateTimeOffset now)
        {
            if (throttle == null)
            {
                throw new ArgumentNullException(nameof(throttle));
            }

            // A missing configuration is an unconfigured server, which is a
            // server that is not provisioning.
            if (settings == null || !settings.EnableAutoCreate)
            {
                return ProvisioningPreconditionOutcome.AutoCreateDisabled;
            }

            if (string.IsNullOrWhiteSpace(settings.TemplateUserName))
            {
                return ProvisioningPreconditionOutcome.TemplateNotConfigured;
            }

            // Only a native sign-in reaches this branch, and a native sign-in is
            // exactly what EnableDirectGrant governs.
            if (!settings.EnableDirectGrant)
            {
                return ProvisioningPreconditionOutcome.DirectGrantDisabled;
            }

            // The fourth configuration check, and the reason this whole chain
            // moved above the throttle. GroupGate answers NotConfigured for an
            // unset required group from configuration ALONE - no identity, no
            // token, no network - so a server in that state can and must refuse
            // here, rather than forwarding a real password to the provider in a
            // loop that cannot succeed. Who is admitted does not change: an
            // unset required group refuses every SSO sign-in either way.
            if (string.IsNullOrWhiteSpace(settings.RequiredGroup))
            {
                return ProvisioningPreconditionOutcome.RequiredGroupNotConfigured;
            }

            // Last, and still before anything is sent: from here the caller
            // hands the supplied password to the identity provider, and an
            // unknown username has no Emby account for Emby's own throttle to
            // count against.
            if (throttle.IsThrottled(username, now))
            {
                return ProvisioningPreconditionOutcome.Throttled;
            }

            return ProvisioningPreconditionOutcome.MayContactProvider;
        }
    }
}

using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The outcome of asking whether an EXISTING Emby account belongs to this
    /// plugin. Zero is a refusal, like every other decision enum here: a value
    /// that was never assigned, or one produced by a future member nobody
    /// updated the callers for, must not admit anybody.
    /// </summary>
    internal enum ProviderStampOutcome
    {
        /// <summary>
        /// Fail-closed default. Reachable only from a default-initialised value.
        /// </summary>
        Refused = 0,

        /// <summary>
        /// The account names this plugin as its authentication provider. This is
        /// the ONLY outcome that may sign an existing account in.
        /// </summary>
        StampedToThisPlugin = 1,

        /// <summary>
        /// The account has no authentication provider assigned at all. Emby
        /// offers such an account to EVERY enabled provider, so without this
        /// refusal a freshly created administrator who has never logged in is
        /// reachable through single sign-on by whoever can present its name.
        /// </summary>
        Unstamped = 2,

        /// <summary>
        /// The account belongs to some other provider - Emby's own password
        /// check, or another plugin. It is not ours to authenticate.
        /// </summary>
        StampedToAnotherProvider = 3,
    }

    /// <summary>
    /// Decides whether an existing Emby account is one this plugin may
    /// authenticate.
    ///
    /// WHY THIS EXISTS, and why weakening it re-opens an account-takeover.
    ///
    /// Emby's UserManager.GetAuthenticationProviders (decompiled from a running
    /// 4.9.5.0 server - see .superpowers/security/2026-08-30-owasp-assessment.md
    /// finding F1) offers an account whose Policy.AuthenticationProviderId is
    /// EMPTY to every enabled provider in turn and stamps whichever one first
    /// succeeds. A local Emby account that has never signed in - very much
    /// including a newly created administrator - is exactly that. So the moment
    /// this plugin is installed, every unstamped account becomes reachable
    /// through the identity provider by anyone who can present a token naming
    /// it, and the identity provider is not the authority on who owns local
    /// Emby accounts.
    ///
    /// This plugin therefore refuses to authenticate an existing account unless
    /// the account already names this plugin. Adopting an existing account into
    /// SSO becomes a deliberate operator action - Dashboard -> Users -> Login
    /// provider, or POST /emby/Users/{id}/Policy for an administrator - which is
    /// the workflow the README documents.
    ///
    /// A future reader must not relax this to "unstamped is fine, Emby would
    /// have stamped it anyway". Emby stamping it AFTER a successful sign-in is
    /// precisely the problem: the first successful sign-in is the takeover.
    ///
    /// Nothing here knows the plugin's own type name; the caller supplies it, so
    /// this file carries no Emby dependency and stays under test.
    /// </summary>
    internal static class ProviderStamp
    {
        /// <summary>
        /// Ordinal, not culture- or case-insensitive. The value is a CLR type
        /// name that Emby compares with its own ordinal equality, so accepting a
        /// differently cased spelling here would admit an account Emby does not
        /// actually route to this plugin.
        /// </summary>
        public static ProviderStampOutcome Evaluate(string accountProviderId, string thisProviderId)
        {
            if (string.IsNullOrWhiteSpace(thisProviderId))
            {
                // The caller could not name this plugin. Nothing can match, and
                // guessing is not an option on an authentication decision.
                return ProviderStampOutcome.Refused;
            }

            if (string.IsNullOrWhiteSpace(accountProviderId))
            {
                return ProviderStampOutcome.Unstamped;
            }

            return string.Equals(accountProviderId.Trim(), thisProviderId.Trim(), StringComparison.Ordinal)
                ? ProviderStampOutcome.StampedToThisPlugin
                : ProviderStampOutcome.StampedToAnotherProvider;
        }

        /// <summary>
        /// The single whitelist every caller must go through. Written as an
        /// explicit equality against the one admitting member rather than as a
        /// set of refusals, so that adding a member to
        /// <see cref="ProviderStampOutcome"/> cannot accidentally admit anyone.
        /// </summary>
        public static bool Permits(ProviderStampOutcome outcome)
        {
            return outcome == ProviderStampOutcome.StampedToThisPlugin;
        }
    }
}

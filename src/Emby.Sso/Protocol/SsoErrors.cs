using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Short reasons that are safe to show a user. Anything more specific goes
    /// to the server log, never to the browser.
    /// </summary>
    internal static class SsoErrors
    {
        public const string NotConfigured = "Single sign-on is not configured on this server.";
        public const string ProviderUnreachable = "The sign-in provider could not be reached.";
        public const string ProviderRejected = "The sign-in provider rejected this sign-in.";
        public const string InvalidToken = "The sign-in response could not be verified.";
        public const string SessionExpired = "This sign-in attempt expired. Please try again.";
        public const string UnknownUser = "This account is not set up on this server.";

        /// <summary>
        /// The token carried no groups claim at all. Deliberately identical text to UnknownUser:
        /// the log distinguishes this case and the browser must not, because telling a stranger
        /// "you exist but lack a group" leaks membership.
        /// </summary>
        public const string GroupsClaimMissing = "This account is not set up on this server.";

        /// <summary>
        /// The identity is real and the claim was present, but the group is not among them.
        /// Deliberately identical text to UnknownUser: the log distinguishes this case and the
        /// browser must not, because telling a stranger "you exist but lack a group" leaks membership.
        /// </summary>
        public const string GroupNotHeld = "This account is not set up on this server.";

        /// <summary>
        /// The plugin's licence is missing, invalid or expired.
        ///
        /// DELIBERATELY NOT identical to <see cref="UnknownUser"/>, and it must
        /// never be made so. The three constants above are character-identical
        /// on purpose, because distinguishing them would tell a stranger whether
        /// an account exists or holds a group. This one is the opposite case:
        /// nothing about it is a secret, it is nobody's fault but the
        /// administrator's, and the only way it ever gets fixed is if the person
        /// staring at the refusal can tell it apart from "wrong password".
        /// </summary>
        public const string LicenceInvalid =
            "Single sign-on is unavailable: this server's SSO plugin licence is missing, invalid or expired. "
            + "Please contact the server administrator.";

        public const string DirectGrantDisabled = "Password sign-in is disabled for this account.";
        public const string EmptyCredential = "A username and password are required.";
    }

    /// <summary>
    /// Carries a user-safe reason alongside the diagnostic detail. The message
    /// of the inner exception is for the log; UserSafeReason is for the browser.
    /// </summary>
    internal sealed class SsoException : Exception
    {
        public SsoException(string userSafeReason, string logDetail, Exception inner = null)
            : this(userSafeReason, logDetail, inner, false)
        {
        }

        private SsoException(string userSafeReason, string logDetail, Exception inner, bool providerUnreachable)
            : base(logDetail, inner)
        {
            UserSafeReason = userSafeReason;
            ProviderUnreachable = providerUnreachable;
        }

        public string UserSafeReason { get; }

        /// <summary>
        /// The identity provider could not be reached, so NO CREDENTIAL WAS
        /// TESTED and this failure says nothing whatever about the caller.
        ///
        /// It is a flag on the exception rather than a comparison against
        /// <see cref="SsoErrors.ProviderUnreachable"/> because that constant is
        /// user-facing text - three others in this file are already deliberately
        /// character-identical to one another, and an operator-friendly reword
        /// must never silently change a security decision. Only the code that
        /// issued the request knows it never got an answer, so that is where the
        /// fact is recorded.
        ///
        /// False on every exception built by the public constructor, which is
        /// the whole point: FAIL CLOSED. A credential rejection wrongly marked
        /// unreachable is a hole in the brute-force brake
        /// (<see cref="ProvisioningThrottle"/> does not count these); a
        /// transport failure wrongly left unmarked is only an inconvenience.
        /// When in doubt, do not mark it.
        /// </summary>
        public bool ProviderUnreachable { get; }

        /// <summary>
        /// The only way to produce a <see cref="ProviderUnreachable"/> failure.
        /// It takes no user-safe reason, so an unreachable provider tells the
        /// caller exactly what it has always told them, and it must stay that
        /// way: this flag is a signal to the code that counts failures, never a
        /// new distinction for a stranger to observe.
        ///
        /// Use it only where nothing came back from the provider at all. If the
        /// provider answered - however unwelcome the answer - it is an ordinary
        /// <see cref="SsoException"/>.
        /// </summary>
        public static SsoException Unreachable(string logDetail, Exception inner = null) =>
            new SsoException(SsoErrors.ProviderUnreachable, logDetail, inner, true);
    }
}

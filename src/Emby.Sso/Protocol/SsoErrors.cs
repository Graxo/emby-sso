using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Short reasons that are safe to show a user. Anything more specific goes
    /// to the server log, never to the browser.
    /// </summary>
    public static class SsoErrors
    {
        public const string NotConfigured = "Single sign-on is not configured on this server.";
        public const string ProviderUnreachable = "The sign-in provider could not be reached.";
        public const string ProviderRejected = "The sign-in provider rejected this sign-in.";
        public const string InvalidToken = "The sign-in response could not be verified.";
        public const string SessionExpired = "This sign-in attempt expired. Please try again.";
        public const string UnknownUser = "This account is not set up on this server.";
        public const string DirectGrantDisabled = "Password sign-in is disabled for this account.";
    }

    /// <summary>
    /// Carries a user-safe reason alongside the diagnostic detail. The message
    /// of the inner exception is for the log; UserSafeReason is for the browser.
    /// </summary>
    public sealed class SsoException : Exception
    {
        public SsoException(string userSafeReason, string logDetail, Exception inner = null)
            : base(logDetail, inner)
        {
            UserSafeReason = userSafeReason;
        }

        public string UserSafeReason { get; }
    }
}

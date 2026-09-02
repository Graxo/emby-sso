using System;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using MediaBrowser.Model.Logging;

namespace Emby.Sso
{
    /// <summary>
    /// The Emby-facing half of the licence check: it fetches the three things
    /// <see cref="LicenceCheck"/> needs - the pasted key, the embedded public
    /// key and this server's id - asks it, writes the answer to the log, and
    /// hands the caller either null (proceed) or the sentence to refuse with.
    ///
    /// WHAT ENFORCEMENT MEANS HERE, and why it stops where it does. This gate is
    /// called at the two doors a new sign-in can come through - the
    /// authentication provider and the browser callback - and nowhere else. That
    /// is not an oversight, it is the whole design:
    ///
    ///   * Emby does not consult this plugin for an access token it has already
    ///     issued, so every session that exists when a licence lapses keeps
    ///     working until it is signed out;
    ///   * a local Emby account is authenticated by Emby's own provider, so an
    ///     administrator can always still reach their own server;
    ///   * nothing here disables the plugin, deletes anything, or touches user
    ///     policies.
    ///
    /// An operator whose licence lapses loses NEW single sign-ons and automatic
    /// account creation. They do not lose their media server. Any future change
    /// that makes a licensing failure more punitive than that is a change away
    /// from the agreed behaviour, not a tightening of it.
    ///
    /// The refusal is deliberately legible - see <see cref="SsoErrors
    /// .LicenceInvalid"/>. Every other refusal in this plugin is vague on
    /// purpose; this one is the exception, because the person who can fix it is
    /// the one reading it.
    /// </summary>
    internal static class LicenceGate
    {
        /// <summary>
        /// How often the "expiring soon" warning is repeated. Without a brake it
        /// would be written on every single sign-in, which is how a warning
        /// becomes log noise and stops being read. It is not a suppression: the
        /// first sign-in after a restart always logs it, and so does the first
        /// one every six hours after that.
        /// </summary>
        private static readonly TimeSpan ExpiryWarningInterval = TimeSpan.FromHours(6);

        private static readonly object WarningLock = new object();
        private static DateTimeOffset _lastExpiryWarning = DateTimeOffset.MinValue;

        /// <summary>
        /// Returns null when this server is licensed and may proceed, or the
        /// user-safe sentence to refuse with when it is not. Either way the
        /// specific outcome has already been written to the server log, at Error
        /// for a refusal and at Warn for a licence about to lapse.
        /// </summary>
        public static async Task<string> RefusalAsync(ILogger logger, string door)
        {
            var now = DateTimeOffset.UtcNow;

            // One read of each, so a settings save racing this call cannot have
            // the check and the log line disagree about what was checked.
            var configuration = SsoRuntime.Configuration;
            var status = await LicenceCheck.EvaluateAsync(
                configuration?.LicenceKey,
                LicencePublicKey.TrustedJwks,
                SsoRuntime.ServerId,
                now).ConfigureAwait(false);

            // A licence the vendor has withdrawn. Checked BEFORE the licence
            // itself is judged valid, because a revoked licence is still a
            // perfectly well-formed one - the signature and the expiry say
            // nothing about a refund.
            //
            // It behaves exactly like an expired licence and not one bit more:
            // new single sign-ons stop, sessions already open carry on, and
            // Emby's own accounts are untouched. Nothing is disabled or deleted.
            //
            // This flag is only ever set by a current, correctly signed answer
            // naming this server and this licence. Every other outcome of the
            // daily check - unreachable, unsigned, stale, about another server -
            // leaves it alone. See Protocol.LicenceStatusCheck.
            if (configuration?.LicenceRevoked == true && LicenceCheck.Permits(status.Outcome))
            {
                logger.Error(
                    "SSO refused at {0}: this server's licence has been withdrawn by the vendor. "
                    + "This server's id is {1}. Existing sessions are unaffected and Emby's own accounts still "
                    + "sign in normally. If this is unexpected, contact the vendor - a refund or a chargeback is "
                    + "the usual reason.",
                    door,
                    LogSafeText.Flatten(SsoRuntime.ServerId));

                return SsoErrors.LicenceInvalid;
            }

            if (!LicenceCheck.Permits(status.Outcome))
            {
                // Error, and specific. This is the one refusal in the plugin
                // whose cause is not a secret, and an operator who cannot tell
                // it from an ordinary sign-in failure will spend their time
                // debugging the identity provider instead.
                // The server id is in the message on purpose. A licence names one
                // server, so it is the first thing whoever issues licences will
                // ask for, and somebody who has just installed the plugin and
                // been refused should not have to go and find it. It is not a
                // secret: Emby writes it to this same log at every startup.
                logger.Error(
                    "SSO refused at {0}: the plugin licence is not valid ({1}). {2}. "
                    + "This server's id is {3} - a licence has to be issued for it. "
                    + "Existing sessions are unaffected and Emby's own accounts still sign in normally.",
                    door,
                    status.Outcome,
                    LogSafeText.Flatten(status.Detail),
                    LogSafeText.Flatten(SsoRuntime.ServerId));

                return SsoErrors.LicenceInvalid;
            }

            if (status.Outcome == LicenceOutcome.ExpiringSoon)
            {
                WarnAboutExpiry(logger, status, now);
            }

            return null;
        }

        private static void WarnAboutExpiry(ILogger logger, LicenceStatus status, DateTimeOffset now)
        {
            lock (WarningLock)
            {
                if (now - _lastExpiryWarning < ExpiryWarningInterval)
                {
                    return;
                }

                _lastExpiryWarning = now;
            }

            var days = status.ExpiresAt.HasValue
                ? Math.Max(0, (int)Math.Floor((status.ExpiresAt.Value - now).TotalDays))
                : 0;

            logger.Warn(
                "SSO plugin licence expires in {0} day(s) ({1}). When it does, NEW single sign-ons and "
                + "automatic account creation stop; sessions that are already signed in keep working, and "
                + "Emby's own local accounts are unaffected. Renew before then.",
                days,
                LogSafeText.Flatten(status.Detail));
        }
    }
}

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using MediaBrowser.Model.Logging;
using MediaBrowser.Model.Tasks;

namespace Emby.Sso.Tasks
{
    /// <summary>
    /// Asks the vendor once a day whether this server's licence is still good.
    ///
    /// A SCHEDULED TASK RATHER THAN A TIMER, deliberately. It appears in
    /// Dashboard -> Scheduled Tasks, where an operator can see when it last ran,
    /// run it themselves, change when it runs, or switch it off entirely. A
    /// plugin that phones home should do so somewhere the person running the
    /// server can watch it and stop it - not from a background thread nobody can
    /// see.
    ///
    /// WHAT IT CAN AND CANNOT DO. It can set a flag that stops NEW single
    /// sign-ons, when the vendor returns a correctly signed revocation naming
    /// this server and this licence. It cannot do anything else: not on a
    /// network failure, not on an unsigned answer, not on an answer about
    /// another server, not on a stale one. See Protocol.LicenceStatusCheck,
    /// where every one of those is a test.
    ///
    /// Turning this task off means revocations never arrive. That is the
    /// operator's call and it is not fought: an offline server has always been a
    /// supported way to run this plugin, and a check that cannot be declined is
    /// not a check, it is a leash.
    /// </summary>
    public class LicenceCheckTask : IScheduledTask
    {
        private readonly ILogger _logger;

        public LicenceCheckTask(ILogManager logManager)
        {
            _logger = logManager.GetLogger("AuthentikSso");
        }

        public string Name => "Check the SSO plugin licence";

        public string Key => "AuthentikSsoLicenceCheck";

        public string Description =>
            "Asks the licensing service once a day whether this server's licence is still valid. "
            + "If it cannot be reached, nothing changes and sign-ins carry on as normal.";

        public string Category => "Authentik SSO";

        /// <summary>
        /// Once a day, at an hour chosen from this server's own id rather than a
        /// fixed one.
        ///
        /// If every installation asked at midnight, the vendor's service would
        /// take every check it ever receives inside one minute - which is a
        /// self-inflicted denial of service that grows with the customer list.
        /// Deriving the hour from the server id spreads them across the day and
        /// keeps each server's own time stable, so an operator watching the task
        /// list sees it run at the same time every day.
        /// </summary>
        public IEnumerable<TaskTriggerInfo> GetDefaultTriggers()
        {
            var serverId = SsoRuntime.ServerId ?? string.Empty;
            var spread = 0;

            foreach (var c in serverId)
            {
                spread = ((spread * 31) + c) & 0x7FFFFFF;
            }

            var hour = spread % 24;
            var minute = spread % 60;

            return new[]
            {
                new TaskTriggerInfo
                {
                    Type = "DailyTrigger",
                    TimeOfDayTicks = TimeSpan.FromHours(hour).Add(TimeSpan.FromMinutes(minute)).Ticks,
                },
            };
        }

        public async Task Execute(CancellationToken cancellationToken, IProgress<double> progress)
        {
            progress?.Report(0);

            LicenceStatusOutcome outcome;

            try
            {
                outcome = await SsoRuntime.CheckLicenceStatusAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // A scheduled task that throws is shown as failed, in red, on
                // somebody's dashboard - for a check whose whole contract is
                // that failing changes nothing. The exception TYPE only, for the
                // same reason as everywhere else in this plugin.
                _logger.Warn(
                    "SSO licence check could not be completed ({0}). Nothing has changed and sign-ins are "
                    + "unaffected; it will try again tomorrow.",
                    ex.GetType().Name);

                progress?.Report(100);

                return;
            }

            switch (outcome)
            {
                case LicenceStatusOutcome.Revoked:
                    _logger.Error(
                        "SSO licence check: the vendor has WITHDRAWN this server's licence. New single sign-ons "
                        + "will be refused; sessions already open keep working and Emby's own accounts are "
                        + "unaffected. If this is unexpected, contact the vendor.");

                    break;

                case LicenceStatusOutcome.Valid:
                    _logger.Info("SSO licence check: the licence is still valid.");

                    break;

                case LicenceStatusOutcome.Unknown:
                    // Worth a line, because it is the one answer that means the
                    // vendor's records and this server disagree - a restored
                    // backup, or a store rebuilt without this activation in it.
                    _logger.Info(
                        "SSO licence check: the licensing service does not recognise this licence. Treated as "
                        + "valid and nothing has changed, but the vendor may want to know.");

                    break;

                default:
                    _logger.Debug(
                        "SSO licence check: no usable answer. Nothing has changed; it will try again tomorrow.");

                    break;
            }

            progress?.Report(100);
        }
    }
}

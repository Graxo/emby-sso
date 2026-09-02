using System;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using MediaBrowser.Model.Logging;
using MediaBrowser.Model.Services;

namespace Emby.Sso.Api
{
    /// <summary>
    /// The two configuration-page endpoints that let an administrator buy a
    /// licence and redeem the code they get back.
    ///
    /// A SEPARATE SERVICE FROM <see cref="SsoService"/>, DELIBERATELY. The one
    /// rule this feature must not break is that the activation network call
    /// never lands on a sign-in path: it happens once, when a human presses
    /// Activate, and if the vendor's service is unreachable - or shut down for
    /// good - sign-ins must be completely unaffected, because the licence check
    /// is offline forever after activation. Putting these endpoints in their own
    /// service, with their own HTTP client
    /// (<c>SsoRuntime.ActivationHttp</c>), makes that structural rather than a
    /// promise: there is no call path from <c>LicenceGate</c>,
    /// <c>SsoService</c> or <c>SsoCredentialValidator</c> into this file.
    ///
    /// Both routes are <c>[Authenticated(Roles = "Admin")]</c> on the request
    /// DTO - see <see cref="SsoActivationInfo"/> for how that was verified.
    ///
    /// This class is a shell on purpose. Every decision - which URL, what to
    /// send, what an error code means, and above all whether the returned
    /// licence is genuine - is in <c>Protocol/Activation*.cs</c>, under test.
    /// What is left here is reading configuration, calling that, writing the
    /// result to the plugin configuration and logging it, and none of that can
    /// be tested outside a running Emby.
    /// </summary>
    public class ActivationService : IService
    {
        private readonly ILogger _logger;

        public ActivationService(ILogManager logManager)
        {
            _logger = logManager.GetLogger("AuthentikSso");
        }

        public async Task<object> Get(SsoActivationInfo request)
        {
            // The same check the sign-in path makes, against the same keys and
            // the same server id - so the page cannot say Active while a sign-in
            // is being refused, which is the one disagreement that would send an
            // operator looking in the wrong place.
            var configuration = SsoRuntime.Configuration;

            var status = await LicenceCheck.EvaluateAsync(
                configuration?.LicenceKey,
                LicencePublicKey.TrustedJwks,
                SsoRuntime.ServerId,
                DateTimeOffset.UtcNow).ConfigureAwait(false);

            var licensed = LicenceCheck.Permits(status.Outcome);

            return new ActivationInfoResult
            {
                ServerId = SsoRuntime.ServerId ?? string.Empty,
                BuyUrl = SsoRuntime.BuyUrl() ?? string.Empty,
                Licensed = licensed,
                Status = Describe(status.Outcome),
                ActivationsUsed = configuration?.ActivationsUsed ?? 0,
                ActivationsAllowed = configuration?.ActivationsAllowed ?? 0,
                ExpiresUtc = licensed && status.ExpiresAt.HasValue
                    ? status.ExpiresAt.Value.UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)
                    : string.Empty,
            };
        }

        /// <summary>
        /// The outcome as a phrase for the configuration page.
        ///
        /// Short, and written for somebody deciding what to do next rather than
        /// for a support thread. The log already carries the detail, and this is
        /// the one refusal in the plugin whose cause is not deliberately vague -
        /// see LicenceGate - but "vague" and "a paragraph" are not the only two
        /// options.
        ///
        /// A default that reads as a refusal, like every other decision here: an
        /// outcome nobody updated this for must not print as if it were fine.
        /// </summary>
        private static string Describe(LicenceOutcome outcome)
        {
            switch (outcome)
            {
                case LicenceOutcome.Valid:
                    return "Active";

                case LicenceOutcome.ExpiringSoon:
                    return "Active, expiring soon";

                case LicenceOutcome.Missing:
                    return "Not activated";

                case LicenceOutcome.Expired:
                    return "Expired";

                case LicenceOutcome.WrongServer:
                    return "Issued for a different server";

                case LicenceOutcome.NotYetValid:
                    return "Not valid yet - check this server's clock";

                default:
                    return "Not valid";
            }
        }

        public async Task<object> Post(SsoActivate request)
        {
            ActivationResult result;

            try
            {
                // request.Code is a bearer secret. It goes into the request body
                // built inside ActivationClient and nowhere else - not into a
                // log line, not into an exception message, not into the answer
                // below.
                result = await SsoRuntime.ActivateAsync(request?.Code, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Nothing escapes to Emby's error handling, which would put the
                // exception message in the response body - the same rule
                // SsoService follows. The exception TYPE only: an exception
                // raised while a request carrying the code was being built could
                // otherwise carry it into the log.
                _logger.Error("SSO licence activation failed unexpectedly: {0}", ex.GetType().Name);

                result = ActivationResult.Refused(
                    ActivationOutcome.Failed,
                    "The activation could not be completed. The server log has the detail.",
                    "unhandled failure during activation");
            }

            if (!ActivationResult.Succeeded(result))
            {
                // Warn, not Error: a mistyped code is not a server fault, and
                // the one refusal that IS alarming - a licence this build
                // refused - says so in its own detail.
                _logger.Warn(
                    "SSO licence activation refused ({0}): {1}",
                    result.Outcome,
                    LogSafeText.Flatten(result.LogDetail));

                return new ActivationResponse
                {
                    Activated = false,
                    Outcome = result.Outcome.ToString(),
                    Message = result.Message,
                    LicenceKey = string.Empty,
                    ExpiresUtc = string.Empty,
                };
            }

            // Only here, past ActivationResult.Succeeded - which is only ever
            // true for a licence ActivationClient already verified against this
            // build's embedded public key and this server's own id.
            var stored = Store(result.Licence, result.ActivationsUsed, result.ActivationsAllowed);

            if (!stored)
            {
                return new ActivationResponse
                {
                    Activated = false,
                    Outcome = ActivationOutcome.Failed.ToString(),
                    Message = "The licence was issued and verified, but this server could not save it, so "
                        + "nothing was stored. Check that Emby can write to its plugin configuration "
                        + "directory, then press Activate again - re-activating the same code on this same "
                        + "server does not use up another activation.",
                    LicenceKey = string.Empty,
                    ExpiresUtc = string.Empty,
                };
            }

            _logger.Info(
                "SSO licence activated for this server ({0}). Nothing further is contacted: the licence "
                + "check is offline from here on.",
                LogSafeText.Flatten(result.LogDetail));

            return new ActivationResponse
            {
                Activated = true,
                Outcome = result.Outcome.ToString(),
                Message = result.Message,

                // Echoed back so the page can put it in the Licence key field.
                // Without that, the next Save would write the field's stale
                // value over the licence just stored.
                LicenceKey = result.Licence,
                ExpiresUtc = result.ExpiresUtc ?? string.Empty,
                ActivationsUsed = result.ActivationsUsed ?? 0,
                ActivationsAllowed = result.ActivationsAllowed ?? 0,
            };
        }

        /// <summary>
        /// Writes the licence into the SAME <c>LicenceKey</c> setting a manually
        /// issued licence is pasted into, so there is exactly one thing the
        /// licence check reads and no second source of truth to disagree with
        /// it.
        ///
        /// <c>SaveConfiguration</c> serialises the whole configuration object to
        /// <c>plugins/configurations/Emby.Sso.xml</c>; the directory-creation
        /// callback it needs is supplied by Emby at plugin load
        /// (<c>ApplicationHost.LoadPlugin</c> calls
        /// <c>IHasPluginConfiguration.SetStartupInfo</c>, decompiled from
        /// 4.9.5.0). False when it threw - the licence is then NOT stored and
        /// the caller must not claim it was.
        /// </summary>
        private bool Store(string licence, int? used, int? allowed)
        {
            var plugin = Plugin.Instance;

            if (plugin == null)
            {
                _logger.Error("SSO licence activation: the plugin instance is not available, so the licence was not saved.");

                return false;
            }

            try
            {
                plugin.Configuration.LicenceKey = licence;

                // Activating is the vendor issuing a licence, which settles the
                // question a revocation asked. Without this, somebody who was
                // revoked and then bought again would stay refused until the
                // next daily check happened to run.
                plugin.Configuration.LicenceRevoked = false;
                plugin.Configuration.LicenceCheckedUtc = string.Empty;

                // Only when the service actually said. A null here means it did
                // not report them, and overwriting a previous, real pair with
                // zeroes would turn "2 of 3" into "0 of 0" for no reason.
                if (used.HasValue && allowed.HasValue)
                {
                    plugin.Configuration.ActivationsUsed = used.Value;
                    plugin.Configuration.ActivationsAllowed = allowed.Value;
                }

                plugin.SaveConfiguration();

                return true;
            }
            catch (Exception ex)
            {
                _logger.Error("SSO licence activation: the licence could not be saved ({0}).", ex.GetType().Name);

                return false;
            }
        }
    }
}

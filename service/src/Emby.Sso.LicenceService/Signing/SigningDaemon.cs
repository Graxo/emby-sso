using System;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Emby.Sso.LicenceService.Signing
{
    /// <summary>
    /// Signs whatever is waiting, automatically, so that activation is
    /// self-service.
    ///
    /// WHAT THIS COSTS, stated here because it is the one thing a reader of this
    /// file has to understand. With this running, the private licence signing
    /// key is loaded by the process that answers requests from the internet.
    /// That key mints a valid licence for ANY Emby server, forever, and there is
    /// no revocation - the plugin verifies offline and never calls home. So a
    /// remote-code-execution bug in this service, a dependency compromise, or a
    /// stolen admin session hands over the whole scheme, silently and
    /// permanently.
    ///
    /// It is switched on by LICENCE_SIGNING_KEY_PATH being set, and it is off
    /// otherwise. With it off, the same work happens through /admin/signing:
    /// download what is waiting, sign it with `licencetool sign` on a machine
    /// that answers no requests, upload the result. That is the safer
    /// arrangement and it is still fully supported - it is not instant, which is
    /// why it is not the default any more.
    ///
    /// The trade was made deliberately and by the operator: an activation that
    /// tells a paying customer to come back later is not self-service, and a
    /// vendor who has to be at a keyboard for every sale does not have a
    /// product. Whoever changes this next should change it because that
    /// reasoning stopped holding, not because this comment made them nervous.
    ///
    /// IT SIGNS THROUGH THE SAME DOOR AN OPERATOR USES. Rather than reaching
    /// into the store, it asks <see cref="SigningDesk"/> for exactly the file
    /// the admin page would hand out, signs that, and feeds the result back
    /// through exactly the upload path. Every check that guards a manual upload
    /// therefore guards this too - the signature against the trusted keys, the
    /// audience against the recorded server id, the expiry and issue date
    /// against the recorded terms - so an automated signer cannot quietly issue
    /// something a human signer could not.
    /// </summary>
    public sealed class SigningDaemon : BackgroundService
    {
        /// <summary>
        /// How often it looks. Short, because a customer is waiting on the other
        /// end of it - see ActivationService, which holds the activation request
        /// open for a few seconds so that one press of Activate is enough.
        /// </summary>
        public static readonly TimeSpan Interval = TimeSpan.FromSeconds(2);

        /// <summary>
        /// How long to wait after a failure before trying again. Longer than the
        /// interval so that a broken key does not fill the log at one line every
        /// two seconds.
        /// </summary>
        public static readonly TimeSpan BackOff = TimeSpan.FromMinutes(1);

        private readonly SigningDesk _desk;
        private readonly LicenceIssuer _issuer;
        private readonly string _keyId;
        private readonly TimeProvider _time;
        private readonly ILogger<SigningDaemon> _log;

        public SigningDaemon(
            SigningDesk desk,
            SigningKeyFile.SigningKey key,
            TimeProvider time,
            ILogger<SigningDaemon> log)
        {
            _desk = desk ?? throw new ArgumentNullException(nameof(desk));

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            _issuer = new LicenceIssuer(key.Key);
            _keyId = key.Thumbprint;
            _time = time ?? throw new ArgumentNullException(nameof(time));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        /// <summary>
        /// Signs everything currently waiting. Returns how many were stored.
        ///
        /// Public and separate from the loop so that an activation can call it
        /// directly the moment it creates a request, instead of waiting for the
        /// next tick - which is the difference between a customer pressing
        /// Activate once and pressing it twice.
        /// </summary>
        public async Task<int> SignWaitingAsync()
        {
            var waiting = _desk.Download();

            if (waiting.Requests.Count == 0)
            {
                return 0;
            }

            var signed = new SignedLicenceFile
            {
                SignedUtc = LicenceFormat.Iso(_time.GetUtcNow()),
                KeyId = _keyId,
            };

            foreach (var request in waiting.Requests)
            {
                signed.Licences.Add(new SignedLicence
                {
                    RequestId = request.RequestId,
                    Licence = _issuer.Issue(
                        request.Licensee,
                        request.ServerId,
                        request.IssuedAtUtc,
                        request.ExpiresUtc).Token,
                });
            }

            var report = await _desk.UploadAsync(SigningExchange.Write(signed)).ConfigureAwait(false);

            foreach (var rejection in report.Rejected)
            {
                // Should not happen: this signed exactly what the desk asked
                // for, with a key the desk trusts. If it does, something has
                // disagreed about the terms and a customer is stuck, so it is an
                // error rather than a warning.
                _log.LogError(
                    "signer: the service refused a licence this process just signed. request={Request} reason={Reason}",
                    rejection.RequestId,
                    rejection.Why);
            }

            if (report.Stored > 0)
            {
                _log.LogInformation("signer: signed and stored {Count} licence(s) with key {Key}", report.Stored, _keyId);
            }

            return report.Stored;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _log.LogInformation(
                "signer: ON. Licences are signed automatically with key {Key}, every {Seconds}s. The private key "
                + "is loaded by this process - see SigningDaemon for what that means and what the alternative is.",
                _keyId,
                (int)Interval.TotalSeconds);

            while (!stoppingToken.IsCancellationRequested)
            {
                var wait = Interval;

                try
                {
                    await SignWaitingAsync().ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Shutting down.
                    return;
                }
                catch (Exception ex)
                {
                    // NEVER let the loop die. If it stops, activations queue
                    // silently and the first anyone knows is a customer
                    // complaining - so it backs off and keeps going, and says so
                    // every time.
                    _log.LogError(ex, "signer: a signing pass failed. Retrying in {Seconds}s.", (int)BackOff.TotalSeconds);

                    wait = BackOff;
                }

                try
                {
                    await Task.Delay(wait, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }
}

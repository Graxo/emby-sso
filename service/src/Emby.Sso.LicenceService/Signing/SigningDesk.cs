using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.LicenceService.Signing
{
    /// <summary>
    /// The two halves of getting a licence signed by a machine this service
    /// cannot reach: the file that goes out, and the file that comes back.
    ///
    /// WHY ANY OF THIS EXISTS. This service used to hold the private licence
    /// signing key and mint licences during an activation. That put the one
    /// secret the entire scheme rests on - the thing that can mint a valid
    /// licence for any Emby server, forever - on a host with a port open to the
    /// internet. Every other control here (rate limits, the admin password, the
    /// webhook signature check, the container hardening) is a wall around that
    /// one asset, and any single failure of any one of them loses it completely
    /// and undetectably: a stolen key mints licences that are indistinguishable
    /// from real ones, and there is no revocation because the check is offline.
    ///
    /// So the key left. This service now records what has been paid for and
    /// what terms were agreed, and it hands that out as a file. Somebody with
    /// the key signs it on a machine of their choosing and uploads the result.
    /// A total compromise of this host now yields: the customer list, the
    /// ability to hand out licences that were already signed, and the ability to
    /// stop signing new ones. It does not yield the ability to mint a single
    /// licence, because there is nothing here to mint with.
    ///
    /// WHAT IS CHECKED ON THE WAY BACK IN, and why each check is not paranoia:
    ///
    ///   * the signature, against the PUBLIC keys this service is configured
    ///     with - so a file signed by the wrong key, or by nobody, is caught
    ///     here rather than on a customer's server;
    ///   * the audience, against the server id THIS service recorded - so a
    ///     licence cannot be quietly retargeted at a different server between
    ///     the download and the upload;
    ///   * the expiry and issue date, against the terms recorded at activation -
    ///     so a licence cannot be quietly extended past what was paid for;
    ///   * the licensee, for the same reason;
    ///   * that the request is one this service actually made, and has not
    ///     already been answered.
    ///
    /// Together those mean the upload cannot change the terms of anything: the
    /// only authority it has is to supply the signature for terms this service
    /// already decided. Whoever is at the admin page cannot use it to license a
    /// server nobody paid for.
    /// </summary>
    public sealed class SigningDesk
    {
        private readonly LicenceStore _store;
        private readonly LicenceLedger _ledger;
        private readonly IReadOnlyList<JsonWebKey> _trusted;
        private readonly ServiceOptions _options;
        private readonly TimeProvider _time;
        private readonly ILogger<SigningDesk> _log;

        public SigningDesk(
            LicenceStore store,
            LicenceLedger ledger,
            TrustedKeys trusted,
            ServiceOptions options,
            TimeProvider time,
            ILogger<SigningDesk> log)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
            _trusted = (trusted ?? throw new ArgumentNullException(nameof(trusted))).Keys;
            TrustedKeyNames = trusted.Describe();
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _time = time ?? throw new ArgumentNullException(nameof(time));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public int Waiting => _store.CountWaitingToBeSigned();

        /// <summary>
        /// Which keys this service will accept a signature from, by name. Shown
        /// on the signing page because "the batch was all refused" and "you
        /// signed with the wrong key" are the same event, and the operator can
        /// only tell them apart by comparing this to what `licencetool sign`
        /// printed.
        /// </summary>
        public string TrustedKeyNames { get; }

        /// <summary>Everything waiting, as the file the offline tool reads.</summary>
        public SigningRequestFile Download()
        {
            var file = new SigningRequestFile
            {
                GeneratedUtc = LicenceFormat.Iso(_time.GetUtcNow()),
                Service = _options.PublicBaseUrl,
            };

            foreach (var row in _store.WaitingToBeSigned(SigningExchange.MaximumBatch))
            {
                file.Requests.Add(row.ToExchange());
            }

            return file;
        }

        /// <summary>
        /// Takes the file back. Every licence in it is checked on its own and
        /// stored on its own: one bad entry does not throw away the good ones,
        /// because the good ones are customers waiting, and an operator who has
        /// to fix one row should not have to re-sign the batch.
        /// </summary>
        public async Task<UploadReport> UploadAsync(string json)
        {
            SignedLicenceFile file;

            try
            {
                file = SigningExchange.ReadSigned(json);
            }
            catch (FormatException ex)
            {
                return UploadReport.Unreadable(ex.Message);
            }

            var report = new UploadReport();
            var now = _time.GetUtcNow();

            foreach (var signed in file.Licences)
            {
                if (!SigningRequestId.IsWellFormed(signed.RequestId))
                {
                    report.Reject("(a malformed request id)", "that is not a request id this service issues");

                    continue;
                }

                var row = _store.FindSigningRequest(signed.RequestId);

                if (row == null)
                {
                    // Either a file from a different deployment, or a request
                    // that no longer exists. Named by id only: the id says
                    // nothing about anybody, which is why it is shaped that way.
                    report.Reject(signed.RequestId, "this service has no such request waiting");

                    continue;
                }

                var verdict = await LicenceVerifier.VerifyAsync(signed.Licence, _trusted, row.ToExchange())
                    .ConfigureAwait(false);

                if (!verdict.IsValid)
                {
                    _log.LogWarning(
                        "signing upload REFUSED request={Request} server={Server}: {Problem}",
                        row.RequestId,
                        row.ServerId,
                        verdict.Problem);

                    report.Reject(row.RequestId, verdict.Problem);

                    continue;
                }

                var stored = _store.StoreSignedLicence(
                    row.RequestId,
                    verdict.Licence,
                    verdict.KeyId,
                    verdict.Fingerprint,
                    now);

                switch (stored)
                {
                    case StoreSignedResult.Stored:
                        Record(row, verdict);

                        _log.LogInformation(
                            "signing upload STORED request={Request} server={Server} key={Key} fingerprint={Fingerprint}",
                            row.RequestId,
                            row.ServerId,
                            verdict.KeyId,
                            verdict.Fingerprint);

                        report.Stored++;

                        break;

                    case StoreSignedResult.AlreadyTheSame:
                        // The same file uploaded twice. Nothing happened, and
                        // nothing is wrong; saying so is friendlier than an
                        // error the operator then goes looking for.
                        report.Unchanged++;

                        break;

                    case StoreSignedResult.AlreadySigned:
                        report.Reject(
                            row.RequestId,
                            "a different licence has already been stored for this request. The customer may already "
                            + "be using it; replacing it would stop their server working. Void the code and issue a "
                            + "new one if it really has to change.");

                        break;

                    default:
                        report.Reject(row.RequestId, "this service has no such request waiting");

                        break;
                }
            }

            return report;
        }

        /// <summary>
        /// The compatibility view `licencetool list` reads. Never fatal: the
        /// licence is already stored and the customer is about to get it, and
        /// what has been lost if this fails is a line in a log file.
        /// </summary>
        private void Record(SigningRequestRow row, VerifiedLicence verdict)
        {
            LedgerRecord record;

            try
            {
                record = new LedgerRecord(
                    row.Licensee,
                    row.ServerId,
                    verdict.Fingerprint,
                    row.ToExchange().IssuedAtUtc,
                    row.ToExchange().ExpiresUtc);
            }
            catch (FormatException ex)
            {
                _log.LogWarning("signing upload: request {Request} could not be recorded in the ledger: {Error}", row.RequestId, ex.Message);

                return;
            }

            if (!_ledger.TryAppend(record, out var error))
            {
                _log.LogWarning(
                    "signing upload: the ledger at {Path} could not be appended to ({Error}). The licence IS stored "
                    + "in {Store}; `licencetool list` will not show it. request={Request}",
                    _ledger.Path,
                    error,
                    _store.Path,
                    row.RequestId);
            }
        }
    }

    /// <summary>What one upload did, in terms an operator can act on.</summary>
    public sealed class UploadReport
    {
        private readonly List<Rejection> _rejected = new List<Rejection>();

        public bool IsReadable { get; private set; } = true;

        /// <summary>Set only when the file itself could not be read at all.</summary>
        public string Problem { get; private set; }

        public int Stored { get; set; }

        /// <summary>Already held exactly this licence. The same file, uploaded again.</summary>
        public int Unchanged { get; set; }

        public IReadOnlyList<Rejection> Rejected => _rejected;

        public bool AnythingWrong => !IsReadable || _rejected.Count > 0;

        public static UploadReport Unreadable(string problem)
        {
            return new UploadReport { IsReadable = false, Problem = problem };
        }

        public void Reject(string requestId, string why)
        {
            _rejected.Add(new Rejection(requestId, why));
        }

        public string Summary()
        {
            if (!IsReadable)
            {
                return "That file could not be read: " + Problem;
            }

            var parts = new List<string>();

            if (Stored > 0)
            {
                parts.Add(Stored.ToString(CultureInfo.InvariantCulture) + " licence(s) stored");
            }

            if (Unchanged > 0)
            {
                parts.Add(Unchanged.ToString(CultureInfo.InvariantCulture) + " already stored, unchanged");
            }

            if (_rejected.Count > 0)
            {
                parts.Add(_rejected.Count.ToString(CultureInfo.InvariantCulture) + " refused");
            }

            return parts.Count == 0 ? "That file carried nothing." : string.Join(", ", parts) + ".";
        }

        public sealed class Rejection
        {
            public Rejection(string requestId, string why)
            {
                RequestId = requestId;
                Why = why;
            }

            public string RequestId { get; }

            public string Why { get; }
        }
    }
}

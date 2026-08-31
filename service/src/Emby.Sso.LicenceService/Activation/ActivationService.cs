using System;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.RateLimiting;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;

namespace Emby.Sso.LicenceService.Activation
{
    /// <summary>
    /// POST /v1/activate, with the HTTP taken off.
    ///
    /// The endpoint in Program.cs does nothing but read the body, find the
    /// caller's address and turn what comes back here into a status code, so
    /// that every decision - validation, rate limiting, the state machine, what
    /// gets logged - is testable without a socket.
    ///
    /// The contract this implements is in the task's contract.md and is shared
    /// with the plugin, which was written from the same document by somebody
    /// else. The error codes below are that document's, character for character;
    /// the plugin keys on those strings and not on the status codes, which is
    /// why the mapping to status codes is allowed to live in one line in
    /// Program.cs.
    /// </summary>
    public sealed class ActivationService
    {
        /// <summary>
        /// Emby's SystemId is a 32-character hex string today. This does not
        /// require that: a plugin from a future Emby with a different id format
        /// must still be able to buy a licence, and the id is not a secret or a
        /// lookup key into anything but this service's own rows. It requires only
        /// that it is short and made of characters that cannot be anything but an
        /// identifier.
        /// </summary>
        public const int MaximumServerIdLength = 64;

        public const int MaximumCodeLength = 128;

        public const int MaximumPluginVersionLength = 64;

        private readonly LicenceStore _store;
        private readonly LicenceIssuer _issuer;
        private readonly LicenceLedger _ledger;
        private readonly ActivationRateLimiter _limiter;
        private readonly ServiceOptions _options;
        private readonly TimeProvider _time;
        private readonly ILogger<ActivationService> _log;

        public ActivationService(
            LicenceStore store,
            LicenceIssuer issuer,
            LicenceLedger ledger,
            ActivationRateLimiter limiter,
            ServiceOptions options,
            TimeProvider time,
            ILogger<ActivationService> log)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
            _limiter = limiter ?? throw new ArgumentNullException(nameof(limiter));
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _time = time ?? throw new ArgumentNullException(nameof(time));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public ActivationReply Activate(ActivationRequest request, string clientKey)
        {
            // FIRST, before anything is parsed, normalised, hashed or looked up.
            // See ActivationRateLimiter for the property this guarantees; the
            // part that depends on this line is "a refused caller costs one
            // dictionary lookup and no database work".
            var limit = _limiter.Check(clientKey);

            if (!limit.IsAllowed)
            {
                _log.LogWarning(
                    "activate RATE LIMITED client={Client} scope={Scope} retryAfter={Seconds}s",
                    clientKey,
                    limit.Scope,
                    (int)limit.RetryAfter.TotalSeconds);

                return ActivationReply.Failure(
                    ActivationError.RateLimited,
                    "Too many activation attempts. Wait and try again.",
                    limit.RetryAfter);
            }

            if (request == null || string.IsNullOrWhiteSpace(request.Code))
            {
                return Malformed(clientKey, "no code", "The request must contain a redemption code.");
            }

            if (request.Code.Length > MaximumCodeLength)
            {
                return Malformed(clientKey, "code too long", "That is not a redemption code.");
            }

            if (string.IsNullOrWhiteSpace(request.ServerId))
            {
                return Malformed(clientKey, "no serverId", "The request must contain this server's id.");
            }

            var serverId = request.ServerId.Trim();

            if (!IsPlausibleServerId(serverId))
            {
                return Malformed(clientKey, "serverId not well formed", "That is not an Emby server id.");
            }

            if (!RedemptionCode.TryNormalise(request.Code, out var normalised))
            {
                // Deliberately distinguished from invalid_code. A code that is
                // the wrong length or full of punctuation was mistyped, and the
                // plugin can say "check what you typed" instead of "that code is
                // not valid", which sends the customer to the vendor's inbox. It
                // leaks only the code's length and alphabet, both of which are
                // printed on the email the code arrived in.
                return Malformed(clientKey, "code not well formed", "That redemption code is not in the right format.");
            }

            var hash = RedemptionCode.Hash(normalised);
            var tag = RedemptionCode.LogTag(hash);
            var now = _time.GetUtcNow();
            var pluginVersion = Truncate(request.PluginVersion, MaximumPluginVersionLength);

            ActivationOutcome outcome;

            try
            {
                outcome = _store.Activate(
                    hash,
                    serverId,
                    serverId.ToLowerInvariant(),
                    pluginVersion,
                    now,
                    expires => _issuer.Issue(LicenseeFor(hash), serverId, now, expires));
            }
            catch (Exception ex)
            {
                // Never leaks out: the caller gets server_error and one sentence.
                _log.LogError(
                    ex,
                    "activate FAILED code={Tag} server={Server} client={Client}",
                    tag,
                    serverId,
                    clientKey);

                return ActivationReply.Failure(
                    ActivationError.ServerError,
                    "Something went wrong here. Try again shortly; if it keeps happening, contact the vendor.",
                    TimeSpan.Zero);
            }

            switch (outcome.Status)
            {
                case ActivationStatus.UnknownCode:
                case ActivationStatus.NotPaid:
                case ActivationStatus.Void:
                    _log.LogInformation(
                        "activate REFUSED code={Tag} server={Server} client={Client} reason={Reason}",
                        tag,
                        serverId,
                        clientKey,
                        outcome.Status);

                    return ActivationReply.Failure(
                        ActivationError.InvalidCode,
                        "That redemption code is not valid.",
                        TimeSpan.Zero);

                case ActivationStatus.Exhausted:
                    _log.LogInformation(
                        "activate EXHAUSTED code={Tag} server={Server} client={Client} used={Used}/{Allowed}",
                        tag,
                        serverId,
                        clientKey,
                        outcome.ActivationsUsed,
                        outcome.ActivationsAllowed);

                    return ActivationReply.Failure(
                        ActivationError.CodeExhausted,
                        "That code has already been used on "
                            + outcome.ActivationsAllowed.ToString(System.Globalization.CultureInfo.InvariantCulture)
                            + " servers, which is its limit.",
                        TimeSpan.Zero);

                default:
                    break;
            }

            Record(outcome.Licence, tag);

            _log.LogInformation(
                "activate OK code={Tag} server={Server} client={Client} {Kind} used={Used}/{Allowed} "
                + "expires={Expires} fingerprint={Fingerprint} plugin={Plugin}",
                tag,
                serverId,
                clientKey,
                outcome.Status == ActivationStatus.NewActivation ? "NEW" : "REPEAT",
                outcome.ActivationsUsed,
                outcome.ActivationsAllowed,
                LicenceFormat.Iso(outcome.Licence.ExpiresAt),
                outcome.Licence.Fingerprint,
                pluginVersion ?? "(not sent)");

            return ActivationReply.Success(
                outcome.Licence.Token,
                outcome.Licence.ExpiresAt,
                outcome.ActivationsUsed,
                outcome.ActivationsAllowed);
        }

        /// <summary>
        /// What goes in the licence's `sub` claim.
        ///
        /// The buyer's email is in the store, and it is NOT used here. `sub` ends
        /// up in a token that sits in a config file on somebody else's server,
        /// gets pasted into support threads and forum posts, and is readable by
        /// anyone who can decode base64 - which is everyone. The code tag
        /// identifies the customer to the vendor, against the store and the
        /// outbox, without putting a customer's email address in a string that
        /// travels.
        /// </summary>
        private static string LicenseeFor(string hash)
        {
            return "code:" + RedemptionCode.LogTag(hash);
        }

        private void Record(IssuedLicence licence, string tag)
        {
            if (_ledger.TryAppend(new LedgerRecord(licence), out var error))
            {
                return;
            }

            // Not fatal, and not silent. The activation is already committed to
            // the store, which is the authority; what has been lost is the
            // vendor's `licencetool list` view of it.
            _log.LogWarning(
                "activate: the ledger at {Path} could not be appended to ({Error}). The activation IS recorded in "
                + "{Store}; `licencetool list` will not show it. code={Tag} fingerprint={Fingerprint}",
                _ledger.Path,
                error,
                _store.Path,
                tag,
                licence.Fingerprint);
        }

        private ActivationReply Malformed(string clientKey, string reason, string message)
        {
            _log.LogInformation("activate MALFORMED client={Client} reason={Reason}", clientKey, reason);

            return ActivationReply.Failure(ActivationError.MalformedRequest, message, TimeSpan.Zero);
        }

        /// <summary>
        /// Public because /buy validates the same thing: the server id it is
        /// handed in a query string goes through exactly this rule before it is
        /// echoed to a page or sent to PayPal, so there is one definition of what
        /// an Emby server id may look like rather than two that disagree.
        /// </summary>
        public static bool IsPlausibleServerId(string serverId)
        {
            if (serverId.Length == 0 || serverId.Length > MaximumServerIdLength)
            {
                return false;
            }

            foreach (var c in serverId)
            {
                var ok = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || c == '-' || c == '_' || c == '.';

                if (!ok)
                {
                    return false;
                }
            }

            return true;
        }

        private static string Truncate(string value, int maximum)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            var trimmed = value.Trim();

            return trimmed.Length <= maximum ? trimmed : trimmed.Substring(0, maximum);
        }
    }

    public sealed class ActivationRequest
    {
        public string Code { get; set; }

        public string ServerId { get; set; }

        public string PluginVersion { get; set; }
    }

    /// <summary>
    /// The five machine codes from contract.md. They are the plugin's interface;
    /// changing one is changing the contract.
    /// </summary>
    public static class ActivationError
    {
        public const string InvalidCode = "invalid_code";
        public const string CodeExhausted = "code_exhausted";
        public const string MalformedRequest = "malformed_request";
        public const string RateLimited = "rate_limited";
        public const string ServerError = "server_error";
    }

    public sealed class ActivationReply
    {
        private ActivationReply(
            bool ok,
            string licence,
            DateTimeOffset expires,
            int used,
            int allowed,
            string error,
            string message,
            TimeSpan retryAfter)
        {
            IsSuccess = ok;
            Licence = licence;
            ExpiresUtc = expires;
            ActivationsUsed = used;
            ActivationsAllowed = allowed;
            Error = error;
            Message = message;
            RetryAfter = retryAfter;
        }

        public bool IsSuccess { get; }

        public string Licence { get; }

        public DateTimeOffset ExpiresUtc { get; }

        public int ActivationsUsed { get; }

        public int ActivationsAllowed { get; }

        public string Error { get; }

        public string Message { get; }

        public TimeSpan RetryAfter { get; }

        public static ActivationReply Success(string licence, DateTimeOffset expires, int used, int allowed)
        {
            return new ActivationReply(true, licence, expires, used, allowed, null, null, TimeSpan.Zero);
        }

        public static ActivationReply Failure(string error, string message, TimeSpan retryAfter)
        {
            return new ActivationReply(false, null, default, 0, 0, error, message, retryAfter);
        }
    }
}

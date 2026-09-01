using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
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

        /// <summary>
        /// What a plugin waiting on a signature is asked to wait. Long enough
        /// that a client retrying on a timer does not become a load, short
        /// enough that an operator who signs promptly is not made to look slow.
        /// It is advice, not a lock: the code is not consumed by the wait, and
        /// trying earlier costs nothing but one rate-limiter token.
        /// </summary>
        public static readonly TimeSpan PendingRetryAfter = TimeSpan.FromMinutes(5);

        /// <summary>
        /// How long an activation waits for a signature before giving up and
        /// telling the customer to try again.
        ///
        /// This is what makes one press of Activate enough when this deployment
        /// signs its own licences: the signer works in seconds, so the request
        /// simply waits for it rather than answering "come back later" to
        /// somebody who has just paid. Fifteen seconds is long enough for a
        /// signing pass and short enough that a browser, a reverse proxy and a
        /// plugin all sit well inside their own timeouts.
        ///
        /// With no signer configured this changes nothing: the first poll finds
        /// nothing signed, and the answer is the same pending reply as before.
        /// </summary>
        public static readonly TimeSpan DefaultSignatureWait = TimeSpan.FromSeconds(15);

        /// <summary>
        /// Settable so the suite can shorten it. Production never changes it;
        /// a test that had to sit through fifteen real seconds per pending
        /// activation would be a test somebody deletes.
        /// </summary>
        public TimeSpan SignatureWait { get; set; } = DefaultSignatureWait;

        private static readonly TimeSpan SignaturePoll = TimeSpan.FromMilliseconds(400);

        private readonly LicenceStore _store;
        private readonly ActivationRateLimiter _limiter;
        private readonly ServiceOptions _options;
        private readonly TimeProvider _time;
        private readonly ILogger<ActivationService> _log;

        public ActivationService(
            LicenceStore store,
            ActivationRateLimiter limiter,
            ServiceOptions options,
            TimeProvider time,
            ILogger<ActivationService> log)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _limiter = limiter ?? throw new ArgumentNullException(nameof(limiter));
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _time = time ?? throw new ArgumentNullException(nameof(time));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        /// <summary>
        /// <see cref="Activate"/>, and then - if the answer was "being signed" -
        /// a short wait for the signature to appear before answering.
        ///
        /// The wait polls the STORE rather than calling Activate again, so it
        /// costs the caller nothing: no second rate-limiter token, no second
        /// pass over the activation cap. Whoever signs is somebody else's
        /// problem; this only watches for the row to fill in, which is true
        /// whether the signer is a background service in this process or a
        /// person with a laptop.
        /// </summary>
        public async Task<ActivationReply> ActivateAsync(
            ActivationRequest request,
            string clientKey,
            CancellationToken cancellationToken = default)
        {
            var reply = Activate(request, clientKey);

            if (reply.IsSuccess || !string.Equals(reply.Error, ActivationError.PendingSignature, StringComparison.Ordinal))
            {
                return reply;
            }

            // A MONOTONIC measure, not the injected clock. A timeout asks "how
            // long have I been here", and a wall clock answers "what time is
            // it" - which is a different question the moment NTP steps the
            // clock, and which never moves at all under a test clock, so the
            // loop would spin until something else stopped it.
            var started = Stopwatch.StartNew();

            while (started.Elapsed < SignatureWait && !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(SignaturePoll, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return reply;
                }

                SigningRequestRow row;

                try
                {
                    row = _store.FindSigningRequest(reply.RequestId);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "activate: waiting for a signature failed for request={Request}", reply.RequestId);

                    return reply;
                }

                if (row?.Licence == null)
                {
                    continue;
                }

                _log.LogInformation(
                    "activate SIGNED WHILE WAITING request={Request} server={Server} key={Key}",
                    row.RequestId,
                    row.ServerId,
                    row.KeyId);

                return ActivationReply.Success(
                    row.Licence,
                    reply.ExpiresUtc,
                    reply.ActivationsUsed,
                    reply.ActivationsAllowed);
            }

            return reply;
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
                    SigningRequestId.New);
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

                case ActivationStatus.AwaitingSignature:
                    // NOT A FAILURE, and the customer's activation IS recorded -
                    // the allowance has been spent and the terms are fixed. What
                    // is missing is a signature, and this service cannot produce
                    // one: the private key is not on this host, deliberately, so
                    // that compromising this host cannot mint licences. A person
                    // with the key signs the request and uploads the result, and
                    // the next attempt returns it.
                    _log.LogInformation(
                        "activate WAITING code={Tag} server={Server} client={Client} request={Request} "
                        + "used={Used}/{Allowed} expires={Expires} plugin={Plugin}",
                        tag,
                        serverId,
                        clientKey,
                        outcome.Request.RequestId,
                        outcome.ActivationsUsed,
                        outcome.ActivationsAllowed,
                        outcome.Request.Expires,
                        pluginVersion ?? "(not sent)");

                    return ActivationReply.Pending(
                        "Your licence has been requested and is being signed. This is not an error and your code "
                        + "has not been used up. Press Activate again shortly.",
                        PendingRetryAfter,
                        outcome.Request.RequestId,
                        outcome.ExpiresUtc ?? default,
                        outcome.ActivationsUsed,
                        outcome.ActivationsAllowed);

                default:
                    break;
            }

            _log.LogInformation(
                "activate OK code={Tag} server={Server} client={Client} {Kind} used={Used}/{Allowed} "
                + "expires={Expires} fingerprint={Fingerprint} key={Key} plugin={Plugin}",
                tag,
                serverId,
                clientKey,
                outcome.Status == ActivationStatus.NewActivation ? "NEW" : "REPEAT",
                outcome.ActivationsUsed,
                outcome.ActivationsAllowed,
                outcome.Request.Expires,
                outcome.Request.Fingerprint,
                outcome.Request.KeyId,
                pluginVersion ?? "(not sent)");

            return ActivationReply.Success(
                outcome.Request.Licence,
                outcome.ExpiresUtc ?? default,
                outcome.ActivationsUsed,
                outcome.ActivationsAllowed);
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

        /// <summary>
        /// Added when signing moved off this host. It is NOT a refusal of the
        /// code: the activation is recorded and the licence is coming. A plugin
        /// too old to know this code treats it as an unrecognised error and says
        /// so, which is wrong but harmless - it stores nothing and the next
        /// attempt after the licence is signed succeeds.
        /// </summary>
        public const string PendingSignature = "pending_signature";
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

        /// <summary>Set only on a pending reply, for the caller that waits.</summary>
        public string RequestId { get; private set; }

        public static ActivationReply Success(string licence, DateTimeOffset expires, int used, int allowed)
        {
            return new ActivationReply(true, licence, expires, used, allowed, null, null, TimeSpan.Zero);
        }

        public static ActivationReply Failure(string error, string message, TimeSpan retryAfter)
        {
            return new ActivationReply(false, null, default, 0, 0, error, message, retryAfter);
        }

        /// <summary>
        /// Recorded, allowed, and waiting on a signature. Carries the request id
        /// and the terms so that a caller which waits for the signature can
        /// answer without repeating the decision.
        /// </summary>
        public static ActivationReply Pending(
            string message,
            TimeSpan retryAfter,
            string requestId,
            DateTimeOffset expires,
            int used,
            int allowed)
        {
            return new ActivationReply(
                false,
                null,
                expires,
                used,
                allowed,
                ActivationError.PendingSignature,
                message,
                retryAfter)
            {
                RequestId = requestId,
            };
        }
    }
}

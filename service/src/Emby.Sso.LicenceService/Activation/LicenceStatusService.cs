using System;
using Emby.Sso.LicenceService.RateLimiting;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.LicenceService.Activation
{
    /// <summary>
    /// POST /v1/licence/status - "is this licence still good?", asked once a day
    /// by every installed plugin.
    ///
    /// WHY THIS EXISTS. A licence is verified offline and cannot be recalled, so
    /// a refund, a chargeback or a licence issued in error had no remedy at all.
    /// This is that remedy: the plugin asks daily, and a signed answer of
    /// "revoked" stops NEW single sign-ons on that server.
    ///
    /// WHAT IT IS NOT. It is not enforcement. The plugin FAILS OPEN - no answer
    /// changes nothing - so anyone willing to firewall this endpoint keeps
    /// working, and that is deliberate: the alternative is that the vendor's
    /// server being down silently breaks SSO for everyone who paid. This is a
    /// business control against honest customers, which is what a refund is.
    ///
    /// THE ANSWER IS SIGNED, and that is not optional. The plugin acts on it by
    /// refusing sign-ins, so an unsigned answer would let anyone standing
    /// between a customer and this service switch off their plugin. See
    /// <see cref="LicenceStatusToken"/>.
    ///
    /// WHAT IT LEARNS ABOUT THE CALLER. A server id and a licence fingerprint,
    /// both of which this service issued. Not the licence, which never leaves
    /// the customer's server; not the redemption code, which is a bearer secret.
    /// A fingerprint is one-way, so this endpoint cannot be used to fish for
    /// licences - only to ask about one somebody already holds.
    /// </summary>
    public sealed class LicenceStatusService
    {
        private readonly LicenceStore _store;
        private readonly ActivationRateLimiter _limiter;
        private readonly JsonWebKey _signingKey;
        private readonly TimeProvider _time;
        private readonly ILogger<LicenceStatusService> _log;

        /// <summary>
        /// <paramref name="signingKey"/> is null when this deployment does not
        /// sign for itself. There is then no way to produce a signed answer, so
        /// the endpoint reports that it cannot answer rather than answering
        /// unsigned - and the plugin, which refuses an unsigned answer anyway,
        /// carries on unaffected.
        /// </summary>
        public LicenceStatusService(
            LicenceStore store,
            ActivationRateLimiter limiter,
            JsonWebKey signingKey,
            TimeProvider time,
            ILogger<LicenceStatusService> log)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _limiter = limiter ?? throw new ArgumentNullException(nameof(limiter));
            _signingKey = signingKey;
            _time = time ?? throw new ArgumentNullException(nameof(time));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public bool CanAnswer => _signingKey != null;

        public LicenceStatusReply Check(LicenceStatusRequest request, string clientKey)
        {
            // First, before anything is parsed or looked up - the same rule the
            // activation endpoint follows, for the same reason.
            var limit = _limiter.Check(clientKey);

            if (!limit.IsAllowed)
            {
                return LicenceStatusReply.Refused(429, limit.RetryAfter);
            }

            if (!CanAnswer)
            {
                // Nothing here can sign, so nothing here can answer. 501 rather
                // than 500: it is a deployment that does not offer this, not a
                // deployment that broke.
                return LicenceStatusReply.Refused(501, TimeSpan.Zero);
            }

            if (request == null
                || string.IsNullOrWhiteSpace(request.ServerId)
                || string.IsNullOrWhiteSpace(request.Fingerprint))
            {
                return LicenceStatusReply.Refused(400, TimeSpan.Zero);
            }

            var serverId = request.ServerId.Trim();

            if (!ActivationService.IsPlausibleServerId(serverId) || !IsPlausibleFingerprint(request.Fingerprint))
            {
                return LicenceStatusReply.Refused(400, TimeSpan.Zero);
            }

            var fingerprint = request.Fingerprint.Trim().ToLowerInvariant();
            var now = _time.GetUtcNow();

            string status;

            try
            {
                var code = _store.FindCodeByLicenceFingerprint(fingerprint);

                status = code == null
                    ? LicenceStatusToken.Unknown
                    : string.Equals(code.Status, CodeStatus.Active, StringComparison.Ordinal)
                        ? LicenceStatusToken.Valid
                        : LicenceStatusToken.Revoked;
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "licence status FAILED server={Server}", serverId);

                return LicenceStatusReply.Refused(500, TimeSpan.Zero);
            }

            // Info, not warning, even for revoked: a revoked licence still
            // checking in is the system working, not a problem.
            _log.LogInformation(
                "licence status server={Server} fingerprint={Fingerprint} status={Status} client={Client}",
                serverId,
                fingerprint,
                status,
                clientKey);

            return LicenceStatusReply.Answered(
                LicenceStatusToken.Issue(_signingKey, serverId, fingerprint, status, now));
        }

        /// <summary>
        /// A SHA-256 in the shape <see cref="LicenceFormat.Fingerprint"/> writes:
        /// the literal "sha256:" and 64 lowercase hex characters. Checked before
        /// the lookup so that a malformed one costs a string comparison rather
        /// than a query.
        /// </summary>
        public static bool IsPlausibleFingerprint(string fingerprint)
        {
            const string Prefix = "sha256:";

            if (fingerprint == null)
            {
                return false;
            }

            var value = fingerprint.Trim().ToLowerInvariant();

            if (value.Length != Prefix.Length + 64 || !value.StartsWith(Prefix, StringComparison.Ordinal))
            {
                return false;
            }

            for (var i = Prefix.Length; i < value.Length; i++)
            {
                var c = value[i];

                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                {
                    return false;
                }
            }

            return true;
        }
    }

    public sealed class LicenceStatusRequest
    {
        public string ServerId { get; set; }

        /// <summary>The licence's SHA-256, not the licence. See the service's remarks.</summary>
        public string Fingerprint { get; set; }
    }

    public sealed class LicenceStatusReply
    {
        private LicenceStatusReply(string token, int statusCode, TimeSpan retryAfter)
        {
            Token = token;
            StatusCode = statusCode;
            RetryAfter = retryAfter;
        }

        /// <summary>The signed answer, and only on a 200.</summary>
        public string Token { get; }

        public int StatusCode { get; }

        public TimeSpan RetryAfter { get; }

        public bool IsAnswered => Token != null;

        public static LicenceStatusReply Answered(string token)
        {
            return new LicenceStatusReply(token, 200, TimeSpan.Zero);
        }

        public static LicenceStatusReply Refused(int statusCode, TimeSpan retryAfter)
        {
            return new LicenceStatusReply(null, statusCode, retryAfter);
        }
    }
}

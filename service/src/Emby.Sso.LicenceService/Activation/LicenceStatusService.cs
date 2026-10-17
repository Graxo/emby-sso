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
    ///
    /// IT ALSO DELIVERS RENEWALS. A licence's expiry is fixed when it is
    /// signed, but a code's is not: the vendor API moves it on each paid
    /// renewal, and an operator can extend one. Without this, a renewed
    /// customer's server would run out on the old date. (A server that
    /// re-activates is brought up to date by the activation itself - see
    /// ActivationService.UpToDate - and both renew through
    /// <see cref="LicenceRenewer"/>.) So when the answer is valid and the code now
    /// runs past the licence the caller holds, the reply also carries a new
    /// licence to the code's expiry, which the plugin stores in place of the
    /// old one. It is the same licence in every other respect - same licensee,
    /// same server - so it gives nobody anything their old one did not, and it
    /// is only ever for the server the activation was made for.
    /// </summary>
    public sealed class LicenceStatusService
    {
        private readonly LicenceStore _store;
        private readonly ActivationRateLimiter _limiter;
        private readonly JsonWebKey _signingKey;
        private readonly LicenceRenewer _renewer;
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
            _renewer = signingKey == null ? null : new LicenceRenewer(store, signingKey);
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
            CodeSummary code;

            try
            {
                code = _store.FindCodeByLicenceFingerprint(fingerprint);

                // A released activation is revoked even though its code is
                // still active: the seat went back to the customer, and the
                // server that held it must stop signing people in.
                status = code == null
                    ? LicenceStatusToken.Unknown
                    : string.Equals(code.Status, CodeStatus.Active, StringComparison.Ordinal)
                      && !_store.IsLicenceReleased(fingerprint)
                        ? LicenceStatusToken.Valid
                        : LicenceStatusToken.Revoked;
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "licence status FAILED server={Server}", serverId);

                return LicenceStatusReply.Refused(500, TimeSpan.Zero);
            }

            // A check-in for the portal's history, for every answer that is
            // about an activation - valid or revoked; an unknown fingerprint
            // has no activation to count against. Never fails the answer: a
            // missing tick on a chart is not worth a server going without its
            // status, and the plugin would only ask again.
            if (code != null)
            {
                try
                {
                    _store.RecordStatusCheckin(fingerprint, now);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "licence status: recording the check-in for server={Server} FAILED", serverId);
                }
            }

            // Info, not warning, even for revoked: a revoked licence still
            // checking in is the system working, not a problem.
            _log.LogInformation(
                "licence status server={Server} fingerprint={Fingerprint} status={Status} client={Client}",
                serverId,
                fingerprint,
                status,
                clientKey);

            // Only for valid. Revoked, released, void and unknown never get a
            // licence, whatever their code's expiry says.
            var renewed = string.Equals(status, LicenceStatusToken.Valid, StringComparison.Ordinal)
                ? Renew(code, fingerprint, serverId, now)
                : null;

            return LicenceStatusReply.Answered(
                LicenceStatusToken.Issue(_signingKey, serverId, fingerprint, status, now),
                renewed);
        }

        /// <summary>
        /// A new licence to the code's expiry when that is later than the
        /// licence with <paramref name="fingerprint"/>, or null.
        ///
        /// The comparison is with the licence the CALLER holds, read from the
        /// store by its fingerprint, not with the activation's latest: a server
        /// that never saved yesterday's renewal still holds the old one and must
        /// be renewed again.
        ///
        /// Never fails the status answer. A renewal that cannot be signed or
        /// recorded is logged and left for tomorrow's check; the plugin carries
        /// on with the licence it has, which is still good until its own date.
        /// </summary>
        private string Renew(CodeSummary code, string fingerprint, string serverId, DateTimeOffset now)
        {
            if (code?.ExpiresUtc == null)
            {
                return null;
            }

            var expires = code.ExpiresUtc.Value;

            try
            {
                var held = _store.FindHeldLicence(fingerprint);

                // Whole seconds on both sides - the store keeps no more, and a
                // licence's exp is whole seconds - so an unchanged expiry can
                // never look later by a fraction and renew every day forever.
                if (held == null
                    || LicenceFormat.Iso(expires).CompareTo(LicenceFormat.Iso(held.ExpiresUtc)) <= 0
                    || expires <= now)
                {
                    return null;
                }

                // The licence is for the server the activation was made for,
                // in `aud` exactly as it was first sent. The server id in the
                // question is only the caller's word; it has to agree (the same
                // case-insensitive match activation counts servers by) or no
                // licence is handed back, so knowing somebody's fingerprint is
                // not a way to obtain a licence for a server of one's choosing.
                if (!string.Equals(held.ServerId, serverId, StringComparison.OrdinalIgnoreCase))
                {
                    _log.LogWarning(
                        "licence status: not renewing fingerprint={Fingerprint}, asked by server={Asked} but issued to server={Issued}",
                        fingerprint,
                        serverId,
                        held.ServerId);

                    return null;
                }

                var licence = _renewer.Renew(held, expires, now);

                _log.LogInformation(
                    "licence status RENEWED server={Server} from={Old} to={New} expires={Expires} key={Key}",
                    held.ServerId,
                    fingerprint,
                    licence.Fingerprint,
                    LicenceFormat.Iso(expires),
                    licence.KeyId);

                return licence.Token;
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "licence status: renewing fingerprint={Fingerprint} FAILED", fingerprint);

                return null;
            }
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
        private LicenceStatusReply(string token, string licence, int statusCode, TimeSpan retryAfter)
        {
            Token = token;
            Licence = licence;
            StatusCode = statusCode;
            RetryAfter = retryAfter;
        }

        /// <summary>The signed answer, and only on a 200.</summary>
        public string Token { get; }

        public int StatusCode { get; }

        public TimeSpan RetryAfter { get; }

        /// <summary>
        /// A renewed licence, only when the code's expiry has moved past the one
        /// asked about. Null otherwise - which is almost always.
        /// </summary>
        public string Licence { get; }

        public bool IsAnswered => Token != null;

        public static LicenceStatusReply Answered(string token, string licence = null)
        {
            return new LicenceStatusReply(token, licence, 200, TimeSpan.Zero);
        }

        public static LicenceStatusReply Refused(int statusCode, TimeSpan retryAfter)
        {
            return new LicenceStatusReply(null, null, statusCode, retryAfter);
        }
    }
}

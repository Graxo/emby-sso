using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Whether a renewed licence, handed back by the daily status check, may
    /// replace the one this server holds.
    ///
    /// IT IS ONLY DATA FROM THE NETWORK. The <c>licence</c> property sits beside
    /// the signed status token, not inside it, so nothing about the transport
    /// vouches for it. It is therefore put through exactly the check a licence
    /// gets at activation - <see cref="LicenceCheck"/>, with the trusted keys,
    /// the licence issuer and THIS server's id as audience - and accepted only if
    /// it also runs LONGER than the held one. A forged, mis-addressed, expired or
    /// older licence changes nothing, and a replayed genuine one for this server
    /// can at worst re-store a licence the vendor really issued.
    ///
    /// Like the rest of the daily check this never throws and never costs a
    /// working server anything: every refusal is "keep what you have".
    /// </summary>
    internal sealed class LicenceRenewal
    {
        private LicenceRenewal(bool accepted, DateTimeOffset? expiresAt, string reason)
        {
            Accepted = accepted;
            ExpiresAt = expiresAt;
            Reason = reason;
        }

        /// <summary>True only when the renewed licence is valid for this server and runs longer.</summary>
        public bool Accepted { get; }

        /// <summary>The renewed licence's expiry. Set only when <see cref="Accepted"/>.</summary>
        public DateTimeOffset? ExpiresAt { get; }

        /// <summary>Why a renewal was refused, for the log. Never contains the licence.</summary>
        public string Reason { get; }

        public static async Task<LicenceRenewal> EvaluateAsync(
            string renewed,
            string held,
            IReadOnlyList<string> publicKeyJwks,
            string serverId,
            DateTimeOffset now)
        {
            if (string.IsNullOrWhiteSpace(renewed))
            {
                return Refused("no renewed licence");
            }

            LicenceStatus status;

            try
            {
                status = await LicenceCheck.EvaluateAsync(renewed.Trim(), publicKeyJwks, serverId, now).ConfigureAwait(false);
            }
            catch (Exception)
            {
                return Refused("the renewed licence could not be checked");
            }

            if (!LicenceCheck.Permits(status.Outcome) || !status.ExpiresAt.HasValue)
            {
                // The outcome only, not Detail: it can echo parts of the token.
                return Refused("the renewed licence did not validate (" + status.Outcome + ")");
            }

            var heldExpiry = ReadExpiry(held);

            // Whole seconds on both sides - a JWT's exp is - so equal means
            // "the same licence again", which is nothing to store.
            if (heldExpiry.HasValue && status.ExpiresAt.Value <= heldExpiry.Value)
            {
                return Refused("the renewed licence does not run longer than the one held");
            }

            return new LicenceRenewal(true, status.ExpiresAt, null);
        }

        /// <summary>
        /// The held licence's own <c>exp</c>, read WITHOUT validating it: it is
        /// local, it was validated when it was stored, and if it has since
        /// expired it no longer validates - which is exactly when a renewal
        /// matters most. Null when it cannot be read, in which case the renewed
        /// licence's own validation is all there is to go on.
        /// </summary>
        private static DateTimeOffset? ReadExpiry(string held)
        {
            if (string.IsNullOrWhiteSpace(held))
            {
                return null;
            }

            try
            {
                var jwt = new JsonWebToken(held.Trim());

                return new DateTimeOffset(DateTime.SpecifyKind(jwt.ValidTo, DateTimeKind.Utc));
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>A valid renewal that was not stored because the configured licence changed during the check.</summary>
        public static LicenceRenewal Superseded()
        {
            return Refused("the configured licence changed while the check ran");
        }

        private static LicenceRenewal Refused(string reason)
        {
            return new LicenceRenewal(false, null, reason);
        }
    }
}

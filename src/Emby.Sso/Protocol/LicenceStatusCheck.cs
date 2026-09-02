using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// What the daily licence check decided. Zero is "nothing changes", like
    /// every other decision enum here - but note that here the fail-safe
    /// direction is to KEEP WORKING, which is the opposite of the licence check
    /// itself and is deliberate.
    /// </summary>
    internal enum LicenceStatusOutcome
    {
        /// <summary>
        /// No usable answer: unreachable, unreadable, unsigned, for a different
        /// server, stale, or a status this build does not recognise. THE PLUGIN
        /// CHANGES NOTHING. See <see cref="LicenceStatusCheck"/>.
        /// </summary>
        NoAnswer = 0,

        /// <summary>The vendor says this licence is good.</summary>
        Valid = 1,

        /// <summary>
        /// The vendor has withdrawn this licence. New single sign-ons stop;
        /// sessions already open keep working and Emby's own accounts are
        /// untouched, exactly as for an expired licence.
        /// </summary>
        Revoked = 2,

        /// <summary>
        /// The vendor does not recognise this licence. TREATED AS VALID. A
        /// restored backup or a rebuilt store looks exactly like this, and a
        /// forged licence would have failed its signature check long before
        /// reaching here.
        /// </summary>
        Unknown = 3,
    }

    /// <summary>
    /// Reads the vendor's signed answer to "is this licence still good?".
    ///
    /// THE WHOLE POINT IS THAT IT FAILS OPEN. This runs once a day, over the
    /// network, and the only thing it can do is take a working server's single
    /// sign-on away. So every way it can go wrong - no network, a proxy in the
    /// way, a truncated body, a token signed by nobody, an answer about a
    /// different server, an answer from last month, a status word this build has
    /// never heard of - is <see cref="LicenceStatusOutcome.NoAnswer"/>, and
    /// nothing changes.
    ///
    /// Only one thing turns a working server off: a CURRENT, CORRECTLY SIGNED
    /// token, naming THIS server and THIS licence, that says revoked. Anything
    /// less and the customer carries on. That asymmetry is not laziness - the
    /// vendor's server being unreachable must never become the customer's
    /// outage, and a hostile network must not be able to disable somebody's
    /// plugin by dropping packets.
    ///
    /// It is verified with the same pins as a licence: one algorithm, signed
    /// tokens only, issuer and audience enforced. A token that verifies is one
    /// the vendor signed, for this server, about this licence, recently.
    /// </summary>
    internal static class LicenceStatusCheck
    {
        /// <summary>Distinct from a licence's issuer, so neither can be read as the other.</summary>
        public const string Issuer = "urn:emby-sso:licence-status";

        public const string StatusClaim = "status";

        /// <summary>See LicenceCheck: one element, never empty, never HMAC.</summary>
        private static readonly string[] AllowedAlgorithms = { SecurityAlgorithms.RsaSha256 };

        private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);

        /// <summary>
        /// Reads one answer. <paramref name="fingerprint"/> is the SHA-256 of
        /// the licence this server is asking about; a token about any other
        /// licence is not an answer to this question.
        /// </summary>
        public static async Task<LicenceStatusOutcome> ReadAsync(
            string token,
            IReadOnlyList<string> publicKeyJwks,
            string serverId,
            string fingerprint,
            DateTimeOffset now)
        {
            if (string.IsNullOrWhiteSpace(token)
                || string.IsNullOrWhiteSpace(serverId)
                || string.IsNullOrWhiteSpace(fingerprint))
            {
                return LicenceStatusOutcome.NoAnswer;
            }

            IReadOnlyList<SecurityKey> keys;

            try
            {
                keys = LicenceCheck.ReadTrustedKeys(publicKeyJwks);
            }
            catch (Exception)
            {
                return LicenceStatusOutcome.NoAnswer;
            }

            var parameters = new TokenValidationParameters
            {
                IssuerSigningKeys = keys,
                TryAllIssuerSigningKeys = true,

                ValidIssuer = Issuer,
                ValidateIssuer = true,

                // Bound to this server, so an answer collected from one cannot
                // be replayed at another.
                ValidAudience = serverId.Trim(),
                ValidateAudience = true,

                ValidateIssuerSigningKey = true,
                ValidAlgorithms = AllowedAlgorithms,
                RequireSignedTokens = true,

                // Bound to a moment, so an answer from before a revocation
                // cannot be replayed after it. This is the one place a lifetime
                // check is load-bearing rather than informational.
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = ClockSkew,
                LifetimeValidator = (notBefore, expires, _, __) =>
                {
                    if (!expires.HasValue)
                    {
                        return false;
                    }

                    if (notBefore.HasValue && ToOffset(notBefore.Value) > now + ClockSkew)
                    {
                        return false;
                    }

                    return ToOffset(expires.Value) >= now - ClockSkew;
                },
            };

            TokenValidationResult result;

            try
            {
                result = await new JsonWebTokenHandler().ValidateTokenAsync(token, parameters).ConfigureAwait(false);
            }
            catch (Exception)
            {
                return LicenceStatusOutcome.NoAnswer;
            }

            if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt)
            {
                return LicenceStatusOutcome.NoAnswer;
            }

            // About THIS licence. Without this, a signed answer about any licence
            // the vendor ever issued would apply to this one.
            if (!string.Equals(jwt.Subject, fingerprint, StringComparison.OrdinalIgnoreCase))
            {
                return LicenceStatusOutcome.NoAnswer;
            }

            if (!jwt.TryGetClaim(StatusClaim, out var claim))
            {
                return LicenceStatusOutcome.NoAnswer;
            }

            // A REFUSING default: a status word this build has never heard of
            // must not be able to do anything, in either direction.
            switch (claim.Value)
            {
                case "valid":
                    return LicenceStatusOutcome.Valid;

                case "revoked":
                    return LicenceStatusOutcome.Revoked;

                case "unknown":
                    return LicenceStatusOutcome.Unknown;

                default:
                    return LicenceStatusOutcome.NoAnswer;
            }
        }

        /// <summary>
        /// The single whitelist. Written as an explicit test against the one
        /// member that stops a sign-in, so that adding a member to
        /// <see cref="LicenceStatusOutcome"/> cannot accidentally disable
        /// anybody's server.
        /// </summary>
        public static bool StopsSignIns(LicenceStatusOutcome outcome)
        {
            return outcome == LicenceStatusOutcome.Revoked;
        }

        private static DateTimeOffset ToOffset(DateTime value)
        {
            return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
        }
    }
}

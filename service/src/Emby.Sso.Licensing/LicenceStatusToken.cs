using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Licensing
{
    /// <summary>
    /// The vendor's signed answer to "is this licence still good?".
    ///
    /// WHY IT IS SIGNED AT ALL. The plugin asks this question over the network,
    /// once a day, and acts on the answer by refusing new sign-ins. An unsigned
    /// answer would mean anyone who can stand between a customer's server and
    /// the vendor - a hijacked DNS entry, a proxy, a hostile network - could
    /// switch off somebody's plugin by saying "revoked", or keep a revoked
    /// licence alive by saying "valid". Neither is acceptable for something that
    /// is meant to be a business control.
    ///
    /// It is bound to ONE server and ONE licence, and it expires quickly. A
    /// token collected from one server cannot be replayed at another, and one
    /// collected today cannot be replayed next month.
    ///
    /// It is signed with the SAME key that signs licences, deliberately: both
    /// are the vendor asserting something about a licence, so a key that can do
    /// one can already do the other. That reasoning does NOT extend to plugin
    /// updates, which are code rather than an assertion - see the release key.
    /// </summary>
    public static class LicenceStatusToken
    {
        /// <summary>Distinct from a licence's issuer, so a licence can never be read as a status and vice versa.</summary>
        public const string Issuer = "urn:emby-sso:licence-status";

        /// <summary>The licence is good. The plugin does nothing.</summary>
        public const string Valid = "valid";

        /// <summary>
        /// The licence has been withdrawn - refunded, charged back, or issued in
        /// error. The plugin stops NEW single sign-ons, exactly as it does for
        /// an expired one: sessions already open keep working and Emby's own
        /// accounts are untouched.
        /// </summary>
        public const string Revoked = "revoked";

        /// <summary>
        /// The service does not recognise this licence. Treated as VALID by the
        /// plugin, and that is deliberate: it means the vendor's records and the
        /// customer's licence disagree, which is far more likely to be a
        /// restored backup or a rebuilt store than a forgery - and a forged
        /// licence would have failed its signature check long before this. It is
        /// reported so the vendor can look, not acted on.
        /// </summary>
        public const string Unknown = "unknown";

        /// <summary>
        /// How long an answer is good for. Short, because its only job is to be
        /// fresh: the plugin asks daily and keeps the last answer, so a token
        /// that outlived its usefulness would only widen the window in which a
        /// revocation has not taken effect.
        /// </summary>
        public static readonly TimeSpan Lifetime = TimeSpan.FromDays(2);

        /// <summary>The claim carrying <see cref="Valid"/>, <see cref="Revoked"/> or <see cref="Unknown"/>.</summary>
        public const string StatusClaim = "status";

        /// <summary>
        /// Signs one answer. <paramref name="serverId"/> is the audience and
        /// <paramref name="fingerprint"/> the subject, so the token says which
        /// licence on which server it is about and cannot be moved to another.
        /// </summary>
        public static string Issue(
            JsonWebKey key,
            string serverId,
            string fingerprint,
            string status,
            DateTimeOffset now)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (string.IsNullOrWhiteSpace(serverId))
            {
                throw new ArgumentException("a status must name the server it is about", nameof(serverId));
            }

            if (string.IsNullOrWhiteSpace(fingerprint))
            {
                throw new ArgumentException("a status must name the licence it is about", nameof(fingerprint));
            }

            if (status != Valid && status != Revoked && status != Unknown)
            {
                // A status nobody wrote a case for must not be signable. The
                // plugin's reader has a refusing default; this is the other end
                // of that.
                throw new ArgumentException("'" + status + "' is not a licence status", nameof(status));
            }

            var payload = JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["iss"] = Issuer,
                ["aud"] = serverId,
                ["sub"] = fingerprint,
                [StatusClaim] = status,
                ["iat"] = EpochTime.GetIntDate(now.UtcDateTime),
                ["nbf"] = EpochTime.GetIntDate(now.UtcDateTime),
                ["exp"] = EpochTime.GetIntDate((now + Lifetime).UtcDateTime),
            });

            return new JsonWebTokenHandler().CreateToken(payload, new SigningCredentials(key, LicenceFormat.Algorithm));
        }
    }
}

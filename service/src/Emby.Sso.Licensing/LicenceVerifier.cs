using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Licensing
{
    /// <summary>
    /// Checks a licence the way the plugin will, before this service accepts it
    /// as an answer to a signing request.
    ///
    /// WHY THE SERVICE VERIFIES SOMETHING IT DID NOT SIGN. Since the private key
    /// moved off this host, the service is handed finished licences by whoever
    /// is logged into the admin page. It cannot forge one - it has no key - but
    /// it can be handed the wrong file: last year's key, another customer's
    /// licence, a token for a different server, a truncated paste. Every one of
    /// those would be stored, delivered, and then refused on the customer's
    /// server with an error the customer cannot act on. Checking here turns all
    /// of that into a message on the operator's own screen, while they still
    /// have the file open.
    ///
    /// The parameters below mirror <c>Emby.Sso.Protocol.LicenceCheck</c> in the
    /// plugin exactly where it matters - one pinned algorithm, signed tokens
    /// only, issuer and audience enforced - so a licence this accepts is one the
    /// plugin accepts. It deliberately does NOT check the lifetime against now:
    /// a licence signed a moment ago for a customer whose clock is a minute
    /// ahead is fine, and expiry is checked against the request's own expiry
    /// instead, which is the stronger statement.
    /// </summary>
    public static class LicenceVerifier
    {
        private static readonly string[] AllowedAlgorithms = { LicenceFormat.Algorithm };

        /// <summary>
        /// True if <paramref name="licence"/> is a licence signed by one of
        /// <paramref name="trusted"/> and says exactly what
        /// <paramref name="expected"/> asked for. On false,
        /// <paramref name="problem"/> is one sentence for the operator.
        /// </summary>
        public static async Task<VerifiedLicence> VerifyAsync(
            string licence,
            IReadOnlyList<JsonWebKey> trusted,
            SigningRequest expected)
        {
            if (expected == null)
            {
                throw new ArgumentNullException(nameof(expected));
            }

            if (trusted == null || trusted.Count == 0)
            {
                return VerifiedLicence.Rejected("this service has no trusted licence public keys configured");
            }

            if (string.IsNullOrWhiteSpace(licence))
            {
                return VerifiedLicence.Rejected("the file carries no licence for this request");
            }

            var parameters = new TokenValidationParameters
            {
                IssuerSigningKeys = trusted,

                ValidIssuer = LicenceFormat.Issuer,
                ValidateIssuer = true,

                // The server binding, checked against the request this is
                // supposed to answer rather than against anything in the file.
                ValidAudience = expected.ServerId,
                ValidateAudience = true,

                ValidateIssuerSigningKey = true,

                // One element, never empty. An empty ValidAlgorithms is read by
                // the handler as "no restriction", which would let an HMAC token
                // be verified with a public key everybody has.
                ValidAlgorithms = AllowedAlgorithms,
                RequireSignedTokens = true,

                // Expiry is checked exactly, below, against what was asked for.
                // Validating it against now as well would reject a licence whose
                // request was made before a clock adjustment for no gain.
                ValidateLifetime = false,
                RequireExpirationTime = true,
            };

            TokenValidationResult result;

            try
            {
                result = await new JsonWebTokenHandler().ValidateTokenAsync(licence, parameters).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return VerifiedLicence.Rejected("that is not a licence this service can read (" + ex.GetType().Name + ")");
            }

            if (!result.IsValid)
            {
                return VerifiedLicence.Rejected(Explain(result.Exception));
            }

            if (result.SecurityToken is not JsonWebToken token)
            {
                return VerifiedLicence.Rejected("that validated to something that is not a JWT");
            }

            if (!string.Equals(token.Subject, expected.Licensee, StringComparison.Ordinal))
            {
                return VerifiedLicence.Rejected("it names a different licensee than the request it answers");
            }

            if (!Matches(token.ValidTo, expected.ExpiresUtc))
            {
                return VerifiedLicence.Rejected(
                    "it expires at " + LicenceFormat.Iso(ToOffset(token.ValidTo))
                    + ", and the request asked for " + LicenceFormat.Iso(expected.ExpiresUtc)
                    + ". A licence must last exactly as long as what was paid for.");
            }

            if (!Matches(token.IssuedAt, expected.IssuedAtUtc))
            {
                return VerifiedLicence.Rejected("it is dated differently from the request it answers");
            }

            var keyId = token.Kid;

            if (string.IsNullOrEmpty(keyId))
            {
                // Not fatal to the signature - it verified - but a licence with
                // no `kid` cannot be rotated away from later, and every licence
                // this project mints carries one.
                return VerifiedLicence.Rejected(
                    "it carries no key id. Sign it with a current build of the licence tool, which names the key "
                    + "that signed each licence so that key can be retired later.");
            }

            return VerifiedLicence.Accepted(licence, keyId);
        }

        private static bool Matches(DateTime claim, DateTimeOffset expected)
        {
            // The claims are whole seconds; the request's timestamps are
            // serialised to whole seconds too. Compare on that grid rather than
            // on ticks, which would never be equal.
            return LicenceFormat.Iso(ToOffset(claim)) == LicenceFormat.Iso(expected);
        }

        private static DateTimeOffset ToOffset(DateTime value)
        {
            return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
        }

        private static string Explain(Exception exception)
        {
            switch (exception)
            {
                case SecurityTokenInvalidAudienceException _:
                    return "it was signed for a different Emby server than the request it answers";

                case SecurityTokenInvalidIssuerException _:
                    return "it is a token, but not one of this project's licences";

                case SecurityTokenSignatureKeyNotFoundException _:
                    return "it was signed by a key this service does not trust. Check that the signing machine's key "
                        + "is one of the public keys in LICENCE_PUBLIC_KEYS - a rotation has to reach both.";

                case SecurityTokenInvalidSigningKeyException _:
                case SecurityTokenInvalidAlgorithmException _:
                case SecurityTokenInvalidSignatureException _:
                    return "its signature did not verify against any trusted key";

                default:
                    return "it could not be read as a licence";
            }
        }
    }

    /// <summary>The verdict, carrying the licence only when it is one.</summary>
    public sealed class VerifiedLicence
    {
        private VerifiedLicence(bool ok, string licence, string keyId, string problem)
        {
            IsValid = ok;
            Licence = licence;
            KeyId = keyId;
            Problem = problem;
        }

        public bool IsValid { get; }

        /// <summary>Set only when <see cref="IsValid"/>, so a caller cannot store a rejected token by accident.</summary>
        public string Licence { get; }

        public string KeyId { get; }

        public string Problem { get; }

        public string Fingerprint => Licence == null ? null : LicenceFormat.Fingerprint(Licence);

        public static VerifiedLicence Accepted(string licence, string keyId)
        {
            return new VerifiedLicence(true, licence, keyId, null);
        }

        public static VerifiedLicence Rejected(string problem)
        {
            return new VerifiedLicence(false, null, null, problem);
        }
    }
}

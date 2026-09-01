using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Licensing
{
    /// <summary>
    /// The constants and encodings that a licence is made of.
    ///
    /// Every value here is a copy of one in
    /// <c>tools/Emby.Sso.LicenceTool/Program.cs</c>, which in turn copies the
    /// first two from <c>Emby.Sso.Protocol.LicenceCheck</c> in the plugin. They
    /// must stay character-identical across all three: a mismatch makes every
    /// licence this service issues fail validation on the customer's server with
    /// "wrong issuer", which is at least a loud failure rather than a quiet one.
    ///
    /// <see cref="Emby.Sso.LicenceService.Tests.LicenceToolCompatibilityTests"/>
    /// reads the tool's source and fails if it stops agreeing with this file.
    /// </summary>
    public static class LicenceFormat
    {
        public const string Issuer = "urn:emby-sso:licence";

        /// <summary>
        /// RS256, and pinned. The plugin passes exactly this one value in
        /// <c>ValidAlgorithms</c>, so nothing else will ever verify.
        /// </summary>
        public const string Algorithm = SecurityAlgorithms.RsaSha256;

        /// <summary>The file name <c>licencetool keygen</c> writes.</summary>
        public const string PrivateKeyFileName = "licence-signing-key.private.json";

        /// <summary>The file name <c>licencetool issue</c> appends to, and <c>list</c> reads.</summary>
        public const string LedgerFileName = "licences-issued.jsonl";

        /// <summary>
        /// The `format` field of the file the admin page hands the operator:
        /// the licences that have been paid for and are waiting to be signed on
        /// a machine this service cannot reach.
        /// </summary>
        public const string RequestsFormat = "emby-sso.signing-requests";

        /// <summary>The `format` field of the file the offline tool hands back.</summary>
        public const string SignedFormat = "emby-sso.signed-licences";

        /// <summary>
        /// Bumped only when a reader written for the old shape would misread the
        /// new one. Both sides refuse a version they do not know rather than
        /// guessing, because the thing being exchanged is a signing instruction.
        /// </summary>
        public const int FileVersion = 1;

        /// <summary>
        /// The canonical public half of an RSA JWK: three members, in this
        /// order, no whitespace.
        ///
        /// It is canonical because <see cref="KeyId"/> hashes it. Two programs
        /// that serialise "the same key" differently would derive two different
        /// key ids for it, and a licence would then name a key the verifier
        /// believes it does not have. Everything that needs the public half -
        /// the startup log, the key id, what gets pasted into the plugin - goes
        /// through this one function.
        /// </summary>
        public static string PublicJwk(string modulus, string exponent)
        {
            if (string.IsNullOrEmpty(modulus))
            {
                throw new ArgumentException("an RSA JWK needs a modulus", nameof(modulus));
            }

            if (string.IsNullOrEmpty(exponent))
            {
                throw new ArgumentException("an RSA JWK needs an exponent", nameof(exponent));
            }

            return "{\"kty\":\"RSA\",\"n\":\"" + modulus + "\",\"e\":\"" + exponent + "\"}";
        }

        /// <summary>
        /// The name a licence carries for the key that signed it, in the JWT's
        /// `kid` header.
        ///
        /// WHY THIS EXISTS AT ALL. A build that trusts exactly one public key
        /// cannot survive that key being compromised: the only remedy is a new
        /// keypair and a new build, which invalidates every licence in the field
        /// at once. A build that trusts a SET of named keys can be given the new
        /// one before the old one is dropped, so a rotation is a release rather
        /// than an outage - and dropping a key from that set is what revoking it
        /// means. See <c>Emby.Sso.Protocol.LicencePublicKey</c> in the plugin.
        ///
        /// Derived from the key rather than chosen, so that nobody has to keep a
        /// registry of which name meant which key: the same key always produces
        /// the same id, on both sides, without either having been told.
        /// </summary>
        public static string KeyId(string publicJwk)
        {
            if (string.IsNullOrWhiteSpace(publicJwk))
            {
                throw new ArgumentException("no public key to name", nameof(publicJwk));
            }

            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(publicJwk));

            return Convert.ToHexString(hash).ToLowerInvariant().Substring(0, 16);
        }

        /// <summary>
        /// One timestamp format everywhere: UTC, seconds, no offset. The tool's
        /// <c>list</c> parses the ledger back with <c>ParseExact</c> on exactly
        /// this format, so it has to be exact rather than whatever the machine's
        /// culture prints.
        /// </summary>
        public static string Iso(DateTimeOffset moment)
        {
            return moment.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// What the ledger stores in place of the licence itself: a SHA-256 of
        /// the licence string.
        ///
        /// THE LICENCE IS DELIBERATELY NOT STORED, here for the same reason as in
        /// the tool. It is a live credential, and a service holding every
        /// credential it ever issued is a far worse thing to lose than a list of
        /// server ids. A fingerprint is one-way, so it is not a credential, and
        /// it still answers the question the ledger has to answer about a string
        /// somebody emails back: which row is this, and did we issue it at all.
        /// The tool's <c>show</c> prints the same fingerprint.
        /// </summary>
        public static string Fingerprint(string licence)
        {
            if (licence == null)
            {
                throw new ArgumentNullException(nameof(licence));
            }

            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(licence));

            return "sha256:" + Convert.ToHexString(hash).ToLowerInvariant();
        }
    }
}

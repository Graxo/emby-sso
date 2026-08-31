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

using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Licensing
{
    /// <summary>
    /// The set of PUBLIC keys a licence is allowed to have been signed by, and
    /// the only place that set is parsed.
    ///
    /// A SET, NOT A KEY. This is the whole of key rotation. With one trusted key
    /// there is no recovery from that key leaking short of a new build that
    /// invalidates every licence in the field; with a set, the new key can be
    /// trusted alongside the old one for as long as licences signed by the old
    /// one are still out there, and the old one is dropped when they have
    /// expired. Dropping a key from this set IS revocation: a licence signed by
    /// a key that is not here fails its signature check like any forgery, so a
    /// leaked key is recovered from by shipping a build without it.
    ///
    /// Every key is named by <see cref="LicenceFormat.KeyId"/> and that name
    /// goes in the licence's `kid` header, so a support question - "which key
    /// signed this?" - is answerable from the licence alone.
    ///
    /// PUBLIC ONLY, refused loudly otherwise. The one mistake that would give
    /// the whole scheme away is pasting a private key file where a public one
    /// belongs, and this is the function both the service and the plugin's
    /// equivalent use to make that a startup failure rather than a shipped
    /// disaster.
    /// </summary>
    public static class TrustedLicenceKeys
    {
        /// <summary>
        /// Reads one JWK or a JSON array of them. Throws
        /// <see cref="FormatException"/> naming what is wrong, because every
        /// caller turns that into a refusal to start.
        /// </summary>
        public static IReadOnlyList<JsonWebKey> Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new FormatException("no trusted licence public keys were configured");
            }

            var trimmed = json.Trim();
            var texts = new List<string>();

            if (trimmed.StartsWith("[", StringComparison.Ordinal))
            {
                JsonDocument document;

                try
                {
                    document = JsonDocument.Parse(trimmed);
                }
                catch (JsonException ex)
                {
                    throw new FormatException("the trusted licence keys are not valid JSON: " + ex.Message, ex);
                }

                using (document)
                {
                    foreach (var element in document.RootElement.EnumerateArray())
                    {
                        texts.Add(element.GetRawText());
                    }
                }
            }
            else
            {
                texts.Add(trimmed);
            }

            if (texts.Count == 0)
            {
                throw new FormatException("the trusted licence key list is empty; nothing could ever verify");
            }

            var keys = new List<JsonWebKey>(texts.Count);
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var text in texts)
            {
                var key = ReadOne(text);

                if (!seen.Add(key.Kid))
                {
                    throw new FormatException("the same licence public key (" + key.Kid + ") is listed twice");
                }

                keys.Add(key);
            }

            return keys;
        }

        /// <summary>
        /// One key, checked to be an RSA public half and named by its own
        /// content. Any `kid` already in the JSON is ignored rather than
        /// honoured: a name that does not follow from the key is a name two
        /// programs can disagree about, and the id is used to look the key up.
        /// </summary>
        public static JsonWebKey ReadOne(string json)
        {
            JsonWebKey key;

            try
            {
                key = new JsonWebKey(json);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is JsonException)
            {
                throw new FormatException("a trusted licence key is not a JWK: " + ex.Message, ex);
            }

            if (!string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal))
            {
                throw new FormatException("a trusted licence key is '" + key.Kty + "', not RSA");
            }

            if (string.IsNullOrEmpty(key.N) || string.IsNullOrEmpty(key.E))
            {
                throw new FormatException("a trusted licence key is missing its RSA modulus or exponent");
            }

            if (CarriesPrivateMaterial(key))
            {
                throw new FormatException(
                    "a trusted licence key carries PRIVATE key material. This list is the PUBLIC halves only - "
                    + "the private half signs, and belongs on the offline signing machine and nowhere else.");
            }

            key.Kid = LicenceFormat.KeyId(LicenceFormat.PublicJwk(key.N, key.E));

            return key;
        }

        public static bool CarriesPrivateMaterial(JsonWebKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return !string.IsNullOrEmpty(key.D)
                || !string.IsNullOrEmpty(key.P)
                || !string.IsNullOrEmpty(key.Q)
                || !string.IsNullOrEmpty(key.QI)
                || !string.IsNullOrEmpty(key.DP)
                || !string.IsNullOrEmpty(key.DQ);
        }
    }
}

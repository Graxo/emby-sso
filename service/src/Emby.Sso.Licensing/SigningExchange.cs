using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Emby.Sso.Licensing
{
    /// <summary>
    /// One licence that has been paid for and not yet signed.
    ///
    /// This is the unit of the exchange between the service, which knows who
    /// paid and for what, and the signing machine, which holds the only key that
    /// can turn that into a licence. Everything a signature needs is here and
    /// nothing else is: no email address, no redemption code, no payment id.
    /// The file travels on a USB stick or through a browser download; it should
    /// carry the minimum that makes a licence.
    /// </summary>
    public sealed class SigningRequest
    {
        /// <summary>
        /// Opaque, unique, and the only thing the upload is matched back on. Not
        /// derived from the code or the server id: it is written into a file
        /// that leaves the machine, and it should say nothing about the customer.
        /// </summary>
        [JsonPropertyName("requestId")]
        public string RequestId { get; set; }

        /// <summary>Becomes the licence's `sub`.</summary>
        [JsonPropertyName("licensee")]
        public string Licensee { get; set; }

        /// <summary>Becomes the licence's `aud`, character for character.</summary>
        [JsonPropertyName("serverId")]
        public string ServerId { get; set; }

        [JsonPropertyName("issuedAtUtc")]
        public string IssuedAt { get; set; }

        [JsonPropertyName("expiresUtc")]
        public string Expires { get; set; }

        [JsonIgnore]
        public DateTimeOffset IssuedAtUtc => Moment(IssuedAt, nameof(IssuedAt));

        [JsonIgnore]
        public DateTimeOffset ExpiresUtc => Moment(Expires, nameof(Expires));

        private static DateTimeOffset Moment(string value, string what)
        {
            if (!DateTimeOffset.TryParseExact(
                    value,
                    "yyyy-MM-dd'T'HH:mm:ss'Z'",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var moment))
            {
                throw new FormatException("a signing request's " + what + " is not a UTC timestamp: '" + value + "'");
            }

            return moment;
        }
    }

    /// <summary>The file the admin page hands the operator.</summary>
    public sealed class SigningRequestFile
    {
        [JsonPropertyName("format")]
        public string Format { get; set; } = LicenceFormat.RequestsFormat;

        [JsonPropertyName("version")]
        public int Version { get; set; } = LicenceFormat.FileVersion;

        [JsonPropertyName("generatedUtc")]
        public string GeneratedUtc { get; set; }

        /// <summary>
        /// Which service asked. Not used to route anything - the signed file
        /// goes back by hand - but an operator who runs more than one deployment
        /// needs to be able to tell two downloads apart.
        /// </summary>
        [JsonPropertyName("service")]
        public string Service { get; set; }

        [JsonPropertyName("requests")]
        public List<SigningRequest> Requests { get; set; } = new List<SigningRequest>();
    }

    /// <summary>One signed licence, on its way back.</summary>
    public sealed class SignedLicence
    {
        [JsonPropertyName("requestId")]
        public string RequestId { get; set; }

        [JsonPropertyName("licence")]
        public string Licence { get; set; }
    }

    /// <summary>The file the offline tool hands back.</summary>
    public sealed class SignedLicenceFile
    {
        [JsonPropertyName("format")]
        public string Format { get; set; } = LicenceFormat.SignedFormat;

        [JsonPropertyName("version")]
        public int Version { get; set; } = LicenceFormat.FileVersion;

        [JsonPropertyName("signedUtc")]
        public string SignedUtc { get; set; }

        /// <summary>
        /// Which key signed this batch. Informational - every licence carries
        /// its own `kid` and that is what is checked - but it is the first thing
        /// an operator looks at when a whole batch is refused.
        /// </summary>
        [JsonPropertyName("keyId")]
        public string KeyId { get; set; }

        [JsonPropertyName("licences")]
        public List<SignedLicence> Licences { get; set; } = new List<SignedLicence>();
    }

    /// <summary>
    /// Reading and writing the two files, in one place so both ends agree.
    ///
    /// Every read refuses an unknown `format` or `version` rather than doing its
    /// best with it. These files are signing instructions and finished
    /// credentials; a reader that guesses at a shape it does not know is a
    /// reader that can be steered.
    /// </summary>
    public static class SigningExchange
    {
        /// <summary>
        /// A ceiling on how many requests one file carries. Not a business rule
        /// - it is a bound on what a single upload can make the service do, and
        /// on what a download can be asked to serialise.
        /// </summary>
        public const int MaximumBatch = 500;

        private static readonly JsonSerializerOptions Layout = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        public static string Write(SigningRequestFile file)
        {
            return JsonSerializer.Serialize(file ?? throw new ArgumentNullException(nameof(file)), Layout);
        }

        public static string Write(SignedLicenceFile file)
        {
            return JsonSerializer.Serialize(file ?? throw new ArgumentNullException(nameof(file)), Layout);
        }

        public static SigningRequestFile ReadRequests(string json)
        {
            var file = Read<SigningRequestFile>(json, LicenceFormat.RequestsFormat, f => f.Format, f => f.Version);

            file.Requests ??= new List<SigningRequest>();

            Bound(file.Requests.Count, "requests");

            foreach (var request in file.Requests)
            {
                if (string.IsNullOrWhiteSpace(request.RequestId)
                    || string.IsNullOrWhiteSpace(request.Licensee)
                    || string.IsNullOrWhiteSpace(request.ServerId))
                {
                    throw new FormatException("a signing request in that file is missing its id, licensee or server id");
                }

                // Throws with the offending value named if either is not a
                // timestamp, here rather than at signing time.
                _ = request.IssuedAtUtc;
                _ = request.ExpiresUtc;
            }

            return file;
        }

        public static SignedLicenceFile ReadSigned(string json)
        {
            var file = Read<SignedLicenceFile>(json, LicenceFormat.SignedFormat, f => f.Format, f => f.Version);

            file.Licences ??= new List<SignedLicence>();

            Bound(file.Licences.Count, "licences");

            foreach (var signed in file.Licences)
            {
                if (string.IsNullOrWhiteSpace(signed.RequestId) || string.IsNullOrWhiteSpace(signed.Licence))
                {
                    throw new FormatException("an entry in that file has no request id or no licence in it");
                }
            }

            return file;
        }

        private static void Bound(int count, string what)
        {
            if (count > MaximumBatch)
            {
                throw new FormatException(
                    "that file carries " + count.ToString(CultureInfo.InvariantCulture) + " " + what
                    + ", and the limit is " + MaximumBatch.ToString(CultureInfo.InvariantCulture) + ".");
            }
        }

        private static T Read<T>(string json, string expectedFormat, Func<T, string> format, Func<T, int> version)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new FormatException("that file is empty");
            }

            T file;

            try
            {
                file = JsonSerializer.Deserialize<T>(json);
            }
            catch (JsonException ex)
            {
                throw new FormatException("that file is not valid JSON: " + ex.Message, ex);
            }

            if (file == null)
            {
                throw new FormatException("that file is empty");
            }

            if (!string.Equals(format(file), expectedFormat, StringComparison.Ordinal))
            {
                throw new FormatException(
                    "that is not a " + expectedFormat + " file"
                    + (string.IsNullOrWhiteSpace(format(file)) ? " - it has no format field" : string.Empty) + ".");
            }

            if (version(file) != LicenceFormat.FileVersion)
            {
                throw new FormatException(
                    "that file is version " + version(file).ToString(CultureInfo.InvariantCulture)
                    + " and this build reads version " + LicenceFormat.FileVersion.ToString(CultureInfo.InvariantCulture)
                    + ". Update whichever of the two is older.");
            }

            return file;
        }
    }
}

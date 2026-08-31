using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;

namespace Emby.Sso.LicenceService.PayPal
{
    /// <summary>
    /// Decides whether a POST to /paypal/webhook really came from PayPal.
    ///
    /// THIS IS THE MOST SECURITY-CRITICAL CLASS IN THE SERVICE. The webhook
    /// creates redemption codes. An endpoint that accepts an unverified webhook
    /// is a free-licence dispenser for anyone who finds the URL, and finding it
    /// is one scan away. There is deliberately no configuration flag, no
    /// environment, and no build that skips what follows: the only way to make
    /// this service accept an unsigned webhook is to edit this file.
    ///
    /// It implements PayPal's documented offline verification, the same
    /// algorithm their own SDKs implement:
    ///
    ///   message   = transmissionId | transmissionTime | webhookId | crc32(body)
    ///   signature = base64(RSA-SHA256(message, PayPal's private key))
    ///   verify    with the public key of the certificate at PAYPAL-CERT-URL
    ///
    /// The alternative documented method is to POST the headers and body back to
    /// PayPal's /v1/notifications/verify-webhook-signature and believe the
    /// answer. That was NOT chosen, for one reason that matters here: its
    /// correctness lives on PayPal's servers, so in an environment with no
    /// credentials and no route to PayPal there is no test that can prove a
    /// tampered payload is refused - the whole check would ship untested. The
    /// algorithm below is verifiable offline against a key the test generates,
    /// and PayPalWebhookVerifierTests does exactly that, including proving that
    /// a single flipped byte of body is refused.
    ///
    /// What is NOT provable here, and is marked UNVERIFIED in the README: that a
    /// real PayPal transmission satisfies this. The message layout, header names
    /// and CRC are taken from PayPal's documentation and their SDKs, and the
    /// first sandbox webhook the vendor sends is what confirms them. See
    /// docs/paypal-sandbox-checklist.md.
    /// </summary>
    public sealed class PayPalWebhookVerifier
    {
        public const string TransmissionIdHeader = "paypal-transmission-id";
        public const string TransmissionTimeHeader = "paypal-transmission-time";
        public const string TransmissionSignatureHeader = "paypal-transmission-sig";
        public const string CertificateUrlHeader = "paypal-cert-url";
        public const string AuthAlgorithmHeader = "paypal-auth-algo";

        /// <summary>
        /// The only algorithm accepted, pinned rather than read from the header
        /// and honoured. paypal-auth-algo is attacker-controlled like every other
        /// header, and an implementation that switches on it is one that can be
        /// told to verify with something weaker. PayPal sends exactly this.
        /// </summary>
        public const string RequiredAuthAlgorithm = "SHA256withRSA";

        private readonly IPayPalCertificateSource _certificates;
        private readonly PayPalOptions _options;

        public PayPalWebhookVerifier(IPayPalCertificateSource certificates, PayPalOptions options)
        {
            _certificates = certificates ?? throw new ArgumentNullException(nameof(certificates));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        public async Task<WebhookVerification> VerifyAsync(
            IReadOnlyDictionary<string, string> headers,
            byte[] body,
            CancellationToken cancellationToken)
        {
            if (headers == null)
            {
                throw new ArgumentNullException(nameof(headers));
            }

            if (body == null)
            {
                throw new ArgumentNullException(nameof(body));
            }

            if (string.IsNullOrWhiteSpace(_options.WebhookId))
            {
                // Startup refuses to run without it, so reaching this means the
                // options object was built by hand. Fail closed anyway.
                return WebhookVerification.Rejected("no webhook id is configured, so nothing can be verified");
            }

            var transmissionId = Header(headers, TransmissionIdHeader);
            var transmissionTime = Header(headers, TransmissionTimeHeader);
            var signature = Header(headers, TransmissionSignatureHeader);
            var certificateUrl = Header(headers, CertificateUrlHeader);
            var algorithm = Header(headers, AuthAlgorithmHeader);

            if (transmissionId == null || transmissionTime == null || signature == null
                || certificateUrl == null || algorithm == null)
            {
                return WebhookVerification.Rejected("a required PAYPAL-* header is missing");
            }

            if (!string.Equals(algorithm, RequiredAuthAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                return WebhookVerification.Rejected(
                    "paypal-auth-algo is '" + algorithm + "'; only " + RequiredAuthAlgorithm + " is accepted");
            }

            if (!TryParseCertificateUrl(certificateUrl, out var url, out var urlProblem))
            {
                // Checked before the fetch, not after: this is what stops the
                // header pointing the service at the attacker's own web server
                // to be handed the attacker's own certificate, which would make
                // every other check below pass.
                return WebhookVerification.Rejected(urlProblem);
            }

            byte[] signatureBytes;

            try
            {
                signatureBytes = Convert.FromBase64String(signature);
            }
            catch (FormatException)
            {
                return WebhookVerification.Rejected("paypal-transmission-sig is not base64");
            }

            var message = Encoding.UTF8.GetBytes(string.Join(
                "|",
                transmissionId,
                transmissionTime,
                _options.WebhookId,
                Crc32.Compute(body).ToString(CultureInfo.InvariantCulture)));

            X509Certificate2 certificate;

            try
            {
                certificate = await _certificates.GetAsync(url, cancellationToken).ConfigureAwait(false);
            }
            catch (PayPalCertificateException ex)
            {
                return WebhookVerification.Rejected("the signing certificate was not usable: " + ex.Message);
            }

            if (certificate == null)
            {
                return WebhookVerification.Rejected("no signing certificate could be obtained for " + url);
            }

            using (certificate)
            using (var rsa = certificate.GetRSAPublicKey())
            {
                if (rsa == null)
                {
                    return WebhookVerification.Rejected("the signing certificate carries no RSA public key");
                }

                if (!rsa.VerifyData(message, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                {
                    // The one that matters. Reached when the body was edited (the
                    // CRC in the message changes), when a header was edited, when
                    // the webhook id is not the one PayPal signed for, or when
                    // whoever sent this does not hold PayPal's private key.
                    return WebhookVerification.Rejected("the signature does not match this request");
                }
            }

            return WebhookVerification.Verified(transmissionId);
        }

        /// <summary>
        /// The certificate URL comes out of an attacker-controlled header, so it
        /// is treated as one: https only, and a host that is paypal.com or below
        /// it. Everything else about the certificate - that it chains to a
        /// trusted root, that it is in date - is the certificate source's job.
        /// </summary>
        public static bool TryParseCertificateUrl(string value, out Uri url, out string problem)
        {
            url = null;
            problem = null;

            if (!Uri.TryCreate(value, UriKind.Absolute, out var candidate))
            {
                problem = "paypal-cert-url is not an absolute URL";

                return false;
            }

            if (!string.Equals(candidate.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
            {
                problem = "paypal-cert-url is not https";

                return false;
            }

            var host = candidate.Host;

            if (!string.Equals(host, "paypal.com", StringComparison.OrdinalIgnoreCase)
                && !host.EndsWith(".paypal.com", StringComparison.OrdinalIgnoreCase))
            {
                problem = "paypal-cert-url points at " + host + ", which is not PayPal";

                return false;
            }

            url = candidate;

            return true;
        }

        private static string Header(IReadOnlyDictionary<string, string> headers, string name)
        {
            return headers.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;
        }
    }

    public sealed class WebhookVerification
    {
        private WebhookVerification(bool verified, string transmissionId, string reason)
        {
            IsVerified = verified;
            TransmissionId = transmissionId;
            Reason = reason;
        }

        public bool IsVerified { get; }

        public string TransmissionId { get; }

        /// <summary>
        /// Why it was refused. LOGGED, NEVER RETURNED: the caller gets 401 and
        /// nothing else, because a caller probing for the shape of the check
        /// should learn nothing from it, and a caller who is really PayPal is not
        /// reading the body.
        /// </summary>
        public string Reason { get; }

        public static WebhookVerification Verified(string transmissionId)
        {
            return new WebhookVerification(true, transmissionId, null);
        }

        public static WebhookVerification Rejected(string reason)
        {
            return new WebhookVerification(false, null, reason);
        }
    }
}

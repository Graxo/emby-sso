using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Emby.Sso.LicenceService.PayPal
{
    /// <summary>
    /// Where the verifier gets the certificate named by PAYPAL-CERT-URL.
    ///
    /// It is an interface for one reason and it is not "flexibility": the HTTP
    /// implementation cannot run in a build environment with no route to PayPal,
    /// and the crypto in PayPalWebhookVerifier must still be tested there. The
    /// test double lives in the test project and nowhere else. THERE IS EXACTLY
    /// ONE IMPLEMENTATION IN THE SHIPPED SERVICE and it always validates the
    /// chain - a "source" that returned an unvalidated certificate would defeat
    /// the whole verifier, since the signature would then only prove that
    /// whoever served the certificate also signed the message.
    /// </summary>
    public interface IPayPalCertificateSource
    {
        Task<X509Certificate2> GetAsync(Uri certificateUrl, CancellationToken cancellationToken);
    }

    public sealed class PayPalCertificateException : Exception
    {
        public PayPalCertificateException(string message)
            : base(message)
        {
        }

        public PayPalCertificateException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }

    /// <summary>
    /// Fetches the certificate over HTTPS, checks it is really PayPal's, and
    /// caches it.
    ///
    /// UNVERIFIED: nothing in this repository has ever fetched a real PayPal
    /// certificate, because there is no route to PayPal from where it was
    /// written. What IS tested is the direction that matters - that
    /// <see cref="PayPalCertificateValidator"/> refuses a certificate that does
    /// not chain to a trusted root and refuses one whose subject is not PayPal.
    /// That it ACCEPTS PayPal's own certificate is confirmed by the first
    /// sandbox webhook; see docs/paypal-sandbox-checklist.md.
    /// </summary>
    public sealed class HttpPayPalCertificateSource : IPayPalCertificateSource
    {
        /// <summary>
        /// A certificate is a few kilobytes of PEM. Anything larger is not one,
        /// and reading it would be doing an attacker's memory allocation for
        /// them - the URL host is restricted to paypal.com, but a compromised or
        /// misbehaving endpoint is still not a reason to read unbounded input.
        /// </summary>
        private const int MaximumCertificateBytes = 64 * 1024;

        private readonly ConcurrentDictionary<string, X509Certificate2> _cache =
            new ConcurrentDictionary<string, X509Certificate2>(StringComparer.Ordinal);

        private readonly HttpClient _http;

        public HttpPayPalCertificateSource(HttpClient http)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
        }

        public async Task<X509Certificate2> GetAsync(Uri certificateUrl, CancellationToken cancellationToken)
        {
            if (certificateUrl == null)
            {
                throw new ArgumentNullException(nameof(certificateUrl));
            }

            // The caller has already refused any host that is not PayPal's, but
            // this class is public and the check is cheap, so it does not depend
            // on having been called correctly.
            if (!PayPalWebhookVerifier.TryParseCertificateUrl(certificateUrl.ToString(), out _, out var problem))
            {
                throw new PayPalCertificateException(problem);
            }

            var key = certificateUrl.ToString();

            if (_cache.TryGetValue(key, out var cached) && DateTime.UtcNow < cached.NotAfter.ToUniversalTime())
            {
                return new X509Certificate2(cached.RawData);
            }

            string pem;

            try
            {
                using var response = await _http.GetAsync(certificateUrl, cancellationToken).ConfigureAwait(false);

                response.EnsureSuccessStatusCode();

                if (response.Content.Headers.ContentLength > MaximumCertificateBytes)
                {
                    throw new PayPalCertificateException(
                        "the certificate at " + certificateUrl + " is larger than a certificate could be");
                }

                pem = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new PayPalCertificateException("could not fetch " + certificateUrl + ": " + ex.Message, ex);
            }
            catch (TaskCanceledException ex)
            {
                throw new PayPalCertificateException("timed out fetching " + certificateUrl, ex);
            }

            if (pem.Length > MaximumCertificateBytes)
            {
                throw new PayPalCertificateException(
                    "the certificate at " + certificateUrl + " is larger than a certificate could be");
            }

            var chain = new X509Certificate2Collection();

            try
            {
                chain.ImportFromPem(pem);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is System.Security.Cryptography.CryptographicException)
            {
                throw new PayPalCertificateException("what " + certificateUrl + " served is not a PEM certificate", ex);
            }

            if (chain.Count == 0)
            {
                throw new PayPalCertificateException("what " + certificateUrl + " served contains no certificate");
            }

            var leaf = chain[0];

            PayPalCertificateValidator.Validate(leaf, chain);

            // Cached by URL. PayPal rotates the certificate and changes the URL
            // with it, so a cache entry is never stale for a URL that is still
            // being sent; the NotAfter check above is the belt to that braces.
            _cache[key] = new X509Certificate2(leaf.RawData);

            return new X509Certificate2(leaf.RawData);
        }
    }

    /// <summary>
    /// Is this certificate really PayPal's?
    ///
    /// Two questions, and both have to be yes:
    ///
    ///   1. Does it chain to a root this machine already trusts? Without this,
    ///      an attacker who could aim PAYPAL-CERT-URL at their own host - or
    ///      intercept the fetch - would supply their own certificate, sign the
    ///      message with the matching key, and pass every other check.
    ///   2. Is the subject PayPal's? A valid certificate for
    ///      attacker.example.com chains perfectly well to a trusted root.
    ///
    /// PayPalCertificateValidatorTests proves this refuses a self-signed
    /// certificate and refuses a correctly-chained certificate for the wrong
    /// name. It cannot prove it accepts PayPal's, which is UNVERIFIED until the
    /// sandbox run.
    /// </summary>
    public static class PayPalCertificateValidator
    {
        public static void Validate(X509Certificate2 leaf, X509Certificate2Collection chainCertificates)
        {
            if (leaf == null)
            {
                throw new ArgumentNullException(nameof(leaf));
            }

            var subject = leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: false) ?? string.Empty;

            if (!string.Equals(subject, "paypal.com", StringComparison.OrdinalIgnoreCase)
                && !subject.EndsWith(".paypal.com", StringComparison.OrdinalIgnoreCase))
            {
                throw new PayPalCertificateException(
                    "the certificate is issued to '" + subject + "', which is not a paypal.com name");
            }

            using var chain = new X509Chain();

            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;

            // Revocation is checked, and a revoked certificate is refused (that
            // is the default flag set, minus the two tolerated below). What is
            // tolerated is not being able to REACH the CRL or OCSP responder: an
            // outbound network hiccup must not turn every incoming payment into a
            // silent failure, and an attacker cannot cause "unknown" without
            // already controlling the fetch.
            chain.ChainPolicy.VerificationFlags =
                X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                | X509VerificationFlags.IgnoreEndRevocationUnknown;

            if (chainCertificates != null)
            {
                chain.ChainPolicy.ExtraStore.AddRange(chainCertificates);
            }

            if (chain.Build(leaf))
            {
                return;
            }

            var reasons = new System.Text.StringBuilder();

            foreach (var status in chain.ChainStatus)
            {
                if (reasons.Length > 0)
                {
                    reasons.Append("; ");
                }

                reasons.Append(status.StatusInformation?.Trim());
            }

            throw new PayPalCertificateException(
                "the certificate does not chain to a trusted root: "
                + (reasons.Length > 0 ? reasons.ToString() : "no reason given"));
        }
    }
}

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.PayPal;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// A stand-in for PayPal's signing certificate: a keypair the test owns, so
    /// the test can produce a genuinely valid signature over a message it built
    /// and then prove the verifier accepts that one and refuses every variation.
    ///
    /// WHAT THIS DOES NOT COVER, and the README says the same: this certificate
    /// chains to nothing, so a test using it is testing the SIGNATURE half of the
    /// check and not the TRUST half. The trust half is
    /// PayPalCertificateValidator, which has its own tests proving it refuses a
    /// certificate exactly like this one. Neither can prove the two halves
    /// together accept a real PayPal transmission; only the sandbox run can.
    /// </summary>
    internal sealed class PayPalTestCertificate : IDisposable
    {
        private readonly RSA _key;
        private readonly X509Certificate2 _certificate;

        public PayPalTestCertificate(string subject = "CN=messageverificationcerts.paypal.com")
        {
            _key = RSA.Create(2048);

            var request = new CertificateRequest(subject, _key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            _certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(365));
        }

        /// <summary>A public-only copy, which is all a verifier ever gets.</summary>
        public X509Certificate2 PublicCertificate => new X509Certificate2(_certificate.Export(X509ContentType.Cert));

        /// <summary>
        /// PayPal's documented message: the four fields joined by pipes, with the
        /// CRC-32 of the raw body as an unsigned decimal.
        /// </summary>
        public static string Message(string transmissionId, string transmissionTime, string webhookId, byte[] body)
        {
            return string.Join(
                "|",
                transmissionId,
                transmissionTime,
                webhookId,
                Crc32.Compute(body).ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        public string Sign(string message)
        {
            return Convert.ToBase64String(
                _key.SignData(Encoding.UTF8.GetBytes(message), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        public void Dispose()
        {
            _certificate.Dispose();
            _key.Dispose();
        }
    }

    /// <summary>
    /// Hands the verifier a certificate without going near the network. TEST
    /// ONLY - the shipped service has exactly one IPayPalCertificateSource and
    /// it always validates the chain.
    /// </summary>
    internal sealed class FakeCertificateSource : IPayPalCertificateSource
    {
        private readonly PayPalTestCertificate _certificate;

        public FakeCertificateSource(PayPalTestCertificate certificate)
        {
            _certificate = certificate;
        }

        public int Calls { get; private set; }

        public Task<X509Certificate2> GetAsync(Uri certificateUrl, CancellationToken cancellationToken)
        {
            Calls++;

            return Task.FromResult(_certificate.PublicCertificate);
        }
    }

    /// <summary>A source that refuses, the way the real one does for a certificate it will not trust.</summary>
    internal sealed class RefusingCertificateSource : IPayPalCertificateSource
    {
        public int Calls { get; private set; }

        public Task<X509Certificate2> GetAsync(Uri certificateUrl, CancellationToken cancellationToken)
        {
            Calls++;

            throw new PayPalCertificateException("this certificate does not chain to a trusted root");
        }
    }
}

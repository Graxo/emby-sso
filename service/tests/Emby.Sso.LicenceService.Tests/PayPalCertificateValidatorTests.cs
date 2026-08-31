using System;
using System.Security.Cryptography.X509Certificates;
using Emby.Sso.LicenceService.PayPal;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The trust half of the webhook check, which PayPalWebhookVerifierTests
    /// deliberately steps around by injecting a certificate.
    ///
    /// It can only be tested in one direction here: that this REFUSES a
    /// certificate an attacker could produce. Proving it ACCEPTS PayPal's real
    /// certificate needs PayPal's real certificate, which needs a network route
    /// this repository does not have - so that half is UNVERIFIED and is item 4
    /// of docs/paypal-sandbox-checklist.md.
    ///
    /// Refusing is the direction that matters. If this were a no-op, the
    /// signature check would prove only that whoever served the certificate also
    /// signed the message - which any attacker who could aim PAYPAL-CERT-URL
    /// somewhere of their choosing could arrange.
    /// </summary>
    public class PayPalCertificateValidatorTests
    {
        [Fact]
        public void A_self_signed_certificate_in_PayPals_name_is_refused()
        {
            // Exactly the certificate a forger makes: right name, no chain.
            using var forged = new PayPalTestCertificate("CN=messageverificationcerts.paypal.com");
            using var certificate = forged.PublicCertificate;

            var ex = Assert.Throws<PayPalCertificateException>(
                () => PayPalCertificateValidator.Validate(certificate, new X509Certificate2Collection { certificate }));

            Assert.Contains("does not chain to a trusted root", ex.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("CN=evil.example.com")]
        [InlineData("CN=paypal.com.evil.example.com")]
        [InlineData("CN=notpaypal.com")]
        public void A_certificate_for_a_name_that_is_not_PayPals_is_refused_on_the_name(string subject)
        {
            using var forged = new PayPalTestCertificate(subject);
            using var certificate = forged.PublicCertificate;

            var ex = Assert.Throws<PayPalCertificateException>(
                () => PayPalCertificateValidator.Validate(certificate, new X509Certificate2Collection { certificate }));

            // Refused on the name, before the chain is even built: a real,
            // trusted, valid certificate for the attacker's own domain would
            // otherwise sail through the chain check.
            Assert.Contains("is not a paypal.com name", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void There_is_no_argument_that_makes_this_return_without_checking()
        {
            using var forged = new PayPalTestCertificate();
            using var certificate = forged.PublicCertificate;

            Assert.Throws<PayPalCertificateException>(() => PayPalCertificateValidator.Validate(certificate, null));
            Assert.Throws<ArgumentNullException>(() => PayPalCertificateValidator.Validate(null, null));
        }
    }
}

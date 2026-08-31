using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.PayPal;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// THE TESTS THE BRIEF ASKED FOR BY NAME.
    ///
    /// "A signature check with no test proving it fails when removed is not a
    /// signature check." So: one test where a genuine signature is accepted, and
    /// then one for every way a forger might try - an edited body, an edited
    /// header, somebody else's webhook, a missing header, a weakened algorithm,
    /// a certificate from a host that is not PayPal. Delete the VerifyData call
    /// in PayPalWebhookVerifier and most of this file fails.
    ///
    /// The signature is produced here with a key the test owns, over the message
    /// PayPal documents. That proves the layout is verified as written; it cannot
    /// prove PayPal produces that same layout, which is why the live path is
    /// marked UNVERIFIED and why docs/paypal-sandbox-checklist.md exists.
    /// </summary>
    public class PayPalWebhookVerifierTests
    {
        private const string WebhookId = "WH-8LT19255TP123456-8AH33562K7891234";
        private const string TransmissionId = "e1f7b2c0-9b5e-11ee-8c90-0242ac120002";
        private const string TransmissionTime = "2026-01-05T12:00:00Z";
        private const string CertificateUrl =
            "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-360caa42-fca2a594-1d93a270";

        private static readonly byte[] Body = Encoding.UTF8.GetBytes(
            "{\"id\":\"WH-EVENT-1\",\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\","
            + "\"resource\":{\"id\":\"CAPTURE-1\",\"amount\":{\"value\":\"19.00\",\"currency_code\":\"GBP\"}}}");

        [Fact]
        public async Task A_genuinely_signed_transmission_is_accepted()
        {
            using var certificate = new PayPalTestCertificate();

            var result = await Verify(certificate, Headers(certificate), Body);

            Assert.True(result.IsVerified, result.Reason);
            Assert.Equal(TransmissionId, result.TransmissionId);
        }

        [Fact]
        public async Task A_TAMPERED_BODY_IS_REFUSED()
        {
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate);

            // One byte. The signature covers a CRC-32 of the body, so changing
            // any of it changes the message that was signed.
            var tampered = (byte[])Body.Clone();

            tampered[30] = tampered[30] == (byte)'x' ? (byte)'y' : (byte)'x';

            var result = await Verify(certificate, headers, tampered);

            Assert.False(result.IsVerified);
            Assert.Contains("signature does not match", result.Reason, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_body_that_says_a_much_larger_payment_is_refused()
        {
            // The attack this is really about: take a real webhook off the wire,
            // change the amount or the event type, replay it.
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate);

            var forged = Encoding.UTF8.GetBytes(
                "{\"id\":\"WH-EVENT-1\",\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\","
                + "\"resource\":{\"id\":\"CAPTURE-1\",\"amount\":{\"value\":\"9999.00\",\"currency_code\":\"GBP\"}}}");

            var result = await Verify(certificate, headers, forged);

            Assert.False(result.IsVerified);
        }

        [Fact]
        public async Task A_body_with_the_same_length_but_different_content_is_refused()
        {
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate);
            var swapped = (byte[])Body.Clone();

            (swapped[20], swapped[21]) = (swapped[21], swapped[20]);

            Assert.Equal(Body.Length, swapped.Length);
            Assert.False((await Verify(certificate, headers, swapped)).IsVerified);
        }

        [Fact]
        public async Task An_edited_transmission_id_is_refused()
        {
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate);

            headers[PayPalWebhookVerifier.TransmissionIdHeader] = "00000000-0000-0000-0000-000000000000";

            Assert.False((await Verify(certificate, headers, Body)).IsVerified);
        }

        [Fact]
        public async Task An_edited_transmission_time_is_refused()
        {
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate);

            headers[PayPalWebhookVerifier.TransmissionTimeHeader] = "2020-01-01T00:00:00Z";

            Assert.False((await Verify(certificate, headers, Body)).IsVerified);
        }

        [Fact]
        public async Task A_signature_for_somebody_elses_webhook_is_refused()
        {
            // The webhook id is inside the signed message. A transmission PayPal
            // really did sign, for a different merchant's webhook, does not
            // verify here - which is what stops a signature being lifted from
            // another PayPal integration and replayed at this one.
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate, webhookIdUsedForSigning: "WH-SOMEBODY-ELSE");

            Assert.False((await Verify(certificate, headers, Body)).IsVerified);
        }

        [Fact]
        public async Task A_signature_from_a_key_that_is_not_the_certificates_is_refused()
        {
            using var paypal = new PayPalTestCertificate();
            using var forger = new PayPalTestCertificate();

            var headers = Headers(forger);

            // Signed by the forger, verified against PayPal's certificate.
            var result = await Verify(paypal, headers, Body);

            Assert.False(result.IsVerified);
        }

        [Theory]
        [InlineData(PayPalWebhookVerifier.TransmissionIdHeader)]
        [InlineData(PayPalWebhookVerifier.TransmissionTimeHeader)]
        [InlineData(PayPalWebhookVerifier.TransmissionSignatureHeader)]
        [InlineData(PayPalWebhookVerifier.CertificateUrlHeader)]
        [InlineData(PayPalWebhookVerifier.AuthAlgorithmHeader)]
        public async Task Every_required_header_is_required(string header)
        {
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate);

            headers.Remove(header);

            var result = await Verify(certificate, headers, Body);

            Assert.False(result.IsVerified);
            Assert.Contains("required PAYPAL-* header is missing", result.Reason, StringComparison.Ordinal);
        }

        [Fact]
        public async Task No_headers_at_all_is_refused()
        {
            using var certificate = new PayPalTestCertificate();

            var result = await Verify(
                certificate,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                Body);

            Assert.False(result.IsVerified);
        }

        [Theory]
        [InlineData("SHA1withRSA")]
        [InlineData("none")]
        [InlineData("HS256")]
        [InlineData("")]
        public async Task The_algorithm_is_pinned_and_not_taken_from_the_header(string algorithm)
        {
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate);

            headers[PayPalWebhookVerifier.AuthAlgorithmHeader] = algorithm;

            Assert.False((await Verify(certificate, headers, Body)).IsVerified);
        }

        [Theory]
        [InlineData("https://evil.example.com/cert.pem")]
        [InlineData("https://paypal.com.evil.example.com/cert.pem")]
        [InlineData("http://api.paypal.com/cert.pem")]
        [InlineData("file:///etc/passwd")]
        [InlineData("not a url")]
        [InlineData("https://notpaypal.com/cert.pem")]
        public async Task A_certificate_url_that_is_not_PayPals_is_refused_before_it_is_fetched(string url)
        {
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate);

            headers[PayPalWebhookVerifier.CertificateUrlHeader] = url;

            var source = new FakeCertificateSource(certificate);
            var verifier = new PayPalWebhookVerifier(source, PayPal(WebhookId));

            var result = await verifier.VerifyAsync(headers, Body, CancellationToken.None);

            Assert.False(result.IsVerified);

            // Not fetched at all. The point of the host check is that the service
            // never makes a request to an address an attacker chose.
            Assert.Equal(0, source.Calls);
        }

        [Theory]
        [InlineData("https://api.paypal.com/v1/notifications/certs/CERT-1")]
        [InlineData("https://api.sandbox.paypal.com/v1/notifications/certs/CERT-1")]
        [InlineData("https://paypal.com/certs/CERT-1")]
        public void PayPals_own_certificate_hosts_are_allowed(string url)
        {
            Assert.True(PayPalWebhookVerifier.TryParseCertificateUrl(url, out var parsed, out var problem), problem);
            Assert.NotNull(parsed);
        }

        [Fact]
        public async Task A_signature_that_is_not_base64_is_refused_rather_than_thrown()
        {
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate);

            headers[PayPalWebhookVerifier.TransmissionSignatureHeader] = "!!! not base64 !!!";

            var result = await Verify(certificate, headers, Body);

            Assert.False(result.IsVerified);
            Assert.Contains("not base64", result.Reason, StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_empty_body_with_a_signature_for_a_real_one_is_refused()
        {
            using var certificate = new PayPalTestCertificate();

            var headers = Headers(certificate);

            Assert.False((await Verify(certificate, headers, Array.Empty<byte>())).IsVerified);
        }

        [Fact]
        public async Task With_no_webhook_id_configured_nothing_verifies()
        {
            using var certificate = new PayPalTestCertificate();

            var verifier = new PayPalWebhookVerifier(new FakeCertificateSource(certificate), PayPal(null));

            var result = await verifier.VerifyAsync(Headers(certificate), Body, CancellationToken.None);

            Assert.False(result.IsVerified);
        }

        [Fact]
        public async Task A_certificate_the_source_will_not_trust_is_a_refusal_and_not_a_crash()
        {
            using var certificate = new PayPalTestCertificate();

            var source = new RefusingCertificateSource();
            var verifier = new PayPalWebhookVerifier(source, PayPal(WebhookId));

            var result = await verifier.VerifyAsync(Headers(certificate), Body, CancellationToken.None);

            Assert.False(result.IsVerified);
            Assert.Contains("not usable", result.Reason, StringComparison.Ordinal);
            Assert.Equal(1, source.Calls);
        }

        private static async Task<WebhookVerification> Verify(
            PayPalTestCertificate certificate,
            IDictionary<string, string> headers,
            byte[] body)
        {
            var verifier = new PayPalWebhookVerifier(new FakeCertificateSource(certificate), PayPal(WebhookId));

            return await verifier
                .VerifyAsync((IReadOnlyDictionary<string, string>)headers, body, CancellationToken.None);
        }

        private static PayPalOptions PayPal(string webhookId)
        {
            var options = new PayPalOptions
            {
                Environment = PayPalOptions.Sandbox,
                WebhookId = webhookId,
            };

            return options;
        }

        private static Dictionary<string, string> Headers(
            PayPalTestCertificate certificate,
            string webhookIdUsedForSigning = WebhookId)
        {
            var message = PayPalTestCertificate.Message(TransmissionId, TransmissionTime, webhookIdUsedForSigning, Body);

            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [PayPalWebhookVerifier.TransmissionIdHeader] = TransmissionId,
                [PayPalWebhookVerifier.TransmissionTimeHeader] = TransmissionTime,
                [PayPalWebhookVerifier.TransmissionSignatureHeader] = certificate.Sign(message),
                [PayPalWebhookVerifier.CertificateUrlHeader] = CertificateUrl,
                [PayPalWebhookVerifier.AuthAlgorithmHeader] = PayPalWebhookVerifier.RequiredAuthAlgorithm,

                // A header PayPal does not send, present to prove nothing keys on
                // the header collection being exactly right.
                ["content-type"] = "application/json",
            };
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.PayPal;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// That the host really wires all of this together, through the same
    /// Program.BuildApp that Main runs.
    ///
    /// Worth its own file because the wiring has a sharp edge in it: the webhook
    /// handler takes the mail queue as an OPTIONAL dependency, so a registration
    /// mistake would not fail at startup - it would compile, start, sell, and
    /// email nobody. These drive a real webhook through the container and watch
    /// for the message coming out the other side.
    /// </summary>
    public class MailWiringTests
    {
        private const string WebhookId = "WH-TEST-0001";
        private const string CertificateUrl =
            "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-360caa42-fca2a594-1d93a270";

        [Fact]
        public async Task With_no_smtp_host_nothing_mail_shaped_is_in_the_container_at_all()
        {
            using var service = new TestService();
            using var certificate = new PayPalTestCertificate();

            var app = Build(service, certificate, null);

            try
            {
                await app.StartAsync();

                Assert.Null(app.Services.GetService<CodeDeliveryQueue>());
                Assert.Null(app.Services.GetService<CodeMailer>());
                Assert.Null(app.Services.GetService<ISmtpTransport>());
            }
            finally
            {
                await app.StopAsync();
                await app.DisposeAsync();
            }
        }

        [Fact]
        public async Task With_smtp_configured_a_webhook_ends_in_a_message()
        {
            using var service = new TestService(Configured);
            using var certificate = new PayPalTestCertificate();

            var transport = new FakeSmtpTransport();
            var app = Build(service, certificate, transport);

            try
            {
                await app.StartAsync();

                Assert.NotNull(app.Services.GetService<CodeDeliveryQueue>());

                var handler = app.Services.GetRequiredService<PayPalWebhookHandler>();
                var body = Capture();
                var outcome = await handler.HandleAsync(Sign(certificate, body), body, CancellationToken.None);

                Assert.Equal(WebhookStatus.CodeCreated, outcome.Status);

                var clock = Stopwatch.StartNew();

                while (transport.Sent.Count == 0 && clock.Elapsed < TimeSpan.FromSeconds(10))
                {
                    await Task.Delay(10);
                }

                // The optional dependency really was supplied. If it had not
                // been, everything above would have passed and this would be the
                // only line that noticed.
                Assert.Single(transport.Sent);
                Assert.Equal("buyer@example.com", transport.Sent[0].ToAddress);
            }
            finally
            {
                await app.StopAsync();
                await app.DisposeAsync();
            }
        }

        [Fact]
        public void A_template_that_would_email_no_code_stops_the_service_starting()
        {
            using var service = new TestService(options =>
            {
                Configured(options);

                options.Mail.TemplatePath = Path.Combine(options.DataDirectory, "template.txt");

                File.WriteAllText(options.Mail.TemplatePath, "Thanks for your purchase!");
            });

            using var certificate = new PayPalTestCertificate();

            Assert.Throws<MailTemplateException>(() => Build(service, certificate, new FakeSmtpTransport()));
        }

        private static void Configured(ServiceOptions options)
        {
            options.PayPal.ClientId = null;
            options.PayPal.ClientSecret = null;

            options.Mail.Host = "smtp.example.com";
            options.Mail.Port = 587;
            options.Mail.Security = MailOptions.StartTls;
            options.Mail.FromAddress = "licences@example.com";
            options.Mail.SupportContact = "licences@example.com";
            options.Mail.MaxAttempts = 1;
        }

        private static WebApplication Build(TestService service, PayPalTestCertificate certificate, ISmtpTransport transport)
        {
            return Program.BuildApp(service.Options, builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Services.AddSingleton<IPayPalCertificateSource>(new FakeCertificateSource(certificate));

                if (transport != null)
                {
                    // Replaces MailKitSmtpTransport, so no test in this suite can
                    // open a socket to anything resembling a mail server.
                    builder.Services.AddSingleton(transport);
                }
            });
        }

        private static byte[] Capture()
        {
            return Encoding.UTF8.GetBytes(
                "{\"id\":\"WH-1\",\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\",\"resource\":{"
                + "\"id\":\"CAPTURE-1\",\"amount\":{\"value\":\"19.00\",\"currency_code\":\"GBP\"},"
                + "\"payer\":{\"email_address\":\"buyer@example.com\"}}}");
        }

        private static Dictionary<string, string> Sign(PayPalTestCertificate certificate, byte[] body)
        {
            const string TransmissionTime = "2026-01-05T12:00:00Z";
            const string TransmissionId = "TX-1";

            var message = PayPalTestCertificate.Message(TransmissionId, TransmissionTime, WebhookId, body);

            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [PayPalWebhookVerifier.TransmissionIdHeader] = TransmissionId,
                [PayPalWebhookVerifier.TransmissionTimeHeader] = TransmissionTime,
                [PayPalWebhookVerifier.TransmissionSignatureHeader] = certificate.Sign(message),
                [PayPalWebhookVerifier.CertificateUrlHeader] = CertificateUrl,
                [PayPalWebhookVerifier.AuthAlgorithmHeader] = PayPalWebhookVerifier.RequiredAuthAlgorithm,
            };
        }
    }
}

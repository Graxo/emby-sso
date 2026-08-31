using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.PayPal;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// Delivery seen from the webhook, which is the only place it happens.
    ///
    /// Three promises are kept here, and they are the three that would cost real
    /// money to break:
    ///
    ///   1. With no SMTP configured the webhook does exactly what it did before
    ///      mail existed. That is the operator's working arrangement today and it
    ///      must not stop because a feature was added around it.
    ///   2. A mail failure never fails the webhook. PayPal gets its 2xx, because
    ///      the payment WAS processed correctly and a retry of it would be a
    ///      second decision about a sale already made.
    ///   3. The code survives the failure, in the outbox, where it already was.
    /// </summary>
    public class CodeDeliveryTests : IDisposable
    {
        private const string WebhookId = "WH-TEST-0001";
        private const string CertificateUrl =
            "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-360caa42-fca2a594-1d93a270";

        private readonly TestService _service = new TestService();
        private readonly PayPalTestCertificate _certificate = new PayPalTestCertificate();

        public void Dispose()
        {
            _certificate.Dispose();
            _service.Dispose();
        }

        [Fact]
        public async Task With_no_smtp_configured_the_webhook_writes_the_outbox_and_nothing_else()
        {
            // The unconfigured service, byte for byte: one line, undelivered, no
            // receipt, no second file, nothing.
            var outcome = await Handle(mail: null);

            Assert.Equal(WebhookStatus.CodeCreated, outcome.Status);

            var line = Assert.Single(File.ReadAllLines(_service.Options.OutboxPath));

            using var document = JsonDocument.Parse(line);

            Assert.False(document.RootElement.GetProperty("delivered").GetBoolean());
            Assert.False(document.RootElement.TryGetProperty("record", out _));
            Assert.False(_service.Options.Mail.Configured);
        }

        [Fact]
        public async Task A_configured_service_emails_the_code_and_still_answers_paypal()
        {
            var transport = new FakeSmtpTransport();

            using var queue = Queue(transport, out _);

            await queue.StartAsync(CancellationToken.None);

            var outcome = await Handle(queue);

            Assert.Equal(WebhookStatus.CodeCreated, outcome.Status);

            await WaitUntil(() => transport.Sent.Count == 1);
            await queue.StopAsync(CancellationToken.None);

            // The code in the buyer's email is the code in the outbox is the code
            // that activates. Anything less than all three is a support ticket.
            var code = OutboxCode();

            Assert.Contains(code, transport.Sent[0].Body, StringComparison.Ordinal);
            Assert.Equal("buyer@example.com", transport.Sent[0].ToAddress);

            var reply = _service.Activations.Activate(
                new Activation.ActivationRequest { Code = code, ServerId = "c5bc6e91458540caa295c4efdda1a58a" },
                "10.0.0.1");

            Assert.True(reply.IsSuccess);
        }

        [Fact]
        public async Task A_mail_failure_still_returns_success_to_paypal()
        {
            // If this returned anything but success, PayPal would retry a payment
            // that was already processed - and the whole replay apparatus exists
            // precisely so that never has to happen.
            var transport = new FakeSmtpTransport().AlwaysFail("connection refused", permanent: false);

            using var queue = Queue(transport, out var log, attempts: 2);

            await queue.StartAsync(CancellationToken.None);

            var outcome = await Handle(queue);

            Assert.Equal(WebhookStatus.CodeCreated, outcome.Status);

            await WaitUntil(() => transport.Attempts >= 2);
            await queue.StopAsync(CancellationToken.None);

            Assert.Contains("EMAIL FAILED", log.Everything, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_mail_failure_leaves_the_code_in_the_outbox_and_it_still_activates()
        {
            var transport = new FakeSmtpTransport().AlwaysFail("550 no such mailbox", permanent: true);

            using var queue = Queue(transport, out _, attempts: 2);

            await queue.StartAsync(CancellationToken.None);
            await Handle(queue);
            await WaitUntil(() => transport.Attempts >= 1);
            await queue.StopAsync(CancellationToken.None);

            var lines = File.ReadAllLines(_service.Options.OutboxPath);

            // One line, no delivery receipt: exactly the file the operator works
            // from today.
            Assert.Single(lines);

            var reply = _service.Activations.Activate(
                new Activation.ActivationRequest { Code = OutboxCode(), ServerId = "c5bc6e91458540caa295c4efdda1a58a" },
                "10.0.0.1");

            Assert.True(reply.IsSuccess);
        }

        [Fact]
        public async Task The_webhook_does_not_wait_for_the_mail_server()
        {
            // A relay that hangs must not hold the webhook open. PayPal times out
            // and retries; this is the property that makes that impossible.
            using var held = new SemaphoreSlim(0, 1);

            var transport = new BlockingTransport(held);

            using var queue = Queue(transport, out _);

            await queue.StartAsync(CancellationToken.None);

            var clock = Stopwatch.StartNew();
            var outcome = await Handle(queue);

            clock.Stop();

            Assert.Equal(WebhookStatus.CodeCreated, outcome.Status);
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), "the webhook waited " + clock.Elapsed);

            held.Release();

            await queue.StopAsync(CancellationToken.None);
        }

        [Fact]
        public async Task A_full_queue_is_logged_and_the_sale_still_completes()
        {
            // The queue is bounded, so it can refuse. When it does, the code is
            // in the outbox and the operator is told - which is the same place
            // and the same amount of work as having no mail configured at all.
            var log = new RecordingLogger<PayPalWebhookHandler>();
            var queue = Queue(new FakeSmtpTransport(), out _);

            for (var i = 0; i < CodeDeliveryQueue.Capacity; i++)
            {
                Assert.True(queue.Enqueue(CodeMessageTests.Entry(out _)));
            }

            Assert.False(queue.Enqueue(CodeMessageTests.Entry(out _)));

            var outcome = await Handle(queue, log);

            Assert.Equal(WebhookStatus.CodeCreated, outcome.Status);
            Assert.Single(File.ReadAllLines(_service.Options.OutboxPath));
            Assert.Contains("queue is full", log.Everything, StringComparison.OrdinalIgnoreCase);

            queue.Dispose();
        }

        [Fact]
        public async Task The_webhooks_own_log_never_contains_the_code()
        {
            var log = new RecordingLogger<PayPalWebhookHandler>();

            using var queue = Queue(new FakeSmtpTransport(), out _);

            await queue.StartAsync(CancellationToken.None);
            await Handle(queue, log);
            await queue.StopAsync(CancellationToken.None);

            var code = OutboxCode();

            Assert.NotEmpty(log.Everything);
            Assert.DoesNotContain(code, log.Everything, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(code.Replace("-", string.Empty), log.Everything, StringComparison.OrdinalIgnoreCase);
        }

        private CodeDeliveryQueue Queue(ISmtpTransport transport, out RecordingLogger<CodeMailer> log, int attempts = 4)
        {
            var mail = CodeMessageTests.Mail();

            mail.MaxAttempts = attempts;

            log = new RecordingLogger<CodeMailer>();

            var mailer = new CodeMailer(
                mail,
                transport,
                _service.Outbox,
                CodeMessage.DefaultTemplate,
                log,
                (wait, token) => Task.CompletedTask);

            return new CodeDeliveryQueue(mailer, new RecordingLogger<CodeDeliveryQueue>());
        }

        private static async Task WaitUntil(Func<bool> condition)
        {
            var clock = Stopwatch.StartNew();

            while (!condition() && clock.Elapsed < TimeSpan.FromSeconds(10))
            {
                await Task.Delay(10).ConfigureAwait(false);
            }

            Assert.True(condition(), "the background sender did not get there within ten seconds");
        }

        private string OutboxCode()
        {
            using var document = JsonDocument.Parse(File.ReadAllLines(_service.Options.OutboxPath)[0]);

            return document.RootElement.GetProperty("code").GetString();
        }

        private Task<WebhookOutcome> Handle(
            CodeDeliveryQueue mail,
            ILogger<PayPalWebhookHandler> log = null)
        {
            var body = Capture("WH-1", "CAPTURE-1", "19.00", "GBP");
            var handler = _service.Webhooks(new FakeCertificateSource(_certificate), mail, log);

            return handler.HandleAsync(Sign("TX-1", body), body, CancellationToken.None);
        }

        private static byte[] Capture(string eventId, string captureId, string amount, string currency)
        {
            return Encoding.UTF8.GetBytes(
                "{\"id\":\"" + eventId + "\",\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\",\"resource\":{"
                + "\"id\":\"" + captureId + "\",\"amount\":{\"value\":\"" + amount
                + "\",\"currency_code\":\"" + currency + "\"},"
                + "\"payer\":{\"email_address\":\"buyer@example.com\"}}}");
        }

        private Dictionary<string, string> Sign(string transmissionId, byte[] body)
        {
            const string TransmissionTime = "2026-01-05T12:00:00Z";

            var message = PayPalTestCertificate.Message(transmissionId, TransmissionTime, WebhookId, body);

            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [PayPalWebhookVerifier.TransmissionIdHeader] = transmissionId,
                [PayPalWebhookVerifier.TransmissionTimeHeader] = TransmissionTime,
                [PayPalWebhookVerifier.TransmissionSignatureHeader] = _certificate.Sign(message),
                [PayPalWebhookVerifier.CertificateUrlHeader] = CertificateUrl,
                [PayPalWebhookVerifier.AuthAlgorithmHeader] = PayPalWebhookVerifier.RequiredAuthAlgorithm,
            };
        }

        /// <summary>A relay that has accepted the connection and then stopped answering.</summary>
        private sealed class BlockingTransport : ISmtpTransport
        {
            private readonly SemaphoreSlim _held;

            public BlockingTransport(SemaphoreSlim held)
            {
                _held = held;
            }

            public Task SendAsync(OutgoingMessage message, CancellationToken cancellationToken)
            {
                return _held.WaitAsync(cancellationToken);
            }
        }
    }
}

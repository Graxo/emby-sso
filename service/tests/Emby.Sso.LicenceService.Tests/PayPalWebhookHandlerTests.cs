using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.PayPal;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// What the webhook does once the signature has been believed - and, first
    /// of all, that nothing happens when it has not been.
    /// </summary>
    public class PayPalWebhookHandlerTests : IDisposable
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
        public async Task An_unsigned_request_creates_nothing_at_all()
        {
            var handler = _service.Webhooks(new FakeCertificateSource(_certificate));
            var body = Capture("WH-1", "CAPTURE-1", "19.00", "GBP");

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["content-type"] = "application/json",
            };

            var outcome = await handler.HandleAsync(headers, body, CancellationToken.None);

            Assert.Equal(WebhookStatus.Refused, outcome.Status);
            Assert.False(File.Exists(_service.Options.OutboxPath));
        }

        [Fact]
        public async Task A_tampered_request_creates_nothing_at_all()
        {
            var handler = _service.Webhooks(new FakeCertificateSource(_certificate));
            var body = Capture("WH-1", "CAPTURE-1", "19.00", "GBP");
            var headers = Sign("TX-1", body);

            var tampered = Capture("WH-1", "CAPTURE-1", "19.00", "GBP", extra: " ");

            var outcome = await handler.HandleAsync(headers, tampered, CancellationToken.None);

            Assert.Equal(WebhookStatus.Refused, outcome.Status);
            Assert.False(File.Exists(_service.Options.OutboxPath));
        }

        [Fact]
        public async Task A_completed_capture_creates_one_code_and_writes_it_where_a_human_can_send_it()
        {
            var outcome = await Deliver("WH-1", "CAPTURE-1", "19.00", "GBP");

            Assert.Equal(WebhookStatus.CodeCreated, outcome.Status);

            var line = Assert.Single(File.ReadAllLines(_service.Options.OutboxPath));

            using var document = JsonDocument.Parse(line);

            var root = document.RootElement;

            Assert.False(root.GetProperty("delivered").GetBoolean());
            Assert.Equal("CAPTURE-1", root.GetProperty("paypal_capture_id").GetString());
            Assert.Equal("buyer@example.com", root.GetProperty("buyer_email").GetString());

            // And the code in the outbox is the code that activates.
            var code = root.GetProperty("code").GetString();

            var reply = _service.ActivateAndSign(
                new ActivationRequest { Code = code, ServerId = "c5bc6e91458540caa295c4efdda1a58a" },
                "10.0.0.1");

            Assert.True(reply.IsSuccess);
        }

        [Fact]
        public async Task The_outbox_is_owner_readable_only()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            await Deliver("WH-1", "CAPTURE-1", "19.00", "GBP");

            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(_service.Options.OutboxPath));
        }

        [Fact]
        public async Task The_same_event_delivered_twice_creates_one_code()
        {
            var first = await Deliver("WH-1", "CAPTURE-1", "19.00", "GBP");
            var second = await Deliver("WH-1", "CAPTURE-1", "19.00", "GBP", transmissionId: "TX-2");

            Assert.Equal(WebhookStatus.CodeCreated, first.Status);
            Assert.Equal(WebhookStatus.Replay, second.Status);
            Assert.Single(File.ReadAllLines(_service.Options.OutboxPath));
        }

        [Fact]
        public async Task Two_different_events_for_the_same_payment_create_one_code()
        {
            // PayPal has been known to send more than one event id for a single
            // capture. The event id alone would let that through; the UNIQUE
            // index on the capture id is what stops it.
            var first = await Deliver("WH-1", "CAPTURE-1", "19.00", "GBP");
            var second = await Deliver("WH-2", "CAPTURE-1", "19.00", "GBP");

            Assert.Equal(WebhookStatus.CodeCreated, first.Status);
            Assert.Equal(WebhookStatus.Replay, second.Status);
            Assert.Single(File.ReadAllLines(_service.Options.OutboxPath));
        }

        [Fact]
        public async Task Two_genuinely_different_payments_create_two_codes()
        {
            await Deliver("WH-1", "CAPTURE-1", "19.00", "GBP");
            await Deliver("WH-2", "CAPTURE-2", "19.00", "GBP");

            Assert.Equal(2, File.ReadAllLines(_service.Options.OutboxPath).Length);
        }

        [Theory]
        [InlineData("0.01")]
        [InlineData("1.00")]
        [InlineData("18.99")]
        public async Task A_capture_below_the_price_buys_nothing(string amount)
        {
            var outcome = await Deliver("WH-1", "CAPTURE-1", amount, "GBP");

            Assert.Equal(WebhookStatus.Ignored, outcome.Status);
            Assert.False(File.Exists(_service.Options.OutboxPath));
        }

        [Fact]
        public async Task A_capture_in_the_wrong_currency_buys_nothing()
        {
            // No exchange rate is guessed at: 19.00 in a weaker currency is not
            // 19.00, and a service that converts is a service that sells at
            // whatever rate an attacker can find.
            var outcome = await Deliver("WH-1", "CAPTURE-1", "19.00", "JPY");

            Assert.Equal(WebhookStatus.Ignored, outcome.Status);
            Assert.False(File.Exists(_service.Options.OutboxPath));
        }

        [Fact]
        public async Task A_capture_for_more_than_the_price_is_fine()
        {
            var outcome = await Deliver("WH-1", "CAPTURE-1", "25.00", "GBP");

            Assert.Equal(WebhookStatus.CodeCreated, outcome.Status);
        }

        [Fact]
        public async Task An_event_type_we_do_not_sell_on_buys_nothing()
        {
            var body = Encoding.UTF8.GetBytes(
                "{\"id\":\"WH-9\",\"event_type\":\"CHECKOUT.ORDER.APPROVED\",\"resource\":{\"id\":\"ORDER-1\"}}");

            var outcome = await Handle(body, Sign("TX-9", body));

            Assert.Equal(WebhookStatus.Ignored, outcome.Status);
            Assert.False(File.Exists(_service.Options.OutboxPath));
        }

        [Fact]
        public async Task A_refund_voids_the_code_that_capture_bought()
        {
            await Deliver("WH-1", "CAPTURE-1", "19.00", "GBP");

            var code = OutboxCode();

            Assert.True(_service.ActivateAndSign(
                new ActivationRequest { Code = code, ServerId = "c5bc6e91458540caa295c4efdda1a58a" },
                "10.0.0.1").IsSuccess);

            var refund = Encoding.UTF8.GetBytes(
                "{\"id\":\"WH-REFUND\",\"event_type\":\"PAYMENT.CAPTURE.REFUNDED\","
                + "\"resource\":{\"id\":\"REFUND-1\",\"capture_id\":\"CAPTURE-1\"}}");

            var outcome = await Handle(refund, Sign("TX-R", refund));

            Assert.Equal(WebhookStatus.Ignored, outcome.Status);

            var afterwards = _service.ActivateAndSign(
                new ActivationRequest { Code = code, ServerId = "aaaa1111bbbb2222cccc3333dddd4444" },
                "10.0.0.1");

            Assert.False(afterwards.IsSuccess);
            Assert.Equal(ActivationError.InvalidCode, afterwards.Error);
        }

        [Fact]
        public async Task A_signed_body_that_is_not_JSON_is_reported_rather_than_swallowed()
        {
            var body = Encoding.UTF8.GetBytes("this is not json");

            var outcome = await Handle(body, Sign("TX-X", body));

            Assert.Equal(WebhookStatus.Unusable, outcome.Status);
        }

        [Fact]
        public async Task A_signed_event_with_no_id_is_refused_because_it_cannot_be_de_duplicated()
        {
            var body = Encoding.UTF8.GetBytes("{\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\"}");

            var outcome = await Handle(body, Sign("TX-X", body));

            Assert.Equal(WebhookStatus.Unusable, outcome.Status);
        }

        [Fact]
        public async Task The_server_id_the_purchase_started_from_is_recorded_but_binds_nothing()
        {
            var body = Encoding.UTF8.GetBytes(
                "{\"id\":\"WH-1\",\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\",\"resource\":{"
                + "\"id\":\"CAPTURE-1\",\"custom_id\":\"c5bc6e91458540caa295c4efdda1a58a\","
                + "\"amount\":{\"value\":\"19.00\",\"currency_code\":\"GBP\"},"
                + "\"payer\":{\"email_address\":\"buyer@example.com\"}}}");

            await Handle(body, Sign("TX-1", body));

            // Recorded for support...
            var stored = ReadColumn("SELECT origin_server_id FROM codes LIMIT 1;");

            Assert.Equal("c5bc6e91458540caa295c4efdda1a58a", stored);

            // ...and binds nothing: the code activates on a completely different
            // server, because a code is server-agnostic until it is activated.
            var reply = _service.ActivateAndSign(
                new ActivationRequest { Code = OutboxCode(), ServerId = "9999aaaa8888bbbb7777cccc6666dddd" },
                "10.0.0.1");

            Assert.True(reply.IsSuccess);
        }

        [Fact]
        public async Task The_licensee_never_comes_from_the_field_a_buy_link_controls()
        {
            var body = Encoding.UTF8.GetBytes(
                "{\"id\":\"WH-1\",\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\",\"resource\":{"
                + "\"id\":\"CAPTURE-1\",\"custom_id\":\"Definitely Not A Server Id\","
                + "\"amount\":{\"value\":\"19.00\",\"currency_code\":\"GBP\"}}}");

            await Handle(body, Sign("TX-1", body));

            var licensee = ReadColumn("SELECT licensee FROM codes LIMIT 1;");

            Assert.DoesNotContain("Definitely Not A Server Id", licensee, StringComparison.Ordinal);
        }

        private string OutboxCode()
        {
            var line = File.ReadAllLines(_service.Options.OutboxPath)[0];

            using var document = JsonDocument.Parse(line);

            return document.RootElement.GetProperty("code").GetString();
        }

        private string ReadColumn(string sql)
        {
            using var connection = new Microsoft.Data.Sqlite.SqliteConnection(
                "Data Source=" + _service.Options.DatabasePath);

            connection.Open();

            using var command = connection.CreateCommand();

            command.CommandText = sql;

            var value = command.ExecuteScalar();

            return value == null || value == DBNull.Value ? null : value.ToString();
        }

        private Task<WebhookOutcome> Deliver(
            string eventId,
            string captureId,
            string amount,
            string currency,
            string transmissionId = "TX-1")
        {
            var body = Capture(eventId, captureId, amount, currency);

            return Handle(body, Sign(transmissionId, body));
        }

        private Task<WebhookOutcome> Handle(byte[] body, Dictionary<string, string> headers)
        {
            var handler = _service.Webhooks(new FakeCertificateSource(_certificate));

            return handler.HandleAsync(headers, body, CancellationToken.None);
        }

        private static byte[] Capture(string eventId, string captureId, string amount, string currency, string extra = "")
        {
            return Encoding.UTF8.GetBytes(
                "{\"id\":\"" + eventId + "\",\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\",\"resource\":{"
                + "\"id\":\"" + captureId + "\",\"amount\":{\"value\":\"" + amount
                + "\",\"currency_code\":\"" + currency + "\"},"
                + "\"payer\":{\"email_address\":\"buyer@example.com\"}}}" + extra);
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
    }
}

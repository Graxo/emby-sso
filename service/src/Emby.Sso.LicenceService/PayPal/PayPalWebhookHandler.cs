using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;

namespace Emby.Sso.LicenceService.PayPal
{
    /// <summary>
    /// What happens after <see cref="PayPalWebhookVerifier"/> has said the
    /// request is genuinely PayPal's.
    ///
    /// The order of everything below is deliberate:
    ///
    ///   verify -> parse -> is this a type we act on -> is the money enough ->
    ///   record the event and create the code in ONE transaction -> write the
    ///   code where a human can send it.
    ///
    /// Nothing is created before verification, so an unsigned request cannot
    /// even cost a database row. The event id is the primary key of
    /// webhook_events, so PayPal's retries - which are frequent and expected -
    /// find the row already there and create nothing; the capture id is UNIQUE on
    /// codes, so even a genuinely new event id for a payment already seen buys
    /// nothing. Both are enforced by the database inside the transaction rather
    /// than by a lookup that could race a second delivery arriving at the same
    /// moment.
    /// </summary>
    public sealed class PayPalWebhookHandler
    {
        public const string CaptureCompleted = "PAYMENT.CAPTURE.COMPLETED";
        public const string CaptureRefunded = "PAYMENT.CAPTURE.REFUNDED";
        public const string CaptureReversed = "PAYMENT.CAPTURE.REVERSED";

        private readonly PayPalWebhookVerifier _verifier;
        private readonly LicenceStore _store;
        private readonly CodeOutbox _outbox;
        private readonly ServiceOptions _options;
        private readonly TimeProvider _time;
        private readonly ILogger<PayPalWebhookHandler> _log;

        public PayPalWebhookHandler(
            PayPalWebhookVerifier verifier,
            LicenceStore store,
            CodeOutbox outbox,
            ServiceOptions options,
            TimeProvider time,
            ILogger<PayPalWebhookHandler> log)
        {
            _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _outbox = outbox ?? throw new ArgumentNullException(nameof(outbox));
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _time = time ?? throw new ArgumentNullException(nameof(time));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public async Task<WebhookOutcome> HandleAsync(
            IReadOnlyDictionary<string, string> headers,
            byte[] body,
            CancellationToken cancellationToken)
        {
            var verification = await _verifier.VerifyAsync(headers, body, cancellationToken).ConfigureAwait(false);

            if (!verification.IsVerified)
            {
                // Warning, not error, and with the reason: this fires every time
                // somebody scans the URL, so it must not page anybody, but the
                // vendor has to be able to see it happening.
                _log.LogWarning(
                    "paypal webhook REFUSED: {Reason}. Nothing was created. bytes={Bytes}",
                    verification.Reason,
                    body?.Length ?? 0);

                return WebhookOutcome.Refused(verification.Reason);
            }

            PayPalEvent paypalEvent;

            if (!TryParse(body, out paypalEvent, out var parseProblem))
            {
                // Signed by PayPal and yet not something we understand. That is
                // not an attack, it is PayPal having changed something, and it
                // deserves a louder log than a forged request does.
                _log.LogError(
                    "paypal webhook VERIFIED but not understood: {Problem}. transmission={Transmission}",
                    parseProblem,
                    verification.TransmissionId);

                return WebhookOutcome.Unusable(parseProblem);
            }

            var now = _time.GetUtcNow();

            switch (paypalEvent.EventType)
            {
                case CaptureCompleted:
                    return Paid(paypalEvent, verification, now);

                case CaptureRefunded:
                case CaptureReversed:
                    return Reversed(paypalEvent, verification, now);

                default:
                    _store.RecordIgnoredEvent(
                        paypalEvent.EventId,
                        verification.TransmissionId,
                        paypalEvent.EventType,
                        "ignored_type",
                        now);

                    _log.LogInformation(
                        "paypal webhook verified, type {Type} is not one we act on. event={Event}",
                        paypalEvent.EventType,
                        paypalEvent.EventId);

                    return WebhookOutcome.Ignored("nothing to do for " + paypalEvent.EventType);
            }
        }

        private WebhookOutcome Paid(PayPalEvent paypalEvent, WebhookVerification verification, DateTimeOffset now)
        {
            if (!IsEnough(paypalEvent, out var amountProblem))
            {
                // A verified capture really did happen; it was just not for
                // enough money to be this product. Recorded, so the vendor can
                // see it and so a redelivery is a duplicate rather than a fresh
                // decision.
                _store.RecordIgnoredEvent(
                    paypalEvent.EventId,
                    verification.TransmissionId,
                    paypalEvent.EventType,
                    "amount_below_minimum",
                    now);

                _log.LogWarning(
                    "paypal capture {Capture} verified but bought nothing: {Problem}",
                    paypalEvent.CaptureId,
                    amountProblem);

                return WebhookOutcome.Ignored(amountProblem);
            }

            var code = RedemptionCode.Generate();
            var hash = RedemptionCode.Hash(code);
            var licensee = paypalEvent.Licensee ?? ("PayPal capture " + paypalEvent.CaptureId);

            var record = _store.RecordPayment(
                paypalEvent.EventId,
                verification.TransmissionId,
                paypalEvent.EventType,
                paypalEvent.CaptureId,
                paypalEvent.BuyerEmail,
                licensee,
                paypalEvent.OriginServerId,
                hash,
                _options.ActivationsAllowed,
                _options.LicenceDays,
                now);

            if (record.Outcome != PaymentOutcome.CodeCreated)
            {
                _log.LogInformation(
                    "paypal webhook {Event} for capture {Capture} is a REPLAY ({Reason}); no code created",
                    paypalEvent.EventId,
                    paypalEvent.CaptureId,
                    record.Outcome);

                return WebhookOutcome.Replay(record.Outcome.ToString());
            }

            try
            {
                _outbox.Append(new OutboxEntry
                {
                    CreatedUtc = now,
                    Code = code,
                    Licensee = licensee,
                    BuyerEmail = paypalEvent.BuyerEmail,
                    ActivationsAllowed = _options.ActivationsAllowed,
                    LicenceDays = _options.LicenceDays,
                    PayPalEventId = paypalEvent.EventId,
                    PayPalCaptureId = paypalEvent.CaptureId,
                });
            }
            catch (Exception ex) when (ex is System.IO.IOException || ex is UnauthorizedAccessException)
            {
                // The code exists, hashed, and the only readable copy has just
                // been lost - it is a local variable about to go out of scope,
                // and it is NOT logged, because a log file is not where live
                // credentials belong even in a disaster. The sale is recoverable
                // by hand and the message says how. Still a 200: PayPal retrying
                // would find the event already recorded and change nothing.
                _log.LogCritical(
                    ex,
                    "CODE LOST: capture {Capture} for {Buyer} was recorded but its code could not be written to {Outbox}. "
                    + "The buyer has paid and has no code. Fix the volume, then: mark that code void in licences.db and "
                    + "run `issue-code` to give them a new one. See service/README.md, 'When a code cannot be delivered'.",
                    paypalEvent.CaptureId,
                    paypalEvent.BuyerEmail,
                    _outbox.Path);

                return WebhookOutcome.Undeliverable(record.CodeId);
            }

            _log.LogInformation(
                "paypal capture {Capture} accepted: code {Tag} created for {Buyer}, {Allowed} activations, {Days} days, "
                + "started from server {Origin}",
                paypalEvent.CaptureId,
                RedemptionCode.LogTag(hash),
                paypalEvent.BuyerEmail ?? "(no email in the event)",
                _options.ActivationsAllowed,
                _options.LicenceDays,
                paypalEvent.OriginServerId ?? "(not recorded)");

            return WebhookOutcome.CodeCreated(record.CodeId);
        }

        private WebhookOutcome Reversed(PayPalEvent paypalEvent, WebhookVerification verification, DateTimeOffset now)
        {
            // For a refund the resource is the refund, and the capture it
            // reverses is in links or in resource.id depending on the event; both
            // are tried by the parser. A refund with no capture we can name
            // cannot void anything, and says so.
            var voided = !string.IsNullOrEmpty(paypalEvent.CaptureId)
                && _store.VoidCodeForCapture(paypalEvent.CaptureId, now);

            _store.RecordIgnoredEvent(
                paypalEvent.EventId,
                verification.TransmissionId,
                paypalEvent.EventType,
                voided ? "code_voided" : "reversal_matched_no_code",
                now);

            _log.LogWarning(
                "paypal {Type} for capture {Capture}: {Result}. Licences ALREADY issued from that code keep working "
                + "until they expire - the plugin verifies offline and there is no revocation.",
                paypalEvent.EventType,
                paypalEvent.CaptureId ?? "(unknown)",
                voided ? "the code is now void and will not activate again" : "no code matched, nothing changed");

            return WebhookOutcome.Ignored(voided ? "code voided" : "no code matched that capture");
        }

        private bool IsEnough(PayPalEvent paypalEvent, out string problem)
        {
            problem = null;

            if (!Money.TryParse(_options.PayPal.MinimumAmount, out var minimum))
            {
                problem = "PAYPAL_MINIMUM_AMOUNT is not a number, so no capture can be judged against it";

                return false;
            }

            if (paypalEvent.Amount == null || !Money.TryParse(paypalEvent.Amount, out var paid))
            {
                problem = "the capture carries no amount this service can read";

                return false;
            }

            if (!string.Equals(paypalEvent.Currency, _options.PayPal.Currency, StringComparison.OrdinalIgnoreCase))
            {
                problem = "the capture is in " + paypalEvent.Currency + ", not " + _options.PayPal.Currency
                    + " - no conversion is attempted, because guessing at an exchange rate is how a service sells "
                    + "a licence for a fraction of its price";

                return false;
            }

            if (paid < minimum)
            {
                problem = "the capture is for " + paypalEvent.Amount + " " + paypalEvent.Currency
                    + ", below the minimum of " + _options.PayPal.MinimumAmount;

                return false;
            }

            return true;
        }

        /// <summary>
        /// Pulls the handful of fields that matter out of the event body.
        ///
        /// Defensive to the point of pedantry, because this parses a document
        /// from outside: every field is optional in the reader even where PayPal
        /// documents it as present, and a missing one produces a refusal with a
        /// reason rather than an exception in a request handler. The body has
        /// been verified as PayPal's by the time this runs, so this is not a
        /// trust boundary - it is a compatibility boundary, and PayPal changes
        /// their payloads.
        /// </summary>
        internal static bool TryParse(byte[] body, out PayPalEvent result, out string problem)
        {
            result = null;
            problem = null;

            JsonDocument document;

            try
            {
                document = JsonDocument.Parse(body);
            }
            catch (JsonException ex)
            {
                problem = "the body is not JSON: " + ex.Message;

                return false;
            }

            using (document)
            {
                var root = document.RootElement;

                if (root.ValueKind != JsonValueKind.Object)
                {
                    problem = "the body is not a JSON object";

                    return false;
                }

                var eventId = String(root, "id");
                var eventType = String(root, "event_type");

                if (string.IsNullOrEmpty(eventId))
                {
                    problem = "the event has no id, so it cannot be de-duplicated and will not be acted on";

                    return false;
                }

                if (string.IsNullOrEmpty(eventType))
                {
                    problem = "the event has no event_type";

                    return false;
                }

                var parsed = new PayPalEvent
                {
                    EventId = eventId,
                    EventType = eventType,
                };

                if (root.TryGetProperty("resource", out var resource) && resource.ValueKind == JsonValueKind.Object)
                {
                    parsed.CaptureId = String(resource, "id");

                    if (resource.TryGetProperty("amount", out var amount) && amount.ValueKind == JsonValueKind.Object)
                    {
                        parsed.Amount = String(amount, "value");
                        parsed.Currency = String(amount, "currency_code");
                    }

                    if (resource.TryGetProperty("payer", out var payer) && payer.ValueKind == JsonValueKind.Object)
                    {
                        parsed.BuyerEmail = String(payer, "email_address");
                    }

                    // A refund names the capture it reverses here rather than in
                    // resource.id, which is the refund's own id.
                    var reversed = String(resource, "capture_id");

                    if (!string.IsNullOrEmpty(reversed))
                    {
                        parsed.CaptureId = reversed;
                    }

                    // custom_id is what /buy put there: the Emby server id the
                    // purchase was started from. Support metadata, nothing more -
                    // the code it buys is not bound to it, and it came from a
                    // query string, so it is length-capped here and HTML-encoded
                    // wherever it is shown.
                    var origin = String(resource, "custom_id");

                    parsed.OriginServerId = origin != null && origin.Length <= 128 ? origin : null;

                    // The licensee never comes from custom_id: that field is
                    // attacker-influenced through the /buy link, and the licensee
                    // ends up in a signed token.
                    parsed.Licensee = parsed.BuyerEmail ?? String(resource, "invoice_id");
                }

                result = parsed;

                return true;
            }
        }

        private static string String(JsonElement element, string name)
        {
            if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            var text = value.GetString();

            return string.IsNullOrWhiteSpace(text) ? null : text.Trim();
        }
    }

    internal sealed class PayPalEvent
    {
        public string EventId { get; set; }

        public string EventType { get; set; }

        public string CaptureId { get; set; }

        public string Amount { get; set; }

        public string Currency { get; set; }

        public string BuyerEmail { get; set; }

        public string Licensee { get; set; }

        public string OriginServerId { get; set; }
    }

    public enum WebhookStatus
    {
        /// <summary>The signature did not verify. 401, and nothing happened.</summary>
        Refused,

        /// <summary>Verified, and a code now exists.</summary>
        CodeCreated,

        /// <summary>Verified, and this payment had already been seen.</summary>
        Replay,

        /// <summary>Verified, and correctly no code: wrong type, too little money, a refund.</summary>
        Ignored,

        /// <summary>Verified, but not a document this service can read.</summary>
        Unusable,

        /// <summary>A code was created and could not be written where a human can send it.</summary>
        Undeliverable,
    }

    public sealed class WebhookOutcome
    {
        private WebhookOutcome(WebhookStatus status, string detail, long codeId)
        {
            Status = status;
            Detail = detail;
            CodeId = codeId;
        }

        public WebhookStatus Status { get; }

        /// <summary>For the log. Only ever a fixed string reaches the caller.</summary>
        public string Detail { get; }

        public long CodeId { get; }

        public static WebhookOutcome Refused(string reason) => new WebhookOutcome(WebhookStatus.Refused, reason, 0);

        public static WebhookOutcome CodeCreated(long codeId) => new WebhookOutcome(WebhookStatus.CodeCreated, null, codeId);

        public static WebhookOutcome Replay(string detail) => new WebhookOutcome(WebhookStatus.Replay, detail, 0);

        public static WebhookOutcome Ignored(string detail) => new WebhookOutcome(WebhookStatus.Ignored, detail, 0);

        public static WebhookOutcome Unusable(string detail) => new WebhookOutcome(WebhookStatus.Unusable, detail, 0);

        public static WebhookOutcome Undeliverable(long codeId) => new WebhookOutcome(WebhookStatus.Undeliverable, null, codeId);
    }
}

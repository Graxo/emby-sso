using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;

namespace Emby.Sso.LicenceService.Delivery
{
    /// <summary>
    /// Reads back what <see cref="CodeOutbox"/> wrote.
    ///
    /// The outbox is append-only and holds two kinds of line: one per code
    /// created, and one per code successfully emailed. Delivery is therefore not
    /// a column anywhere - it is the presence of a second line naming the same
    /// twelve-character hash tag - and this class is the one place that pairing
    /// is done, so `list-codes` and `list-outbox` cannot disagree about what
    /// "sent" means.
    ///
    /// WHAT A MISSING LINE MEANS, and why this class refuses to guess. The
    /// README tells the operator to send a code and then delete its line, so a
    /// code with no line at all is the normal end state of a delivered sale - it
    /// is NOT evidence that anything went wrong. Only a code line with no
    /// delivery line beside it is outstanding. That is why <see cref="TryFind"/>
    /// returning false is reported as "-" and never as a problem.
    ///
    /// It holds plaintext codes, because the file does. See <see cref="OutboxRecord.Code"/>.
    /// </summary>
    public sealed class OutboxLog
    {
        private readonly Dictionary<string, OutboxRecord> _byTag =
            new Dictionary<string, OutboxRecord>(StringComparer.OrdinalIgnoreCase);

        private readonly List<OutboxRecord> _records = new List<OutboxRecord>();

        private OutboxLog()
        {
        }

        /// <summary>What an operator with no outbox file has: nothing outstanding, and no error.</summary>
        public static OutboxLog Empty { get; } = new OutboxLog();

        /// <summary>In file order, which is creation order.</summary>
        public IReadOnlyList<OutboxRecord> Records => _records;

        /// <summary>
        /// Reads the file, skipping and reporting any line it cannot parse - one
        /// damaged record must never hide the rest, which is the rule the
        /// offline tool's `list` already follows for the ledger.
        /// </summary>
        public static OutboxLog Read(string path, Action<string> warn)
        {
            var log = new OutboxLog();

            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return log;
            }

            var lineNumber = 0;

            foreach (var line in File.ReadLines(path))
            {
                lineNumber++;

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                JsonElement root;

                try
                {
                    using var document = JsonDocument.Parse(line);

                    root = document.RootElement.Clone();
                }
                catch (JsonException ex)
                {
                    warn?.Invoke(path + " line " + lineNumber.ToString(CultureInfo.InvariantCulture)
                        + " is not readable and was skipped: " + ex.Message);

                    continue;
                }

                if (root.ValueKind != JsonValueKind.Object)
                {
                    warn?.Invoke(path + " line " + lineNumber.ToString(CultureInfo.InvariantCulture)
                        + " is not an object and was skipped");

                    continue;
                }

                var tag = Text(root, "code_tag");

                if (string.IsNullOrEmpty(tag))
                {
                    warn?.Invoke(path + " line " + lineNumber.ToString(CultureInfo.InvariantCulture)
                        + " names no code and was skipped");

                    continue;
                }

                if (string.Equals(Text(root, "record"), "delivered", StringComparison.Ordinal))
                {
                    if (log._byTag.TryGetValue(tag, out var delivered))
                    {
                        delivered.Delivered = true;
                        delivered.DeliveredUtc = Text(root, "delivered_utc");
                        delivered.DeliveredTo = Text(root, "recipient");
                    }

                    // A receipt whose code line has already been pruned names a
                    // code that is finished with. Nothing to record.
                    continue;
                }

                var record = new OutboxRecord
                {
                    LineNumber = lineNumber,
                    CodeTag = tag,
                    CreatedUtc = Text(root, "created_utc"),
                    Code = Text(root, "code"),
                    Licensee = Text(root, "licensee"),
                    BuyerEmail = Text(root, "buyer_email"),
                    ActivationsAllowed = Number(root, "activations_allowed"),
                    LicenceDays = Number(root, "licence_days"),
                    PayPalEventId = Text(root, "paypal_event_id"),
                    PayPalCaptureId = Text(root, "paypal_capture_id"),
                };

                log._records.Add(record);
                log._byTag[tag] = record;
            }

            return log;
        }

        /// <summary>The outbox line for a code, if there still is one.</summary>
        public bool TryFind(string codeTag, out OutboxRecord record)
        {
            record = null;

            return !string.IsNullOrEmpty(codeTag) && _byTag.TryGetValue(codeTag, out record);
        }

        private static string Text(JsonElement root, string name)
        {
            return root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
        }

        private static int Number(JsonElement root, string name)
        {
            return root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number
                && value.TryGetInt32(out var number)
                ? number
                : 0;
        }
    }

    /// <summary>One code's line in the outbox, and whether a receipt was ever written beside it.</summary>
    public sealed class OutboxRecord
    {
        public int LineNumber { get; set; }

        public string CodeTag { get; set; }

        public string CreatedUtc { get; set; }

        /// <summary>
        /// THE CODE, IN THE CLEAR. It is in the file - that is what the outbox
        /// is for - so it is here too, and nothing prints it unless the operator
        /// asks for it by name. See `list-outbox --reveal`.
        /// </summary>
        public string Code { get; set; }

        public string Licensee { get; set; }

        public string BuyerEmail { get; set; }

        public int ActivationsAllowed { get; set; }

        public int LicenceDays { get; set; }

        public string PayPalEventId { get; set; }

        public string PayPalCaptureId { get; set; }

        public bool Delivered { get; set; }

        public string DeliveredUtc { get; set; }

        public string DeliveredTo { get; set; }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using Emby.Sso.Licensing;

namespace Emby.Sso.LicenceService.Delivery
{
    /// <summary>
    /// Where a freshly-created redemption code goes so that a human can send it
    /// to the person who paid for it.
    ///
    /// READ THIS BEFORE DEPLOYING. This file is the ONE PLACE a redemption code
    /// exists in readable form. The database holds only SHA-256 hashes, so a
    /// stolen database yields nothing usable; this file yields every code that
    /// has not yet been pruned from it. It is written owner-read/write only, it
    /// lives on the same mounted volume as the signing key's data directory, and
    /// the vendor is expected to send each code and then delete its line.
    ///
    /// It exists because a code has to reach the buyer somehow, and every
    /// alternative has the same property - an SMTP queue, a "here is your code"
    /// page, a support inbox - so the choice is where the plaintext sits and for
    /// how long, not whether it exists. A file the vendor prunes is the version
    /// where that is obvious.
    ///
    /// Mail, when SMTP_HOST is set, is layered ON TOP of this rather than
    /// instead of it. The append below happens first and unconditionally, and
    /// the email is attempted afterwards; so the file is still the durable
    /// record of every code this service has ever created, and an operator who
    /// has not configured mail sees a file identical to the one they see today.
    /// A successful send appends a second line - see RecordDelivered - which
    /// names the code's hash tag and NOT the code, so that pruning is a decision
    /// the operator can make from the file alone.
    /// </summary>
    public sealed class CodeOutbox
    {
        private readonly object _gate = new object();

        public CodeOutbox(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("the outbox needs a path", nameof(path));
            }

            Path = System.IO.Path.GetFullPath(path);
        }

        public string Path { get; }

        /// <summary>
        /// Appends one undelivered code. Throws rather than returning false: a
        /// code that exists in the database and nowhere a human can read it is a
        /// sale that cannot be completed, and the caller has to know.
        /// </summary>
        public void Append(OutboxEntry entry)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            AppendLine(new Dictionary<string, object>
            {
                ["created_utc"] = LicenceFormat.Iso(entry.CreatedUtc),
                ["delivered"] = false,
                ["code"] = RedemptionCode.Format(entry.Code),
                ["code_tag"] = RedemptionCode.LogTag(RedemptionCode.Hash(entry.Code)),
                ["licensee"] = entry.Licensee,
                ["buyer_email"] = entry.BuyerEmail,
                ["activations_allowed"] = entry.ActivationsAllowed,
                ["licence_days"] = entry.LicenceDays,
                ["paypal_event_id"] = entry.PayPalEventId,
                ["paypal_capture_id"] = entry.PayPalCaptureId,
            });
        }

        /// <summary>
        /// Notes that a code was emailed successfully, as a second line rather
        /// than by rewriting the first.
        ///
        /// Append-only on purpose. Rewriting a line in place means reading a file
        /// of live credentials into memory, writing it back, and having a window
        /// where a crash truncates it - to save the operator a grep. It carries
        /// the code's HASH TAG and never the code, so the receipt is safe to keep
        /// after the code line has been pruned.
        /// </summary>
        public void RecordDelivered(OutboxEntry entry, string recipient, DateTimeOffset when)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            AppendLine(new Dictionary<string, object>
            {
                ["record"] = "delivered",
                ["delivered_utc"] = LicenceFormat.Iso(when),
                ["delivered"] = true,
                ["code_tag"] = RedemptionCode.LogTag(RedemptionCode.Hash(entry.Code)),
                ["recipient"] = recipient,
                ["paypal_capture_id"] = entry.PayPalCaptureId,
            });
        }

        private void AppendLine(Dictionary<string, object> fields)
        {
            var line = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(fields) + "\n");

            var directory = System.IO.Path.GetDirectoryName(Path);

            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var options = new FileStreamOptions
            {
                Mode = FileMode.Append,
                Access = FileAccess.Write,
                Share = FileShare.ReadWrite,
            };

            if (!OperatingSystem.IsWindows())
            {
                // At creation, not chmod-ed after: there must be no moment when a
                // file full of live redemption codes exists at the umask default.
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            lock (_gate)
            {
                using var file = new FileStream(Path, options);

                file.Write(line, 0, line.Length);
                file.Flush(flushToDisk: true);
            }
        }
    }

    public sealed class OutboxEntry
    {
        public DateTimeOffset CreatedUtc { get; set; }

        /// <summary>The normalised code. This is a live credential.</summary>
        public string Code { get; set; }

        public string Licensee { get; set; }

        public string BuyerEmail { get; set; }

        public int ActivationsAllowed { get; set; }

        public int LicenceDays { get; set; }

        public string PayPalEventId { get; set; }

        public string PayPalCaptureId { get; set; }
    }
}

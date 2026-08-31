using System;
using System.Globalization;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.Storage;

namespace Emby.Sso.LicenceService.Management
{
    /// <summary>
    /// How a code is described to a person, in words, once.
    ///
    /// The command line and the admin page both show the same rows to the same
    /// operator, and the rules here are the ones that would be quietly wrong if
    /// each front end wrote its own: a comp's note must never be dressed up as
    /// a buyer's email address, and an empty field must look empty rather than
    /// look like a value.
    ///
    /// NOTHING HERE PRODUCES A REDEMPTION CODE. It cannot: it is given a
    /// <see cref="CodeSummary"/>, and that type has no field a code could live
    /// in, because the store holds only a SHA-256.
    /// </summary>
    public static class CodeText
    {
        /// <summary>
        /// Who a code is for. Angle brackets for a buyer's address, parentheses
        /// for a note - a comp's `--note` lives in the same column as a buyer's
        /// email (see <see cref="CodeSummary.BuyerEmailOrNote"/>) and must not
        /// be mistaken for one.
        /// </summary>
        public static string Describe(CodeSummary code)
        {
            if (code == null)
            {
                return "-";
            }

            var who = string.IsNullOrWhiteSpace(code.Licensee) ? "(no licensee)" : code.Licensee;

            if (string.IsNullOrWhiteSpace(code.BuyerEmailOrNote)
                || string.Equals(code.BuyerEmailOrNote, code.Licensee, StringComparison.OrdinalIgnoreCase))
            {
                return who;
            }

            return code.IsManual
                ? who + " (" + code.BuyerEmailOrNote + ")"
                : who + " <" + code.BuyerEmailOrNote + ">";
        }

        /// <summary>What the Delivery line says: sent, not sent, or not applicable.</summary>
        public static string DescribeDelivery(CodeSummary code, OutboxRecord delivery)
        {
            if (delivery == null)
            {
                return code != null && code.IsManual
                    ? "n/a - `issue-code` printed this one to whoever ran it"
                    : "no line in the outbox: sent and pruned, or written before this service kept one";
            }

            return delivery.Delivered
                ? "emailed to " + Empty(delivery.DeliveredTo) + " at " + Empty(delivery.DeliveredUtc)
                : "NOT SENT - line " + delivery.LineNumber.ToString(CultureInfo.InvariantCulture)
                    + " of the outbox, with no receipt beside it";
        }

        public static string Empty(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "-" : value;
        }

        public static string Date(DateTimeOffset when)
        {
            return when.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        }

        public static string Relative(DateTimeOffset when, DateTimeOffset now)
        {
            var days = (int)Math.Floor((when - now).TotalDays);

            if (days < 0)
            {
                return "lapsed " + (-days).ToString(CultureInfo.InvariantCulture) + " days ago";
            }

            return "in " + days.ToString(CultureInfo.InvariantCulture) + " days";
        }

        public static string Count(int number, string noun)
        {
            return number.ToString(CultureInfo.InvariantCulture) + " " + noun + (number == 1 ? string.Empty : "s");
        }
    }
}

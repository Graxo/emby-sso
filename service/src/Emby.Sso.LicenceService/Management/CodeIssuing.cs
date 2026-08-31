using System;
using System.Collections.Generic;
using System.Globalization;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;

namespace Emby.Sso.LicenceService.Management
{
    /// <summary>
    /// Minting a code that no payment bought - the `issue-code` command, and the
    /// admin page's Issue form, which are the same thing called from two places.
    ///
    /// This is the highest-privilege action either front end offers: it creates
    /// a bearer credential worth the price of the product. There is exactly one
    /// implementation so that the validation, the defaults and what gets written
    /// to the store cannot drift between them.
    ///
    /// THE ONE MOMENT A CODE EXISTS IN THE CLEAR. The store keeps a SHA-256 and
    /// nothing else, so the string returned by <see cref="Issue"/> is the only
    /// copy there will ever be. Both callers show it exactly once - the command
    /// on stdout, the page on the result screen - and neither writes it to a
    /// log, an audit line, a URL or a redirect. Losing it means issuing another.
    /// </summary>
    public static class CodeIssuing
    {
        /// <summary>
        /// A sane ceiling on both numbers, so a typo in a web form cannot mint a
        /// code good for ten thousand servers or two centuries. Far above
        /// anything a real sale uses; the command line has the same ceiling
        /// because there is only one implementation.
        /// </summary>
        public const int MaximumActivations = 1000;

        /// <summary>Twenty years. A licence longer than the business is not a licence.</summary>
        public const int MaximumDays = 7300;

        /// <summary>
        /// A licensee is written into the store and read back onto a page, so it
        /// is bounded here rather than at the page: an unbounded field is a
        /// database row somebody else chose the size of.
        /// </summary>
        public const int MaximumTextLength = 200;

        public sealed class Request
        {
            public string Licensee { get; set; }

            public int ActivationsAllowed { get; set; }

            public int LicenceDays { get; set; }

            /// <summary>Optional. Why this code exists - a ticket number, a name, a reason.</summary>
            public string Note { get; set; }
        }

        public sealed class Issued
        {
            /// <summary>The row in the store.</summary>
            public long Id { get; set; }

            /// <summary>
            /// The code, formatted for a human, in the clear. THE ONLY COPY.
            /// Show it once; never log it, never redirect with it.
            /// </summary>
            public string Code { get; set; }

            /// <summary>The SHA-256 the store holds. Safe to log.</summary>
            public string CodeHash { get; set; }

            /// <summary>The twelve characters the logs and the audit trail use.</summary>
            public string Tag => RedemptionCode.LogTag(CodeHash);
        }

        /// <summary>
        /// Everything wrong with the request, all at once - the same shape
        /// <see cref="Configuration.ServiceOptions.Problems"/> uses, so a web
        /// form can show every mistake at once instead of one per submission.
        /// An empty list is the only thing that issues a code.
        /// </summary>
        public static IReadOnlyList<string> Problems(Request request)
        {
            var problems = new List<string>();

            if (request == null)
            {
                problems.Add("Nothing was submitted.");

                return problems;
            }

            if (string.IsNullOrWhiteSpace(request.Licensee))
            {
                problems.Add("Licensee is required: who is this code for? It is what `list-codes` shows you later.");
            }
            else if (request.Licensee.Trim().Length > MaximumTextLength)
            {
                problems.Add("Licensee must be at most " + MaximumTextLength.ToString(CultureInfo.InvariantCulture)
                    + " characters.");
            }

            if (request.Note != null && request.Note.Trim().Length > MaximumTextLength)
            {
                problems.Add("Note must be at most " + MaximumTextLength.ToString(CultureInfo.InvariantCulture)
                    + " characters.");
            }

            if (request.ActivationsAllowed < 1)
            {
                problems.Add("Activations must be at least 1; a code nobody can activate is not a product.");
            }
            else if (request.ActivationsAllowed > MaximumActivations)
            {
                problems.Add("Activations must be at most " + MaximumActivations.ToString(CultureInfo.InvariantCulture)
                    + ". More than that is a typo, not a sale.");
            }

            if (request.LicenceDays < 1)
            {
                problems.Add("Days must be at least 1; a licence must expire, and it must be usable first.");
            }
            else if (request.LicenceDays > MaximumDays)
            {
                problems.Add("Days must be at most " + MaximumDays.ToString(CultureInfo.InvariantCulture)
                    + " (twenty years). There is no revocation, so a long licence is a permanent one.");
            }

            return problems;
        }

        /// <summary>
        /// Draws a code, stores its hash, and hands back the only copy of it.
        /// Call <see cref="Problems"/> first; this throws if the request is not
        /// one that should have been accepted, because a caller that skipped the
        /// check is a bug rather than a user error.
        /// </summary>
        public static Issued Issue(LicenceStore store, Request request, DateTimeOffset now)
        {
            if (store == null)
            {
                throw new ArgumentNullException(nameof(store));
            }

            var problems = Problems(request);

            if (problems.Count > 0)
            {
                throw new ArgumentException(string.Join(" ", problems), nameof(request));
            }

            var code = RedemptionCode.Generate();
            var hash = RedemptionCode.Hash(code);

            var id = store.CreateManualCode(
                hash,
                request.Licensee.Trim(),
                request.ActivationsAllowed,
                request.LicenceDays,
                string.IsNullOrWhiteSpace(request.Note) ? null : request.Note.Trim(),
                now);

            return new Issued
            {
                Id = id,
                Code = RedemptionCode.Format(code),
                CodeHash = hash,
            };
        }
    }
}

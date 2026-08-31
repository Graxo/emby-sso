using System;
using System.Collections.Generic;
using System.Globalization;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;

namespace Emby.Sso.LicenceService.Management
{
    /// <summary>
    /// The paragraph that has to appear wherever voiding is offered, written
    /// once.
    ///
    /// It is here rather than at each call site because the thing it says - that
    /// voiding takes back nothing already issued - is the single most likely
    /// thing for an operator to assume wrongly, and a second copy of it
    /// somewhere would eventually be the copy that got softened. The command
    /// line prints these lines; the admin page renders the same lines as
    /// paragraphs, BEFORE the button, not after it.
    /// </summary>
    public static class VoidExplanation
    {
        /// <summary>
        /// The sentence that must be impossible to miss. Shouted in the
        /// terminal, and the heading of the warning box on the page.
        /// </summary>
        public const string Headline = "THIS DOES NOT RECALL A LICENCE ALREADY ISSUED FROM THIS CODE.";

        /// <summary>
        /// The whole explanation, as the lines a terminal shows: pre-wrapped,
        /// with blank lines separating paragraphs. <see cref="Paragraphs"/>
        /// turns the same lines into paragraphs for HTML, so the two front ends
        /// cannot say different things about what voiding cannot do.
        ///
        /// The first line is always <see cref="Headline"/>.
        /// </summary>
        public static IReadOnlyList<string> Lines(CodeSummary code)
        {
            if (code == null)
            {
                throw new ArgumentNullException(nameof(code));
            }

            var lines = new List<string> { Headline };

            if (code.ActivationsUsed == 0)
            {
                lines.Add("Nothing has ever been activated with it, so in this case there is nothing");
                lines.Add("running that could have needed recalling - but that is luck, not a guarantee");
                lines.Add("this command offers.");
            }
            else
            {
                lines.Add(
                    "  " + code.ActivationsUsed.ToString(CultureInfo.InvariantCulture)
                    + " server(s) have already been given a licence from it"
                    + (code.ExpiresUtc.HasValue
                        ? ", and each keeps working until " + LicenceFormat.Iso(code.ExpiresUtc.Value) + "."
                        : "."));
                lines.Add("  `show-code` lists them.");
            }

            lines.Add(string.Empty);
            lines.Add("The plugin verifies its licence offline against a public key compiled into it and");
            lines.Add("never calls this service, so no revocation exists and none can be added here.");
            lines.Add("Voiding stops the NEXT activation. That is the whole of what it does. If a refunded");
            lines.Add("customer must actually lose the plugin, the only remedy is a new signing keypair and");
            lines.Add("a new plugin build - which invalidates every other customer at the same time.");

            return lines;
        }

        /// <summary>
        /// The same text as paragraphs, for a page: consecutive lines joined
        /// with a space, blank lines starting a new one. The HTML renderer
        /// escapes every one of them.
        ///
        /// <see cref="Headline"/> is NOT among them - the page renders it as the
        /// heading of the warning box, which is why it is a constant.
        /// </summary>
        public static IReadOnlyList<string> Paragraphs(CodeSummary code)
        {
            var paragraphs = new List<string>();
            var current = new List<string>();

            foreach (var line in Lines(code))
            {
                if (string.Equals(line, Headline, StringComparison.Ordinal))
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    Flush(paragraphs, current);

                    continue;
                }

                current.Add(line.Trim());
            }

            Flush(paragraphs, current);

            return paragraphs;
        }

        private static void Flush(List<string> paragraphs, List<string> current)
        {
            if (current.Count == 0)
            {
                return;
            }

            paragraphs.Add(string.Join(" ", current));
            current.Clear();
        }
    }
}

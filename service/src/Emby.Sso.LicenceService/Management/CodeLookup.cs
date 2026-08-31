using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.Data.Sqlite;

namespace Emby.Sso.LicenceService.Management
{
    /// <summary>
    /// Turning what a person typed into a row, and explaining what happened when
    /// it did not.
    ///
    /// Both front ends need this and they must not disagree about it. There are
    /// three ways to fail to find a code and they mean different things -
    /// "that is not a code at all", "that is a code and this store has never
    /// held it", "that is the start of more than one hash" - and an operator
    /// answering a customer needs to be told which.
    ///
    /// A CODE GIVEN HERE IS NEVER GIVEN BACK. It is normalised, hashed, and used
    /// to look up a row; the row has no code in it, and neither does any message
    /// this class produces. `show-code` confirms a code it was handed; it cannot
    /// reveal one, and neither can the page.
    /// </summary>
    public static class CodeLookup
    {
        public enum Failure
        {
            None = 0,

            /// <summary>Neither a code nor a tag was given.</summary>
            NothingGiven,

            /// <summary>Both were given. Which one did they mean?</summary>
            BothGiven,

            /// <summary>Not a redemption code at all - /v1/activate would refuse it too.</summary>
            MalformedCode,

            /// <summary>A well-formed code this store has never held.</summary>
            UnknownCode,

            /// <summary>Not a hash prefix: too short, or not hexadecimal.</summary>
            MalformedTag,

            /// <summary>No hash in this store starts with it.</summary>
            NoSuchTag,

            /// <summary>More than one does.</summary>
            AmbiguousTag,

            /// <summary>The store would not answer.</summary>
            Unreadable,
        }

        public sealed class Result
        {
            public CodeSummary Code { get; set; }

            public Failure Reason { get; set; }

            /// <summary>The candidates, when a tag prefix matched more than one.</summary>
            public IReadOnlyList<CodeSummary> Matches { get; set; }

            /// <summary>What the tag prefix was, for the message. Never a code.</summary>
            public string Prefix { get; set; }

            /// <summary>SQLite's own message, when the store would not answer.</summary>
            public string Detail { get; set; }

            public bool Found => Reason == Failure.None && Code != null;

            /// <summary>
            /// What to tell the person, as lines. The command line writes these
            /// to stderr; the page renders them as paragraphs. One wording.
            /// </summary>
            public IReadOnlyList<string> Explain()
            {
                var lines = new List<string>();

                switch (Reason)
                {
                    case Failure.NothingGiven:
                        lines.Add("Give --code <the code the customer typed> or --tag <the 12 characters the logs show>.");

                        break;

                    case Failure.BothGiven:
                        lines.Add("Give either --code or --tag, not both.");

                        break;

                    case Failure.MalformedCode:
                        lines.Add("That is not a well-formed redemption code, whatever else it is.");
                        lines.Add("A code is " + RedemptionCode.Symbols.ToString(CultureInfo.InvariantCulture)
                            + " characters from " + RedemptionCode.Alphabet + ", usually written in groups of five.");
                        lines.Add("Nothing was looked up: /v1/activate would refuse this one before reaching the store.");

                        break;

                    case Failure.UnknownCode:
                        lines.Add("That is a well-formed code, and this store has never held it.");
                        lines.Add("It was issued by a different service, mistyped in a way that is still");
                        lines.Add("well-formed, or invented.");

                        break;

                    case Failure.MalformedTag:
                        lines.Add("--tag is hexadecimal, at least 4 characters: the start of the code's SHA-256,");
                        lines.Add("which is what `code=` in the log lines and TAG in `list-codes` show.");

                        break;

                    case Failure.NoSuchTag:
                        lines.Add("No code in this store has a hash starting " + Prefix + ".");

                        break;

                    case Failure.AmbiguousTag:
                        lines.Add(CodeText.Count(Matches?.Count ?? 0, "code") + " start with " + Prefix + ". Give more of it:");

                        foreach (var match in Matches ?? Array.Empty<CodeSummary>())
                        {
                            lines.Add("  " + match.Tag + "  " + CodeText.Describe(match));
                        }

                        break;

                    case Failure.Unreadable:
                        lines.Add("The store could not be read: " + Detail);

                        break;
                }

                return lines;
            }
        }

        /// <summary>
        /// The code as a human sends it: any case, with or without the hyphens,
        /// with whitespace round it, and with I, L and O read as the 1, 1 and 0
        /// they were meant to be. That is the same normalisation /v1/activate
        /// applies, so a code this rejects is a code the service would refuse.
        /// </summary>
        public static Result ByCode(LicenceStore store, string typed)
        {
            if (store == null)
            {
                throw new ArgumentNullException(nameof(store));
            }

            if (string.IsNullOrWhiteSpace(typed))
            {
                return new Result { Reason = Failure.NothingGiven };
            }

            if (!RedemptionCode.TryNormalise(typed, out var normalised))
            {
                return new Result { Reason = Failure.MalformedCode };
            }

            try
            {
                var found = store.FindCodeByHash(RedemptionCode.Hash(normalised));

                return found == null
                    ? new Result { Reason = Failure.UnknownCode }
                    : new Result { Code = found };
            }
            catch (SqliteException ex)
            {
                return new Result { Reason = Failure.Unreadable, Detail = ex.Message };
            }
        }

        /// <summary>The twelve characters the logs record, or any prefix of four or more.</summary>
        public static Result ByTag(LicenceStore store, string tag)
        {
            if (store == null)
            {
                throw new ArgumentNullException(nameof(store));
            }

            if (string.IsNullOrWhiteSpace(tag))
            {
                return new Result { Reason = Failure.NothingGiven };
            }

            var prefix = tag.Trim().ToLowerInvariant();

            if (prefix.Length < 4 || !prefix.All(Uri.IsHexDigit))
            {
                return new Result { Reason = Failure.MalformedTag, Prefix = prefix };
            }

            try
            {
                var matches = store.FindCodesByHashPrefix(prefix);

                if (matches.Count == 0)
                {
                    return new Result { Reason = Failure.NoSuchTag, Prefix = prefix };
                }

                if (matches.Count > 1)
                {
                    return new Result { Reason = Failure.AmbiguousTag, Prefix = prefix, Matches = matches };
                }

                return new Result { Code = matches[0], Prefix = prefix };
            }
            catch (SqliteException ex)
            {
                return new Result { Reason = Failure.Unreadable, Detail = ex.Message, Prefix = prefix };
            }
        }

        /// <summary>
        /// Exactly one of a code and a tag. What `--code`/`--tag` on the command
        /// line means, and what the page's lookup form means.
        /// </summary>
        public static Result ByEither(LicenceStore store, string typedCode, string tag)
        {
            var hasCode = !string.IsNullOrWhiteSpace(typedCode);
            var hasTag = !string.IsNullOrWhiteSpace(tag);

            if (hasCode && hasTag)
            {
                return new Result { Reason = Failure.BothGiven };
            }

            if (!hasCode && !hasTag)
            {
                return new Result { Reason = Failure.NothingGiven };
            }

            return hasCode ? ByCode(store, typedCode) : ByTag(store, tag);
        }
    }
}

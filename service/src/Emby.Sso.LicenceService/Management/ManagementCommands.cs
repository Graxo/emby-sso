using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.Data.Sqlite;

namespace Emby.Sso.LicenceService.Management
{
    /// <summary>
    /// The four commands that answer the questions selling a licence actually
    /// produces: who has a code, what is this one, stop that one working, and
    /// which sale has not reached its buyer.
    ///
    /// WHY THESE ARE COMMANDS AND NOT ROUTES. This service is on the internet
    /// and holds the signing key. An admin HTTP surface on it needs
    /// authentication, sessions, CSRF, an audit trail and a way to be sure a
    /// bug in any of that does not expose the key - a far larger thing to get
    /// right than a command that requires a shell on the box. Shell access here
    /// is already total access, so a command adds no authority that an attacker
    /// with a shell did not already have, and it is the same reasoning that
    /// keeps `issue-code` off HTTP.
    ///
    /// TWO RULES HOLD ACROSS ALL OF THEM.
    ///
    /// 1. NO COMMAND CAN PRINT A CODE THE STORE HOLDS BY HASH. `issue-code`
    ///    prints one at creation because that is the only moment it exists in
    ///    the clear. Afterwards the store has a SHA-256 and nothing else, so
    ///    `list-codes` cannot show one and `show-code` - which takes a code as
    ///    INPUT - can only confirm the one it was handed. The single exception
    ///    is `list-outbox --reveal`, and only because the outbox file itself
    ///    holds plaintext: it reads back what is already on that disk.
    ///
    /// 2. A READ-ONLY COMMAND NEVER CREATES A STORE. SQLite's default is to
    ///    create the file, so `list-codes` against a mistyped LICENCE_DATA_DIR
    ///    would otherwise print an empty table - which reads as "no customers" -
    ///    and leave a stray database behind. They open <see
    ///    cref="StoreAccess.ReadOnly"/> and check the file exists first, so the
    ///    answer to the wrong directory is "there is no store here".
    /// </summary>
    internal static class ManagementCommands
    {
        /// <summary>sysexits.h EX_NOINPUT: there is no store at the path we were pointed at.</summary>
        public const int NoStore = 66;

        /// <summary>sysexits.h EX_CONFIG, the same code every other refusal in this service uses.</summary>
        public const int ConfigurationError = 78;

        /// <summary>Bad usage, or a code that is not in this store. Not an error in the service.</summary>
        public const int NotFound = 1;

        /// <summary>
        /// The paragraph that has to appear wherever voiding is discussed.
        ///
        /// It is here, once, rather than written out at each call site, because
        /// the thing it says is the single most likely thing for an operator to
        /// assume wrongly, and a copy of it somewhere would eventually be the
        /// copy that got softened.
        /// </summary>
        private static void ExplainWhatVoidingCannotDo(TextWriter output, CodeSummary code)
        {
            output.WriteLine();
            output.WriteLine("THIS DOES NOT RECALL A LICENCE ALREADY ISSUED FROM THIS CODE.");

            if (code.ActivationsUsed == 0)
            {
                output.WriteLine("Nothing has ever been activated with it, so in this case there is nothing");
                output.WriteLine("running that could have needed recalling - but that is luck, not a guarantee");
                output.WriteLine("this command offers.");
            }
            else
            {
                output.WriteLine(
                    "  " + code.ActivationsUsed.ToString(CultureInfo.InvariantCulture)
                    + " server(s) have already been given a licence from it"
                    + (code.ExpiresUtc.HasValue
                        ? ", and each keeps working until " + LicenceFormat.Iso(code.ExpiresUtc.Value) + "."
                        : "."));
                output.WriteLine("  `show-code` lists them.");
            }

            output.WriteLine();
            output.WriteLine("The plugin verifies its licence offline against a public key compiled into it and");
            output.WriteLine("never calls this service, so no revocation exists and none can be added here.");
            output.WriteLine("Voiding stops the NEXT activation. That is the whole of what it does. If a refunded");
            output.WriteLine("customer must actually lose the plugin, the only remedy is a new signing keypair and");
            output.WriteLine("a new plugin build - which invalidates every other customer at the same time.");
        }

        // ---------------------------------------------------------------- list

        /// <summary>
        /// `list-codes` - every code, what state it is in, and who it is for.
        /// </summary>
        public static int ListCodes(
            IDictionary<string, string> args,
            ServiceOptions options,
            TextWriter output,
            TextWriter error,
            DateTimeOffset now)
        {
            if (!TryOpenForReading(options, error, out var store, out var failure))
            {
                return failure;
            }

            var soon = Number(args, "soon", CodeInventory.DefaultSoonDays);

            if (soon < 0)
            {
                error.WriteLine("--soon must be a number of days.");

                return NotFound;
            }

            IReadOnlyList<CodeSummary> rows;

            try
            {
                rows = store.ListCodes();
            }
            catch (SqliteException ex)
            {
                return CannotRead(store, error, ex);
            }

            var outbox = OutboxLog.Read(options.OutboxPath, warning => error.WriteLine("warning: " + warning));
            var all = CodeInventory.Build(rows, outbox, now, soon);
            var shown = (IEnumerable<ManagedCode>)all;

            if (args.ContainsKey("needs-attention"))
            {
                shown = shown.Where(code => code.NeedsAttention);
            }

            if (args.TryGetValue("for", out var who) && !string.IsNullOrWhiteSpace(who))
            {
                shown = shown.Where(code =>
                    Contains(code.Code.Licensee, who)
                    || Contains(code.Code.BuyerEmailOrNote, who)
                    || Contains(code.Code.Tag, who));
            }

            var list = shown.ToList();

            if (all.Count == 0)
            {
                output.WriteLine("There are no codes in " + store.Path + " yet.");
                output.WriteLine("The store is there and readable; nothing has been sold or issued.");

                return 0;
            }

            if (list.Count == 0)
            {
                output.WriteLine("None of the " + Count(all.Count, "code") + " in " + store.Path + " match that.");

                return 0;
            }

            var table = new Table("STATE", "CREATED", "TAG", "SOURCE", "USED", "DAYS", "EXPIRES", "FOR");

            foreach (var code in list)
            {
                table.Add(
                    code.StateText,
                    Date(code.Code.CreatedUtc),
                    code.Tag,
                    code.Code.Source,
                    code.Code.ActivationsUsed.ToString(CultureInfo.InvariantCulture) + "/"
                        + code.Code.ActivationsAllowed.ToString(CultureInfo.InvariantCulture),
                    code.Code.LicenceDays.ToString(CultureInfo.InvariantCulture),
                    code.Code.ExpiresUtc.HasValue ? Date(code.Code.ExpiresUtc.Value) : "-",
                    Describe(code.Code));
            }

            table.WriteTo(output);

            var attention = all.Count(code => code.NeedsAttention);

            output.WriteLine();
            output.WriteLine(
                Count(all.Count, "code") + " in " + store.Path + ", "
                + (attention == 0 ? "none needing attention" : attention.ToString(CultureInfo.InvariantCulture) + " needing attention")
                + (list.Count == all.Count ? "." : "; " + list.Count.ToString(CultureInfo.InvariantCulture) + " shown."));

            if (attention > 0 && !args.ContainsKey("needs-attention"))
            {
                output.WriteLine("`list-codes --needs-attention` shows only those.");
            }

            output.WriteLine();
            output.WriteLine("No code appears above and none can: this store holds only their SHA-256 hashes.");
            output.WriteLine("TAG is the first 12 characters of that hash, which is what the logs record and what");
            output.WriteLine("`show-code --tag` and `void-code --tag` take. UNDELIVERED means a line in the outbox");
            output.WriteLine("with no delivery receipt beside it - see `list-outbox`.");

            return 0;
        }

        // ---------------------------------------------------------------- show

        /// <summary>
        /// `show-code` - the support command. Somebody pastes a code into a chat
        /// window and the first question is what it actually is.
        /// </summary>
        public static int ShowCode(
            IDictionary<string, string> args,
            ServiceOptions options,
            TextWriter output,
            TextWriter error,
            DateTimeOffset now)
        {
            if (!TryOpenForReading(options, error, out var store, out var failure))
            {
                return failure;
            }

            if (!TryFindCode(args, store, error, out var code))
            {
                return NotFound;
            }

            var outbox = OutboxLog.Read(options.OutboxPath, warning => error.WriteLine("warning: " + warning));

            outbox.TryFind(code.Tag, out var delivery);

            var state = CodeInventory.Classify(code, delivery, now, Number(args, "soon", CodeInventory.DefaultSoonDays));

            IReadOnlyList<ActivationRow> activations;

            try
            {
                activations = store.ActivationsFor(code.Id);
            }
            catch (SqliteException ex)
            {
                return CannotRead(store, error, ex);
            }

            var lines = new Table();

            lines.Add("Tag", code.Tag + "   (what the logs record; give this to `void-code --tag`)");
            lines.Add("State", new ManagedCode { Code = code, Delivery = delivery, State = state }.StateText);
            lines.Add("Source", code.IsManual ? "issue-code (no payment)" : code.Source);
            lines.Add("Licensee", Empty(code.Licensee));
            lines.Add(code.IsManual ? "Note" : "Buyer", Empty(code.BuyerEmailOrNote));

            if (!code.IsManual)
            {
                lines.Add("PayPal", "capture " + Empty(code.PayPalCaptureId) + ", event " + Empty(code.PayPalEventId));
                lines.Add("Bought from", Empty(code.OriginServerId) + "   (the server id on the /buy link; it binds nothing)");
            }

            lines.Add("Created", LicenceFormat.Iso(code.CreatedUtc));
            lines.Add("Licence", code.LicenceDays.ToString(CultureInfo.InvariantCulture) + " days from first activation");
            lines.Add(
                "Expires",
                code.ExpiresUtc.HasValue
                    ? LicenceFormat.Iso(code.ExpiresUtc.Value) + "   (" + Relative(code.ExpiresUtc.Value, now) + ")"
                    : "-   (fixed at first activation, which has not happened)");
            lines.Add(
                "Activations",
                code.ActivationsUsed.ToString(CultureInfo.InvariantCulture) + " of "
                    + code.ActivationsAllowed.ToString(CultureInfo.InvariantCulture) + " used");
            lines.Add("Delivery", DescribeDelivery(code, delivery));

            if (code.VoidedUtc.HasValue || string.Equals(code.Status, CodeStatus.Void, StringComparison.Ordinal))
            {
                lines.Add(
                    "Voided",
                    (code.VoidedUtc.HasValue ? LicenceFormat.Iso(code.VoidedUtc.Value) : "(before this was recorded)")
                        + "   " + Empty(code.VoidReason));
            }

            lines.WriteTo(output, separator: " : ");

            output.WriteLine();

            if (activations.Count == 0)
            {
                output.WriteLine("No server has ever activated this code.");
            }
            else
            {
                var table = new Table("SERVER", "FIRST SEEN", "LAST SEEN", "ISSUES", "PLUGIN", "LAST LICENCE");

                foreach (var activation in activations)
                {
                    table.Add(
                        activation.ServerId,
                        activation.FirstSeenUtc,
                        activation.LastSeenUtc,
                        activation.IssueCount.ToString(CultureInfo.InvariantCulture),
                        Empty(activation.PluginVersion),
                        Empty(activation.LastFingerprint));
                }

                table.WriteTo(output);

                output.WriteLine();
                output.WriteLine("LAST LICENCE is the fingerprint `licencetool show` prints for a licence somebody");
                output.WriteLine("emails back, so a token in an inbox can be matched to a row above.");
            }

            output.WriteLine();
            output.WriteLine("This command confirms a code it is given. It cannot reveal one: the store holds a");
            output.WriteLine("SHA-256 and never the code itself.");

            return 0;
        }

        // ---------------------------------------------------------------- void

        /// <summary>
        /// `void-code` - a refund, a mistake, a code that leaked.
        /// </summary>
        public static int VoidCode(
            IDictionary<string, string> args,
            ServiceOptions options,
            TextWriter output,
            TextWriter error,
            DateTimeOffset now)
        {
            if (string.IsNullOrWhiteSpace(options.DataDirectory))
            {
                error.WriteLine("LICENCE_DATA_DIR is not set, so there is no store to look in.");

                return ConfigurationError;
            }

            if (!LicenceStore.Exists(options.DatabasePath))
            {
                return SayThereIsNoStore(options, error);
            }

            // ExistingOnly, not CreateIfMissing: this writes, but a void against
            // the wrong directory must still be "there is no store here" rather
            // than a new database with nothing in it.
            var store = new LicenceStore(options.DatabasePath, StoreAccess.ExistingOnly);

            if (!TryFindCode(args, store, error, out var code))
            {
                return NotFound;
            }

            args.TryGetValue("reason", out var reason);

            if (string.IsNullOrWhiteSpace(reason))
            {
                reason = "voided from the command line (no --reason given)";
            }

            VoidOutcome outcome;

            try
            {
                outcome = store.VoidCodeByHash(code.CodeHash, reason, now);
            }
            catch (SqliteException ex)
            {
                error.WriteLine("The store at " + store.Path + " could not be written: " + ex.Message);

                return NoStore;
            }

            switch (outcome)
            {
                case VoidOutcome.NoSuchCode:
                    // It was there a moment ago, when TryFindCode read it.
                    error.WriteLine("The code " + code.Tag + " disappeared between being found and being voided.");

                    return NotFound;

                case VoidOutcome.AlreadyVoid:
                    output.WriteLine("Code " + code.Tag + " (" + Describe(code) + ") was ALREADY void"
                        + (code.VoidedUtc.HasValue ? ", since " + LicenceFormat.Iso(code.VoidedUtc.Value) : string.Empty) + ".");

                    if (!string.IsNullOrWhiteSpace(code.VoidReason))
                    {
                        output.WriteLine("Recorded reason: " + code.VoidReason);
                    }

                    output.WriteLine("Nothing changed. Voiding twice is not an error and does nothing the second time.");
                    ExplainWhatVoidingCannotDo(output, code);

                    return 0;

                default:
                    output.WriteLine("VOIDED code " + code.Tag + " (" + Describe(code) + ").");
                    output.WriteLine("Reason recorded: " + reason);
                    output.WriteLine("It will not activate again. Any attempt now answers `invalid_code`, the same");
                    output.WriteLine("answer an unknown code gets - the caller learns nothing about your account.");
                    ExplainWhatVoidingCannotDo(output, code);

                    return 0;
            }
        }

        // -------------------------------------------------------------- outbox

        /// <summary>
        /// `list-outbox` - the sales that have not reached their buyer.
        /// </summary>
        public static int ListOutbox(
            IDictionary<string, string> args,
            ServiceOptions options,
            TextWriter output,
            TextWriter error,
            DateTimeOffset now)
        {
            if (!TryOpenForReading(options, error, out var store, out var failure))
            {
                return failure;
            }

            var outbox = OutboxLog.Read(options.OutboxPath, warning => error.WriteLine("warning: " + warning));

            if (outbox.Records.Count == 0)
            {
                output.WriteLine("Nothing is waiting to be sent.");
                output.WriteLine("There is no readable outbox at " + options.OutboxPath + " - either nothing has been");
                output.WriteLine("sold yet, or every line has been pruned after sending, which is what pruning means.");

                return 0;
            }

            IReadOnlyList<CodeSummary> rows;

            try
            {
                rows = store.ListCodes();
            }
            catch (SqliteException ex)
            {
                return CannotRead(store, error, ex);
            }

            var byTag = rows.ToDictionary(row => row.Tag, StringComparer.OrdinalIgnoreCase);
            var all = args.ContainsKey("all");
            var reveal = args.ContainsKey("reveal");

            var shown = outbox.Records.Where(record => all || !record.Delivered).ToList();

            if (shown.Count == 0)
            {
                output.WriteLine("Nothing is waiting to be sent: every one of the "
                    + Count(outbox.Records.Count, "code") + " still in " + options.OutboxPath
                    + " has a delivery receipt beside it.");
                output.WriteLine("`list-outbox --all` lists them anyway.");

                return 0;
            }

            var headings = new List<string> { "CREATED", "TAG", "BUYER", "SENT", "ACTS", "DAYS", "CAPTURE", "IN THE STORE" };

            if (reveal)
            {
                headings.Insert(2, "CODE");
            }

            var table = new Table(headings.ToArray());

            foreach (var record in shown)
            {
                var cells = new List<string>
                {
                    Empty(record.CreatedUtc),
                    Empty(record.CodeTag),
                    Empty(record.BuyerEmail),
                    record.Delivered ? Empty(record.DeliveredUtc) : "NO",
                    record.ActivationsAllowed.ToString(CultureInfo.InvariantCulture),
                    record.LicenceDays.ToString(CultureInfo.InvariantCulture),
                    Empty(record.PayPalCaptureId),
                    StoreNote(byTag, record),
                };

                if (reveal)
                {
                    cells.Insert(2, Empty(record.Code));
                }

                table.Add(cells.ToArray());
            }

            table.WriteTo(output);

            var outstanding = outbox.Records.Count(record => !record.Delivered);

            output.WriteLine();
            output.WriteLine(
                Count(outstanding, "code") + " in " + options.OutboxPath + " with no delivery receipt"
                + (all ? "; " + Count(shown.Count, "line") + " shown." : "."));

            if (!reveal && outstanding > 0)
            {
                output.WriteLine();
                output.WriteLine("The codes themselves are NOT above. They are in that file in the clear - it is the");
                output.WriteLine("one place they exist in readable form - and `list-outbox --reveal` prints them into");
                output.WriteLine("this terminal, which is a decision to make deliberately rather than by running a");
                output.WriteLine("listing. Everything else needed to send one by hand is here already.");
            }

            output.WriteLine();
            output.WriteLine("SENT is 'NO' until a successful email appends a receipt. With SMTP_HOST unset no");
            output.WriteLine("receipt is ever written, so send each code and then DELETE ITS LINE from that file:");
            output.WriteLine("a pruned line is how this command knows a code is finished with, and it is also how a");
            output.WriteLine("live credential stops sitting on the disk.");

            return 0;
        }

        // -------------------------------------------------------------- shared

        /// <summary>
        /// Opens the store for a command that must not change anything - and
        /// must not bring a store into existence by looking for one.
        /// </summary>
        private static bool TryOpenForReading(
            ServiceOptions options,
            TextWriter error,
            out LicenceStore store,
            out int failure)
        {
            store = null;
            failure = 0;

            if (string.IsNullOrWhiteSpace(options.DataDirectory))
            {
                error.WriteLine("LICENCE_DATA_DIR is not set, so there is no store to look in.");
                failure = ConfigurationError;

                return false;
            }

            if (!LicenceStore.Exists(options.DatabasePath))
            {
                failure = SayThereIsNoStore(options, error);

                return false;
            }

            store = new LicenceStore(options.DatabasePath, StoreAccess.ReadOnly);

            return true;
        }

        /// <summary>
        /// The message that keeps an operator from reading an empty table as
        /// "no customers". A missing store is almost always the wrong
        /// LICENCE_DATA_DIR, so it says which path it looked at.
        /// </summary>
        private static int SayThereIsNoStore(ServiceOptions options, TextWriter error)
        {
            error.WriteLine("There is no licence store at " + Path.GetFullPath(options.DatabasePath) + ".");
            error.WriteLine();
            error.WriteLine("Nothing was created. This command will not bring a store into existence, because an");
            error.WriteLine("empty table here would read as 'no customers' when what it means is 'wrong directory'.");
            error.WriteLine("LICENCE_DATA_DIR is " + options.DataDirectory + "; inside the container it should be");
            error.WriteLine("/data, and the store appears the first time the service starts.");

            return NoStore;
        }

        /// <summary>
        /// A store that is there and will not be read. Two causes are worth
        /// naming, because neither is guessable from SQLite's message:
        ///
        ///   * a volume from before this version, whose `codes` table has not
        ///     yet been given the columns that record a void. Starting the
        ///     service once adds them;
        ///   * a database left with an unfinished write-ahead log by an unclean
        ///     stop. Recovering that log is a WRITE, and these commands open the
        ///     file read-only precisely so they cannot do one. Starting the
        ///     service - which opens it for writing - recovers it.
        ///
        /// Both fixes are the same sentence, which is why it is one message.
        /// </summary>
        private static int CannotRead(LicenceStore store, TextWriter error, SqliteException ex)
        {
            error.WriteLine("The store at " + store.Path + " could not be read: " + ex.Message);
            error.WriteLine();
            error.WriteLine("These commands open it read-only and will not write to it, so two things they");
            error.WriteLine("cannot do for you are adding a column a newer service needs and recovering a");
            error.WriteLine("write-ahead log left behind by an unclean stop. Starting the service once does");
            error.WriteLine("both. Nothing here was changed.");

            return NoStore;
        }

        /// <summary>
        /// Turns `--code` or `--tag` into a row, or explains why it could not.
        ///
        /// `--code` takes the code in whatever shape a human sends it: any case,
        /// with or without the hyphens, with whitespace round it, and with I, L
        /// and O read as the 1, 1 and 0 they were meant to be. That is the same
        /// normalisation /v1/activate applies, so a code this rejects is a code
        /// the service would also refuse.
        /// </summary>
        private static bool TryFindCode(
            IDictionary<string, string> args,
            LicenceStore store,
            TextWriter error,
            out CodeSummary code)
        {
            code = null;

            args.TryGetValue("code", out var typed);
            args.TryGetValue("tag", out var tag);

            var hasCode = !string.IsNullOrWhiteSpace(typed);
            var hasTag = !string.IsNullOrWhiteSpace(tag);

            if (hasCode == hasTag)
            {
                error.WriteLine(hasCode
                    ? "Give either --code or --tag, not both."
                    : "Give --code <the code the customer typed> or --tag <the 12 characters the logs show>.");

                return false;
            }

            try
            {
                if (hasCode)
                {
                    if (!RedemptionCode.TryNormalise(typed, out var normalised))
                    {
                        error.WriteLine("That is not a well-formed redemption code, whatever else it is.");
                        error.WriteLine("A code is " + RedemptionCode.Symbols.ToString(CultureInfo.InvariantCulture)
                            + " characters from " + RedemptionCode.Alphabet + ", usually written in groups of five.");
                        error.WriteLine("Nothing was looked up: /v1/activate would refuse this one before reaching the store.");

                        return false;
                    }

                    code = store.FindCodeByHash(RedemptionCode.Hash(normalised));

                    if (code == null)
                    {
                        error.WriteLine("That is a well-formed code, and this store has never held it.");
                        error.WriteLine("It was issued by a different service, mistyped in a way that is still");
                        error.WriteLine("well-formed, or invented.");

                        return false;
                    }

                    return true;
                }

                var prefix = tag.Trim().ToLowerInvariant();

                if (prefix.Length < 4 || !prefix.All(Uri.IsHexDigit))
                {
                    error.WriteLine("--tag is hexadecimal, at least 4 characters: the start of the code's SHA-256,");
                    error.WriteLine("which is what `code=` in the log lines and TAG in `list-codes` show.");

                    return false;
                }

                var matches = store.FindCodesByHashPrefix(prefix);

                if (matches.Count == 0)
                {
                    error.WriteLine("No code in this store has a hash starting " + prefix + ".");

                    return false;
                }

                if (matches.Count > 1)
                {
                    error.WriteLine(Count(matches.Count, "code") + " start with " + prefix + ". Give more of it:");

                    foreach (var match in matches)
                    {
                        error.WriteLine("  " + match.Tag + "  " + Describe(match));
                    }

                    return false;
                }

                code = matches[0];

                return true;
            }
            catch (SqliteException ex)
            {
                error.WriteLine("The store at " + store.Path + " could not be read: " + ex.Message);

                return false;
            }
        }

        private static string DescribeDelivery(CodeSummary code, OutboxRecord delivery)
        {
            if (delivery == null)
            {
                return code.IsManual
                    ? "n/a - `issue-code` printed this one to whoever ran it"
                    : "no line in the outbox: sent and pruned, or written before this service kept one";
            }

            return delivery.Delivered
                ? "emailed to " + Empty(delivery.DeliveredTo) + " at " + Empty(delivery.DeliveredUtc)
                : "NOT SENT - line " + delivery.LineNumber.ToString(CultureInfo.InvariantCulture)
                    + " of the outbox, with no receipt beside it";
        }

        private static string StoreNote(IDictionary<string, CodeSummary> byTag, OutboxRecord record)
        {
            if (!byTag.TryGetValue(record.CodeTag ?? string.Empty, out var code))
            {
                return "NO SUCH CODE";
            }

            if (string.Equals(code.Status, CodeStatus.Void, StringComparison.Ordinal))
            {
                return "void - do not send";
            }

            if (code.ActivationsUsed > 0)
            {
                return "already activated " + code.ActivationsUsed.ToString(CultureInfo.InvariantCulture) + "x";
            }

            return "waiting";
        }

        private static string Describe(CodeSummary code)
        {
            var who = string.IsNullOrWhiteSpace(code.Licensee) ? "(no licensee)" : code.Licensee;

            if (string.IsNullOrWhiteSpace(code.BuyerEmailOrNote)
                || string.Equals(code.BuyerEmailOrNote, code.Licensee, StringComparison.OrdinalIgnoreCase))
            {
                return who;
            }

            // Angle brackets for a buyer's address, parentheses for a note. A
            // comp's `--note` lives in the same column as a buyer's email (see
            // CodeSummary.BuyerEmailOrNote) and must not be dressed up as one.
            return code.IsManual
                ? who + " (" + code.BuyerEmailOrNote + ")"
                : who + " <" + code.BuyerEmailOrNote + ">";
        }

        private static bool Contains(string haystack, string needle)
        {
            return haystack != null && haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string Empty(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "-" : value;
        }

        private static string Date(DateTimeOffset when)
        {
            return when.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        }

        private static string Relative(DateTimeOffset when, DateTimeOffset now)
        {
            var days = (int)Math.Floor((when - now).TotalDays);

            if (days < 0)
            {
                return "lapsed " + (-days).ToString(CultureInfo.InvariantCulture) + " days ago";
            }

            return "in " + days.ToString(CultureInfo.InvariantCulture) + " days";
        }

        private static string Count(int number, string noun)
        {
            return number.ToString(CultureInfo.InvariantCulture) + " " + noun + (number == 1 ? string.Empty : "s");
        }

        private static int Number(IDictionary<string, string> args, string name, int fallback)
        {
            if (!args.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
            {
                return fallback;
            }

            return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) ? number : -1;
        }

        /// <summary>
        /// A plain aligned table. Every column is padded to its widest cell
        /// except the last, which is left ragged so a long licensee never pushes
        /// the line past a terminal's width for every other row.
        /// </summary>
        private sealed class Table
        {
            private readonly List<string[]> _rows = new List<string[]>();
            private readonly string[] _headings;

            public Table(params string[] headings)
            {
                _headings = headings != null && headings.Length > 0 ? headings : null;
            }

            public void Add(params string[] cells)
            {
                _rows.Add(cells);
            }

            public void WriteTo(TextWriter output, string separator = "  ")
            {
                var columns = _rows.Count == 0 ? 0 : _rows.Max(row => row.Length);

                if (_headings != null)
                {
                    columns = Math.Max(columns, _headings.Length);
                }

                var widths = new int[columns];

                foreach (var row in Rows())
                {
                    for (var i = 0; i < row.Length; i++)
                    {
                        widths[i] = Math.Max(widths[i], (row[i] ?? string.Empty).Length);
                    }
                }

                foreach (var row in Rows())
                {
                    var line = new StringBuilder();

                    for (var i = 0; i < row.Length; i++)
                    {
                        if (i > 0)
                        {
                            line.Append(separator);
                        }

                        var cell = row[i] ?? string.Empty;

                        line.Append(i == row.Length - 1 ? cell : cell.PadRight(widths[i]));
                    }

                    output.WriteLine(line.ToString().TrimEnd());
                }
            }

            private IEnumerable<string[]> Rows()
            {
                if (_headings != null)
                {
                    yield return _headings;
                }

                foreach (var row in _rows)
                {
                    yield return row;
                }
            }
        }
    }
}

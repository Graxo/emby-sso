using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Management;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The four management commands, driven the way an operator drives them:
    /// through the same argument parser <c>Main</c> uses, against a real store
    /// in a temporary directory.
    ///
    /// The promises being held up here are the ones that are easy to break by
    /// accident later:
    ///
    ///   * no command prints a code the store holds only as a hash;
    ///   * a read-only command against a missing store says so and creates
    ///     nothing;
    ///   * `void-code` says, in its own output, that it cannot recall a licence
    ///     that has already been issued;
    ///   * `show-code` finds a code however a human spelled it.
    /// </summary>
    public class ManagementCommandTests : IDisposable
    {
        private const string ServerA = "c5bc6e91458540caa295c4efdda1a58a";
        private const string ServerB = "aaaa1111bbbb2222cccc3333dddd4444";

        private readonly TestService _service = new TestService();

        public void Dispose()
        {
            _service.Dispose();
        }

        // ------------------------------------------------ the missing store

        [Theory]
        [InlineData("list-codes")]
        [InlineData("show-code", "--tag", "abcdef01")]
        [InlineData("list-outbox")]
        public void A_read_only_command_against_a_missing_store_fails_and_creates_nothing(params string[] command)
        {
            var elsewhere = Elsewhere();

            var run = Run(command, elsewhere);

            Assert.Equal(ManagementCommands.NoStore, run.ExitCode);
            Assert.Contains("There is no licence store at", run.Error);
            Assert.Contains("Nothing was created", run.Error);
            Assert.False(File.Exists(elsewhere.DatabasePath), "the command created a database it was only meant to read");
        }

        [Fact]
        public void Void_against_a_missing_store_also_creates_nothing()
        {
            var elsewhere = Elsewhere();

            var run = Run(new[] { "void-code", "--tag", "abcdef01" }, elsewhere);

            Assert.Equal(ManagementCommands.NoStore, run.ExitCode);
            Assert.False(File.Exists(elsewhere.DatabasePath));
        }

        [Fact]
        public void An_empty_store_that_does_exist_says_it_is_empty_rather_than_missing()
        {
            var run = Run(new[] { "list-codes" });

            Assert.Equal(0, run.ExitCode);
            Assert.Contains("no codes in", run.Output);
            Assert.DoesNotContain("There is no licence store", run.Output + run.Error);
        }

        [Fact]
        public void A_read_only_command_leaves_the_store_byte_for_byte_as_it_found_it()
        {
            _service.GiveOutACode();

            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

            var before = Digest(_service.Options.DatabasePath);

            Assert.Equal(0, Run(new[] { "list-codes" }).ExitCode);

            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

            Assert.Equal(before, Digest(_service.Options.DatabasePath));
        }

        // -------------------------------------------------------- list-codes

        [Fact]
        public void List_never_prints_a_code()
        {
            var code = _service.GiveOutACode();

            var run = Run(new[] { "list-codes" });

            Assert.Equal(0, run.ExitCode);
            Assert.DoesNotContain(code, run.Output);
            Assert.DoesNotContain(code.Replace("-", string.Empty), run.Output);
            Assert.Contains("No code appears above and none can", run.Output);
        }

        [Fact]
        public void List_shows_the_tag_the_logs_use_and_the_counts()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var run = Run(new[] { "list-codes" });

            Assert.Contains(RedemptionCode.LogTag(HashOf(code)), run.Output);
            Assert.Contains("1/3", run.Output);
            Assert.Contains("365", run.Output);
        }

        [Fact]
        public void List_puts_what_needs_attention_first_and_can_show_only_that()
        {
            var quiet = _service.GiveOutACode();
            var undelivered = _service.GiveOutACode();

            WriteOutbox(undelivered, "buyer@example.com", delivered: false);

            var run = Run(new[] { "list-codes" });

            var attentionLine = run.Output.IndexOf("UNDELIVERED", StringComparison.Ordinal);
            var quietLine = run.Output.IndexOf(RedemptionCode.LogTag(HashOf(quiet)), StringComparison.Ordinal);

            Assert.True(attentionLine >= 0 && attentionLine < quietLine, "the undelivered code was not at the top");

            var narrowed = Run(new[] { "list-codes", "--needs-attention" });

            Assert.Contains(RedemptionCode.LogTag(HashOf(undelivered)), narrowed.Output);
            Assert.DoesNotContain(RedemptionCode.LogTag(HashOf(quiet)), narrowed.Output);
        }

        [Fact]
        public void List_can_be_narrowed_to_one_customer()
        {
            _service.Store.CreateManualCode(Hash('1'), "Acme Media", 3, 365, "acme@example.com", _service.Clock.GetUtcNow());
            _service.Store.CreateManualCode(Hash('2'), "Other Person", 3, 365, "other@example.com", _service.Clock.GetUtcNow());

            var run = Run(new[] { "list-codes", "--for", "acme@" });

            Assert.Contains("Acme Media", run.Output);
            Assert.DoesNotContain("Other Person", run.Output);
        }

        // --------------------------------------------------------- show-code

        [Theory]
        [InlineData("as issued")]
        [InlineData("lower case")]
        [InlineData("no separators")]
        [InlineData("spaces instead")]
        [InlineData("surrounded by whitespace")]
        [InlineData("with the letters people mistype")]
        public void Show_finds_a_code_however_a_human_spelled_it(string spelling)
        {
            var code = _service.GiveOutACode();
            var typed = Respell(code, spelling);

            var run = Run(new[] { "show-code", "--code", typed });

            Assert.Equal(0, run.ExitCode);
            Assert.Contains(RedemptionCode.LogTag(HashOf(code)), run.Output);
        }

        [Fact]
        public void Show_does_not_echo_the_code_it_was_given()
        {
            // Support output gets pasted into chat windows and bug reports. The
            // code that was typed in must not come back out of this command.
            var code = _service.GiveOutACode();

            var run = Run(new[] { "show-code", "--code", code });

            Assert.DoesNotContain(code, run.Output);
            Assert.DoesNotContain(code.Replace("-", string.Empty), run.Output);
            Assert.Contains("It cannot reveal one", run.Output);
        }

        [Fact]
        public void Show_lists_every_server_the_code_has_been_activated_onto()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);
            Activate(code, ServerB);

            var run = Run(new[] { "show-code", "--code", code });

            Assert.Contains(ServerA, run.Output);
            Assert.Contains(ServerB, run.Output);
            Assert.Contains("2 of 3 used", run.Output);
        }

        [Fact]
        public void Show_of_a_well_formed_code_this_store_never_held_says_exactly_that()
        {
            var stranger = RedemptionCode.Format(RedemptionCode.Generate());

            var run = Run(new[] { "show-code", "--code", stranger });

            Assert.Equal(ManagementCommands.NotFound, run.ExitCode);
            Assert.Contains("never held it", run.Error);
        }

        [Fact]
        public void Show_of_something_that_is_not_a_code_does_not_even_look_it_up()
        {
            var run = Run(new[] { "show-code", "--code", "have you tried turning it off and on again" });

            Assert.Equal(ManagementCommands.NotFound, run.ExitCode);
            Assert.Contains("not a well-formed redemption code", run.Error);
        }

        [Fact]
        public void Show_needs_one_of_code_or_tag_and_not_both()
        {
            Assert.Equal(ManagementCommands.NotFound, Run(new[] { "show-code" }).ExitCode);
            Assert.Equal(
                ManagementCommands.NotFound,
                Run(new[] { "show-code", "--code", "x", "--tag", "abcdef01" }).ExitCode);
        }

        [Fact]
        public void A_tag_that_matches_more_than_one_code_is_refused_rather_than_guessed()
        {
            _service.Store.CreateManualCode("abcdef0000" + new string('1', 54), "First", 3, 365, null, _service.Clock.GetUtcNow());
            _service.Store.CreateManualCode("abcdef0000" + new string('2', 54), "Second", 3, 365, null, _service.Clock.GetUtcNow());

            var run = Run(new[] { "show-code", "--tag", "abcdef" });

            Assert.Equal(ManagementCommands.NotFound, run.ExitCode);
            Assert.Contains("2 codes start with abcdef", run.Error);
            Assert.Contains("First", run.Error);
            Assert.Contains("Second", run.Error);
        }

        // --------------------------------------------------------- void-code

        [Fact]
        public void A_voided_code_refuses_the_next_activation()
        {
            var code = _service.GiveOutACode();

            Assert.True(Activate(code, ServerA).IsSuccess);
            Assert.Equal(0, Run(new[] { "void-code", "--code", code, "--reason", "refunded" }).ExitCode);

            var afterwards = Activate(code, ServerB);

            Assert.False(afterwards.IsSuccess);

            // The same answer an unknown code gets: the caller learns nothing
            // about the vendor's account from having been refused.
            Assert.Equal(ActivationError.InvalidCode, afterwards.Error);
        }

        [Fact]
        public void Void_says_in_its_own_output_that_it_cannot_recall_a_licence_already_issued()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var run = Run(new[] { "void-code", "--code", code, "--reason", "refunded" });

            Assert.Equal(0, run.ExitCode);
            Assert.Contains("THIS DOES NOT RECALL A LICENCE ALREADY ISSUED FROM THIS CODE.", run.Output);
            Assert.Contains("1 server(s) have already been given a licence from it", run.Output);
            Assert.Contains("never calls this service", run.Output);
        }

        [Fact]
        public void Void_of_a_code_nobody_has_used_still_says_what_voiding_cannot_do()
        {
            var code = _service.GiveOutACode();

            var run = Run(new[] { "void-code", "--code", code });

            Assert.Contains("THIS DOES NOT RECALL A LICENCE ALREADY ISSUED FROM THIS CODE.", run.Output);
        }

        [Fact]
        public void Voiding_twice_is_not_an_error_and_keeps_the_first_reason()
        {
            var code = _service.GiveOutACode();

            Assert.Equal(0, Run(new[] { "void-code", "--code", code, "--reason", "refunded, case 12345" }).ExitCode);

            var again = Run(new[] { "void-code", "--code", code, "--reason", "a different reason" });

            Assert.Equal(0, again.ExitCode);
            Assert.Contains("ALREADY void", again.Output);
            Assert.Contains("refunded, case 12345", again.Output);
            Assert.Contains("THIS DOES NOT RECALL A LICENCE ALREADY ISSUED FROM THIS CODE.", again.Output);
        }

        [Fact]
        public void Void_records_when_and_why_so_show_code_can_answer_for_it_later()
        {
            var code = _service.GiveOutACode();

            Run(new[] { "void-code", "--code", code, "--reason", "leaked on a forum" });

            var shown = Run(new[] { "show-code", "--code", code });

            Assert.Contains("Voided", shown.Output);
            Assert.Contains("leaked on a forum", shown.Output);
        }

        [Fact]
        public void Void_of_a_code_this_store_never_held_changes_nothing()
        {
            var mine = _service.GiveOutACode();
            var stranger = RedemptionCode.Format(RedemptionCode.Generate());

            var run = Run(new[] { "void-code", "--code", stranger });

            Assert.Equal(ManagementCommands.NotFound, run.ExitCode);
            Assert.True(Activate(mine, ServerA).IsSuccess);
        }

        /// <summary>
        /// The refund webhook and this command must not be two definitions of
        /// what voided means. They are one method on the store; this asserts
        /// they leave a row in the same state.
        /// </summary>
        [Fact]
        public void The_command_and_a_refund_leave_the_code_in_the_same_state()
        {
            var byCommand = _service.GiveOutACode();

            Run(new[] { "void-code", "--code", byCommand, "--reason", "by hand" });

            _service.Store.CreateManualCode(Hash('7'), "Refunded", 3, 365, null, _service.Clock.GetUtcNow());

            // The refund path finds its code by capture id; give this one one.
            using (var connection = new Microsoft.Data.Sqlite.SqliteConnection(
                "Data Source=" + _service.Options.DatabasePath))
            {
                connection.Open();

                using var command = connection.CreateCommand();

                command.CommandText = "UPDATE codes SET paypal_capture_id = 'CAPTURE-X' WHERE code_hash = $h;";
                command.Parameters.AddWithValue("$h", Hash('7'));
                command.ExecuteNonQuery();
            }

            Assert.True(_service.Store.VoidCodeForCapture("CAPTURE-X", _service.Clock.GetUtcNow()));

            Assert.Equal(CodeStatus.Void, _service.Store.FindCodeByHash(HashOf(byCommand)).Status);
            Assert.Equal(CodeStatus.Void, _service.Store.FindCodeByHash(Hash('7')).Status);

            // And the second refund event for the same capture is not a failure.
            Assert.False(_service.Store.VoidCodeForCapture("CAPTURE-X", _service.Clock.GetUtcNow()));
        }

        // ------------------------------------------------------- list-outbox

        [Fact]
        public void The_outbox_lists_what_has_no_delivery_receipt_and_not_what_has_one()
        {
            var waiting = _service.GiveOutACode();
            var sent = _service.GiveOutACode();

            WriteOutbox(waiting, "waiting@example.com", delivered: false);
            WriteOutbox(sent, "sent@example.com", delivered: true);

            var run = Run(new[] { "list-outbox" });

            Assert.Equal(0, run.ExitCode);
            Assert.Contains("waiting@example.com", run.Output);
            Assert.DoesNotContain("sent@example.com", run.Output);
        }

        [Fact]
        public void The_outbox_does_not_print_codes_unless_it_is_asked_to()
        {
            var waiting = _service.GiveOutACode();

            WriteOutbox(waiting, "waiting@example.com", delivered: false);

            var quiet = Run(new[] { "list-outbox" });

            Assert.DoesNotContain(waiting, quiet.Output);
            Assert.Contains("--reveal", quiet.Output);

            var revealed = Run(new[] { "list-outbox", "--reveal" });

            // The outbox file holds the code in the clear - that is what it is
            // for - so this one command can read it back on request.
            Assert.Contains(waiting, revealed.Output);
        }

        [Fact]
        public void The_outbox_says_when_a_waiting_code_has_since_been_voided()
        {
            var refunded = _service.GiveOutACode();

            WriteOutbox(refunded, "refunded@example.com", delivered: false);
            Run(new[] { "void-code", "--code", refunded, "--reason", "refunded" });

            var run = Run(new[] { "list-outbox" });

            Assert.Contains("void - do not send", run.Output);
        }

        [Fact]
        public void No_outbox_file_is_nothing_waiting_rather_than_an_error()
        {
            _service.GiveOutACode();

            var run = Run(new[] { "list-outbox" });

            Assert.Equal(0, run.ExitCode);
            Assert.Contains("Nothing is waiting to be sent", run.Output);
        }

        [Fact]
        public void A_damaged_outbox_line_is_skipped_with_its_line_number_and_hides_nothing()
        {
            var waiting = _service.GiveOutACode();

            File.WriteAllText(_service.Options.OutboxPath, "{ this is not json" + Environment.NewLine);
            WriteOutbox(waiting, "waiting@example.com", delivered: false);

            var run = Run(new[] { "list-outbox" });

            Assert.Equal(0, run.ExitCode);
            Assert.Contains("line 1", run.Error);
            Assert.Contains("waiting@example.com", run.Output);
        }

        // ------------------------------------------------------------ usage

        /// <summary>
        /// A command nobody can find is a command that does not exist. This
        /// reads the same string `--help` prints rather than redirecting the
        /// console, which is process-wide state the rest of the suite shares.
        /// </summary>
        [Fact]
        public void Every_command_the_binary_answers_to_is_in_the_usage_text()
        {
            foreach (var command in new[] { "issue-code", "list-codes", "show-code", "void-code", "list-outbox", "healthcheck" })
            {
                Assert.Contains(command, Program.Usage);
            }

            // And the two things an operator has to be told, in the place they
            // will actually look.
            Assert.Contains("NO CODE IS PRINTED", Program.Usage);
            Assert.Contains("recall a licence already issued", Program.Usage);
        }

        // ----------------------------------------------------------- helpers

        private sealed class CommandRun
        {
            public int ExitCode { get; set; }

            public string Output { get; set; }

            public string Error { get; set; }
        }

        /// <summary>
        /// Runs one command through the same argument parser <c>Main</c> uses,
        /// so a test drives what an operator types rather than a dictionary the
        /// test made up.
        /// </summary>
        private CommandRun Run(string[] command, ServiceOptions options = null)
        {
            var output = new StringWriter();
            var error = new StringWriter();
            var args = Program.ParseArguments(command);
            var target = options ?? _service.Options;
            var now = _service.Clock.GetUtcNow();

            int exit;

            switch (command[0])
            {
                case "list-codes":
                    exit = ManagementCommands.ListCodes(args, target, output, error, now);
                    break;

                case "show-code":
                    exit = ManagementCommands.ShowCode(args, target, output, error, now);
                    break;

                case "void-code":
                    exit = ManagementCommands.VoidCode(args, target, output, error, now);
                    break;

                case "list-outbox":
                    exit = ManagementCommands.ListOutbox(args, target, output, error, now);
                    break;

                default:
                    throw new ArgumentException("no such command: " + command[0]);
            }

            return new CommandRun { ExitCode = exit, Output = output.ToString(), Error = error.ToString() };
        }

        private ServiceOptions Elsewhere()
        {
            return new ServiceOptions { DataDirectory = TestKeys.TempDirectory() };
        }

        private ActivationReply Activate(string code, string serverId)
        {
            // Through the whole round trip - activate, sign, activate - because
            // these tests care whether a code still works, and a code that works
            // is one that ends in a licence.
            return _service.ActivateAndSign(
                new ActivationRequest { Code = code, ServerId = serverId },
                "10.0.0.1");
        }

        private void WriteOutbox(string code, string buyer, bool delivered)
        {
            var tag = RedemptionCode.LogTag(HashOf(code));
            var lines = new List<string>
            {
                "{\"created_utc\":\"2026-01-01T00:00:00Z\",\"delivered\":false,\"code\":\"" + code
                    + "\",\"code_tag\":\"" + tag + "\",\"licensee\":\"" + buyer + "\",\"buyer_email\":\"" + buyer
                    + "\",\"activations_allowed\":3,\"licence_days\":365,\"paypal_capture_id\":\"CAPTURE-" + tag + "\"}",
            };

            if (delivered)
            {
                lines.Add("{\"record\":\"delivered\",\"delivered_utc\":\"2026-01-01T00:01:00Z\",\"delivered\":true,"
                    + "\"code_tag\":\"" + tag + "\",\"recipient\":\"" + buyer + "\"}");
            }

            File.AppendAllLines(_service.Options.OutboxPath, lines);
        }

        private static string HashOf(string formatted)
        {
            Assert.True(RedemptionCode.TryNormalise(formatted, out var normalised));

            return RedemptionCode.Hash(normalised);
        }

        private static string Hash(char filler)
        {
            return new string(filler, 64);
        }

        private static string Digest(string path)
        {
            using var stream = File.OpenRead(path);

            return Convert.ToHexString(SHA256.HashData(stream));
        }

        /// <summary>Every shape of the same code a customer might actually send.</summary>
        private static string Respell(string code, string how)
        {
            switch (how)
            {
                case "lower case":
                    return code.ToLowerInvariant();

                case "no separators":
                    return code.Replace("-", string.Empty);

                case "spaces instead":
                    return code.Replace('-', ' ');

                case "surrounded by whitespace":
                    return "  \t" + code + "\n";

                case "with the letters people mistype":
                    // Crockford excludes I, L and O so that nothing ever draws
                    // them; a person reading a code aloud puts them back. The
                    // normaliser maps them to the 1, 1 and 0 they were.
                    return code.Replace('1', 'I').Replace('0', 'O');

                default:
                    return code;
            }
        }
    }
}

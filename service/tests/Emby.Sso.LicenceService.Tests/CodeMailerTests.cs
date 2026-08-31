using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The retry rules, and the two properties that matter more than any of them:
    /// the code is in the outbox whatever happens, and neither the code nor the
    /// SMTP password ever reaches a log line.
    /// </summary>
    public class CodeMailerTests : IDisposable
    {
        private readonly string _directory = TestKeys.TempDirectory();

        [Fact]
        public async Task A_successful_send_carries_the_code_to_the_buyer()
        {
            var transport = new FakeSmtpTransport();
            var entry = CodeMessageTests.Entry(out var code);
            var mailer = Mailer(transport, out var outbox, out _);

            Assert.Equal(MailOutcome.Sent, await mailer.DeliverAsync(entry, CancellationToken.None));

            var sent = Assert.Single(transport.Sent);

            Assert.Equal("buyer@example.com", sent.ToAddress);
            Assert.Contains(RedemptionCode.Format(code), sent.Body, StringComparison.Ordinal);
            Assert.Equal(1, transport.Attempts);
            Assert.NotNull(outbox);
        }

        [Fact]
        public async Task A_relay_that_is_briefly_down_costs_a_retry_and_nothing_else()
        {
            // The case the retry exists for: a relay restarting while somebody
            // pays. Losing that sale to a five-second outage would be absurd.
            var transport = new FakeSmtpTransport()
                .ThenFail("connection refused", permanent: false)
                .ThenFail("connection refused", permanent: false);

            var mailer = Mailer(transport, out _, out var log);

            Assert.Equal(MailOutcome.Sent, await mailer.DeliverAsync(CodeMessageTests.Entry(out _), CancellationToken.None));
            Assert.Equal(3, transport.Attempts);
            Assert.Single(transport.Sent);
            Assert.Empty(log.At(LogLevel.Error));
        }

        [Fact]
        public async Task Retries_are_bounded_and_then_it_gives_up_loudly()
        {
            var transport = new FakeSmtpTransport().AlwaysFail("connection refused", permanent: false);
            var mailer = Mailer(transport, out _, out var log, attempts: 4);

            Assert.Equal(MailOutcome.Failed, await mailer.DeliverAsync(CodeMessageTests.Entry(out _), CancellationToken.None));

            Assert.Equal(4, transport.Attempts);
            Assert.Contains(log.At(LogLevel.Error), l => l.Rendered.Contains("EMAIL FAILED", StringComparison.Ordinal));

            // The line has to tell the operator what to do about it.
            Assert.Contains(log.At(LogLevel.Error), l => l.Rendered.Contains("send it", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task A_permanent_refusal_is_not_retried_at_all()
        {
            // "No such mailbox" and "bad password" do not get better. Retrying
            // them only delays the log line the operator has to act on.
            var transport = new FakeSmtpTransport().AlwaysFail("550 no such user", permanent: true);
            var mailer = Mailer(transport, out _, out var log, attempts: 4);

            Assert.Equal(MailOutcome.Refused, await mailer.DeliverAsync(CodeMessageTests.Entry(out _), CancellationToken.None));

            Assert.Equal(1, transport.Attempts);
            Assert.Contains(log.At(LogLevel.Error), l => l.Rendered.Contains("EMAIL FAILED", StringComparison.Ordinal));
        }

        [Fact]
        public async Task An_unexpected_exception_is_treated_as_transient_and_still_never_escapes()
        {
            var transport = new FakeSmtpTransport()
                .ThenThrow(new InvalidOperationException("something nobody predicted"));

            var mailer = Mailer(transport, out _, out _);

            Assert.Equal(MailOutcome.Sent, await mailer.DeliverAsync(CodeMessageTests.Entry(out _), CancellationToken.None));
        }

        [Fact]
        public async Task A_total_failure_leaves_the_code_in_the_outbox_exactly_as_before()
        {
            // The fallback IS the old behaviour. After every attempt has failed,
            // what the operator has in front of them is the file they use today.
            var entry = CodeMessageTests.Entry(out var code);
            var transport = new FakeSmtpTransport().AlwaysFail("connection refused", permanent: false);
            var mailer = Mailer(transport, out var outbox, out _);

            outbox.Append(entry);

            await mailer.DeliverAsync(entry, CancellationToken.None);

            var lines = File.ReadAllLines(outbox.Path);

            Assert.Single(lines);
            Assert.Contains(RedemptionCode.Format(code), lines[0], StringComparison.Ordinal);
            Assert.Contains("\"delivered\":false", lines[0], StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_successful_send_appends_a_receipt_that_does_not_contain_the_code()
        {
            var entry = CodeMessageTests.Entry(out var code);
            var mailer = Mailer(new FakeSmtpTransport(), out var outbox, out _);

            outbox.Append(entry);

            await mailer.DeliverAsync(entry, CancellationToken.None);

            var lines = File.ReadAllLines(outbox.Path);

            Assert.Equal(2, lines.Length);
            Assert.Contains("\"record\":\"delivered\"", lines[1], StringComparison.Ordinal);
            Assert.Contains("buyer@example.com", lines[1], StringComparison.Ordinal);

            // The receipt outlives the code line, so it must be safe to keep.
            Assert.DoesNotContain(RedemptionCode.Format(code), lines[1], StringComparison.Ordinal);
            Assert.DoesNotContain(code, lines[1], StringComparison.OrdinalIgnoreCase);

            // It names the code by the same hash tag every log line uses.
            Assert.Contains(RedemptionCode.LogTag(RedemptionCode.Hash(code)), lines[1], StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_buyer_with_no_email_address_is_a_warning_and_not_a_retry_loop()
        {
            var entry = CodeMessageTests.Entry(out _);

            entry.BuyerEmail = null;

            var transport = new FakeSmtpTransport();
            var mailer = Mailer(transport, out _, out var log);

            Assert.Equal(MailOutcome.NoRecipient, await mailer.DeliverAsync(entry, CancellationToken.None));

            Assert.Equal(0, transport.Attempts);
            Assert.Contains(log.At(LogLevel.Warning), l => l.Rendered.Contains("outbox", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task Shutdown_gives_up_rather_than_hanging_on_to_the_code()
        {
            using var stopping = new CancellationTokenSource();

            var transport = new FakeSmtpTransport().AlwaysFail("connection refused", permanent: false);

            var mailer = new CodeMailer(
                MailWith(attempts: 4),
                transport,
                new CodeOutbox(Path.Combine(_directory, "codes-outbox.jsonl")),
                CodeMessage.DefaultTemplate,
                new RecordingLogger<CodeMailer>(),
                (wait, token) =>
                {
                    stopping.Cancel();

                    return Task.FromCanceled(token);
                });

            Assert.Equal(
                MailOutcome.Abandoned,
                await mailer.DeliverAsync(CodeMessageTests.Entry(out _), stopping.Token));
        }

        [Fact]
        public async Task No_log_line_anywhere_contains_the_redemption_code()
        {
            // The single most important assertion in this file. Every path -
            // success, transient failure, permanent refusal, no recipient - is
            // driven, and then the entire rendered log is searched for the code
            // in both the grouped and the ungrouped form.
            var lines = new List<string>();

            foreach (var transport in new[]
            {
                new FakeSmtpTransport(),
                new FakeSmtpTransport().ThenFail("connection refused", permanent: false),
                new FakeSmtpTransport().AlwaysFail("connection refused", permanent: false),
                new FakeSmtpTransport().AlwaysFail("550 no such user", permanent: true),
            })
            {
                var entry = CodeMessageTests.Entry(out var code);
                var mailer = Mailer(transport, out _, out var log);

                await mailer.DeliverAsync(entry, CancellationToken.None);

                Assert.DoesNotContain(code, log.Everything, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(RedemptionCode.Format(code), log.Everything, StringComparison.OrdinalIgnoreCase);

                lines.Add(log.Everything);
            }

            // And it is not that nothing was logged.
            Assert.Contains(lines, l => l.Length > 0);
        }

        [Fact]
        public async Task No_log_line_anywhere_contains_the_smtp_password()
        {
            // Same treatment PAYPAL_CLIENT_SECRET gets: the value is handed to
            // one library call and named nowhere else, including in the error
            // paths, where a "here is what I tried" message is the usual way a
            // secret escapes.
            var mail = MailWith(attempts: 2);

            mail.Password = "correct-horse-battery-staple";

            var log = new RecordingLogger<CodeMailer>();

            var mailer = new CodeMailer(
                mail,
                new FakeSmtpTransport().AlwaysFail("the relay refused the SMTP login for user 'licences@example.com'", permanent: true),
                new CodeOutbox(Path.Combine(_directory, "codes-outbox.jsonl")),
                CodeMessage.DefaultTemplate,
                log,
                NoDelay);

            await mailer.DeliverAsync(CodeMessageTests.Entry(out _), CancellationToken.None);

            Assert.NotEmpty(log.Everything);
            Assert.DoesNotContain("correct-horse-battery-staple", log.Everything, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task The_failure_log_names_the_relay_so_it_can_be_fixed()
        {
            var log = new RecordingLogger<CodeMailer>();

            var mailer = new CodeMailer(
                MailWith(attempts: 1),
                new FakeSmtpTransport().AlwaysFail("connection refused", permanent: false),
                new CodeOutbox(Path.Combine(_directory, "codes-outbox.jsonl")),
                CodeMessage.DefaultTemplate,
                log,
                NoDelay);

            await mailer.DeliverAsync(CodeMessageTests.Entry(out _), CancellationToken.None);

            Assert.Contains("smtp.example.com:587", log.Everything, StringComparison.Ordinal);
        }

        private CodeMailer Mailer(
            ISmtpTransport transport,
            out CodeOutbox outbox,
            out RecordingLogger<CodeMailer> log,
            int attempts = 4)
        {
            outbox = new CodeOutbox(Path.Combine(_directory, "codes-outbox.jsonl"));
            log = new RecordingLogger<CodeMailer>();

            return new CodeMailer(MailWith(attempts), transport, outbox, CodeMessage.DefaultTemplate, log, NoDelay);
        }

        private static MailOptions MailWith(int attempts)
        {
            var mail = CodeMessageTests.Mail();

            mail.MaxAttempts = attempts;

            return mail;
        }

        /// <summary>
        /// The retry schedule is minutes long by design. Injecting the wait keeps
        /// these tests in milliseconds without pretending the schedule is shorter
        /// than it is.
        /// </summary>
        private static Task NoDelay(TimeSpan wait, CancellationToken token) => Task.CompletedTask;

        public void Dispose()
        {
            try
            {
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}

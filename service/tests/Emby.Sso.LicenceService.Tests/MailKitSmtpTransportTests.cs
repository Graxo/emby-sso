using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.Licensing;
using MailKit.Security;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The one class that opens a socket, held to what can honestly be asserted
    /// without a mail server.
    ///
    /// Three things are provable here. First, that the operator's word for a
    /// transport mode maps to the MailKit option that implements it - and in
    /// particular that 'starttls' maps to the one that FAILS when the server does
    /// not offer STARTTLS, not the one that shrugs and continues in the clear.
    /// Second, that the MIME message is a single plain-text part with the right
    /// envelope on it. Third, against a loopback listener this process owns, that
    /// the whole thing really does speak SMTP and that a 5xx from a server becomes
    /// a permanent failure rather than four pointless retries.
    ///
    /// WHAT IS NOT PROVABLE HERE, and is listed as UNVERIFIED in the report: that
    /// implicit TLS and STARTTLS work against a real relay, and that any of it
    /// authenticates. Those need a certificate the client trusts and credentials
    /// this environment does not have.
    /// </summary>
    public class MailKitSmtpTransportTests
    {
        [Fact]
        public void Implicit_tls_connects_inside_tls_from_the_first_byte()
        {
            Assert.Equal(SecureSocketOptions.SslOnConnect, MailKitSmtpTransport.SocketOptionsFor(MailOptions.ImplicitTls));
        }

        [Fact]
        public void Starttls_is_the_mode_that_fails_closed()
        {
            // NOT StartTlsWhenAvailable. An operator who asked for STARTTLS must
            // not silently get a cleartext session carrying a redemption code
            // because a relay stopped advertising it.
            Assert.Equal(SecureSocketOptions.StartTls, MailKitSmtpTransport.SocketOptionsFor(MailOptions.StartTls));
            Assert.NotEqual(SecureSocketOptions.StartTlsWhenAvailable, MailKitSmtpTransport.SocketOptionsFor(MailOptions.StartTls));
        }

        [Fact]
        public void No_encryption_means_no_encryption()
        {
            Assert.Equal(SecureSocketOptions.None, MailKitSmtpTransport.SocketOptionsFor(MailOptions.NoEncryption));
        }

        [Fact]
        public void An_unrecognised_mode_falls_back_to_the_safe_one()
        {
            // Unreachable in practice - Problems() refuses to start on it - but
            // the fallback must be the encrypted direction, not the other one.
            Assert.Equal(SecureSocketOptions.StartTls, MailKitSmtpTransport.SocketOptionsFor("nonsense"));
            Assert.Equal(SecureSocketOptions.StartTls, MailKitSmtpTransport.SocketOptionsFor(null));
        }

        [Fact]
        public void The_mime_message_is_one_plain_text_part_with_the_right_envelope()
        {
            var mime = MailKitSmtpTransport.ToMimeMessage(new OutgoingMessage
            {
                FromAddress = "licences@example.com",
                FromName = "Example licences",
                ReplyTo = "help@example.com",
                ToAddress = "buyer@example.com",
                Subject = "Your code",
                Body = "hello",
            });

            Assert.Equal("licences@example.com", mime.From.Mailboxes.Single().Address);
            Assert.Equal("Example licences", mime.From.Mailboxes.Single().Name);
            Assert.Equal("help@example.com", mime.ReplyTo.Mailboxes.Single().Address);
            Assert.Equal("buyer@example.com", mime.To.Mailboxes.Single().Address);
            Assert.Equal("Your code", mime.Subject);

            var text = Assert.IsType<MimeKit.TextPart>(mime.Body);

            Assert.True(text.IsPlain);
            Assert.Equal("hello", text.Text);

            // No HTML alternative: nothing in the message can fetch a remote
            // image and turn a credential into a read receipt.
            Assert.Null(mime.HtmlBody);
        }

        [Fact]
        public async Task It_really_speaks_smtp()
        {
            using var server = new LoopbackSmtpServer();

            var entry = CodeMessageTests.Entry(out var code);
            var transport = new MailKitSmtpTransport(Loopback(server.Port));

            await transport.SendAsync(CodeMessage.Build(Mail(), entry, CodeMessage.DefaultTemplate), CancellationToken.None);

            var message = Assert.Single(server.Messages);

            Assert.Contains("To: buyer@example.com", message, StringComparison.Ordinal);
            Assert.Contains(MailOptions.DefaultSubject, message, StringComparison.Ordinal);
            Assert.Contains(RedemptionCode.Format(code), message, StringComparison.Ordinal);

            Assert.Contains(server.Commands, c => c.StartsWith("EHLO", StringComparison.Ordinal));
            Assert.Contains(server.Commands, c => c.StartsWith("DATA", StringComparison.Ordinal));
            Assert.Contains(server.Commands, c => c.StartsWith("QUIT", StringComparison.Ordinal));
        }

        [Fact]
        public async Task A_5xx_from_a_real_server_is_a_permanent_failure()
        {
            using var server = new LoopbackSmtpServer("550 no such mailbox");

            var transport = new MailKitSmtpTransport(Loopback(server.Port));
            var message = CodeMessage.Build(Mail(), CodeMessageTests.Entry(out _), CodeMessage.DefaultTemplate);

            var ex = await Assert.ThrowsAsync<MailDeliveryException>(
                () => transport.SendAsync(message, CancellationToken.None));

            Assert.True(ex.Permanent, "550 must not be retried");
            Assert.Contains("550", ex.Message, StringComparison.Ordinal);
            Assert.Empty(server.Messages);
        }

        [Fact]
        public async Task A_4xx_from_a_real_server_is_worth_retrying()
        {
            using var server = new LoopbackSmtpServer("451 try again later");

            var transport = new MailKitSmtpTransport(Loopback(server.Port));
            var message = CodeMessage.Build(Mail(), CodeMessageTests.Entry(out _), CodeMessage.DefaultTemplate);

            var ex = await Assert.ThrowsAsync<MailDeliveryException>(
                () => transport.SendAsync(message, CancellationToken.None));

            Assert.False(ex.Permanent, "451 is the relay saying 'not now'");
        }

        [Fact]
        public async Task Nothing_listening_is_a_transient_failure_rather_than_an_escape()
        {
            // A port nothing is on: the same shape as a relay that is down, which
            // is the case the retry loop exists for.
            var options = Loopback(1);

            var ex = await Assert.ThrowsAsync<MailDeliveryException>(
                () => new MailKitSmtpTransport(options).SendAsync(
                    CodeMessage.Build(Mail(), CodeMessageTests.Entry(out _), CodeMessage.DefaultTemplate),
                    CancellationToken.None));

            Assert.False(ex.Permanent);
        }

        [Fact]
        public async Task The_password_is_not_in_any_exception_this_class_throws()
        {
            using var server = new LoopbackSmtpServer("550 no such mailbox");

            var options = Loopback(server.Port);

            options.Password = "correct-horse-battery-staple";

            var ex = await Assert.ThrowsAsync<MailDeliveryException>(
                () => new MailKitSmtpTransport(options).SendAsync(
                    CodeMessage.Build(Mail(), CodeMessageTests.Entry(out _), CodeMessage.DefaultTemplate),
                    CancellationToken.None));

            Assert.DoesNotContain("correct-horse", ex.ToString(), StringComparison.OrdinalIgnoreCase);
        }

        private static MailOptions Mail() => CodeMessageTests.Mail();

        /// <summary>
        /// Loopback only, no encryption, no authentication. There is no route out
        /// of this machine in any of these tests.
        /// </summary>
        private static MailOptions Loopback(int port)
        {
            var mail = CodeMessageTests.Mail();

            mail.Host = "127.0.0.1";
            mail.Port = port;
            mail.Security = MailOptions.NoEncryption;
            mail.Username = null;
            mail.Password = null;
            mail.TimeoutSeconds = 10;

            return mail;
        }
    }
}

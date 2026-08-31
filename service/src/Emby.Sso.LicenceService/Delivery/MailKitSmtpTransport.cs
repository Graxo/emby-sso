using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace Emby.Sso.LicenceService.Delivery
{
    /// <summary>
    /// The one class in this service that talks SMTP, kept as thin as it can be
    /// because it is the one class that cannot be fully tested here.
    ///
    /// WHY MAILKIT AND NOT System.Net.Mail.SmtpClient
    ///
    /// Two reasons, and the first is not a matter of taste. SmtpClient cannot do
    /// implicit TLS: its EnableSsl issues STARTTLS on a connection that begins in
    /// the clear, so a relay that expects TLS from the first byte on port 465 -
    /// which is most hosted mail today - is simply unreachable through it. The
    /// brief requires all three transport modes and SmtpClient can only offer
    /// two. Second, Microsoft's own documentation for SmtpClient says it is not
    /// recommended for new development and points at MailKit by name.
    ///
    /// Beyond that: MailKit's StartTls FAILS CLOSED. If the server does not
    /// advertise STARTTLS it throws rather than continuing unencrypted, so an
    /// operator who asked for STARTTLS cannot silently get a cleartext session
    /// carrying a redemption code. (StartTlsWhenAvailable is the downgradeable
    /// one. It is deliberately not offered here.) Certificate validation is
    /// MailKit's default - the system trust store - and there is no option in
    /// this service to weaken it.
    ///
    /// The cost is two transitive dependencies, MimeKit and BouncyCastle, in the
    /// vendor's service image. Nothing in src/ references any of it and the
    /// plugin does not ship it.
    /// </summary>
    public sealed class MailKitSmtpTransport : ISmtpTransport
    {
        private readonly MailOptions _options;

        public MailKitSmtpTransport(MailOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// The mapping from the operator's word to MailKit's. Separated and
        /// internal so the three modes can be asserted without a socket, which
        /// is the part of this class a test can actually hold on to.
        /// </summary>
        internal static SecureSocketOptions SocketOptionsFor(string security)
        {
            if (string.Equals(security, MailOptions.ImplicitTls, StringComparison.OrdinalIgnoreCase))
            {
                return SecureSocketOptions.SslOnConnect;
            }

            if (string.Equals(security, MailOptions.NoEncryption, StringComparison.OrdinalIgnoreCase))
            {
                return SecureSocketOptions.None;
            }

            // Not StartTlsWhenAvailable. A server that does not offer STARTTLS
            // must fail the send, not quietly get the code in the clear.
            return SecureSocketOptions.StartTls;
        }

        internal static MimeMessage ToMimeMessage(OutgoingMessage message)
        {
            var mime = new MimeMessage();

            mime.From.Add(new MailboxAddress(message.FromName ?? string.Empty, message.FromAddress));
            mime.To.Add(MailboxAddress.Parse(message.ToAddress));

            if (!string.IsNullOrWhiteSpace(message.ReplyTo))
            {
                mime.ReplyTo.Add(MailboxAddress.Parse(message.ReplyTo));
            }

            mime.Subject = message.Subject;

            // TextPart, not BodyBuilder with an HtmlBody: see CodeMessage for why
            // a credential someone retypes goes out as plain text only.
            mime.Body = new TextPart("plain") { Text = message.Body };

            return mime;
        }

        public async Task SendAsync(OutgoingMessage message, CancellationToken cancellationToken)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            var mime = ToMimeMessage(message);

            using var client = new SmtpClient
            {
                Timeout = (int)TimeSpan.FromSeconds(_options.TimeoutSeconds).TotalMilliseconds,
            };

            try
            {
                await client.ConnectAsync(
                    _options.Host,
                    _options.Port,
                    SocketOptionsFor(_options.Security),
                    cancellationToken).ConfigureAwait(false);

                if (_options.UsesAuthentication)
                {
                    await client.AuthenticateAsync(_options.Username, _options.Password, cancellationToken)
                        .ConfigureAwait(false);
                }

                await client.SendAsync(mime, cancellationToken).ConfigureAwait(false);
                await client.DisconnectAsync(quit: true, cancellationToken).ConfigureAwait(false);
            }
            catch (AuthenticationException ex)
            {
                // The password is wrong, or the relay wants an app password.
                // Retrying cannot fix it and the message must NOT contain what
                // was tried.
                throw new MailDeliveryException(
                    "the relay refused the SMTP login for user '" + (_options.Username ?? "(none)") + "'",
                    permanent: true,
                    ex);
            }
            catch (SmtpCommandException ex)
            {
                // 4xx is the relay saying "not now"; 5xx is the relay saying
                // "no". MailKit models that as StatusCode, and getting the
                // distinction right is the difference between a retry that helps
                // and a queue that spins against a mailbox that does not exist.
                var permanent = (int)ex.StatusCode >= 500;

                throw new MailDeliveryException(
                    "the relay refused the message with " + (int)ex.StatusCode + " (" + ex.ErrorCode + ")",
                    permanent,
                    ex);
            }
            catch (SmtpProtocolException ex)
            {
                throw new MailDeliveryException("the relay broke the SMTP protocol: " + ex.Message, permanent: false, ex);
            }
            catch (SslHandshakeException ex)
            {
                // Almost always a certificate the system does not trust, or a
                // port/mode mismatch - STARTTLS pointed at 465, or the reverse.
                // Permanent, because it will keep failing until somebody looks.
                throw new MailDeliveryException(
                    "TLS to " + _options.Host + ":" + _options.Port + " failed (" + _options.Security
                    + "). Check SMTP_SECURITY matches the port, and that the relay's certificate is trusted: "
                    + ex.Message,
                    permanent: true,
                    ex);
            }
            catch (NotSupportedException ex)
            {
                // What MailKit throws for StartTls against a server that does not
                // offer it. Failing closed, which is the point of choosing it.
                throw new MailDeliveryException(
                    "the relay would not start TLS and this service will not send a redemption code in the clear: "
                    + ex.Message,
                    permanent: true,
                    ex);
            }
            catch (Exception ex) when (ex is SocketException || ex is IOException || ex is TimeoutException)
            {
                throw new MailDeliveryException(
                    "could not reach " + _options.Host + ":" + _options.Port + ": " + ex.Message,
                    permanent: false,
                    ex);
            }
        }
    }
}

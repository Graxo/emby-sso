using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// About sixty lines of SMTP, on 127.0.0.1, on a port the operating system
    /// picks, for the length of one test.
    ///
    /// WHY THIS EXISTS. Everything else in the mail path is tested through
    /// FakeSmtpTransport, which proves the retry rules and the wording but proves
    /// nothing about MailKit - the one piece that could be wired up wrongly and
    /// still compile. This listener closes that gap for the unencrypted mode: it
    /// makes MailKitSmtpTransport really connect, really speak EHLO/MAIL/RCPT/
    /// DATA, and really put the message on a wire, and it lets a test assert that
    /// a 550 from a server becomes a permanent failure rather than four pointless
    /// retries.
    ///
    /// IT IS NOT A MAIL SERVER. It does not relay, forward, queue or deliver
    /// anything; it reads bytes from a loopback socket into a list in this
    /// process and closes. Nothing leaves the machine. The TLS modes remain
    /// UNVERIFIED here - a test would need a certificate chain the client trusts,
    /// and the mapping to MailKit's options is asserted separately.
    /// </summary>
    internal sealed class LoopbackSmtpServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _stopping = new CancellationTokenSource();
        private readonly Task _loop;

        public LoopbackSmtpServer(string rcptResponse = "250 recipient ok")
        {
            RcptResponse = rcptResponse;

            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();

            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _loop = Task.Run(() => AcceptAsync(_stopping.Token));
        }

        public int Port { get; }

        /// <summary>What the server says to RCPT TO. A 5xx here is a permanent refusal.</summary>
        public string RcptResponse { get; }

        /// <summary>The full DATA payload of every message that got as far as being sent.</summary>
        public List<string> Messages { get; } = new List<string>();

        public List<string> Commands { get; } = new List<string>();

        private async Task AcceptAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;

                try
                {
                    client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    return;
                }

                using (client)
                {
                    try
                    {
                        await ConverseAsync(client).ConfigureAwait(false);
                    }
                    catch (IOException)
                    {
                        // A client that hangs up mid-conversation is one of the
                        // things being tested; it is not a failure of the server.
                    }
                }
            }
        }

        private async Task ConverseAsync(TcpClient client)
        {
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
            using var writer = new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" };

            await writer.WriteLineAsync("220 loopback.test ESMTP").ConfigureAwait(false);

            string line;

            while ((line = await reader.ReadLineAsync().ConfigureAwait(false)) != null)
            {
                lock (Commands)
                {
                    Commands.Add(line);
                }

                var verb = line.Split(' ')[0].ToUpperInvariant();

                switch (verb)
                {
                    case "EHLO":
                        // No STARTTLS and no AUTH advertised: this is the
                        // unencrypted mode and nothing here should offer more.
                        await writer.WriteLineAsync("250-loopback.test").ConfigureAwait(false);
                        await writer.WriteLineAsync("250-8BITMIME").ConfigureAwait(false);
                        await writer.WriteLineAsync("250 SIZE 10485760").ConfigureAwait(false);
                        break;

                    case "HELO":
                        await writer.WriteLineAsync("250 loopback.test").ConfigureAwait(false);
                        break;

                    case "MAIL":
                        await writer.WriteLineAsync("250 sender ok").ConfigureAwait(false);
                        break;

                    case "RCPT":
                        await writer.WriteLineAsync(RcptResponse).ConfigureAwait(false);
                        break;

                    case "DATA":
                        await writer.WriteLineAsync("354 send it").ConfigureAwait(false);
                        await ReadMessageAsync(reader).ConfigureAwait(false);
                        await writer.WriteLineAsync("250 queued").ConfigureAwait(false);
                        break;

                    case "RSET":
                    case "NOOP":
                        await writer.WriteLineAsync("250 ok").ConfigureAwait(false);
                        break;

                    case "QUIT":
                        await writer.WriteLineAsync("221 bye").ConfigureAwait(false);
                        return;

                    default:
                        await writer.WriteLineAsync("502 not implemented").ConfigureAwait(false);
                        break;
                }
            }
        }

        private async Task ReadMessageAsync(StreamReader reader)
        {
            var message = new StringBuilder();

            string line;

            while ((line = await reader.ReadLineAsync().ConfigureAwait(false)) != null)
            {
                if (line == ".")
                {
                    break;
                }

                // Undo dot-stuffing, so an assertion about the body is about the
                // body rather than about SMTP.
                message.AppendLine(line.StartsWith("..", StringComparison.Ordinal) ? line.Substring(1) : line);
            }

            lock (Messages)
            {
                Messages.Add(message.ToString());
            }
        }

        public void Dispose()
        {
            _stopping.Cancel();

            try
            {
                _listener.Stop();
            }
            catch (SocketException)
            {
            }

            try
            {
                _loop.Wait(TimeSpan.FromSeconds(5));
            }
            catch (AggregateException)
            {
            }

            _stopping.Dispose();
        }
    }
}

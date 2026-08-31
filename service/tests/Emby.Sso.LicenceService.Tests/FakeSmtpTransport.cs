using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Delivery;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// An SMTP transport that never opens a socket.
    ///
    /// The whole suite uses this rather than a mail server, so no test run can
    /// send mail anywhere, to anyone, by accident or by misconfiguration - which
    /// matters more than usual for a service whose messages contain live
    /// credentials. The one test that does speak SMTP does it to a listener on
    /// 127.0.0.1 that this process owns; see LoopbackSmtpServer.
    /// </summary>
    internal sealed class FakeSmtpTransport : ISmtpTransport
    {
        private readonly Queue<Func<Exception>> _script = new Queue<Func<Exception>>();

        public List<OutgoingMessage> Sent { get; } = new List<OutgoingMessage>();

        public int Attempts { get; private set; }

        /// <summary>The next attempt fails this way; after the script runs out, attempts succeed.</summary>
        public FakeSmtpTransport ThenFail(string message, bool permanent)
        {
            _script.Enqueue(() => new MailDeliveryException(message, permanent));

            return this;
        }

        public FakeSmtpTransport ThenThrow(Exception exception)
        {
            _script.Enqueue(() => exception);

            return this;
        }

        public FakeSmtpTransport AlwaysFail(string message, bool permanent)
        {
            for (var i = 0; i < 50; i++)
            {
                ThenFail(message, permanent);
            }

            return this;
        }

        public Task SendAsync(OutgoingMessage message, CancellationToken cancellationToken)
        {
            Attempts++;

            cancellationToken.ThrowIfCancellationRequested();

            if (_script.Count > 0)
            {
                throw _script.Dequeue()();
            }

            Sent.Add(message);

            return Task.CompletedTask;
        }
    }
}

using System;

namespace Emby.Sso.LicenceService.Delivery
{
    /// <summary>
    /// One plain-text message, built and ready to hand to a transport.
    ///
    /// <see cref="Body"/> CONTAINS A LIVE REDEMPTION CODE. Nothing in this class
    /// overrides ToString, and nothing anywhere logs an instance of it: the log
    /// line for a send names the recipient and the code's hash tag, which is
    /// what support actually needs, and nothing else.
    /// </summary>
    public sealed class OutgoingMessage
    {
        public string FromAddress { get; set; }

        public string FromName { get; set; }

        public string ReplyTo { get; set; }

        public string ToAddress { get; set; }

        public string Subject { get; set; }

        /// <summary>Plain text. A live credential is in here.</summary>
        public string Body { get; set; }
    }

    /// <summary>
    /// Why a send failed, and - the part that matters - whether trying again
    /// could possibly help.
    ///
    /// The distinction is the whole point of the class. A relay that is down
    /// deserves the retries; a relay that has said "no such mailbox" or "bad
    /// password" deserves none, and retrying it only delays the moment the
    /// operator finds out from the log that they have to send this one by hand.
    /// </summary>
    public sealed class MailDeliveryException : Exception
    {
        public MailDeliveryException(string message, bool permanent)
            : base(message)
        {
            Permanent = permanent;
        }

        public MailDeliveryException(string message, bool permanent, Exception inner)
            : base(message, inner)
        {
            Permanent = permanent;
        }

        /// <summary>True when no number of retries would change the answer.</summary>
        public bool Permanent { get; }
    }

    /// <summary>
    /// The seam. One method, so the tests can drive every path through
    /// <see cref="CodeMailer"/> - success, a transient failure that then
    /// succeeds, a permanent refusal, a total failure - without a mail server,
    /// and so that no test can ever send mail anywhere by accident.
    /// </summary>
    public interface ISmtpTransport
    {
        /// <summary>
        /// Sends, or throws <see cref="MailDeliveryException"/>. Any other
        /// exception type is treated by the caller as transient and unexpected.
        /// </summary>
        System.Threading.Tasks.Task SendAsync(OutgoingMessage message, System.Threading.CancellationToken cancellationToken);
    }
}

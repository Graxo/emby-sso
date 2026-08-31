using System;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;

namespace Emby.Sso.LicenceService.Delivery
{
    /// <summary>
    /// Sends one code to one buyer, retries a bounded number of times, and never
    /// throws at its caller.
    ///
    /// THE ORDER OF THINGS. By the time this runs, the code has already been
    /// created inside a database transaction and already written to the outbox.
    /// That is not incidental - it is what makes mail safe to attempt at all.
    /// The outbox write is the durable step; the email is a convenience on top of
    /// it. If this class fails completely, nothing has been lost that was not
    /// already recoverable by the operator reading the outbox, which is exactly
    /// what they do today.
    ///
    /// WHAT IS NOT LOGGED. Not the code, not the rendered body, not the SMTP
    /// password. A send is logged as the recipient plus the code's hash tag - the
    /// same twelve hex characters every other line about that code uses - so that
    /// "did this reach them?" is answerable from the log without the log becoming
    /// a place credentials live. This follows what the service already does with
    /// PAYPAL_CLIENT_SECRET, which appears in no log line anywhere.
    /// </summary>
    public sealed class CodeMailer
    {
        private readonly MailOptions _options;
        private readonly ISmtpTransport _transport;
        private readonly CodeOutbox _outbox;
        private readonly string _template;
        private readonly ILogger<CodeMailer> _log;
        private readonly Func<TimeSpan, CancellationToken, Task> _delay;

        public CodeMailer(
            MailOptions options,
            ISmtpTransport transport,
            CodeOutbox outbox,
            string template,
            ILogger<CodeMailer> log,
            Func<TimeSpan, CancellationToken, Task> delay = null)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _outbox = outbox ?? throw new ArgumentNullException(nameof(outbox));
            _template = template ?? CodeMessage.DefaultTemplate;
            _log = log ?? throw new ArgumentNullException(nameof(log));

            // Injectable so the retry schedule can be asserted in a test that
            // finishes in milliseconds instead of ten minutes.
            _delay = delay ?? ((wait, token) => Task.Delay(wait, token));
        }

        /// <summary>
        /// Attempts delivery. Returns what happened; never throws, because the
        /// only caller is a background loop draining a queue and an exception
        /// there would take the loop down with it.
        /// </summary>
        public async Task<MailOutcome> DeliverAsync(OutboxEntry entry, CancellationToken cancellationToken)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            var tag = RedemptionCode.LogTag(RedemptionCode.Hash(entry.Code));

            OutgoingMessage message;

            try
            {
                message = CodeMessage.Build(_options, entry, _template);
            }
            catch (Exception ex)
            {
                _log.LogError(
                    ex,
                    "code {Tag} could not be turned into a message. It is in the outbox; send it by hand.",
                    tag);

                return MailOutcome.NotAttempted;
            }

            if (message == null)
            {
                // PayPal did not give us a payer address. Not an error and not a
                // retry: there is nowhere to send it, and the outbox already has
                // it with whatever PayPal did tell us.
                _log.LogWarning(
                    "code {Tag} has no buyer email address in the PayPal event, so nothing was emailed. "
                    + "It is in {Outbox} for you to send by hand.",
                    tag,
                    _outbox.Path);

                return MailOutcome.NoRecipient;
            }

            var attempts = Math.Max(1, _options.MaxAttempts);
            var wait = TimeSpan.FromSeconds(Math.Max(1, _options.RetrySeconds));

            for (var attempt = 1; attempt <= attempts; attempt++)
            {
                try
                {
                    await _transport.SendAsync(message, cancellationToken).ConfigureAwait(false);

                    _log.LogInformation(
                        "code {Tag} emailed to {Buyer} on attempt {Attempt}",
                        tag,
                        message.ToAddress,
                        attempt);

                    RecordDelivered(entry, message.ToAddress, tag);

                    return MailOutcome.Sent;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    // The service is stopping. The code is in the outbox, which
                    // is the whole reason it is safe to give up here.
                    _log.LogWarning(
                        "shutting down before code {Tag} could be emailed. It is in {Outbox}; send it by hand.",
                        tag,
                        _outbox.Path);

                    return MailOutcome.Abandoned;
                }
                catch (Exception ex)
                {
                    var permanent = ex is MailDeliveryException delivery && delivery.Permanent;
                    var last = attempt >= attempts;

                    if (permanent || last)
                    {
                        // LOUD, and with everything the operator needs to finish
                        // the sale by hand - except the code, which is in the
                        // outbox where it belongs and not in the log where it
                        // does not.
                        _log.LogError(
                            ex,
                            "EMAIL FAILED for code {Tag} to {Buyer} after {Attempts} attempt(s) via {Relay}: {Reason}. "
                            + "The buyer has paid and has a code they have not been sent. It is in {Outbox} - send it "
                            + "by hand, then fix the relay. The payment itself was recorded correctly and PayPal was "
                            + "told so; nothing needs replaying.",
                            tag,
                            message.ToAddress,
                            attempt,
                            _options.Describe(),
                            ex.Message,
                            _outbox.Path);

                        return permanent ? MailOutcome.Refused : MailOutcome.Failed;
                    }

                    _log.LogWarning(
                        "email attempt {Attempt} of {Total} for code {Tag} failed ({Reason}); retrying in {Wait}s",
                        attempt,
                        attempts,
                        tag,
                        ex.Message,
                        (int)wait.TotalSeconds);

                    try
                    {
                        await _delay(wait, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        _log.LogWarning(
                            "shutting down before code {Tag} could be emailed. It is in {Outbox}; send it by hand.",
                            tag,
                            _outbox.Path);

                        return MailOutcome.Abandoned;
                    }

                    // Quadrupled rather than doubled: a relay that is down is
                    // usually down for minutes, and four attempts at 30s, 2m and
                    // 8m covers most of that without a queue that grinds.
                    wait = TimeSpan.FromSeconds(Math.Min(wait.TotalSeconds * 4, 3600));
                }
            }

            return MailOutcome.Failed;
        }

        private void RecordDelivered(OutboxEntry entry, string recipient, string tag)
        {
            try
            {
                _outbox.RecordDelivered(entry, recipient, DateTimeOffset.UtcNow);
            }
            catch (Exception ex)
            {
                // A receipt that could not be written is a tidiness problem, not
                // a delivery problem. The buyer has their code.
                _log.LogWarning(
                    ex,
                    "code {Tag} was emailed but the delivery receipt could not be appended to {Outbox}. "
                    + "The line for that code still reads as undelivered.",
                    tag,
                    _outbox.Path);
            }
        }
    }

    public enum MailOutcome
    {
        /// <summary>Mail is not configured, or there was nothing to do.</summary>
        NotAttempted,

        /// <summary>The relay accepted it.</summary>
        Sent,

        /// <summary>The PayPal event carried no address to send to.</summary>
        NoRecipient,

        /// <summary>Every attempt failed for a reason that might not be permanent.</summary>
        Failed,

        /// <summary>The relay said no in a way retrying cannot fix.</summary>
        Refused,

        /// <summary>The service stopped before it could be sent.</summary>
        Abandoned,
    }
}

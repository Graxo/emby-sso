using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Emby.Sso.LicenceService.Delivery
{
    /// <summary>
    /// The thing that keeps a mail server out of PayPal's way.
    ///
    /// WHY A QUEUE AND NOT JUST A try/catch IN THE WEBHOOK. PayPal needs its 2xx,
    /// and it needs it promptly: a webhook that does not answer quickly enough is
    /// retried, and a retry of a payment that was processed correctly is exactly
    /// the thing this service works hard everywhere else to make impossible. A
    /// send with a 30-second timeout and three retries behind it cannot happen
    /// inside a request that has to answer in seconds. So the webhook does the
    /// durable work - the transaction, the outbox - hands the code to this queue,
    /// and returns. Mail happens afterwards, on a background thread, where taking
    /// eleven minutes to give up costs nobody anything.
    ///
    /// That also makes "a mail failure never fails the webhook" structural rather
    /// than a matter of catching the right exceptions: the webhook is not on the
    /// same call stack as the send and there is no path by which one can fail the
    /// other.
    ///
    /// THE QUEUE IS BOUNDED AND ITS OVERFLOW IS SAFE. If the channel is full the
    /// enqueue fails immediately and loudly, and the code is still in the outbox,
    /// which is the same place it would have been with no mail configured at all.
    /// Nothing is ever lost by this class being unable to keep up; the worst it
    /// can do is degrade to the behaviour the service had before it existed.
    /// </summary>
    public sealed class CodeDeliveryQueue : BackgroundService
    {
        /// <summary>
        /// Far more than a one-person vendor's sales rate, and small enough that
        /// a stuck relay cannot make the process hold an unbounded number of
        /// plaintext codes in memory.
        /// </summary>
        public const int Capacity = 256;

        private readonly Channel<OutboxEntry> _queue;
        private readonly CodeMailer _mailer;
        private readonly ILogger<CodeDeliveryQueue> _log;

        public CodeDeliveryQueue(CodeMailer mailer, ILogger<CodeDeliveryQueue> log)
        {
            _mailer = mailer ?? throw new ArgumentNullException(nameof(mailer));
            _log = log ?? throw new ArgumentNullException(nameof(log));

            _queue = Channel.CreateBounded<OutboxEntry>(new BoundedChannelOptions(Capacity)
            {
                // Wait, but only ever reached through TryWrite, which does not
                // wait: a full queue refuses the write immediately and the
                // caller logs it. DropWrite would lose one silently, and any
                // waiting mode reached through WriteAsync would put a mail
                // server on the webhook's critical path, which is the whole
                // thing this class exists to prevent.
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false,
            });
        }

        /// <summary>
        /// Hands a code to the background sender. Returns false if it could not
        /// be accepted, which the caller logs and otherwise ignores - the outbox
        /// has already got it.
        ///
        /// Never blocks, never throws, and never touches the network on the
        /// caller's thread.
        /// </summary>
        public bool Enqueue(OutboxEntry entry)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            return _queue.Writer.TryWrite(entry);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                await foreach (var entry in _queue.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
                {
                    // DeliverAsync does not throw. This catch is for the case
                    // where that stops being true: a background loop that dies
                    // silently would turn every later sale into an undelivered
                    // one with no log line saying so.
                    try
                    {
                        await _mailer.DeliverAsync(entry, stoppingToken).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (!(ex is OperationCanceledException))
                    {
                        _log.LogError(ex, "the code mailer threw; the code is in the outbox. Delivery continues.");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Shutting down. Anything still queued is in the outbox.
                var left = _queue.Reader.Count;

                if (left > 0)
                {
                    _log.LogWarning(
                        "stopping with {Count} code(s) not yet emailed. Every one of them is in the outbox; "
                        + "send those by hand.",
                        left);
                }
            }
        }
    }
}

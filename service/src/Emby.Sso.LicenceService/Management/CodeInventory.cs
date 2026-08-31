using System;
using System.Collections.Generic;
using System.Linq;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.Storage;

namespace Emby.Sso.LicenceService.Management
{
    /// <summary>
    /// What state a code is in, in the order an operator should look at them.
    ///
    /// The numbers are the sort order and the priority at once: a code is
    /// labelled with the FIRST of these that is true of it, and the table is
    /// sorted by the same number, so what needs attention is at the top and
    /// nothing has to be scrolled to.
    /// </summary>
    public enum CodeState
    {
        /// <summary>
        /// A sale that has not reached its buyer: there is a line in the outbox
        /// for this code and no delivery receipt beside it. First, because it is
        /// the only state where somebody has paid and has nothing.
        /// </summary>
        Undelivered = 0,

        /// <summary>Created but not paid for. Cannot activate.</summary>
        Unpaid = 1,

        /// <summary>The licence issued from it has already run out.</summary>
        Lapsed = 2,

        /// <summary>The licence runs out within the window - see `--soon`.</summary>
        Lapsing = 3,

        /// <summary>Every activation the code allows has been used.</summary>
        Exhausted = 4,

        /// <summary>Paid for and never activated. Normal for a code just sold, or a comp nobody has redeemed.</summary>
        Unused = 5,

        /// <summary>In use, with activations to spare and a licence with time on it.</summary>
        Active = 6,

        /// <summary>
        /// Voided - refunded, leaked, or a mistake. Last on purpose: it is the
        /// one state that is already dealt with, so it never pushes a live
        /// problem down the page. It outranks Undelivered because a refunded
        /// sale is not one to chase.
        /// </summary>
        Void = 7,
    }

    /// <summary>
    /// One code as the operator sees it: the row from the store, the outbox line
    /// if there is still one, and the state the two together put it in.
    ///
    /// There is no field on this type for the code itself. The store has never
    /// held one - only a SHA-256 - and this is the type `list-codes` renders,
    /// so a change that made it print a code would have to invent somewhere to
    /// get one from.
    /// </summary>
    public sealed class ManagedCode
    {
        public CodeSummary Code { get; set; }

        /// <summary>The outbox line, or null: pruned, or never written (a manual code).</summary>
        public OutboxRecord Delivery { get; set; }

        public CodeState State { get; set; }

        public string Tag => Code.Tag;

        /// <summary>
        /// Whether `list-codes --needs-attention` shows it. Exhausted and void
        /// are deliberately not here: both are answers, not questions.
        /// </summary>
        public bool NeedsAttention =>
            State == CodeState.Undelivered
            || State == CodeState.Unpaid
            || State == CodeState.Lapsed
            || State == CodeState.Lapsing;

        /// <summary>What the STATE column prints. Shouted when it wants a human, quiet when it does not.</summary>
        public string StateText
        {
            get
            {
                switch (State)
                {
                    case CodeState.Undelivered: return "UNDELIVERED";
                    case CodeState.Unpaid: return "UNPAID";
                    case CodeState.Lapsed: return "LAPSED";
                    case CodeState.Lapsing: return "LAPSING";
                    case CodeState.Exhausted: return "EXHAUSTED";
                    case CodeState.Unused: return "unused";
                    case CodeState.Void: return "void";
                    default: return "active";
                }
            }
        }
    }

    /// <summary>
    /// Turns rows and outbox lines into the list the commands print.
    ///
    /// It is a static function of its inputs so that the classification - which
    /// is the part with the judgement in it - can be tested without a database,
    /// a file or a clock.
    /// </summary>
    public static class CodeInventory
    {
        /// <summary>
        /// The default window in which a licence counts as LAPSING. The same 21
        /// days the offline tool uses, and for the same reason: it is the point
        /// at which the customer's own Emby server has already begun warning
        /// them in its log, so it is when they are about to ask.
        /// </summary>
        public const int DefaultSoonDays = 21;

        public static IReadOnlyList<ManagedCode> Build(
            IEnumerable<CodeSummary> codes,
            OutboxLog outbox,
            DateTimeOffset now,
            int soonDays)
        {
            if (codes == null)
            {
                throw new ArgumentNullException(nameof(codes));
            }

            var log = outbox ?? OutboxLog.Empty;

            var built = codes
                .Select(code =>
                {
                    log.TryFind(code.Tag, out var delivery);

                    return new ManagedCode
                    {
                        Code = code,
                        Delivery = delivery,
                        State = Classify(code, delivery, now, soonDays),
                    };
                })
                .ToList();

            // Attention first; then, within a state, oldest first - by expiry
            // where the state is about an expiry and by creation where it is
            // not. An undelivered sale from a fortnight ago is more urgent than
            // one from this morning, and the licence lapsing on Tuesday is more
            // urgent than the one lapsing in three weeks.
            built.Sort((left, right) =>
            {
                var byState = ((int)left.State).CompareTo((int)right.State);

                if (byState != 0)
                {
                    return byState;
                }

                var byTime = SortKey(left).CompareTo(SortKey(right));

                return byTime != 0 ? byTime : left.Code.Id.CompareTo(right.Code.Id);
            });

            return built;
        }

        /// <summary>
        /// The first true thing about a code, in the order that decides what an
        /// operator does about it.
        ///
        /// VOID IS TESTED BEFORE UNDELIVERED on purpose: a refunded sale whose
        /// code never went out is finished with, and listing it as an
        /// outstanding delivery would send the operator to email a code to
        /// somebody who has their money back.
        /// </summary>
        public static CodeState Classify(CodeSummary code, OutboxRecord delivery, DateTimeOffset now, int soonDays)
        {
            if (code == null)
            {
                throw new ArgumentNullException(nameof(code));
            }

            if (string.Equals(code.Status, CodeStatus.Void, StringComparison.Ordinal))
            {
                return CodeState.Void;
            }

            if (string.Equals(code.Status, CodeStatus.Unpaid, StringComparison.Ordinal))
            {
                return CodeState.Unpaid;
            }

            // Only a code line with no receipt beside it is outstanding. A code
            // with no outbox line at all has either been pruned after sending -
            // which the README tells the operator to do - or was never written
            // there, which is every code from `issue-code`. Neither is a
            // delivery failure and neither is claimed to be one.
            if (delivery != null && !delivery.Delivered && code.ActivationsUsed == 0)
            {
                return CodeState.Undelivered;
            }

            if (code.ExpiresUtc.HasValue)
            {
                if (code.ExpiresUtc.Value <= now)
                {
                    return CodeState.Lapsed;
                }

                if (soonDays > 0 && code.ExpiresUtc.Value <= now.AddDays(soonDays))
                {
                    return CodeState.Lapsing;
                }
            }

            if (code.ActivationsUsed >= code.ActivationsAllowed)
            {
                return CodeState.Exhausted;
            }

            return code.ActivationsUsed == 0 ? CodeState.Unused : CodeState.Active;
        }

        private static DateTimeOffset SortKey(ManagedCode managed)
        {
            var byExpiry = managed.State == CodeState.Lapsed || managed.State == CodeState.Lapsing;

            return byExpiry && managed.Code.ExpiresUtc.HasValue ? managed.Code.ExpiresUtc.Value : managed.Code.CreatedUtc;
        }
    }
}

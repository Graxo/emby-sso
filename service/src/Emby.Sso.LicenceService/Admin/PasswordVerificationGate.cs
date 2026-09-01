using System;
using System.Threading;

namespace Emby.Sso.LicenceService.Admin
{
    /// <summary>
    /// A ceiling on how many admin-password verifications may run at once.
    ///
    /// Verifying a password is 210,000 rounds of PBKDF2 by design - expensive on
    /// purpose, so that guessing is slow. The login throttle
    /// (<see cref="AdminLoginThrottle"/>) is meant to stop a guesser reaching that
    /// cost repeatedly, but its <c>Check</c> is deliberately non-consuming: it
    /// does not spend anything, so an operator who submits twice by accident is
    /// not punished. That is the right call for a person, and wrong for a burst -
    /// the counter only advances AFTER a verification finishes, so N requests
    /// arriving together all pass the gate and all compute PBKDF2 in parallel,
    /// on the one host that holds the signing key. The throttle cannot see them
    /// until the first one has already paid.
    ///
    /// This closes that specific gap without touching the throttle's semantics:
    /// it bounds the number of verifications in flight at any instant. A person
    /// submitting twice still sails through; a burst of a hundred is served a few
    /// at a time and the throttle catches up between them. When the ceiling is
    /// full, <see cref="TryEnter"/> refuses rather than queues - a queue is just
    /// the amplification wearing a hat, holding the work to do later.
    ///
    /// The number is small on purpose. A human logging in needs one slot; the
    /// only caller wanting several at once is the burst this exists to cap.
    /// </summary>
    public sealed class PasswordVerificationGate : IDisposable
    {
        /// <summary>
        /// How many verifications may run at once. Four leaves a real operator
        /// untouched (they use one) while holding parallel PBKDF2 to a handful of
        /// cores rather than however many a caller cares to open at once.
        /// </summary>
        public const int MaxConcurrent = 4;

        private readonly SemaphoreSlim _slots;

        public PasswordVerificationGate()
            : this(MaxConcurrent)
        {
        }

        public PasswordVerificationGate(int maxConcurrent)
        {
            if (maxConcurrent < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(maxConcurrent));
            }

            _slots = new SemaphoreSlim(maxConcurrent, maxConcurrent);
        }

        /// <summary>
        /// Take a slot if one is free, without waiting. True means the caller
        /// holds a slot and MUST call <see cref="Exit"/> when the verification is
        /// done, in a finally. False means the ceiling is full and the caller
        /// should refuse the attempt exactly as the throttle would - the client
        /// can try again, and a slot will have freed by then.
        /// </summary>
        public bool TryEnter()
        {
            return _slots.Wait(TimeSpan.Zero);
        }

        /// <summary>Release a slot taken by <see cref="TryEnter"/>.</summary>
        public void Exit()
        {
            _slots.Release();
        }

        public void Dispose()
        {
            _slots.Dispose();
        }
    }
}

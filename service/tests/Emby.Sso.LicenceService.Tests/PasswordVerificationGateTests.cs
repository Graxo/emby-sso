using System;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Admin;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The ceiling on how many admin-password verifications run at once.
    ///
    /// The property under test is the one the login throttle cannot give,
    /// because its Check is deliberately non-consuming: no matter how many
    /// callers arrive together, only a bounded number can be inside a PBKDF2
    /// verification at any instant. These tests fail if
    /// <see cref="PasswordVerificationGate"/> is reduced to a pass-through.
    /// </summary>
    public sealed class PasswordVerificationGateTests
    {
        [Fact]
        public void Admits_up_to_the_ceiling_and_no_more()
        {
            using var gate = new PasswordVerificationGate(maxConcurrent: 3);

            Assert.True(gate.TryEnter());
            Assert.True(gate.TryEnter());
            Assert.True(gate.TryEnter());

            // The fourth simultaneous holder is refused, not queued.
            Assert.False(gate.TryEnter());
        }

        [Fact]
        public void A_freed_slot_is_reusable()
        {
            using var gate = new PasswordVerificationGate(maxConcurrent: 1);

            Assert.True(gate.TryEnter());
            Assert.False(gate.TryEnter());

            gate.Exit();

            Assert.True(gate.TryEnter());
        }

        [Fact]
        public async Task A_burst_never_has_more_than_the_ceiling_inside_at_once()
        {
            const int ceiling = 4;
            const int callers = 200;

            using var gate = new PasswordVerificationGate(ceiling);

            var inside = 0;
            var peak = 0;
            var admitted = 0;
            var start = new ManualResetEventSlim(false);

            var work = new Task[callers];

            for (var i = 0; i < callers; i++)
            {
                work[i] = Task.Run(() =>
                {
                    start.Wait();

                    if (!gate.TryEnter())
                    {
                        return;
                    }

                    try
                    {
                        Interlocked.Increment(ref admitted);

                        var now = Interlocked.Increment(ref inside);

                        // Record the high-water mark of concurrent holders.
                        int seen;
                        do
                        {
                            seen = Volatile.Read(ref peak);
                        }
                        while (now > seen && Interlocked.CompareExchange(ref peak, now, seen) != seen);

                        // Hold the slot briefly so the burst genuinely overlaps -
                        // this stands in for the PBKDF2 work the real caller does.
                        Thread.Sleep(20);

                        Interlocked.Decrement(ref inside);
                    }
                    finally
                    {
                        gate.Exit();
                    }
                });
            }

            start.Set();
            await Task.WhenAll(work);

            // The whole point: however many raced in, never more than the ceiling
            // were computing at once. Without the gate this would reach ~callers.
            Assert.True(peak <= ceiling, "peak concurrency was " + peak + ", ceiling was " + ceiling);

            // And every admitted slot was released - the store is back to full.
            Assert.True(gate.TryEnter());
        }

        [Fact]
        public void Rejects_a_ceiling_below_one()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordVerificationGate(0));
        }
    }
}

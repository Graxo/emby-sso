using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class ProvisioningThrottleTests
    {
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

        private static void Fail(ProvisioningThrottle throttle, string username, int times, DateTimeOffset now)
        {
            for (var index = 0; index < times; index++)
            {
                throttle.RecordFailure(username, now);
            }
        }

        [Fact]
        public void A_username_with_no_history_is_not_throttled()
        {
            Assert.False(new ProvisioningThrottle().IsThrottled("alice", Now));
        }

        [Fact]
        public void Failures_below_the_per_username_limit_do_not_close_the_branch()
        {
            var throttle = new ProvisioningThrottle();

            Fail(throttle, "alice", ProvisioningThrottle.MaxFailuresPerUsername - 1, Now);

            Assert.False(throttle.IsThrottled("alice", Now));
        }

        [Fact]
        public void The_username_bucket_closes_on_the_limit()
        {
            var throttle = new ProvisioningThrottle();

            Fail(throttle, "alice", ProvisioningThrottle.MaxFailuresPerUsername, Now);

            Assert.True(throttle.IsThrottled("alice", Now));

            // ...and only for that username, while the global bucket is still
            // well below its own limit.
            Assert.False(throttle.IsThrottled("bob", Now));
        }

        [Fact]
        public void One_username_is_one_bucket_however_it_is_spelled()
        {
            // UsernameMatcher treats these as the same person, so a separate
            // budget for each spelling would multiply the guesses available.
            var throttle = new ProvisioningThrottle();

            Fail(throttle, "alice", 5, Now);
            Fail(throttle, "ALICE", 3, Now);
            Fail(throttle, "  Alice  ", 2, Now);

            Assert.True(throttle.IsThrottled("alice", Now));
            Assert.Equal(1, throttle.TrackedUsernames(Now));
        }

        [Fact]
        public void Success_clears_that_username_so_earlier_typos_cannot_lock_anyone_out()
        {
            var throttle = new ProvisioningThrottle();

            Fail(throttle, "alice", ProvisioningThrottle.MaxFailuresPerUsername - 1, Now);
            throttle.RecordSuccess("alice", Now);

            // The whole budget is available again: a first-time user who fumbled
            // their password and then got it right starts clean.
            Fail(throttle, "alice", ProvisioningThrottle.MaxFailuresPerUsername - 1, Now);

            Assert.False(throttle.IsThrottled("alice", Now));
        }

        [Fact]
        public void Success_for_one_username_does_not_clear_another()
        {
            var throttle = new ProvisioningThrottle();

            Fail(throttle, "alice", ProvisioningThrottle.MaxFailuresPerUsername, Now);
            throttle.RecordSuccess("bob", Now);

            Assert.True(throttle.IsThrottled("alice", Now));
        }

        [Fact]
        public void Success_does_not_reopen_the_global_bucket()
        {
            // The attack this guards against: an attacker who holds one valid
            // identity signing in with it to reset the only brake that
            // constrains walking a list of names.
            var throttle = new ProvisioningThrottle();

            for (var index = 0; index < ProvisioningThrottle.MaxFailuresGlobally; index++)
            {
                throttle.RecordFailure("victim" + index, Now);
            }

            throttle.RecordSuccess("attacker", Now);

            Assert.True(throttle.IsThrottled("someone-else", Now));
        }

        [Fact]
        public void The_global_bucket_closes_the_branch_for_a_username_with_no_failures_of_its_own()
        {
            var throttle = new ProvisioningThrottle();

            // One short of the per-username limit on each of enough names to
            // pass the global limit: no single name is closed, and the branch is
            // shut anyway.
            const int justUnder = ProvisioningThrottle.MaxFailuresPerUsername - 1;
            var names = (ProvisioningThrottle.MaxFailuresGlobally / justUnder) + 1;

            for (var index = 0; index < names; index++)
            {
                Fail(throttle, "victim" + index, justUnder, Now);
            }

            Assert.False(new ProvisioningThrottle().IsThrottled("victim0", Now));
            Assert.True(throttle.IsThrottled("never-seen-before", Now));
        }

        [Fact]
        public void A_bucket_is_closed_right_up_to_the_end_of_its_window()
        {
            var throttle = new ProvisioningThrottle();

            Fail(throttle, "alice", ProvisioningThrottle.MaxFailuresPerUsername, Now);

            Assert.True(throttle.IsThrottled("alice", Now + ProvisioningThrottle.Window - TimeSpan.FromTicks(1)));
        }

        [Fact]
        public void The_window_clears_itself_so_no_lockout_is_permanent()
        {
            var throttle = new ProvisioningThrottle();

            Fail(throttle, "alice", ProvisioningThrottle.MaxFailuresPerUsername, Now);

            var later = Now + ProvisioningThrottle.Window;

            Assert.False(throttle.IsThrottled("alice", later));
            Assert.Equal(0, throttle.TrackedUsernames(later));
        }

        [Fact]
        public void Continued_failures_do_not_push_the_window_out()
        {
            // The window is measured from the FIRST counted failure. If later
            // failures extended it, an attacker could hold a legitimate user's
            // name locked indefinitely by attempting it once a minute.
            var throttle = new ProvisioningThrottle();

            Fail(throttle, "alice", ProvisioningThrottle.MaxFailuresPerUsername, Now);

            var nearlyOver = Now + ProvisioningThrottle.Window - TimeSpan.FromMinutes(1);
            Fail(throttle, "alice", 5, nearlyOver);

            Assert.True(throttle.IsThrottled("alice", nearlyOver));
            Assert.False(throttle.IsThrottled("alice", Now + ProvisioningThrottle.Window));
        }

        [Fact]
        public void The_global_window_clears_itself_too()
        {
            var throttle = new ProvisioningThrottle();

            for (var index = 0; index < ProvisioningThrottle.MaxFailuresGlobally; index++)
            {
                throttle.RecordFailure("victim" + index, Now);
            }

            Assert.True(throttle.IsThrottled("never-seen-before", Now));
            Assert.False(throttle.IsThrottled("never-seen-before", Now + ProvisioningThrottle.Window));
        }

        [Fact]
        public void The_map_stays_bounded_when_every_attempt_invents_a_new_username()
        {
            // A caller that consults IsThrottled first can never get here - the
            // global bucket closes long before - so this exercises the structural
            // bound rather than the arithmetic one.
            var throttle = new ProvisioningThrottle();

            for (var index = 0; index < ProvisioningThrottle.MaxTrackedUsernames * 2; index++)
            {
                throttle.RecordFailure("invented" + index, Now);
            }

            Assert.Equal(ProvisioningThrottle.MaxTrackedUsernames, throttle.TrackedUsernames(Now));
        }

        [Fact]
        public void A_full_map_never_forgets_a_recorded_failure()
        {
            // The eviction rule is "no eviction": at capacity a NEW username
            // simply gets no bucket of its own and is counted globally. Dropping
            // a live bucket to make room would hand that name a fresh ten-guess
            // budget, which is a wrong ALLOW.
            //
            // Seeing that requires the one state in which the cap can decide
            // anything: the global bucket's window rolled over while
            // longer-lived per-username buckets are still live. While the global
            // bucket is up it refuses everyone regardless, so an eviction is
            // invisible - which is exactly why this test is built the awkward
            // way round rather than asserting at a single instant.
            var throttle = new ProvisioningThrottle();

            // Opens the global window at Now, so it expires before anything
            // recorded below it does.
            throttle.RecordFailure("earliest", Now);

            // The victim is deliberately the oldest bucket left once "earliest"
            // has expired, so any rule that makes room by dropping the oldest,
            // the least recently seen or the soonest to expire takes this one.
            var victimAt = Now + TimeSpan.FromSeconds(1);
            Fail(throttle, "victim", ProvisioningThrottle.MaxFailuresPerUsername, victimAt);

            var floodAt = Now + TimeSpan.FromSeconds(2);

            for (var index = 0; index < ProvisioningThrottle.MaxTrackedUsernames * 2; index++)
            {
                throttle.RecordFailure("invented" + index, floodAt);
            }

            Assert.Equal(ProvisioningThrottle.MaxTrackedUsernames, throttle.TrackedUsernames(floodAt));

            // The global window has rolled over by here; the victim's has not.
            var afterGlobalWindow = Now + ProvisioningThrottle.Window + TimeSpan.FromMilliseconds(500);

            Assert.True(throttle.IsThrottled("victim", afterGlobalWindow));
            Assert.False(throttle.IsThrottled("never-seen-before", afterGlobalWindow));
        }

        [Fact]
        public void An_empty_username_is_a_key_like_any_other_and_does_not_throw()
        {
            var throttle = new ProvisioningThrottle();

            throttle.RecordFailure(null, Now);
            throttle.RecordFailure("", Now);
            throttle.RecordFailure("   ", Now);
            throttle.RecordSuccess(null, Now);

            Assert.False(throttle.IsThrottled(null, Now));
            Assert.Equal(0, throttle.TrackedUsernames(Now));
        }

        [Fact]
        public void A_throttled_refusal_says_exactly_what_an_ordinary_refusal_says()
        {
            // Character-identical, not merely similar: anything that
            // distinguished the two would tell a caller which usernames are
            // worth counting.
            Assert.Equal(SsoErrors.UnknownUser, ProvisioningThrottle.RefusalReason);

            // ...and the same sentence the group gate hands back, so a throttled
            // caller cannot be told apart from a non-member either.
            Assert.Equal(SsoErrors.GroupNotHeld, ProvisioningThrottle.RefusalReason);
            Assert.Equal(SsoErrors.GroupsClaimMissing, ProvisioningThrottle.RefusalReason);
        }

        [Fact]
        public async Task Concurrent_failures_on_one_username_are_never_lost()
        {
            // A lost increment is a free guess. One fewer than the limit must
            // leave the branch open and the limit itself must close it, so any
            // dropped update shows up as an off-by-one here.
            const int callers = ProvisioningThrottle.MaxFailuresPerUsername - 1;

            var throttle = new ProvisioningThrottle();
            var ready = new ManualResetEventSlim(false);

            var workers = Enumerable.Range(0, callers).Select(index => Task.Run(() =>
            {
                ready.Wait();
                throttle.RecordFailure("alice", Now);
            })).ToArray();

            ready.Set();
            await Task.WhenAll(workers);

            Assert.False(throttle.IsThrottled("alice", Now));

            throttle.RecordFailure("alice", Now);

            Assert.True(throttle.IsThrottled("alice", Now));
        }

        [Fact]
        public async Task Concurrent_invented_usernames_keep_the_map_bounded_and_the_branch_closed()
        {
            const int callers = 256;
            const int failuresEach = 8;

            var throttle = new ProvisioningThrottle();
            var faults = new ConcurrentBag<Exception>();
            var ready = new ManualResetEventSlim(false);

            var workers = Enumerable.Range(0, callers).Select(index => Task.Run(() =>
            {
                ready.Wait();

                try
                {
                    for (var attempt = 0; attempt < failuresEach; attempt++)
                    {
                        throttle.RecordFailure("invented" + index + "-" + attempt, Now);
                        throttle.IsThrottled("invented" + index, Now);
                    }
                }
                catch (Exception ex)
                {
                    faults.Add(ex);
                }
            })).ToArray();

            ready.Set();
            await Task.WhenAll(workers);

            Assert.Empty(faults);
            Assert.True(throttle.TrackedUsernames(Now) <= ProvisioningThrottle.MaxTrackedUsernames);

            // 2048 failures is far past the global limit, so whatever the
            // interleaving the branch is shut.
            Assert.True(throttle.IsThrottled("never-seen-before", Now));
        }
    }
}

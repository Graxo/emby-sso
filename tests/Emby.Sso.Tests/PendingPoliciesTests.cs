using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class PendingPoliciesTests
    {
        private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(10);
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

        private const string PolicyA = "{\"EnableAllFolders\":false,\"IsAdministrator\":false}";
        private const string PolicyB = "{\"EnableAllFolders\":true,\"IsAdministrator\":false}";

        private static PendingPolicies CreateStore() => new PendingPolicies(Lifetime);

        [Fact]
        public void Take_returns_the_policy_that_was_armed()
        {
            var store = CreateStore();
            store.Arm("alice", PolicyA, Now);

            var taken = store.Take(Now);

            Assert.NotNull(taken);
            Assert.Equal("alice", taken.Username);
            Assert.Equal(PolicyA, taken.PolicyJson);
        }

        [Fact]
        public void Take_on_an_empty_store_returns_null()
        {
            Assert.Null(CreateStore().Take(Now));
        }

        [Fact]
        public void Take_consumes_the_entry()
        {
            var store = CreateStore();
            store.Arm("alice", PolicyA, Now);

            Assert.NotNull(store.Take(Now));
            Assert.Null(store.Take(Now));
        }

        [Fact]
        public void An_entry_is_claimable_right_up_to_its_expiry()
        {
            var store = CreateStore();
            store.Arm("alice", PolicyA, Now);

            Assert.NotNull(store.Take(Now + Lifetime - TimeSpan.FromTicks(1)));
        }

        [Fact]
        public void An_expired_entry_is_never_served()
        {
            var store = CreateStore();
            store.Arm("alice", PolicyA, Now);

            Assert.Null(store.Take(Now + Lifetime));
            Assert.Equal(0, store.Count(Now + Lifetime));
        }

        [Fact]
        public void Expiry_removes_the_entry_even_when_nothing_claims_it()
        {
            var store = CreateStore();
            store.Arm("alice", PolicyA, Now);

            Assert.Equal(1, store.Count(Now));
            Assert.Equal(0, store.Count(Now + Lifetime));
        }

        [Fact]
        public void Unanimous_entries_are_each_served_the_shared_policy()
        {
            var store = CreateStore();
            store.Arm("alice", PolicyA, Now);
            store.Arm("bob", PolicyA, Now);
            store.Arm("carol", PolicyA, Now);

            var first = store.Take(Now);
            var second = store.Take(Now);
            var third = store.Take(Now);

            Assert.Equal(PolicyA, first.PolicyJson);
            Assert.Equal(PolicyA, second.PolicyJson);
            Assert.Equal(PolicyA, third.PolicyJson);
            Assert.Null(store.Take(Now));
        }

        [Fact]
        public void A_disagreeing_entry_makes_every_claim_in_the_burst_fail_closed()
        {
            var store = CreateStore();
            store.Arm("alice", PolicyA, Now);
            store.Arm("bob", PolicyB, Now);

            // Answering either claim would mean handing one sign-in's policy to
            // the other's account, so neither is answered...
            Assert.Null(store.Take(Now));

            // ...and the whole set is dropped, so the second claim cannot then be
            // served the survivor.
            Assert.Equal(0, store.Count(Now));
            Assert.Null(store.Take(Now));
        }

        [Fact]
        public void A_stale_disagreeing_entry_stops_poisoning_claims_once_it_expires()
        {
            var store = CreateStore();
            store.Arm("stale", PolicyB, Now);

            var later = Now + Lifetime;
            store.Arm("alice", PolicyA, later);

            var taken = store.Take(later);

            Assert.NotNull(taken);
            Assert.Equal("alice", taken.Username);
        }

        [Fact]
        public void Arm_refuses_rather_than_evicting_when_the_store_is_full()
        {
            var store = CreateStore();

            for (var index = 0; index < PendingPolicies.Capacity; index++)
            {
                store.Arm("user" + index, PolicyA, Now);
            }

            var refusal = Assert.Throws<SsoException>(() => store.Arm("overflow", PolicyA, Now));

            // The user-safe reason must be a constant, never the diagnostic text.
            Assert.Equal(SsoErrors.SessionExpired, refusal.UserSafeReason);

            // Nothing was evicted: every armed sign-in can still claim, which is
            // the property that stops a surplus claim landing on someone else.
            Assert.Equal(PendingPolicies.Capacity, store.Count(Now));

            for (var index = 0; index < PendingPolicies.Capacity; index++)
            {
                Assert.NotNull(store.Take(Now));
            }

            Assert.Null(store.Take(Now));
        }

        [Fact]
        public void Expiry_frees_capacity_again()
        {
            var store = CreateStore();

            for (var index = 0; index < PendingPolicies.Capacity; index++)
            {
                store.Arm("user" + index, PolicyA, Now);
            }

            Assert.Throws<SsoException>(() => store.Arm("overflow", PolicyA, Now));

            var later = Now + Lifetime;
            store.Arm("later", PolicyA, later);

            var taken = store.Take(later);
            Assert.NotNull(taken);
            Assert.Equal("later", taken.Username);
        }

        [Fact]
        public async Task Claims_never_outnumber_arms_under_real_concurrency()
        {
            // The failure this guards against: an arm that is silently dropped
            // still leaves a claim behind, and that surplus claim used to be
            // answered with a substitute policy for somebody else's account.
            // Every caller here arms and then claims exactly once, the way a
            // provisioning sign-in does, so served + refused must equal the
            // number of arms that succeeded.
            const int callers = 128;

            var store = CreateStore();
            var served = 0;
            var refusedArms = 0;
            var wrongPolicy = new ConcurrentBag<string>();
            var ready = new ManualResetEventSlim(false);

            var workers = Enumerable.Range(0, callers).Select(index => Task.Run(() =>
            {
                ready.Wait();

                try
                {
                    store.Arm("user" + index, PolicyA, Now);
                }
                catch (SsoException)
                {
                    Interlocked.Increment(ref refusedArms);
                    return;
                }

                var taken = store.Take(Now);

                if (taken == null)
                {
                    return;
                }

                if (!string.Equals(taken.PolicyJson, PolicyA, StringComparison.Ordinal))
                {
                    wrongPolicy.Add(taken.PolicyJson);
                }

                Interlocked.Increment(ref served);
            })).ToArray();

            ready.Set();
            await Task.WhenAll(workers);

            Assert.Empty(wrongPolicy);

            // Whatever the interleaving, an arm that succeeded is an entry that
            // exists, so exactly as many claims are answered as arms succeeded
            // and nothing is left behind.
            Assert.Equal(callers - refusedArms, served);
            Assert.Equal(0, store.Count(Now));
        }

        [Fact]
        public async Task Concurrent_arms_beyond_capacity_refuse_instead_of_dropping_entries()
        {
            const int callers = 256;

            var store = CreateStore();
            var armed = 0;
            var ready = new ManualResetEventSlim(false);

            var workers = Enumerable.Range(0, callers).Select(index => Task.Run(() =>
            {
                ready.Wait();

                try
                {
                    store.Arm("user" + index, PolicyA, Now);
                    Interlocked.Increment(ref armed);
                }
                catch (SsoException)
                {
                }
            })).ToArray();

            ready.Set();
            await Task.WhenAll(workers);

            // Nobody claimed, so every successful arm must still be present: the
            // store never makes room by throwing an entry away.
            Assert.Equal(PendingPolicies.Capacity, armed);
            Assert.Equal(PendingPolicies.Capacity, store.Count(Now));
        }
    }
}

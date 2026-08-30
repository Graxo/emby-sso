using System;
using System.Linq;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class PendingLoginStoreTests
    {
        private readonly TestClock _clock = new TestClock();

        private PendingLoginStore CreateStore(int maxEntries = 256) =>
            new PendingLoginStore(_clock.Func, TimeSpan.FromMinutes(5), maxEntries);

        [Fact]
        public void Create_produces_distinct_state_nonce_and_verifier()
        {
            var store = CreateStore();
            var login = store.Create();

            Assert.False(string.IsNullOrWhiteSpace(login.State));
            Assert.False(string.IsNullOrWhiteSpace(login.Nonce));
            Assert.False(string.IsNullOrWhiteSpace(login.CodeVerifier));
            Assert.NotEqual(login.State, login.Nonce);
            Assert.NotEqual(login.State, login.CodeVerifier);
        }

        [Fact]
        public void Create_derives_the_challenge_from_the_verifier()
        {
            var store = CreateStore();
            var login = store.Create();

            Assert.Equal(SecureRandom.CreateCodeChallenge(login.CodeVerifier), login.CodeChallenge);
        }

        [Fact]
        public void Consume_returns_the_matching_login()
        {
            var store = CreateStore();
            var created = store.Create();

            var consumed = store.Consume(created.State);

            Assert.NotNull(consumed);
            Assert.Equal(created.Nonce, consumed.Nonce);
            Assert.Equal(created.CodeVerifier, consumed.CodeVerifier);
        }

        [Fact]
        public void Consume_rejects_a_replayed_state()
        {
            var store = CreateStore();
            var created = store.Create();

            Assert.NotNull(store.Consume(created.State));
            Assert.Null(store.Consume(created.State));
        }

        [Fact]
        public void Consume_rejects_an_unknown_state()
        {
            var store = CreateStore();
            store.Create();

            Assert.Null(store.Consume("never-issued"));
        }

        [Fact]
        public void Consume_rejects_null_and_empty_state()
        {
            var store = CreateStore();

            Assert.Null(store.Consume(null));
            Assert.Null(store.Consume(string.Empty));
        }

        [Fact]
        public void Consume_rejects_an_expired_state()
        {
            var store = CreateStore();
            var created = store.Create();

            _clock.Advance(TimeSpan.FromMinutes(6));

            Assert.Null(store.Consume(created.State));
        }

        [Fact]
        public void The_store_evicts_the_oldest_entries_past_its_limit_once_they_are_old_enough()
        {
            var store = CreateStore(maxEntries: 3);
            var first = store.Create();

            // Past the store's default eviction-age floor, so the oldest entry
            // is a legitimate target for eviction rather than a fresh, in-flight
            // login that a burst of new creates must not be able to displace.
            _clock.Advance(TimeSpan.FromSeconds(31));

            store.Create();
            store.Create();
            store.Create();

            Assert.Null(store.Consume(first.State));
        }

        [Fact]
        public void A_burst_of_anonymous_creates_cannot_evict_a_fresh_login_within_the_age_floor()
        {
            // /Sso/Start takes no credentials, so nothing stops a flood of
            // requests arriving within the same instant. None of them may evict
            // an entry created moments ago - that entry could belong to a real
            // user mid-redirect to the identity provider.
            var store = CreateStore(maxEntries: 3);
            var first = store.Create();

            store.Create();
            store.Create();
            store.Create();
            store.Create();

            Assert.NotNull(store.Consume(first.State));
        }
    }
}

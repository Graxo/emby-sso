using System;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class HandoffSecretStoreTests
    {
        private readonly TestClock _clock = new TestClock();

        private HandoffSecretStore CreateStore() =>
            new HandoffSecretStore(_clock.Func, TimeSpan.FromSeconds(30));

        [Fact]
        public void A_freshly_issued_secret_is_accepted()
        {
            var store = CreateStore();
            var secret = store.Issue("alice");

            Assert.True(store.TryConsume("alice", secret));
        }

        [Fact]
        public void A_secret_cannot_be_used_twice()
        {
            var store = CreateStore();
            var secret = store.Issue("alice");

            Assert.True(store.TryConsume("alice", secret));
            Assert.False(store.TryConsume("alice", secret));
        }

        [Fact]
        public void A_secret_expires_after_the_ttl()
        {
            var store = CreateStore();
            var secret = store.Issue("alice");

            _clock.Advance(TimeSpan.FromSeconds(31));

            Assert.False(store.TryConsume("alice", secret));
        }

        [Fact]
        public void A_secret_is_bound_to_one_username()
        {
            var store = CreateStore();
            var secret = store.Issue("alice");

            Assert.False(store.TryConsume("bob", secret));
            Assert.True(store.TryConsume("alice", secret));
        }

        [Fact]
        public void Username_matching_is_case_insensitive()
        {
            var store = CreateStore();
            var secret = store.Issue("Alice");

            Assert.True(store.TryConsume("alice", secret));
        }

        [Fact]
        public void A_wrong_secret_is_rejected()
        {
            var store = CreateStore();
            store.Issue("alice");

            Assert.False(store.TryConsume("alice", "not-the-secret"));
        }

        [Fact]
        public void An_empty_secret_is_rejected()
        {
            var store = CreateStore();
            store.Issue("alice");

            Assert.False(store.TryConsume("alice", string.Empty));
            Assert.False(store.TryConsume("alice", null));
        }

        [Fact]
        public void Issuing_a_second_secret_invalidates_the_first()
        {
            var store = CreateStore();
            var first = store.Issue("alice");
            var second = store.Issue("alice");

            Assert.False(store.TryConsume("alice", first));
            Assert.True(store.TryConsume("alice", second));
        }
    }
}

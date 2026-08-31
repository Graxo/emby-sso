using System;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The PIN store, and above all the limit that carries the security weight:
    /// how many guesses one issued PIN admits, and whose budget an attempt can
    /// spend.
    /// </summary>
    public class SignInPinStoreTests
    {
        private readonly TestClock _clock = new TestClock();

        private SignInPinStore CreateStore() =>
            new SignInPinStore(_clock.Func, SignInPinStore.DefaultTtl);

        /// <summary>
        /// A PIN-shaped value that is definitely not the one issued. Built from
        /// the alphabet so it reaches the comparison rather than being turned
        /// away as unshaped.
        /// </summary>
        private static string AWrongPin(string issued)
        {
            var wrong = issued[0] == '2' ? "3" : "2";

            return wrong + issued.Substring(1);
        }

        [Fact]
        public void A_freshly_issued_pin_is_accepted()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            Assert.True(store.TryConsume("alice", pin));
        }

        [Fact]
        public void A_pin_cannot_be_used_twice()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            Assert.True(store.TryConsume("alice", pin));
            Assert.False(store.TryConsume("alice", pin));
        }

        [Fact]
        public void A_pin_expires_after_the_ttl()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            _clock.Advance(SignInPinStore.DefaultTtl + TimeSpan.FromSeconds(1));

            Assert.False(store.TryConsume("alice", pin));
        }

        [Fact]
        public void A_pin_is_still_good_a_moment_before_it_expires()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            _clock.Advance(SignInPinStore.DefaultTtl - TimeSpan.FromSeconds(1));

            Assert.True(store.TryConsume("alice", pin));
        }

        [Fact]
        public void The_ttl_is_the_single_digit_minutes_the_design_calls_for()
        {
            Assert.InRange(SignInPinStore.DefaultTtl.TotalMinutes, 1, 9);
        }

        [Fact]
        public void Issuing_a_second_pin_invalidates_the_first()
        {
            var store = CreateStore();
            var first = store.Issue("alice");

            store.Issue("alice");

            Assert.False(store.TryConsume("alice", first));
        }

        /// <summary>
        /// The corner this design has, recorded so nobody discovers it as a
        /// surprise: a user who asks for a PIN twice and then types the OLDER
        /// one spends the newer one, because from the store's side a stale PIN
        /// is indistinguishable from a guess. Keeping superseded PINs around to
        /// tell the two apart would mean keeping dead credentials alive, which
        /// is worse than the inconvenience. The user asks for another.
        /// </summary>
        [Fact]
        public void Presenting_a_superseded_pin_spends_the_live_one()
        {
            var store = CreateStore();
            var first = store.Issue("alice");
            var second = store.Issue("alice");

            // The superseded PIN is simply wrong now, and being wrong spends
            // the live PIN's allowance like any other wrong guess.
            for (var attempt = 0; attempt < SignInPinStore.MaxAttemptsPerPin; attempt++)
            {
                Assert.False(store.TryConsume("alice", first));
            }

            Assert.False(store.TryConsume("alice", second));
        }

        [Fact]
        public void The_displayed_form_of_a_pin_is_accepted()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            Assert.True(store.TryConsume("alice", SignInPin.Format(pin).ToLowerInvariant()));
        }

        // ------------------------------------------------------------------
        // Account binding
        // ------------------------------------------------------------------

        [Fact]
        public void A_live_pin_presented_with_a_different_username_is_refused()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            Assert.False(store.TryConsume("bob", pin));
        }

        /// <summary>
        /// And refusing it must not spend it. Otherwise naming somebody else
        /// would be a way to destroy their PIN with a value you already hold -
        /// and, worse, a way to destroy it without even knowing whose it was.
        /// </summary>
        [Fact]
        public void Presenting_a_pin_under_the_wrong_username_does_not_consume_it()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            Assert.False(store.TryConsume("bob", pin));
            Assert.True(store.TryConsume("alice", pin));
        }

        [Fact]
        public void Username_matching_is_case_insensitive_and_trimmed()
        {
            var store = CreateStore();
            var pin = store.Issue("Alice");

            Assert.True(store.TryConsume(" alice ", pin));
        }

        // ------------------------------------------------------------------
        // The attempt limit: what it costs, and what it must never cost
        // ------------------------------------------------------------------

        [Fact]
        public void A_wrong_guess_destroys_the_pin_so_it_cannot_be_ground_down()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            // A slip is survivable - the whole reason the allowance is not one.
            for (var attempt = 0; attempt < SignInPinStore.MaxAttemptsPerPin - 1; attempt++)
            {
                Assert.False(store.TryConsume("alice", AWrongPin(pin)));
            }

            Assert.True(store.TryConsume("alice", pin));

            // Exhausting the allowance is not. A fresh PIN, guessed at until
            // the allowance is gone, is dead even to its rightful owner.
            var second = store.Issue("alice");

            for (var attempt = 0; attempt < SignInPinStore.MaxAttemptsPerPin; attempt++)
            {
                Assert.False(store.TryConsume("alice", AWrongPin(second)));
            }

            Assert.False(store.TryConsume("alice", second));
        }

        [Fact]
        public void One_pin_admits_exactly_the_documented_number_of_failed_guesses()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            for (var attempt = 0; attempt < SignInPinStore.MaxAttemptsPerPin; attempt++)
            {
                Assert.False(store.TryConsume("alice", AWrongPin(pin)));
            }

            // Spent. Even the right PIN no longer works, which is the point:
            // the guesser's budget against one issued PIN is finite and small.
            Assert.False(store.TryConsume("alice", pin));
            Assert.Equal(0, store.Count());
        }

        /// <summary>
        /// The rule that keeps the feature usable at all. Three credential
        /// shapes arrive in one password field, and a user with a live PIN who
        /// types their own password on the television must not thereby destroy
        /// the PIN they were about to use.
        /// </summary>
        [Fact]
        public void A_value_that_is_not_pin_shaped_does_not_spend_the_pin()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            Assert.False(store.TryConsume("alice", "correct horse battery staple"));
            Assert.False(store.TryConsume("alice", SecureRandom.CreateToken(32)));
            Assert.False(store.TryConsume("alice", string.Empty));
            Assert.False(store.TryConsume("alice", null));

            Assert.True(store.TryConsume("alice", pin));
        }

        [Fact]
        public void An_attempt_against_a_username_with_no_pin_does_nothing_at_all()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            Assert.False(store.TryConsume("nobody", "ABCD-EFGH"));

            Assert.True(store.TryConsume("alice", pin));
        }

        // ------------------------------------------------------------------
        // THE AVAILABILITY PROPERTY
        //
        // The same guarantee ProvisioningThrottle makes, reached differently:
        // the only thing an attempt can consume is the PIN of the username it
        // names. Nothing anybody does to one account can refuse anything to
        // another.
        // ------------------------------------------------------------------

        [Fact]
        public void Burning_one_users_pin_leaves_every_other_users_pin_untouched()
        {
            var store = CreateStore();
            var alice = store.Issue("alice");
            var bob = store.Issue("bob");

            // Bob's PIN is guessed at until its allowance is gone, and dies.
            for (var attempt = 0; attempt < SignInPinStore.MaxAttemptsPerPin; attempt++)
            {
                Assert.False(store.TryConsume("bob", AWrongPin(bob)));
            }

            Assert.False(store.TryConsume("bob", bob));

            // Alice never notices.
            Assert.True(store.TryConsume("alice", alice));
        }

        [Fact]
        public void An_attacker_guessing_across_invented_usernames_cannot_refuse_a_real_ones_pin()
        {
            var store = CreateStore();
            var alice = store.Issue("alice");

            for (var i = 0; i < 10000; i++)
            {
                Assert.False(store.TryConsume("invented-" + i, "ABCD-EFGH"));
            }

            // No aggregate counter exists to be filled, so there is nothing an
            // attacker can fill. Alice's PIN is exactly as good as it was.
            Assert.True(store.TryConsume("alice", alice));
        }

        /// <summary>
        /// A stranger's guessing must not be able to grow the store either -
        /// only a completed browser sign-in can put an entry in it.
        /// </summary>
        [Fact]
        public void A_failed_attempt_never_creates_an_entry()
        {
            var store = CreateStore();

            for (var i = 0; i < 1000; i++)
            {
                store.TryConsume("invented-" + i, "ABCD-EFGH");
            }

            Assert.Equal(0, store.Count());
        }

        [Fact]
        public void Expired_pins_are_dropped_from_the_store()
        {
            var store = CreateStore();
            store.Issue("alice");
            store.Issue("bob");

            _clock.Advance(SignInPinStore.DefaultTtl + TimeSpan.FromSeconds(1));

            Assert.Equal(0, store.Count());
        }

        [Fact]
        public void A_pin_cannot_be_issued_without_a_username()
        {
            var store = CreateStore();

            Assert.Throws<ArgumentException>(() => store.Issue(null));
            Assert.Throws<ArgumentException>(() => store.Issue("   "));
        }

        [Fact]
        public void An_attempt_without_a_username_is_refused()
        {
            var store = CreateStore();
            var pin = store.Issue("alice");

            Assert.False(store.TryConsume(null, pin));
            Assert.False(store.TryConsume("   ", pin));
            Assert.True(store.TryConsume("alice", pin));
        }
    }
}

using System;
using Emby.Sso.LicenceService.Admin;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.RateLimiting;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The brake on guessing the admin password, and the properties it claims.
    ///
    /// Each test names one of the guarantees in
    /// <see cref="AdminLoginThrottle"/>'s remarks. The two that matter most are
    /// the ones a conventional design gets the other way round: nothing is ever
    /// locked, and this budget is not the activation endpoint's.
    /// </summary>
    public class AdminLoginThrottleTests
    {
        private static readonly DateTimeOffset Start = new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

        private const string Guesser = "203.0.113.9";
        private const string Operator = "198.51.100.4";

        private static AdminLoginThrottle Make(TestClock clock, int first = 2, int max = 60)
        {
            return new AdminLoginThrottle(
                new AdminOptions { LoginDelaySeconds = first, LoginMaxDelaySeconds = max },
                new RateLimitOptions(),
                clock);
        }

        [Fact]
        public void A_first_attempt_is_allowed()
        {
            Assert.True(Make(new TestClock(Start)).Check(Guesser).IsAllowed);
        }

        [Fact]
        public void A_wrong_password_buys_a_wait_before_the_next_attempt()
        {
            var clock = new TestClock(Start);
            var throttle = Make(clock);

            throttle.Failed(Guesser);

            var refused = throttle.Check(Guesser);

            Assert.False(refused.IsAllowed);
            Assert.True(refused.RetryAfter >= TimeSpan.FromSeconds(1));
        }

        /// <summary>
        /// The wait doubles. Remove the doubling and the third failure costs the
        /// same as the first, which is what this asserts it does not.
        /// </summary>
        [Fact]
        public void Each_further_wrong_password_costs_more_than_the_last()
        {
            var clock = new TestClock(Start);
            var throttle = Make(clock);

            var waits = new TimeSpan[4];

            for (var i = 0; i < waits.Length; i++)
            {
                throttle.Failed(Guesser);
                waits[i] = throttle.Check(Guesser).RetryAfter;
                clock.Advance(waits[i]);
            }

            Assert.True(waits[1] > waits[0], "the second failure cost no more than the first");
            Assert.True(waits[2] > waits[1], "the third failure cost no more than the second");
            Assert.True(waits[3] > waits[2], "the fourth failure cost no more than the third");
        }

        [Fact]
        public void The_wait_stops_growing_at_the_configured_ceiling()
        {
            var clock = new TestClock(Start);
            var throttle = Make(clock, first: 2, max: 16);

            for (var i = 0; i < 30; i++)
            {
                throttle.Failed(Guesser);
            }

            Assert.True(throttle.Check(Guesser).RetryAfter <= TimeSpan.FromSeconds(16));
        }

        /// <summary>
        /// THE ONE THAT MATTERS MOST. There is one operator; an attacker who
        /// could lock the account could stop the only person able to fix this
        /// service from reaching it. However many times a guesser is wrong, the
        /// wait expires and the door opens again.
        /// </summary>
        [Fact]
        public void Nothing_is_ever_locked_out_permanently()
        {
            var clock = new TestClock(Start);
            var throttle = Make(clock, first: 2, max: 60);

            for (var i = 0; i < 500; i++)
            {
                throttle.Failed(Guesser);
            }

            Assert.False(throttle.Check(Guesser).IsAllowed);

            clock.Advance(TimeSpan.FromSeconds(61));

            Assert.True(throttle.Check(Guesser).IsAllowed, "500 wrong guesses locked the operator out for good");
        }

        [Fact]
        public void A_correct_password_forgives_the_wait()
        {
            var clock = new TestClock(Start);
            var throttle = Make(clock);

            throttle.Failed(Operator);
            throttle.Failed(Operator);

            clock.Advance(TimeSpan.FromSeconds(60));

            throttle.Succeeded(Operator);
            throttle.Failed(Guesser);

            clock.Advance(TimeSpan.FromSeconds(AdminLoginThrottle.GlobalMaximumSeconds + 1));

            Assert.True(throttle.Check(Operator).IsAllowed);
        }

        /// <summary>
        /// Guessing from many addresses must not be many times faster than
        /// guessing from one. The global wait is small on purpose - see the
        /// class remarks - so this asserts it exists rather than that it is
        /// long.
        /// </summary>
        [Fact]
        public void Guessing_from_a_fresh_address_every_time_still_costs_something()
        {
            var clock = new TestClock(Start);
            var throttle = Make(clock);

            for (var i = 0; i < 6; i++)
            {
                throttle.Failed("203.0.113." + i.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }

            var refused = throttle.Check("203.0.113.200");

            Assert.False(refused.IsAllowed);
            Assert.Equal("global", refused.Scope);
        }

        [Fact]
        public void The_global_wait_is_short_enough_that_it_never_shuts_the_operator_out()
        {
            var clock = new TestClock(Start);
            var throttle = Make(clock);

            for (var i = 0; i < 1000; i++)
            {
                throttle.Failed("203.0.113." + (i % 254).ToString(System.Globalization.CultureInfo.InvariantCulture));
            }

            clock.Advance(TimeSpan.FromSeconds(AdminLoginThrottle.GlobalMaximumSeconds + 1));

            Assert.True(
                throttle.Check(Operator).IsAllowed,
                "a distributed flood kept the operator out for longer than the global ceiling");
        }

        /// <summary>
        /// The brief asks for a budget separate from /v1/activate's, and this is
        /// what separate means: a flood on one leaves the other untouched, in
        /// both directions. Wire them to one limiter and this fails.
        /// </summary>
        [Fact]
        public void The_login_budget_and_the_activation_budget_are_not_the_same_budget()
        {
            var clock = new TestClock(Start);
            var limits = new RateLimitOptions { PerClientBurst = 3, PerClientPerMinute = 3, GlobalPerMinute = 10 };
            var throttle = new AdminLoginThrottle(new AdminOptions(), limits, clock);
            var activations = new ActivationRateLimiter(limits, clock);

            for (var i = 0; i < 50; i++)
            {
                throttle.Failed(Guesser);
            }

            Assert.False(throttle.Check(Guesser).IsAllowed);
            Assert.True(activations.Check(Guesser).IsAllowed, "guessing the admin password spent an activation budget");

            var fresh = new AdminLoginThrottle(new AdminOptions(), limits, clock);

            for (var i = 0; i < 50; i++)
            {
                activations.Check(Operator);
            }

            Assert.False(activations.Check(Operator).IsAllowed);
            Assert.True(fresh.Check(Operator).IsAllowed, "a flood of activations delayed the operator's login");
        }

        [Fact]
        public void Checking_does_not_itself_lengthen_the_wait()
        {
            var clock = new TestClock(Start);
            var throttle = Make(clock);

            throttle.Failed(Guesser);

            var first = throttle.Check(Guesser).RetryAfter;

            for (var i = 0; i < 20; i++)
            {
                throttle.Check(Guesser);
            }

            Assert.Equal(first, throttle.Check(Guesser).RetryAfter);
        }

        [Fact]
        public void The_number_of_tracked_clients_is_bounded()
        {
            var clock = new TestClock(Start);
            var limits = new RateLimitOptions { MaxTrackedClients = 64 };
            var throttle = new AdminLoginThrottle(new AdminOptions(), limits, clock);

            for (var i = 0; i < 500; i++)
            {
                throttle.Failed("10.1." + (i / 254).ToString(System.Globalization.CultureInfo.InvariantCulture)
                    + "." + (i % 254).ToString(System.Globalization.CultureInfo.InvariantCulture));
            }

            Assert.True(throttle.TrackedClients <= limits.MaxTrackedClients);
        }
    }
}

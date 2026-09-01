using System;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.RateLimiting;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The four properties written down in ActivationRateLimiter's comment, each
    /// one asserted. A limiter whose behaviour is only described in prose is a
    /// number somebody picked.
    /// </summary>
    public class RateLimiterTests
    {
        private static readonly DateTimeOffset Start = new DateTimeOffset(2026, 1, 5, 12, 0, 0, TimeSpan.Zero);

        [Fact]
        public void A_client_can_spend_its_burst_and_then_no_more()
        {
            var clock = new TestClock(Start);
            var limiter = new ActivationRateLimiter(Options(burst: 5, perMinute: 10, global: 1000), clock);

            for (var i = 0; i < 5; i++)
            {
                Assert.True(limiter.Check("1.2.3.4").IsAllowed, "attempt " + i + " should have been allowed");
            }

            Assert.False(limiter.Check("1.2.3.4").IsAllowed);
        }

        [Fact]
        public void The_bucket_refills_at_the_configured_rate_and_no_faster()
        {
            var clock = new TestClock(Start);
            var limiter = new ActivationRateLimiter(Options(burst: 5, perMinute: 60, global: 1000), clock);

            for (var i = 0; i < 5; i++)
            {
                limiter.Check("1.2.3.4");
            }

            Assert.False(limiter.Check("1.2.3.4").IsAllowed);

            // 60 a minute is one a second.
            clock.Advance(TimeSpan.FromSeconds(1));

            Assert.True(limiter.Check("1.2.3.4").IsAllowed);
            Assert.False(limiter.Check("1.2.3.4").IsAllowed);
        }

        [Fact]
        public void The_long_run_ceiling_for_one_client_is_the_configured_rate()
        {
            var clock = new TestClock(Start);
            var limiter = new ActivationRateLimiter(Options(burst: 5, perMinute: 10, global: 100000), clock);

            var allowed = 0;

            // An hour, checked every second: 60 x 10 sustained, plus the initial
            // burst of 5 that was already in the bucket.
            for (var second = 0; second < 3600; second++)
            {
                if (limiter.Check("1.2.3.4").IsAllowed)
                {
                    allowed++;
                }

                clock.Advance(TimeSpan.FromSeconds(1));
            }

            Assert.InRange(allowed, 600, 606);
        }

        [Fact]
        public void One_noisy_client_does_not_spend_another_clients_budget()
        {
            var clock = new TestClock(Start);
            var limiter = new ActivationRateLimiter(Options(burst: 3, perMinute: 10, global: 1000), clock);

            for (var i = 0; i < 10; i++)
            {
                limiter.Check("1.2.3.4");
            }

            Assert.True(limiter.Check("5.6.7.8").IsAllowed);
        }

        [Fact]
        public void The_global_ceiling_holds_when_the_attempts_come_from_everywhere()
        {
            var clock = new TestClock(Start);
            var limiter = new ActivationRateLimiter(Options(burst: 100, perMinute: 100, global: 10), clock);

            var allowed = 0;

            for (var i = 0; i < 50; i++)
            {
                if (limiter.Check("10.0.0." + i).IsAllowed)
                {
                    allowed++;
                }
            }

            Assert.Equal(10, allowed);
        }

        [Fact]
        public void A_client_refused_by_the_global_ceiling_does_not_lose_its_own_budget()
        {
            var clock = new TestClock(Start);
            var limiter = new ActivationRateLimiter(Options(burst: 5, perMinute: 5, global: 2), clock);

            // Somebody else exhausts the global bucket.
            limiter.Check("9.9.9.9");
            limiter.Check("9.9.9.9");

            Assert.False(limiter.Check("1.2.3.4").IsAllowed);

            // A minute later the global bucket has refilled. The customer who was
            // caught in somebody else's flood must still have their full budget,
            // not four fifths of it.
            clock.Advance(TimeSpan.FromMinutes(1));

            var allowed = 0;

            for (var i = 0; i < 5; i++)
            {
                if (limiter.Check("1.2.3.4").IsAllowed)
                {
                    allowed++;
                }
            }

            Assert.Equal(2, allowed);
        }

        [Fact]
        public void A_refusal_always_says_how_long_to_wait_and_never_says_zero()
        {
            var clock = new TestClock(Start);
            var limiter = new ActivationRateLimiter(Options(burst: 1, perMinute: 1, global: 1000), clock);

            limiter.Check("1.2.3.4");

            var refused = limiter.Check("1.2.3.4");

            Assert.False(refused.IsAllowed);
            Assert.True(refused.RetryAfter >= TimeSpan.FromSeconds(1));
            Assert.Equal("client", refused.Scope);
        }

        [Fact]
        public void Memory_is_bounded_however_many_addresses_show_up()
        {
            var clock = new TestClock(Start);
            var options = Options(burst: 5, perMinute: 60, global: 1000000);

            options.MaxTrackedClients = 100;

            var limiter = new ActivationRateLimiter(options, clock);

            for (var i = 0; i < 5000; i++)
            {
                limiter.Check("10." + (i / 65536) + "." + ((i / 256) % 256) + "." + (i % 256));

                // Each caller arrives a second apart, so earlier buckets refill
                // and become droppable - the eviction that costs nobody anything.
                clock.Advance(TimeSpan.FromSeconds(1));
            }

            Assert.True(limiter.TrackedClients <= 100, "tracked " + limiter.TrackedClients + " clients");
        }

        [Fact]
        public void An_unknown_client_key_is_still_counted_rather_than_waved_through()
        {
            var clock = new TestClock(Start);
            var limiter = new ActivationRateLimiter(Options(burst: 2, perMinute: 2, global: 1000), clock);

            Assert.True(limiter.Check(null).IsAllowed);
            Assert.True(limiter.Check(null).IsAllowed);
            Assert.False(limiter.Check(null).IsAllowed);
        }

        [Fact]
        public void The_limit_is_spent_before_the_code_is_looked_up()
        {
            using var service = new TestService(options =>
            {
                options.RateLimit.PerClientBurst = 1;
                options.RateLimit.PerClientPerMinute = 1;
            });

            var code = service.GiveOutACode();

            // The first call is allowed through - it spends the budget whether
            // or not it can hand a licence back. Since the private key left this
            // host, a first activation answers "being signed" rather than a
            // licence; what matters here is that it was not rate limited.
            Assert.NotEqual(
                ActivationError.RateLimited,
                service.Activations.Activate(Request(code), "1.2.3.4").Error);

            var refused = service.Activations.Activate(Request(code), "1.2.3.4");

            Assert.Equal(ActivationError.RateLimited, refused.Error);
            Assert.True(refused.RetryAfter > TimeSpan.Zero);
        }

        [Fact]
        public void A_malformed_request_still_costs_the_caller_an_attempt()
        {
            // Otherwise the cheapest way to enumerate is to send rubbish, which
            // costs nothing and keeps the budget for the guesses that count.
            using var service = new TestService(options =>
            {
                options.RateLimit.PerClientBurst = 2;
                options.RateLimit.PerClientPerMinute = 2;
            });

            Assert.Equal(ActivationError.MalformedRequest, service.Activations.Activate(Request("rubbish"), "1.2.3.4").Error);
            Assert.Equal(ActivationError.MalformedRequest, service.Activations.Activate(Request("rubbish"), "1.2.3.4").Error);
            Assert.Equal(ActivationError.RateLimited, service.Activations.Activate(Request("rubbish"), "1.2.3.4").Error);
        }

        private static ActivationRequest Request(string code)
        {
            return new ActivationRequest { Code = code, ServerId = "c5bc6e91458540caa295c4efdda1a58a" };
        }

        private static RateLimitOptions Options(int burst, int perMinute, int global)
        {
            return new RateLimitOptions
            {
                PerClientBurst = burst,
                PerClientPerMinute = perMinute,
                GlobalPerMinute = global,
                MaxTrackedClients = 20000,
            };
        }
    }
}

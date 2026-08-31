using System;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// A clock the test moves by hand. Everything that depends on time in this
    /// service - licence expiry, the rate limiter's refill - takes a
    /// TimeProvider for this reason: a test that proves a token bucket refills
    /// by sleeping is a test that is slow and flaky in equal measure.
    /// </summary>
    internal sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now;

        public TestClock(DateTimeOffset start)
        {
            _now = start;
        }

        public override DateTimeOffset GetUtcNow()
        {
            return _now;
        }

        public void Advance(TimeSpan by)
        {
            _now = _now.Add(by);
        }
    }
}

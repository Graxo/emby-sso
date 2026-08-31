using System;
using Emby.Sso.LicenceService.Configuration;

namespace Emby.Sso.LicenceService.RateLimiting
{
    /// <summary>
    /// A second budget, with the same shape and guarantees as
    /// <see cref="ActivationRateLimiter"/>, spent by POST /buy/start.
    ///
    /// It is separate rather than shared for one reason: creating a PayPal order
    /// and activating a licence are different things to run out of. A crawler
    /// hammering the buy page must not be able to use up the budget a customer
    /// needs to activate the licence they already paid for, and vice versa.
    ///
    /// What it protects is the vendor's PayPal API quota and this service's
    /// outbound connections, both of which an unauthenticated GET-then-POST could
    /// otherwise spend for them.
    /// </summary>
    public sealed class CheckoutRateLimiter
    {
        private readonly ActivationRateLimiter _inner;

        public CheckoutRateLimiter(RateLimitOptions options, TimeProvider time)
        {
            _inner = new ActivationRateLimiter(options, time);
        }

        public RateLimitDecision Check(string clientKey)
        {
            return _inner.Check(clientKey);
        }
    }
}

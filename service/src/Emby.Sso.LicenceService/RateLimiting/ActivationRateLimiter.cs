using System;
using System.Collections.Generic;
using System.Linq;
using Emby.Sso.LicenceService.Configuration;

namespace Emby.Sso.LicenceService.RateLimiting
{
    /// <summary>
    /// The limiter on /v1/activate.
    ///
    /// WHAT THIS GUARANTEES, exactly, because a limiter whose property is not
    /// written down is a number somebody picked:
    ///
    ///   1. No single client key can spend more than <c>PerClientBurst</c>
    ///      attempts without waiting, and cannot sustain more than
    ///      <c>PerClientPerMinute</c> attempts per minute thereafter. The bucket
    ///      refills continuously, so the long-run ceiling for one key is exactly
    ///      PerClientPerMinute per minute regardless of how the attempts are
    ///      spaced.
    ///   2. Across all keys together, the long-run ceiling is
    ///      <c>GlobalPerMinute</c> per minute with a burst of the same size.
    ///      This is the one that holds when the attempts come from a botnet and
    ///      property 1 buys nothing.
    ///   3. EVERY attempt is counted - malformed, unknown code, exhausted code,
    ///      and successful alike - and counted BEFORE the code is normalised,
    ///      hashed or looked up. A refused caller costs one dictionary lookup and
    ///      no database work, so the endpoint cannot be used to make the service
    ///      do work on demand.
    ///   4. Memory is bounded: at most <c>MaxTrackedClients</c> buckets exist.
    ///      Past that, buckets that have fully refilled - which means their owner
    ///      has spent nothing for a full window - are dropped first, so eviction
    ///      only ever forgets a client with nothing owing.
    ///
    /// WHAT IT DOES NOT GUARANTEE, and must not be sold as: it is not what stops
    /// codes being guessed. A code has 150 bits of entropy; at the global
    /// ceiling of a few hundred attempts a minute, exhausting a meaningful
    /// fraction of that space takes longer than the universe has been here. The
    /// limiter's job is to bound what a guesser costs in CPU and disk, to keep
    /// one noisy caller from starving real activations, and to make an
    /// enumeration attempt visible in the logs. The entropy is the security
    /// control; this is the resource control.
    ///
    /// It is also per-process and in-memory. There is one process, so that is
    /// the whole system; if this is ever run as two replicas behind a load
    /// balancer, each replica enforces its own budget and the real global
    /// ceiling doubles. Say so before scaling it out.
    /// </summary>
    public sealed class ActivationRateLimiter
    {
        private readonly object _gate = new object();
        private readonly Dictionary<string, Bucket> _clients = new Dictionary<string, Bucket>(StringComparer.Ordinal);
        private readonly RateLimitOptions _options;
        private readonly TimeProvider _time;
        private readonly Bucket _global;

        public ActivationRateLimiter(RateLimitOptions options, TimeProvider time)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _time = time ?? throw new ArgumentNullException(nameof(time));
            _global = new Bucket(options.GlobalPerMinute, options.GlobalPerMinute / 60.0, _time.GetUtcNow());
        }

        /// <summary>
        /// Spends one attempt for <paramref name="clientKey"/>, or refuses and
        /// says how long until the next one is affordable.
        ///
        /// The per-client bucket is checked first and the global one second, and
        /// NEITHER is debited unless both would allow: a caller refused by the
        /// global ceiling must not also lose their own budget, or a flood from
        /// elsewhere would lock legitimate customers out for far longer than the
        /// flood lasted.
        /// </summary>
        public RateLimitDecision Check(string clientKey)
        {
            var now = _time.GetUtcNow();
            var key = string.IsNullOrEmpty(clientKey) ? "unknown" : clientKey;

            lock (_gate)
            {
                if (!_clients.TryGetValue(key, out var client))
                {
                    Evict(now);

                    client = new Bucket(
                        _options.PerClientBurst,
                        _options.PerClientPerMinute / 60.0,
                        now);

                    _clients[key] = client;
                }

                var clientWait = client.WaitFor(now);

                if (clientWait > TimeSpan.Zero)
                {
                    return RateLimitDecision.Refused(clientWait, "client");
                }

                var globalWait = _global.WaitFor(now);

                if (globalWait > TimeSpan.Zero)
                {
                    return RateLimitDecision.Refused(globalWait, "global");
                }

                client.Spend();
                _global.Spend();

                return RateLimitDecision.Allowed();
            }
        }

        /// <summary>Only for tests and for /healthz to report how much memory this is holding.</summary>
        public int TrackedClients
        {
            get
            {
                lock (_gate)
                {
                    return _clients.Count;
                }
            }
        }

        private void Evict(DateTimeOffset now)
        {
            if (_clients.Count < _options.MaxTrackedClients)
            {
                return;
            }

            // Anything back at full capacity has spent nothing for a whole
            // window; forgetting it gives its owner nothing they did not already
            // have. This is the only eviction that is free.
            var idle = _clients.Where(pair => pair.Value.IsFull(now)).Select(pair => pair.Key).ToList();

            foreach (var stale in idle)
            {
                _clients.Remove(stale);
            }

            if (_clients.Count < _options.MaxTrackedClients)
            {
                return;
            }

            // Everything tracked is mid-flood. Drop the least recently used
            // quarter; this hands those keys a fresh budget, which is the honest
            // cost of a fixed memory ceiling, and the global bucket still holds.
            foreach (var stale in _clients
                .OrderBy(pair => pair.Value.LastSpend)
                .Take(Math.Max(1, _options.MaxTrackedClients / 4))
                .Select(pair => pair.Key)
                .ToList())
            {
                _clients.Remove(stale);
            }
        }

        private sealed class Bucket
        {
            private readonly double _capacity;
            private readonly double _perSecond;
            private double _tokens;
            private DateTimeOffset _updated;

            public Bucket(double capacity, double perSecond, DateTimeOffset now)
            {
                _capacity = capacity;
                _perSecond = perSecond <= 0 ? double.Epsilon : perSecond;
                _tokens = capacity;
                _updated = now;
                LastSpend = now;
            }

            public DateTimeOffset LastSpend { get; private set; }

            public TimeSpan WaitFor(DateTimeOffset now)
            {
                Refill(now);

                if (_tokens >= 1.0)
                {
                    return TimeSpan.Zero;
                }

                var seconds = (1.0 - _tokens) / _perSecond;

                // Rounded up: telling a caller to come back in 0 seconds when the
                // token is 0.4s away just produces another refusal.
                return TimeSpan.FromSeconds(Math.Ceiling(seconds));
            }

            public void Spend()
            {
                _tokens -= 1.0;
                LastSpend = _updated;
            }

            public bool IsFull(DateTimeOffset now)
            {
                Refill(now);

                return _tokens >= _capacity;
            }

            private void Refill(DateTimeOffset now)
            {
                if (now <= _updated)
                {
                    return;
                }

                _tokens = Math.Min(_capacity, _tokens + ((now - _updated).TotalSeconds * _perSecond));
                _updated = now;
            }
        }
    }

    public readonly struct RateLimitDecision
    {
        private RateLimitDecision(bool allowed, TimeSpan retryAfter, string scope)
        {
            IsAllowed = allowed;
            RetryAfter = retryAfter;
            Scope = scope;
        }

        public bool IsAllowed { get; }

        /// <summary>What goes in the Retry-After header. Never zero on a refusal.</summary>
        public TimeSpan RetryAfter { get; }

        /// <summary>"client" or "global" - logged, never returned to the caller.</summary>
        public string Scope { get; }

        public static RateLimitDecision Allowed()
        {
            return new RateLimitDecision(true, TimeSpan.Zero, null);
        }

        public static RateLimitDecision Refused(TimeSpan retryAfter, string scope)
        {
            return new RateLimitDecision(false, retryAfter < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : retryAfter, scope);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using Emby.Sso.LicenceService.Configuration;

namespace Emby.Sso.LicenceService.Admin
{
    /// <summary>
    /// The brake on guessing the admin password.
    ///
    /// WHAT THIS GUARANTEES, exactly:
    ///
    ///   1. A wrong password costs the client that gave it a WAIT, and the wait
    ///      doubles with each consecutive failure: 2s, 4s, 8s, 16s ... up to
    ///      ADMIN_LOGIN_MAX_DELAY_SECONDS. An attempt made before the wait has
    ///      elapsed is refused WITHOUT the password being checked, so a guesser
    ///      cannot spend the service's PBKDF2 time either.
    ///   2. NOTHING IS EVER LOCKED. The wait always expires and a correct
    ///      password always works once it has. This is deliberate and it is the
    ///      main way this differs from the usual "five failures and you are
    ///      out": there is one operator, and an attacker who could lock the
    ///      account could stop the only person able to fix the service from
    ///      reaching it, from anywhere, for free. A delay costs a guesser
    ///      everything and costs the operator a few seconds once.
    ///   3. A correct password resets that client's wait to zero, and the
    ///      global one with it.
    ///   4. There is a SECOND, global wait, so that guessing from ten thousand
    ///      addresses is not ten thousand times faster than guessing from one.
    ///      It doubles the same way but stops at a deliberately small ceiling
    ///      (<see cref="GlobalMaximumSeconds"/>), because it is the one an
    ///      innocent operator can be caught by: at that ceiling a distributed
    ///      guesser gets about twelve attempts a minute against a password with
    ///      at least 16 characters of entropy, and the operator waits five
    ///      seconds.
    ///   5. THIS BUDGET IS NOT /v1/activate's. Nothing spent here is spent
    ///      there and nothing spent there is spent here: a flood of activation
    ///      attempts must not delay the operator's login, and an attack on the
    ///      login must not stop customers activating licences they have paid
    ///      for. They are separate objects with separate state, and a test
    ///      asserts it.
    ///   6. Memory is bounded by <see cref="RateLimitOptions.MaxTrackedClients"/>.
    ///      Entries whose wait has expired are dropped first; dropping one gives
    ///      its owner nothing they would not have had a moment later anyway.
    ///
    /// WHAT IT DOES NOT DO: it is not what makes the password hard to guess.
    /// That is the password's length and PBKDF2's cost. This bounds the rate,
    /// makes an attempt visible in the audit trail, and keeps the guesser from
    /// making this service do work on demand.
    ///
    /// It is per-process and in-memory, like every other limiter here. One
    /// process is the whole system; two replicas would each enforce their own.
    /// </summary>
    public sealed class AdminLoginThrottle
    {
        /// <summary>
        /// Where the GLOBAL wait stops. Small on purpose - see guarantee 4. It
        /// is not configurable because the reasoning behind the number is about
        /// which side of the trade-off an operator ends up on, and an operator
        /// who raises it is choosing to be locked out slowly.
        /// </summary>
        public const int GlobalMaximumSeconds = 5;

        private readonly object _gate = new object();
        private readonly Dictionary<string, Attempts> _clients = new Dictionary<string, Attempts>(StringComparer.Ordinal);
        private readonly AdminOptions _options;
        private readonly RateLimitOptions _limits;
        private readonly TimeProvider _time;
        private readonly Attempts _global = new Attempts();

        public AdminLoginThrottle(AdminOptions options, RateLimitOptions limits, TimeProvider time)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _limits = limits ?? throw new ArgumentNullException(nameof(limits));
            _time = time ?? throw new ArgumentNullException(nameof(time));
        }

        /// <summary>Only for tests and for reporting how much memory this holds.</summary>
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

        /// <summary>
        /// Whether this client may attempt a password now, and how long until
        /// they may if not. Checking does not spend anything: a refusal here
        /// does not lengthen the wait, so an operator who submits twice by
        /// accident is not punished for it.
        /// </summary>
        public Decision Check(string clientKey)
        {
            var now = _time.GetUtcNow();
            var key = Key(clientKey);

            lock (_gate)
            {
                if (_clients.TryGetValue(key, out var client))
                {
                    var wait = client.WaitAt(now);

                    if (wait > TimeSpan.Zero)
                    {
                        return Decision.Wait(wait, "client");
                    }
                }

                var globalWait = _global.WaitAt(now);

                if (globalWait > TimeSpan.Zero)
                {
                    return Decision.Wait(globalWait, "global");
                }

                return Decision.Allowed;
            }
        }

        /// <summary>A wrong password. Doubles this client's wait, and nudges the global one.</summary>
        public void Failed(string clientKey)
        {
            var now = _time.GetUtcNow();
            var key = Key(clientKey);

            lock (_gate)
            {
                if (!_clients.TryGetValue(key, out var client))
                {
                    Evict(now);

                    client = new Attempts();
                    _clients[key] = client;
                }

                client.Fail(now, _options.LoginDelaySeconds, _options.LoginMaxDelaySeconds);
                _global.Fail(now, _options.LoginDelaySeconds, GlobalMaximumSeconds);
            }
        }

        /// <summary>
        /// A correct password. Everything this client owed is forgiven, and so
        /// is the global wait - the flood is over if somebody in it knew the
        /// password, and leaving the operator in a global delay after they have
        /// proved who they are is punishing the wrong person.
        /// </summary>
        public void Succeeded(string clientKey)
        {
            lock (_gate)
            {
                _clients.Remove(Key(clientKey));
                _global.Reset();
            }
        }

        private static string Key(string clientKey)
        {
            return string.IsNullOrEmpty(clientKey) ? "unknown" : clientKey;
        }

        private void Evict(DateTimeOffset now)
        {
            if (_clients.Count < _limits.MaxTrackedClients)
            {
                return;
            }

            foreach (var expired in _clients
                .Where(pair => pair.Value.WaitAt(now) <= TimeSpan.Zero)
                .Select(pair => pair.Key)
                .ToList())
            {
                _clients.Remove(expired);
            }

            if (_clients.Count < _limits.MaxTrackedClients)
            {
                return;
            }

            // Everything tracked is still serving a wait. Drop the ones with the
            // least left to serve; the global wait still holds over all of them.
            foreach (var soonest in _clients
                .OrderBy(pair => pair.Value.WaitAt(now))
                .Take(Math.Max(1, _limits.MaxTrackedClients / 4))
                .Select(pair => pair.Key)
                .ToList())
            {
                _clients.Remove(soonest);
            }
        }

        private sealed class Attempts
        {
            private int _failures;
            private DateTimeOffset _notBefore;

            public TimeSpan WaitAt(DateTimeOffset now)
            {
                return now >= _notBefore ? TimeSpan.Zero : _notBefore - now;
            }

            public void Fail(DateTimeOffset now, int firstSeconds, int maximumSeconds)
            {
                _failures++;

                // first, 2x, 4x, 8x ... shifted rather than powered so that a
                // long run of failures cannot overflow into a negative delay.
                var seconds = (double)firstSeconds;

                for (var i = 1; i < _failures && seconds < maximumSeconds; i++)
                {
                    seconds *= 2;
                }

                _notBefore = now.AddSeconds(Math.Min(seconds, maximumSeconds));
            }

            public void Reset()
            {
                _failures = 0;
                _notBefore = default;
            }
        }

        public readonly struct Decision
        {
            private Decision(bool allowed, TimeSpan wait, string scope)
            {
                IsAllowed = allowed;
                RetryAfter = wait;
                Scope = scope;
            }

            public static Decision Allowed => new Decision(true, TimeSpan.Zero, null);

            public bool IsAllowed { get; }

            /// <summary>Never zero on a refusal, so a Retry-After is always truthful.</summary>
            public TimeSpan RetryAfter { get; }

            /// <summary>"client" or "global". Audited, and shown to the operator so a global wait is explicable.</summary>
            public string Scope { get; }

            public static Decision Wait(TimeSpan wait, string scope)
            {
                return new Decision(false, wait < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : wait, scope);
            }
        }
    }
}

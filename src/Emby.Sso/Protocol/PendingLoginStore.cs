using System;
using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Holds browser logins between the redirect to the identity provider and
    /// the callback. Entries are single-use and bounded, because the endpoint
    /// that creates them is reachable without authentication.
    /// </summary>
    public sealed class PendingLoginStore
    {
        /// <summary>
        /// /Sso/Start takes no credentials, so this bounds how many logins an
        /// anonymous caller can have in flight at once. Sized well above any
        /// realistic legitimate concurrency so raising it further would not
        /// meaningfully help an attacker who has already reached it.
        /// </summary>
        private const int DefaultMaxEntries = 2048;

        /// <summary>
        /// An entry younger than this is never evicted to make room for a new
        /// one, however full the store is - see <see cref="Create"/>.
        /// </summary>
        private static readonly TimeSpan DefaultMinEvictionAge = TimeSpan.FromSeconds(30);

        private readonly Dictionary<string, PendingLogin> _entries = new Dictionary<string, PendingLogin>(StringComparer.Ordinal);
        private readonly List<string> _insertionOrder = new List<string>();
        private readonly object _lock = new object();
        private readonly Func<DateTimeOffset> _clock;
        private readonly TimeSpan _ttl;
        private readonly int _maxEntries;
        private readonly TimeSpan _minEvictionAge;

        public PendingLoginStore(Func<DateTimeOffset> clock, TimeSpan ttl, int maxEntries = DefaultMaxEntries, TimeSpan? minEvictionAge = null)
        {
            _clock = clock ?? throw new ArgumentNullException(nameof(clock));
            _ttl = ttl;
            _maxEntries = maxEntries > 0 ? maxEntries : throw new ArgumentOutOfRangeException(nameof(maxEntries));
            _minEvictionAge = minEvictionAge ?? DefaultMinEvictionAge;
        }

        public PendingLogin Create()
        {
            var login = new PendingLogin(
                SecureRandom.CreateToken(32),
                SecureRandom.CreateToken(32),
                SecureRandom.CreateCodeVerifier(),
                _clock().Add(_ttl),
                SecureRandom.CreateToken(32));

            lock (_lock)
            {
                var now = _clock();
                RemoveExpired(now);
                EvictForSpace(now);

                _entries[login.State] = login;
                _insertionOrder.Add(login.State);
            }

            return login;
        }

        public PendingLogin Consume(string state)
        {
            if (string.IsNullOrEmpty(state))
            {
                return null;
            }

            lock (_lock)
            {
                RemoveExpired(_clock());

                if (!_entries.TryGetValue(state, out var login))
                {
                    return null;
                }

                _entries.Remove(state);
                _insertionOrder.Remove(state);
                return login;
            }
        }

        /// <summary>
        /// Evicts the oldest entries, one at a time, while the store is at
        /// capacity - but only entries already at least <see cref="_minEvictionAge"/>
        /// old. A flood of anonymous <c>/Sso/Start</c> requests must not be able
        /// to evict a legitimate, freshly-created login before its browser has
        /// had a chance to complete the round trip: if the oldest entry is still
        /// within that protected window, every entry is, so nothing is evicted
        /// and the store is briefly allowed to exceed <see cref="_maxEntries"/>
        /// instead. It self-corrects as soon as an entry ages past the floor or
        /// expires, so the store stays bounded rather than becoming unbounded.
        /// </summary>
        private void EvictForSpace(DateTimeOffset now)
        {
            while (_insertionOrder.Count >= _maxEntries)
            {
                var oldest = _insertionOrder[0];

                if (!_entries.TryGetValue(oldest, out var oldestLogin))
                {
                    // The two collections are kept in sync everywhere else; if
                    // this ever happened, drop the stale index entry and move on
                    // rather than spin forever on it.
                    _insertionOrder.RemoveAt(0);
                    continue;
                }

                var createdAt = oldestLogin.ExpiresAt - _ttl;

                if (now - createdAt < _minEvictionAge)
                {
                    break;
                }

                _insertionOrder.RemoveAt(0);
                _entries.Remove(oldest);
            }
        }

        private void RemoveExpired(DateTimeOffset now)
        {
            ExpiryPolicy.RemoveExpired(_entries, login => login.ExpiresAt, now, key => _insertionOrder.Remove(key));
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Holds browser logins between the redirect to the identity provider and
    /// the callback. Entries are single-use and bounded, because the endpoint
    /// that creates them is reachable without authentication.
    /// </summary>
    public sealed class PendingLoginStore
    {
        private readonly Dictionary<string, PendingLogin> _entries = new Dictionary<string, PendingLogin>(StringComparer.Ordinal);
        private readonly List<string> _insertionOrder = new List<string>();
        private readonly object _lock = new object();
        private readonly Func<DateTimeOffset> _clock;
        private readonly TimeSpan _ttl;
        private readonly int _maxEntries;

        public PendingLoginStore(Func<DateTimeOffset> clock, TimeSpan ttl, int maxEntries = 256)
        {
            _clock = clock ?? throw new ArgumentNullException(nameof(clock));
            _ttl = ttl;
            _maxEntries = maxEntries > 0 ? maxEntries : throw new ArgumentOutOfRangeException(nameof(maxEntries));
        }

        public PendingLogin Create()
        {
            var login = new PendingLogin(
                SecureRandom.CreateToken(32),
                SecureRandom.CreateToken(32),
                SecureRandom.CreateCodeVerifier(),
                _clock().Add(_ttl));

            lock (_lock)
            {
                RemoveExpired();

                while (_insertionOrder.Count >= _maxEntries)
                {
                    var oldest = _insertionOrder[0];
                    _insertionOrder.RemoveAt(0);
                    _entries.Remove(oldest);
                }

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
                RemoveExpired();

                if (!_entries.TryGetValue(state, out var login))
                {
                    return null;
                }

                _entries.Remove(state);
                _insertionOrder.Remove(state);
                return login;
            }
        }

        private void RemoveExpired()
        {
            var now = _clock();
            var stale = _entries.Where(pair => pair.Value.ExpiresAt <= now).Select(pair => pair.Key).ToList();

            foreach (var key in stale)
            {
                _entries.Remove(key);
                _insertionOrder.Remove(key);
            }
        }
    }
}

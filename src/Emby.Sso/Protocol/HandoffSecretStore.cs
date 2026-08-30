using System;
using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Holds the single-use secrets that carry a completed browser login into
    /// Emby's ordinary login form. One live secret per user at a time.
    /// </summary>
    public sealed class HandoffSecretStore
    {
        private readonly Dictionary<string, Entry> _entries =
            new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);

        private readonly object _lock = new object();
        private readonly Func<DateTimeOffset> _clock;
        private readonly TimeSpan _ttl;

        public HandoffSecretStore(Func<DateTimeOffset> clock, TimeSpan ttl)
        {
            _clock = clock ?? throw new ArgumentNullException(nameof(clock));
            _ttl = ttl;
        }

        public string Issue(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("username is required", nameof(username));
            }

            var secret = SecureRandom.CreateToken(32);

            lock (_lock)
            {
                RemoveExpired();
                _entries[username] = new Entry(secret, _clock().Add(_ttl));
            }

            return secret;
        }

        public bool TryConsume(string username, string secret)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(secret))
            {
                return false;
            }

            lock (_lock)
            {
                RemoveExpired();

                if (!_entries.TryGetValue(username, out var entry))
                {
                    return false;
                }

                if (!FixedTime.Equals(entry.Secret, secret))
                {
                    return false;
                }

                _entries.Remove(username);
                return true;
            }
        }

        private void RemoveExpired()
        {
            var now = _clock();
            var stale = new List<string>();

            foreach (var pair in _entries)
            {
                if (pair.Value.ExpiresAt <= now)
                {
                    stale.Add(pair.Key);
                }
            }

            foreach (var key in stale)
            {
                _entries.Remove(key);
            }
        }

        private sealed class Entry
        {
            public Entry(string secret, DateTimeOffset expiresAt)
            {
                Secret = secret;
                ExpiresAt = expiresAt;
            }

            public string Secret { get; }

            public DateTimeOffset ExpiresAt { get; }
        }
    }
}

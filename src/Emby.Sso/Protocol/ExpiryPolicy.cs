using System;
using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The eviction policy <see cref="PendingLoginStore"/> and
    /// <see cref="HandoffSecretStore"/> both implement: remove every entry whose
    /// expiry has passed. Factors only that shared rule, not either store's
    /// storage shape - <see cref="PendingLoginStore"/> keeps an extra
    /// insertion-order list alongside its dictionary, which
    /// <paramref name="onRemove"/> exists to keep in sync.
    /// </summary>
    internal static class ExpiryPolicy
    {
        public static void RemoveExpired<TKey, TValue>(
            IDictionary<TKey, TValue> entries,
            Func<TValue, DateTimeOffset> expiresAt,
            DateTimeOffset now,
            Action<TKey> onRemove = null)
        {
            List<TKey> stale = null;

            foreach (var pair in entries)
            {
                if (expiresAt(pair.Value) <= now)
                {
                    if (stale == null)
                    {
                        stale = new List<TKey>();
                    }

                    stale.Add(pair.Key);
                }
            }

            if (stale == null)
            {
                return;
            }

            foreach (var key in stale)
            {
                entries.Remove(key);
                onRemove?.Invoke(key);
            }
        }
    }
}

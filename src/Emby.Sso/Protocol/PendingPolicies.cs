using System;
using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// One armed provisioning: the policy an account is about to be created
    /// with, the username that armed it, and when the arm stops being claimable.
    /// </summary>
    public sealed class PendingPolicy
    {
        /// <summary>
        /// For the log only, and only ever indicative — <see cref="PendingPolicies.Take"/>
        /// returns the oldest entry rather than a matched one, so under
        /// concurrency this may not name the account being created. Nothing is
        /// ever decided from it.
        /// </summary>
        public string Username { get; set; }

        public string PolicyJson { get; set; }

        public DateTimeOffset ExpiresAt { get; set; }
    }

    /// <summary>
    /// Correlates a gated sign-in with Emby's follow-up call to
    /// <c>IHasNewUserPolicy.GetNewUserPolicy()</c>, which takes no arguments and
    /// so cannot say which sign-in it is asking about. An AsyncLocal set inside
    /// Authenticate does not flow back to Emby's continuation (spike §9), so the
    /// correlation has to be shared state; the probe used one static volatile
    /// string, which is not safe to ship.
    ///
    /// Every entry holds an already-serialised policy, a username for the log,
    /// and an expiry. Reads consume. Concurrency is handled by refusing to
    /// guess: a claim is answered only when every live entry carries the same
    /// policy, in which case which one it belongs to cannot matter, and
    /// otherwise the whole set is dropped and the caller gets nothing.
    ///
    /// This type deliberately holds nothing but strings, a timestamp and a lock,
    /// and references no MediaBrowser type, so it lives in Protocol/ where the
    /// test project can reach it. The Emby-facing serialisation of a UserPolicy
    /// into <see cref="PendingPolicy.PolicyJson"/> stays in the Auth layer.
    /// </summary>
    public sealed class PendingPolicies
    {
        /// <summary>
        /// A ceiling on entries that were armed but never claimed. Arming
        /// requires a full gate pass, so this is not an anonymous DoS surface;
        /// it is here so a pathological caller cannot grow the list without
        /// bound inside one expiry window.
        /// </summary>
        public const int Capacity = 32;

        private readonly List<PendingPolicy> _entries = new List<PendingPolicy>();
        private readonly object _lock = new object();
        private readonly TimeSpan _lifetime;

        public PendingPolicies(TimeSpan lifetime)
        {
            _lifetime = lifetime;
        }

        /// <summary>
        /// Records a policy for the claim that is about to arrive. Throws when
        /// the store is full rather than making room.
        ///
        /// It used to evict the oldest entry, which was wrong in a way that is
        /// easy to miss: every armed sign-in goes on to claim exactly once, so
        /// dropping an entry does not drop a claim — it makes claims outnumber
        /// entries, and the surplus claim lands on some *other* caller, who then
        /// gets an account created with whatever the claim-failure path returns.
        /// Throwing here instead makes the overflow a failed sign-in, which the
        /// user can simply retry. That trade is the whole point: a failed login
        /// is recoverable, and an account created in the wrong shape under a
        /// real username is not (Emby resolves the name from then on, so the
        /// provisioning branch is never re-entered).
        /// </summary>
        public void Arm(string username, string policyJson, DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);

                if (_entries.Count >= Capacity)
                {
                    throw new SsoException(
                        SsoErrors.SessionExpired,
                        "too many first sign-ins are being provisioned at once; refusing rather than evicting an armed policy");
                }

                _entries.Add(new PendingPolicy
                {
                    Username = username,
                    PolicyJson = policyJson,
                    ExpiresAt = now + _lifetime,
                });
            }
        }

        /// <summary>
        /// The entry to create the account from, or null when this store cannot
        /// say which sign-in the caller means. Null is the fail-closed answer,
        /// never an empty or default policy — the caller must refuse outright.
        /// </summary>
        public PendingPolicy Take(DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);

                if (_entries.Count == 0)
                {
                    return null;
                }

                var candidate = _entries[0];

                for (var index = 1; index < _entries.Count; index++)
                {
                    if (!string.Equals(_entries[index].PolicyJson, candidate.PolicyJson, StringComparison.Ordinal))
                    {
                        // Not unanimous, so answering would mean picking one
                        // sign-in's policy for another's account. Drop them
                        // all: every racing claim in this burst fails closed.
                        _entries.Clear();
                        return null;
                    }
                }

                _entries.RemoveAt(0);
                return candidate;
            }
        }

        /// <summary>Live (unexpired) entries. For tests and diagnostics only.</summary>
        public int Count(DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);
                return _entries.Count;
            }
        }

        private void Purge(DateTimeOffset now)
        {
            for (var index = _entries.Count - 1; index >= 0; index--)
            {
                if (_entries[index].ExpiresAt <= now)
                {
                    _entries.RemoveAt(index);
                }
            }
        }
    }
}

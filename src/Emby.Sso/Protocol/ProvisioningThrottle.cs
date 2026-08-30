using System;
using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The brake on the one branch that will hand an unauthenticated stranger's
    /// guess to the identity provider.
    ///
    /// Emby's own throttle (<c>InvalidLoginAttemptCount</c>, <c>LockedOutDate</c>)
    /// lives on a <c>UserPolicy</c>, so it can only count against an account that
    /// already exists. The provisioning branch is by definition the branch where
    /// there is no such account: an unknown username reaches
    /// <c>SsoAuthenticationProvider.ProvisionOrRefuse</c>, which forwards the
    /// supplied password to the identity provider as a direct grant. Without
    /// something here, that makes the plugin an unmetered credential-stuffing
    /// relay against every identity-provider account the operator has not yet
    /// onboarded. This is the Emby-side half of the brake; the operator is also
    /// required to configure the identity provider's own failed-login policy,
    /// because only that one sees attempts that never reach Emby at all.
    ///
    /// Deliberate shape, all of it load-bearing:
    ///
    /// - <b>It is consulted BEFORE the credential is sent.</b> Counting after the
    ///   round trip would still let every guess be tried, which is both the
    ///   oracle and the load this exists to cut.
    /// - <b>Only failures are counted, and a success clears that username's
    ///   bucket.</b> A first-time user who mistypes their password must not be
    ///   locked out by their own typos once they get it right.
    /// - <b>Two buckets: one per username, one global.</b> A per-username budget
    ///   alone is no brake at all against an attacker who simply moves on to the
    ///   next name, which on this branch is the whole attack - the interesting
    ///   accounts are precisely the ones with no Emby user.
    /// - <b>The client's address is NOT a key, and cannot be.</b> Emby hands an
    ///   <c>IAuthenticationProvider</c> a username, a password and (on the
    ///   <c>IRequiresResolvedUser</c> overload) the resolved user - nothing else.
    ///   Verified by decompiling MediaBrowser.Controller 4.9.1.90: the three
    ///   interfaces this plugin implements expose no request, no headers and no
    ///   remote endpoint. A future reader looking for the missing per-IP bucket
    ///   should stop looking here; per-source limiting belongs in front of Emby
    ///   or in the identity provider.
    /// - <b>A refusal from here says exactly what the ordinary refusal says</b>
    ///   (<see cref="RefusalReason"/>). Telling a caller "you are rate limited"
    ///   confirms that their attempts are worth counting, and a distinct message
    ///   for a real username would leak which names exist.
    ///
    /// Holds nothing but strings, counters, timestamps and a lock, and references
    /// no <c>MediaBrowser.*</c> type, so it lives in Protocol/ where the test
    /// project can reach it - the same rule <see cref="PendingPolicies"/> follows.
    /// </summary>
    public sealed class ProvisioningThrottle
    {
        /// <summary>
        /// Failures one username may accumulate inside a <see cref="Window"/>
        /// before that username is refused without being tried.
        ///
        /// Ten is chosen to sit far above human error and far below useful
        /// guessing: it survives a first-time user fumbling their password
        /// several times, and it caps an attacker at forty guesses an hour
        /// against any one name, which is worthless against any password worth
        /// the name.
        ///
        /// Constants, not configuration, on purpose. These are a safety floor
        /// rather than a preference, and an operator who could raise them from
        /// the settings page could switch the brake off without meaning to.
        /// </summary>
        public const int MaxFailuresPerUsername = 10;

        /// <summary>
        /// Failures across ALL usernames inside a <see cref="Window"/> before the
        /// whole provisioning branch closes. This is the bucket that matters
        /// against the real attack, which walks a list of names rather than
        /// hammering one.
        ///
        /// A hundred is well above what provisioning legitimately produces - a
        /// server onboards a handful of new people a day, and each of them fails
        /// at most a few times - and it caps this branch's load on the identity
        /// provider at one token request every nine seconds in the worst case.
        /// </summary>
        public const int MaxFailuresGlobally = 100;

        /// <summary>
        /// A hard ceiling on tracked usernames, so an attacker who invents a new
        /// name for every attempt cannot grow the map without bound.
        ///
        /// It is deliberately far above <see cref="MaxFailuresGlobally"/>: a
        /// bucket is only ever created by a counted failure, and the global
        /// bucket closes the branch after a hundred of those per window, so a
        /// caller that consults <see cref="IsThrottled"/> first can never get
        /// near this. The cap is what makes the bound structural rather than
        /// arithmetical - it holds even if some future caller records failures
        /// without asking first.
        /// </summary>
        public const int MaxTrackedUsernames = 1024;

        /// <summary>
        /// What a throttled caller is told. Character-identical to the refusal an
        /// ordinary unknown username gets, and it must stay that way: a distinct
        /// sentence here would tell an attacker that this name is worth counting,
        /// which is the same membership leak the group gate's three identical
        /// messages exist to avoid. Do not "improve" this into a helpful
        /// "too many attempts, try again later".
        /// </summary>
        public const string RefusalReason = SsoErrors.UnknownUser;

        /// <summary>
        /// How long a bucket lives, measured from its FIRST counted failure -
        /// later failures raise the count but never push the expiry out. So a
        /// bucket cannot be kept alive by continued attempts, every lockout
        /// clears itself within this window, and the map drains on its own.
        ///
        /// Fifteen minutes is short enough that a legitimate new user who locked
        /// themselves out can simply wait rather than needing an operator, and
        /// long enough that an attacker's throughput stays negligible.
        /// </summary>
        public static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

        private sealed class Bucket
        {
            public int Failures;

            public DateTimeOffset ExpiresAt;
        }

        /// <summary>
        /// Keyed the way <see cref="UsernameMatcher"/> compares - trimmed, then
        /// ordinal case-insensitive - so "Alice", "alice" and " alice " share one
        /// budget, exactly as the rest of the plugin treats them as one person.
        /// </summary>
        private readonly Dictionary<string, Bucket> _perUsername =
            new Dictionary<string, Bucket>(UsernameMatcher.Comparer);

        private readonly object _lock = new object();

        /// <summary>Null means no counted failure is live in this window.</summary>
        private Bucket _global;

        /// <summary>
        /// Whether this attempt must be refused WITHOUT being tried. Ask before
        /// touching the network; a true answer means no credential leaves this
        /// process for this attempt.
        /// </summary>
        public bool IsThrottled(string username, DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);

                if (_global != null && _global.Failures >= MaxFailuresGlobally)
                {
                    return true;
                }

                return _perUsername.TryGetValue(UsernameMatcher.NormalizeKey(username), out var bucket)
                    && bucket.Failures >= MaxFailuresPerUsername;
            }
        }

        /// <summary>
        /// One attempt that was tried and did not end in a provisioned account.
        /// This overload counts unconditionally, which is what makes it the safe
        /// one to reach for: the caller has already decided this failure is the
        /// caller's own.
        ///
        /// Every failing exit of the provisioning branch below the check counts,
        /// including ones that never sent anything to the identity provider,
        /// because those are free for an attacker to generate and leaving them
        /// uncounted would be a way around the brake rather than a kindness. The
        /// single exception is a provider that could not be reached, which is
        /// not decided here - see
        /// <see cref="RecordFailure(string, SsoCredentialResult, DateTimeOffset)"/>,
        /// the overload a caller must use when the failure came from a
        /// validator result.
        ///
        /// A refusal by this throttle is NOT recorded - nothing was tried, and
        /// recording it would let a caller who is already refused keep the map
        /// growing.
        /// </summary>
        public void RecordFailure(string username, DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);

                if (_global == null)
                {
                    _global = new Bucket { Failures = 0, ExpiresAt = now + Window };
                }

                _global.Failures++;

                var key = UsernameMatcher.NormalizeKey(username);

                if (_perUsername.TryGetValue(key, out var bucket))
                {
                    bucket.Failures++;
                    return;
                }

                // The eviction rule, and the reason it cannot produce a wrong
                // ALLOW: at capacity a NEW username simply gets no bucket of its
                // own and is counted globally only. Nothing live is ever evicted
                // and no recorded failure is ever forgotten, so no attempt that
                // the recorded state says to refuse can become one that is
                // allowed. Making room by dropping the oldest bucket would do
                // exactly that - it would hand back a fresh ten-guess budget to
                // whichever name was dropped, which is the name an attacker
                // cycling through a list would reach again next.
                if (_perUsername.Count < MaxTrackedUsernames)
                {
                    _perUsername[key] = new Bucket { Failures = 1, ExpiresAt = now + Window };
                }
            }
        }

        /// <summary>
        /// The same counted failure, described by the validator result that
        /// produced it. This overload is where the ONE exemption lives: a result
        /// that says the identity provider could not be reached is not counted,
        /// because no credential was tested and an outage is not an attempt.
        ///
        /// Why it matters operationally: an identity-provider outage plus
        /// ordinary users retrying would otherwise fill both buckets, and the
        /// global one is small enough that a mass migration - many people
        /// signing in for the first time at once - could shut provisioning for
        /// EVERYONE for a further fifteen minutes after the provider came back.
        /// Nothing about that trades away brute-force protection: a guesser
        /// learns nothing from a request that got no answer.
        ///
        /// Everything else counts, and the exemption is deliberately narrow. A
        /// null result counts. A rejection the provider issued counts. A refusal
        /// this process decided without asking anyone - empty credential,
        /// plugin not configured, direct grant off - counts, because those are
        /// free for an attacker to produce. An identity that names somebody else
        /// and a group-gate refusal are counted by the caller through
        /// <see cref="RecordFailure(string, DateTimeOffset)"/>, which has no
        /// exemption at all.
        ///
        /// A future reader must not widen this into "do not count failures that
        /// never reached the provider". Uncounted failures are the hole this
        /// class exists to close; only the case where the network, not the
        /// caller, decided the outcome may be free.
        /// </summary>
        public void RecordFailure(string username, SsoCredentialResult result, DateTimeOffset now)
        {
            // Note the direction: anything other than an explicit unreachable
            // result - a null included - falls through and is counted.
            if (result != null && result.ProviderUnreachable)
            {
                return;
            }

            RecordFailure(username, now);
        }

        /// <summary>
        /// A credential that was accepted, so this username's failures were
        /// somebody getting their own password right eventually. Clears that
        /// username's bucket only.
        ///
        /// The global bucket is deliberately NOT cleared: an attacker who holds
        /// one valid identity would otherwise be able to reset the global brake
        /// at will, which is the only brake that constrains an attack that walks
        /// a list of names.
        /// </summary>
        public void RecordSuccess(string username, DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);
                _perUsername.Remove(UsernameMatcher.NormalizeKey(username));
            }
        }

        /// <summary>Live (unexpired) username buckets. For tests and diagnostics only.</summary>
        public int TrackedUsernames(DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);
                return _perUsername.Count;
            }
        }

        private void Purge(DateTimeOffset now)
        {
            ExpiryPolicy.RemoveExpired(_perUsername, bucket => bucket.ExpiresAt, now);

            if (_global != null && _global.ExpiresAt <= now)
            {
                _global = null;
            }
        }
    }
}

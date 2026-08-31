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
    /// THE PROPERTY THIS CLASS GUARANTEES (assessment finding F3). An attempt is
    /// refused here if, and only if, the failures recorded against THAT SAME
    /// username inside the current <see cref="Window"/> have reached the
    /// allowance in force. Nothing another caller does can refuse it. In
    /// particular a username with no recorded failure of its own is never
    /// refused, whatever anyone else is doing - so a stranger burning attempts
    /// on invented usernames cannot stop a legitimate first-time user who has
    /// their password right from signing in. That is
    /// <c>ProvisioningThrottleTests.An_attacker_burning_invented_usernames_cannot_refuse_a_clean_username</c>,
    /// and it is the whole reason this class no longer has a global lockout.
    ///
    /// WHAT THE OLD SHAPE DID, AND WHY IT HAD TO GO. There used to be a second
    /// bucket that counted failures across ALL usernames and, at a hundred of
    /// them, refused every attempt for the rest of the window. It needed no
    /// valid credential to fill: a hundred requests carrying invented usernames
    /// - the cheapest thing an unauthenticated caller can send - shut first-time
    /// provisioning for everybody for fifteen minutes, which is precisely the
    /// mass-onboarding case the branch exists to serve. A brake an attacker can
    /// pull is a weapon, not a brake.
    ///
    /// WHAT REPLACED IT, AND WHY THE GLOBAL COUNT SURVIVES. The count is still
    /// kept, and it still constrains what this branch can push at the identity
    /// provider - but it now TIGHTENS the per-username allowance rather than
    /// closing the door. Below <see cref="GlobalSurgeThreshold"/> failures in a
    /// window each username may fail <see cref="MaxFailuresPerUsername"/> times;
    /// at or above it, each username may fail only
    /// <see cref="SurgeFailuresPerUsername"/> times. Under a surge, therefore,
    /// what any one name can push at the provider drops by more than two thirds,
    /// while a name that has not failed keeps its first attempt. The distinction
    /// the old design lacked is exactly the one the assessment asked for:
    /// "this username has been failing" is a reason to refuse, "the server is
    /// busy being attacked" is not.
    ///
    /// WHAT IS HONESTLY GIVEN UP. There is no longer a hard ceiling on the
    /// number of round trips this branch can make to the identity provider in a
    /// window; the bound is now per username (at most
    /// <see cref="MaxFailuresPerUsername"/>, or
    /// <see cref="SurgeFailuresPerUsername"/> under surge, per name per window)
    /// and therefore scales with the number of DISTINCT names a caller sends.
    /// That is not an oversight, it is arithmetic: any aggregate ceiling is by
    /// definition reachable by an unauthenticated caller, and a reached ceiling
    /// is a refusal for whoever asks next - which is the denial of service being
    /// removed. You may have an aggregate cap or an availability guarantee, not
    /// both, and the aggregate cap is the one the operator can restore outside
    /// this process: per-source rate limiting in front of Emby, and the identity
    /// provider's own failed-login/reputation policy, which the README requires
    /// rather than suggests. Note also that the plugin never amplifies - one
    /// inbound attempt is at most one outbound token request, and an attacker
    /// able to send N requests here could send N requests to the provider
    /// directly.
    ///
    /// The rest of the shape is unchanged and still load-bearing:
    ///
    /// - <b>It is consulted BEFORE the credential is sent.</b> Counting after the
    ///   round trip would still let every guess be tried, which is both the
    ///   oracle and the load this exists to cut.
    /// - <b>Only failures are counted, and a success clears that username's
    ///   bucket.</b> A first-time user who mistypes their password must not be
    ///   locked out by their own typos once they get it right.
    /// - <b>The client's address is NOT a key, and cannot be.</b> Emby hands an
    ///   <c>IAuthenticationProvider</c> a username, a password and (on the
    ///   <c>IRequiresResolvedUser</c> overload) the resolved user - nothing else.
    ///   Verified by decompiling MediaBrowser.Controller 4.9.1.90: the three
    ///   interfaces this plugin implements expose no request, no headers and no
    ///   remote endpoint. A future reader looking for the missing per-IP bucket
    ///   should stop looking here; per-source limiting belongs in front of Emby
    ///   or in the identity provider. It is also why the guarantee above is
    ///   stated in terms of usernames: the username is the only thing this class
    ///   is ever told.
    /// - <b>A refusal from here says exactly what the ordinary refusal says</b>
    ///   (<see cref="RefusalReason"/>). Telling a caller "you are rate limited"
    ///   confirms that their attempts are worth counting, and a distinct message
    ///   for a real username would leak which names exist.
    ///
    /// Holds nothing but strings, counters, timestamps and a lock, and references
    /// no <c>MediaBrowser.*</c> type, so it lives in Protocol/ where the test
    /// project can reach it - the same rule <see cref="PendingPolicies"/> follows.
    /// </summary>
    internal sealed class ProvisioningThrottle
    {
        /// <summary>
        /// Failures one username may accumulate inside a <see cref="Window"/>
        /// before that username is refused without being tried, when the branch
        /// is NOT under a global surge.
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
        /// The allowance one username gets while the branch IS under a global
        /// surge - see <see cref="GlobalSurgeThreshold"/>.
        ///
        /// Three, not one, deliberately. One would be the strongest brake and
        /// would also mean that during a surge a single mistyped password locks
        /// a legitimate newcomer out for the rest of the window; three still
        /// leaves room for a fat-fingered phone keyboard while cutting what any
        /// one name can push at the identity provider by seventy per cent.
        ///
        /// The cost, stated plainly: an attacker who knows a not-yet-onboarded
        /// user's name and can raise a surge can lock that ONE name out with
        /// three attempts instead of ten. That is a smaller and more targeted
        /// harm than the branch-wide lockout this replaced - it needs the
        /// victim's name, it affects only that name, and it clears itself inside
        /// <see cref="Window"/>.
        /// </summary>
        public const int SurgeFailuresPerUsername = 3;

        /// <summary>
        /// Failures across ALL usernames inside a <see cref="Window"/> before the
        /// per-username allowance tightens from <see cref="MaxFailuresPerUsername"/>
        /// to <see cref="SurgeFailuresPerUsername"/>.
        ///
        /// A hundred is well above what provisioning legitimately produces - a
        /// server onboards a handful of new people a day, and each of them fails
        /// at most a few times - so a real onboarding burst does not reach it,
        /// and an attack does.
        ///
        /// It is a THRESHOLD, not a budget: crossing it changes the allowance,
        /// it never refuses an attempt on its own. A future reader must not turn
        /// this back into "and then refuse everybody" - see the class comment for
        /// what that cost.
        /// </summary>
        public const int GlobalSurgeThreshold = 100;

        /// <summary>
        /// A hard ceiling on tracked usernames, so an attacker who invents a new
        /// name for every attempt cannot grow the map without bound.
        ///
        /// This cap is now genuinely REACHABLE, which it was not before: the old
        /// global lockout closed the branch after a hundred failures, long
        /// before a thousand names could be recorded, so what happened at
        /// capacity never mattered. Now that the branch stays open, it does -
        /// see the eviction rule in
        /// <see cref="RecordFailure(string, DateTimeOffset)"/>.
        /// </summary>
        public const int MaxTrackedUsernames = 4096;

        /// <summary>
        /// How much of a username is kept as a map key. The map is bounded in
        /// ENTRIES by <see cref="MaxTrackedUsernames"/>, but an entry holds a
        /// caller-supplied string, so without this the memory bound would be
        /// whatever length of username an attacker chooses to send. Truncating
        /// makes the worst case a few megabytes.
        ///
        /// The only cost is that two names sharing a 128-character prefix share
        /// one budget. No Emby account name is anywhere near that long, and an
        /// attacker who wanted to collide with a real name would have to know it
        /// already - at which point they can simply spend that name's budget
        /// directly.
        /// </summary>
        public const int MaxTrackedUsernameLength = 128;

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
        ///
        /// The one and only reason it can answer true is this username's own
        /// recorded failures. See the class comment: that is the guarantee.
        /// </summary>
        public bool IsThrottled(string username, DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);

                return _perUsername.TryGetValue(Key(username), out var bucket)
                    && bucket.Failures >= AllowanceLocked();
            }
        }

        /// <summary>
        /// Whether enough failures have been counted across all usernames in this
        /// window to tighten the per-username allowance. For the log line that
        /// tells an operator an attack is under way, and for tests. It refuses
        /// nothing by itself.
        /// </summary>
        public bool IsGlobalSurge(DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);
                return SurgeLocked();
            }
        }

        /// <summary>
        /// Failures one username may accumulate right now before it is refused:
        /// <see cref="MaxFailuresPerUsername"/>, or
        /// <see cref="SurgeFailuresPerUsername"/> during a surge.
        /// </summary>
        public int AllowanceFor(DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);
                return AllowanceLocked();
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

                var key = Key(username);

                if (_perUsername.TryGetValue(key, out var bucket))
                {
                    bucket.Failures++;
                    return;
                }

                // The eviction rule, and why it is now the opposite of what it
                // was. While the global bucket still closed the branch outright
                // this cap was unreachable, so "at capacity, do not track the
                // new name" cost nothing and never forgetting a recorded failure
                // was free. With the branch staying open, refusing to track is
                // no longer the safe direction: an attacker who fills the map
                // with junk would leave every name arriving afterwards - a real
                // target included - permanently untracked, which is an unlimited
                // guessing budget for that target. Not tracking is the wrong
                // ALLOW now, so room is made.
                //
                // Room is made by dropping the WEAKEST bucket - fewest failures,
                // and among equals the one closest to expiring anyway - never an
                // arbitrary or an oldest one. What that costs an attacker is the
                // point: to push a name that is accumulating failures out of the
                // map, every one of the 4096 tracked names must be carrying at
                // least as many failures as it is, so displacing a name that is
                // nine failures deep costs on the order of forty thousand
                // attempts inside one fifteen-minute window - and has to be
                // repeated as those buckets expire. Dropping the oldest instead
                // would cost one.
                if (_perUsername.Count >= MaxTrackedUsernames)
                {
                    EvictWeakestLocked();
                }

                _perUsername[key] = new Bucket { Failures = 1, ExpiresAt = now + Window };
            }
        }

        /// <summary>
        /// The same counted failure, described by the validator result that
        /// produced it. This overload is where the ONE exemption lives: a result
        /// that says the identity provider could not be reached is not counted,
        /// because no credential was tested and an outage is not an attempt.
        ///
        /// Why it matters operationally: an identity-provider outage plus
        /// ordinary users retrying would otherwise fill the buckets, and a mass
        /// migration - many people signing in for the first time at once - would
        /// both lock individual newcomers out of their own retries and raise a
        /// surge that tightens everybody else's allowance, for a further fifteen
        /// minutes after the provider came back. Nothing about that trades away
        /// brute-force protection: a guesser learns nothing from a request that
        /// got no answer.
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
        /// The global count is deliberately NOT cleared: an attacker who holds
        /// one valid identity would otherwise be able to lift the surge - and
        /// with it the tightened allowance - at will, by signing in as
        /// themselves between guesses.
        /// </summary>
        public void RecordSuccess(string username, DateTimeOffset now)
        {
            lock (_lock)
            {
                Purge(now);
                _perUsername.Remove(Key(username));
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

        /// <summary>
        /// The map key: the comparison the rest of the plugin uses, then capped
        /// at <see cref="MaxTrackedUsernameLength"/> so a caller cannot choose
        /// how much memory an entry costs.
        /// </summary>
        private static string Key(string username)
        {
            // NormalizeKey answers string.Empty for a null, never null itself,
            // so an empty username is an ordinary key rather than a crash.
            var key = UsernameMatcher.NormalizeKey(username);

            return key.Length <= MaxTrackedUsernameLength
                ? key
                : key.Substring(0, MaxTrackedUsernameLength);
        }

        // Caller holds _lock, and has purged.
        private bool SurgeLocked()
        {
            return _global != null && _global.Failures >= GlobalSurgeThreshold;
        }

        // Caller holds _lock, and has purged.
        private int AllowanceLocked()
        {
            return SurgeLocked() ? SurgeFailuresPerUsername : MaxFailuresPerUsername;
        }

        // Caller holds _lock. Drops the least informative live bucket so a new
        // one can be recorded; see RecordFailure for why this direction.
        private void EvictWeakestLocked()
        {
            string weakestKey = null;
            var weakestFailures = int.MaxValue;
            var weakestExpiry = DateTimeOffset.MaxValue;

            foreach (var entry in _perUsername)
            {
                if (entry.Value.Failures < weakestFailures
                    || (entry.Value.Failures == weakestFailures && entry.Value.ExpiresAt < weakestExpiry))
                {
                    weakestKey = entry.Key;
                    weakestFailures = entry.Value.Failures;
                    weakestExpiry = entry.Value.ExpiresAt;
                }
            }

            if (weakestKey != null)
            {
                _perUsername.Remove(weakestKey);
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

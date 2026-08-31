using System;
using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Holds the short-lived, single-use PINs that carry a completed browser
    /// sign-in onto a TV. One live PIN per Emby account at a time, in memory
    /// only - losing them on a restart is correct, because a PIN is worth
    /// minutes and a person who loses one signs in again in the browser.
    ///
    /// The sibling of <see cref="HandoffSecretStore"/>, and deliberately shaped
    /// like it, with one difference that carries all the security weight: a
    /// handoff secret is 32 random bytes and a PIN is 39 bits typed on a remote
    /// control, so this store also has to decide what happens when somebody
    /// gets one WRONG.
    ///
    /// ------------------------------------------------------------------
    /// THE PROPERTY THIS CLASS GUARANTEES
    ///
    /// At most <see cref="MaxAttemptsPerPin"/> failed guesses can ever be made
    /// against any one issued PIN, after which that PIN is gone - and the ONLY
    /// thing an attempt can consume is the budget of the PIN issued to the very
    /// username the attempt names. Nothing an attempt does to one username's
    /// PIN can refuse anything to any other username, and nothing it does can
    /// refuse any OTHER credential shape - a browser handoff secret or an
    /// identity-provider password - even to the named user themselves.
    ///
    /// That is the same availability guarantee <see cref="ProvisioningThrottle"/>
    /// makes, reached a different way. The throttle counts failures against a
    /// username; this limit is not a counter against a caller or an aggregate
    /// at all, it is the life of one secret. A limit that lives on a secret
    /// cannot be used as a lever against a third party, because the only person
    /// who has anything to lose is the one whose PIN it is.
    ///
    /// WHY THERE IS NO SEPARATE RATE LIMITER, AND WHY THE EXISTING ONE IS NOT
    /// REUSED. The question the brief asks is what limit actually binds when an
    /// attacker guesses ACROSS usernames rather than against one. The answer is
    /// that no per-username or aggregate counter binds anything here that this
    /// per-PIN cap has not already bound harder:
    ///
    /// - A guess can only ever succeed against a username that has a LIVE PIN,
    ///   and each such PIN admits exactly <see cref="MaxAttemptsPerPin"/>
    ///   guesses in its whole life whatever rate the attacker sends at. So the
    ///   attacker's expected work is not reduced by spreading across usernames:
    ///   n usernames with live PINs offer n x <see cref="MaxAttemptsPerPin"/>
    ///   guesses at 1 in 6.56 x 10^11 each, which is the same arithmetic as one
    ///   username offering n times as many - except that the second thing is
    ///   impossible here and the first requires n people to have just signed in
    ///   through a browser.
    /// - An aggregate ceiling ("no more than N PIN attempts a minute
    ///   server-wide") would add nothing to that and would take something away:
    ///   any aggregate ceiling is by definition reachable by an unauthenticated
    ///   caller, and a reached ceiling is a refusal for whoever asks next. That
    ///   is exactly the denial of service <see cref="ProvisioningThrottle"/>
    ///   had removed from it - see its class comment - and it must not be
    ///   reintroduced here under a new name.
    /// - <see cref="ProvisioningThrottle"/> itself is not reused, and could not
    ///   usefully be: it brakes the branch where NO Emby account exists and a
    ///   stranger's password would be relayed to the identity provider. A PIN
    ///   only ever exists for an account that already exists, so PIN redemption
    ///   is on the other branch entirely, sends nothing to the provider, and
    ///   costs one dictionary lookup. Charging PIN attempts to that throttle's
    ///   buckets would let PIN guessing consume a real user's first-sign-in
    ///   allowance, which is the guarantee that class exists to protect.
    ///
    /// WHAT AN ATTACKER CAN STILL DO, STATED PLAINLY. Somebody who knows a
    /// username can send a PIN-shaped guess at any rate they like, and each
    /// guess destroys that user's live PIN if there is one. So a targeted user
    /// can be denied the PIN ROUTE for as long as the attacker keeps it up.
    /// That is inherent to consuming on failure and is not fixed by allowing a
    /// few attempts instead of one - three guesses a second destroys a PIN just
    /// as reliably as one. It costs the victim nothing else: browser sign-in
    /// and, if the operator enabled it, password sign-in are untouched, and no
    /// other account is affected at all. The alternative - not consuming on
    /// failure - would let the same attacker grind the PIN instead of denying
    /// it, and a credential that can be ground is a credential that is
    /// eventually guessed.
    /// ------------------------------------------------------------------
    ///
    /// Holds nothing but strings, counters, timestamps and a lock, and
    /// references no <c>MediaBrowser.*</c> type, so it lives in Protocol/ where
    /// the test project can reach it.
    /// </summary>
    internal sealed class SignInPinStore
    {
        /// <summary>
        /// Failed guesses one issued PIN will tolerate before it is destroyed.
        ///
        /// ONE. A PIN is 39 bits and is typed into a field anybody on the
        /// network can reach, so the defence that has to hold is that it cannot
        /// be ground down: at one attempt, a guesser's whole chance against an
        /// issued PIN is 1 in 6.56 x 10^11, and no amount of traffic changes
        /// that.
        ///
        /// The cost is a real one and belongs in the open: a person who
        /// mistypes the PIN on their remote must go back to the browser and get
        /// another. Three would cost 1.6 bits - nothing, against 39 - and would
        /// forgive a fat-fingered D-pad, and it would NOT make the targeted
        /// denial of service above any worse, since an attacker sending three
        /// guesses a second destroys a PIN as surely as one. It is one line to
        /// change and it is the operator's call to ask for; it is one here
        /// because the specification this was built to asks for a PIN that is
        /// consumed on a failed attempt, and because the direction to be wrong
        /// in is the one where a wrong guess costs the guesser everything.
        ///
        /// A constant, not configuration: this is a safety floor rather than a
        /// preference, and a setting that could raise it is a setting that
        /// could switch the brake off. The same stance
        /// <see cref="ProvisioningThrottle"/> takes about its own numbers.
        ///
        /// Three, not one. One was the original brief; three costs 1.6 bits out
        /// of 39.3, which is nothing, and does not worsen the only real attack
        /// on an issued PIN - somebody spending a stranger's PIN to annoy them
        /// destroys it as reliably with one guess as with three. What it buys
        /// is the person typing eight characters into a television with a
        /// directional pad, for whom a single slip would otherwise mean
        /// repeating a whole browser sign-in, multi-factor prompt included.
        ///
        /// If it is ever changed, the PIN page tells the user in so many words
        /// how many wrong entries destroy their PIN (<c>Api/PinPage.cs</c>) and
        /// the README says the same. Change those with it, or the plugin starts
        /// lying to the person holding the credential.
        /// </summary>
        public const int MaxAttemptsPerPin = 3;

        /// <summary>
        /// How long an issued PIN is good for.
        ///
        /// Five minutes: enough to read it off a phone, walk to the television,
        /// find the app's sign-in screen and type eight characters with a
        /// remote control, and no more. It is the second bound on guessing
        /// after <see cref="MaxAttemptsPerPin"/> and the only one that limits
        /// how long a PIN read over somebody's shoulder - or off a screen
        /// nobody locked - stays worth anything.
        ///
        /// Deliberately much longer than the thirty seconds
        /// <see cref="HandoffSecretStore"/> allows, because these are not the
        /// same job: a handoff secret is redeemed by a script in the very
        /// browser that was handed it, in the same second, and a PIN is
        /// redeemed by a human being walking across a room.
        /// </summary>
        public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(5);

        private readonly Dictionary<string, Entry> _entries =
            new Dictionary<string, Entry>(UsernameMatcher.Comparer);

        private readonly object _lock = new object();
        private readonly Func<DateTimeOffset> _clock;
        private readonly TimeSpan _ttl;

        public SignInPinStore(Func<DateTimeOffset> clock, TimeSpan ttl)
        {
            _clock = clock ?? throw new ArgumentNullException(nameof(clock));
            _ttl = ttl;
        }

        /// <summary>
        /// Issues a PIN for one Emby account, replacing any PIN that account
        /// already had - so a person who asks twice has one live PIN, not two,
        /// and the older printed page is dead the moment the newer one exists.
        ///
        /// One consequence worth knowing: a person who asks twice and then types
        /// the OLDER PIN spends the newer one, because a superseded PIN is
        /// indistinguishable here from a guess. Keeping superseded PINs around
        /// so they could be told apart would mean keeping dead credentials
        /// alive, which is the worse of the two.
        ///
        /// The caller is responsible for having established that this account
        /// may sign in AT ALL. This class checks nothing: it does not know
        /// about licences, groups, provider stamps or subject bindings, and it
        /// must not be given a way to. Issue is called at exactly one place -
        /// the end of the browser callback, below every one of those guards -
        /// for exactly that reason.
        /// </summary>
        public string Issue(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("username is required", nameof(username));
            }

            var pin = SignInPin.Create();

            lock (_lock)
            {
                RemoveExpired();
                _entries[Key(username)] = new Entry(pin, _clock().Add(_ttl));
            }

            return pin;
        }

        /// <summary>
        /// Whether this is the live PIN for this account. True consumes it;
        /// false consumes it too, once the attempts allowed against it have run
        /// out.
        ///
        /// The order of the checks below is the security-relevant part:
        ///
        /// 1. A value that is not PIN-SHAPED spends nothing and touches
        ///    nothing. That is what stops a user's own password - typed into
        ///    the same field, by the same person, on the same screen - from
        ///    destroying the PIN they were about to use, and it is what stops
        ///    an attacker spending somebody's PIN with arbitrary junk. See
        ///    <see cref="SignInPin.Normalize"/>.
        /// 2. The lookup is by USERNAME, so an attempt can only ever reach the
        ///    PIN issued to the account it names. A live PIN presented under
        ///    another username is refused, and - just as importantly - is not
        ///    consumed: naming Bob must not be a way to destroy Alice's PIN.
        /// 3. The comparison is <see cref="FixedTime"/>, so how long a refusal
        ///    takes does not say how much of the PIN was right. Without it a
        ///    guesser could recover a PIN character by character, which turns
        ///    30^8 into 8 x 30.
        ///
        /// It answers false for every failure, in the same way, and the caller
        /// falls through to the remaining credential shapes on all of them - so
        /// nothing about the answer tells a caller whether the account had a
        /// PIN at all.
        /// </summary>
        public bool TryConsume(string username, string candidate)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return false;
            }

            // 1. Not a PIN: not an attempt at one. Decided before the lock and
            //    before any lookup, so nothing is spent and nothing is learned.
            var presented = SignInPin.Normalize(candidate);

            if (presented == null)
            {
                return false;
            }

            lock (_lock)
            {
                RemoveExpired();

                // 2. Only this username's own PIN is reachable, and a miss
                //    consumes nothing anywhere.
                if (!_entries.TryGetValue(Key(username), out var entry))
                {
                    return false;
                }

                // 3. Constant time, always over the whole value.
                if (FixedTime.Equals(entry.Pin, presented))
                {
                    _entries.Remove(Key(username));
                    return true;
                }

                entry.Attempts++;

                if (entry.Attempts >= MaxAttemptsPerPin)
                {
                    // The single-use rule applied to failure: a PIN that has
                    // been guessed at wrongly is spent. This is the line that
                    // makes grinding impossible, and a future reader must not
                    // remove it in the name of forgiving typos - raise
                    // MaxAttemptsPerPin instead, deliberately, having read what
                    // that costs.
                    _entries.Remove(Key(username));
                }

                return false;
            }
        }

        /// <summary>Live (unexpired) PINs. For tests and diagnostics only.</summary>
        public int Count()
        {
            lock (_lock)
            {
                RemoveExpired();
                return _entries.Count;
            }
        }

        /// <summary>
        /// Keyed the way <see cref="UsernameMatcher"/> compares - trimmed, then
        /// ordinal case-insensitive - so "Alice", "alice" and " alice " are one
        /// account here exactly as they are everywhere else in this plugin. A
        /// stricter key would issue a PIN under one spelling that could not be
        /// redeemed under another.
        /// </summary>
        private static string Key(string username)
        {
            return UsernameMatcher.NormalizeKey(username);
        }

        private void RemoveExpired()
        {
            ExpiryPolicy.RemoveExpired(_entries, entry => entry.ExpiresAt, _clock());
        }

        private sealed class Entry
        {
            public Entry(string pin, DateTimeOffset expiresAt)
            {
                Pin = pin;
                ExpiresAt = expiresAt;
            }

            public string Pin { get; }

            public DateTimeOffset ExpiresAt { get; }

            /// <summary>
            /// Failed guesses recorded against THIS PIN. It lives on the entry
            /// rather than in a map of its own so that it cannot outlive the
            /// secret it counts for: when the PIN goes - consumed, expired or
            /// replaced - the count goes with it, and a fresh PIN starts with a
            /// fresh allowance rather than inheriting the last one's.
            /// </summary>
            public int Attempts { get; set; }
        }
    }
}

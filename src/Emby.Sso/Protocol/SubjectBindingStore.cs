using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The outcome of asking whether an identity provider subject may sign in as
    /// a given Emby account. Zero is a refusal, like every other decision enum
    /// here.
    /// </summary>
    internal enum SubjectBindingOutcome
    {
        /// <summary>Fail-closed default: an outcome nobody set, or a malformed request.</summary>
        Refused = 0,

        /// <summary>This subject is already bound to this account. Nothing was written.</summary>
        Bound = 1,

        /// <summary>
        /// <see cref="SubjectBindingStore.Check"/> only: nothing in the store
        /// conflicts, so a binding COULD be made. It has not been - the caller
        /// must still call <see cref="SubjectBindingStore.Bind"/> before the
        /// sign-in completes.
        /// </summary>
        BindingAvailable = 2,

        /// <summary>
        /// <see cref="SubjectBindingStore.Bind"/> only: the binding did not exist
        /// and has now been recorded durably. This is the trust-on-first-use
        /// moment.
        /// </summary>
        BoundOnFirstUse = 3,

        /// <summary>
        /// The token carried no <c>sub</c>. Every OpenID Connect id_token must,
        /// so this means the token is not one this plugin can bind an identity
        /// from - and a sign-in that cannot be bound must not happen.
        /// </summary>
        SubjectMissing = 4,

        /// <summary>
        /// This subject was first seen signing in as a DIFFERENT account. Either
        /// the username claim has been reassigned - the takeover this whole
        /// mechanism exists to stop - or the person was legitimately renamed and
        /// an operator must say so.
        /// </summary>
        SubjectBoundToAnotherAccount = 5,

        /// <summary>
        /// This account already belongs to a different subject. Somebody else's
        /// identity provider principal is presenting a claim that names it.
        /// </summary>
        AccountBoundToAnotherSubject = 6,

        /// <summary>
        /// The store could not be read or could not be written. NOT a licence to
        /// fall back to name-only matching - that is exactly the behaviour this
        /// store replaces - so it refuses.
        /// </summary>
        StoreUnavailable = 7,
    }

    /// <summary>
    /// Remembers which identity-provider subject (<c>sub</c>) each Emby account
    /// belongs to, and refuses any sign-in that contradicts what it remembers.
    ///
    /// WHY (assessment finding F1 / S1b). Before this, every identity decision
    /// in the plugin was a string comparison between a configured claim and an
    /// Emby account name. `sub` was parsed and then read by nothing. An identity
    /// provider user who can edit their own <c>preferred_username</c> - or an
    /// operator who configures <c>email</c> or <c>name</c> as the claim - could
    /// therefore be authenticated as somebody else's Emby account. A username is
    /// a display handle that people and providers reassign; <c>sub</c> is the one
    /// claim OpenID Connect guarantees is stable and unique for the principal.
    ///
    /// TRUST ON FIRST USE. There is nothing to compare against until an account
    /// has signed in once through this plugin, so the first successful sign-in
    /// after this build is installed is what establishes the binding. That
    /// window is real and is documented in the README: if an attacker gets there
    /// first, they get the binding. Two other guards narrow it - the group gate,
    /// and the refusal to adopt an account not already stamped to this plugin
    /// (<see cref="ProviderStamp"/>) - but neither removes it.
    ///
    /// FAIL CLOSED, ALWAYS. Every way this store can fail refuses the sign-in.
    /// It must never degrade to "no binding known, so allow it": that IS the
    /// name-only matching being fixed, and a store that silently disappears
    /// would silently restore the vulnerability. In particular:
    ///
    /// - a file that exists but cannot be parsed is treated as CORRUPT and
    ///   refuses every sign-in for the life of the process. It is deliberately
    ///   never overwritten, so an operator can still read what it contained;
    /// - a file that cannot be read this time (a transient IO error) refuses
    ///   this sign-in and is retried on the next one;
    /// - a binding that cannot be WRITTEN refuses the sign-in, because
    ///   completing it would leave the account permanently unbound - i.e. back
    ///   on name-only matching - with nobody told;
    /// - a store with no path configured refuses everything.
    ///
    /// The one case that is NOT a failure is a file that genuinely does not
    /// exist yet: that is a first run, so the store starts empty and
    /// trust-on-first-use applies. A reader tempted to "fix" that by refusing
    /// should note it would mean the plugin never works on a fresh install; the
    /// honest mitigation is the documented TOFU window, not a refusal nobody can
    /// satisfy. Note how narrowly "does not exist" is decided in
    /// <c>Load</c> - by the exception the read threw, not by a
    /// <c>File.Exists</c> probe, which answers false for an unreadable path too
    /// and would have turned "cannot read the bindings" into "there are none".
    ///
    /// ACCOUNTS ARE KEYED BY NAME, deliberately. The name is the only handle
    /// both provisioning paths share - the native path binds before Emby has
    /// created the account, so no Emby id exists to key on. The comparison is
    /// <see cref="UsernameMatcher"/>'s, so the store cannot consider "Alice"
    /// and "alice" different accounts while the rest of the plugin considers
    /// them the same.
    ///
    /// RENAMING AN EMBY ACCOUNT CUTS BOTH WAYS, and this comment used to state
    /// only the harmless half. A rename does not move the row, so:
    ///
    /// - the person who owned the account IS refused, which is the half that
    ///   was documented: their subject is still recorded against the old name,
    ///   so presenting the new one answers
    ///   <see cref="SubjectBindingOutcome.SubjectBoundToAnotherAccount"/>;
    /// - but the account under its NEW name has no row at all, so as far as
    ///   this store is concerned it has never signed in: the next subject to
    ///   present that name gets <see cref="SubjectBindingOutcome.BindingAvailable"/>
    ///   and adopts it, watch history, policy, library access and all. It is
    ///   the trust-on-first-use window reopened for one account, silently.
    ///
    /// What still stands between that and a takeover is not this store: it is
    /// the group gate and the caller's refusal to adopt an account that is not
    /// already stamped to this plugin (<see cref="ProviderStamp"/>). So the
    /// window needs an identity-provider principal that holds the required
    /// group AND can present the new name as its username claim - an in-group
    /// insider, not a stranger. Narrow, but not closed, and the operator is
    /// told in the README to edit this file in the same maintenance window as
    /// any rename rather than afterwards.
    ///
    /// The callers log an adoption of an already-existing, already-stamped
    /// account at Error for exactly this reason - see
    /// <c>SsoService.LogAdoptionOfAnExistingAccount</c> and its twin in
    /// <c>SsoAuthenticationProvider</c>. It is not logged here: this class is
    /// told a name and a subject and nothing else, so it cannot tell a first
    /// provisioning from an adoption. That distinction is the caller's, and so
    /// is the log line.
    /// </summary>
    internal sealed class SubjectBindingStore
    {
        /// <summary>
        /// The on-disk schema. A file written by a future build with a different
        /// shape must be refused rather than half-understood, so an unexpected
        /// version reads as corrupt.
        /// </summary>
        private const int SchemaVersion = 1;

        private readonly object _lock = new object();
        private readonly string _filePath;
        private readonly Func<DateTimeOffset> _clock;

        // Two indexes over the same records: one keyed by subject (ordinal - a
        // `sub` is an opaque case-sensitive string), one keyed by account name
        // (UsernameMatcher's comparison, so it agrees with the rest of the
        // plugin about what one account is).
        private readonly Dictionary<string, Binding> _bySubject = new Dictionary<string, Binding>(StringComparer.Ordinal);
        private readonly Dictionary<string, Binding> _byAccount = new Dictionary<string, Binding>(UsernameMatcher.Comparer);

        private bool _loaded;
        private bool _corrupt;

        public SubjectBindingStore(string filePath, Func<DateTimeOffset> clock)
        {
            // A blank path is allowed to construct, and then refuses everything.
            // The alternative - throwing - would have to be caught somewhere in
            // the sign-in path, and a caught exception is one edit away from
            // becoming a fallback.
            _filePath = filePath;
            _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        }

        /// <summary>
        /// A store that can never answer anything but a refusal. For the window
        /// before the plugin knows where its data lives.
        /// </summary>
        public static SubjectBindingStore Unavailable { get; } =
            new SubjectBindingStore(null, () => DateTimeOffset.UtcNow);

        /// <summary>
        /// The single whitelist. Every call site must gate on this rather than
        /// listing refusals, so a future <see cref="SubjectBindingOutcome"/>
        /// member cannot admit anyone by being forgotten.
        /// </summary>
        public static bool Permits(SubjectBindingOutcome outcome)
        {
            return outcome == SubjectBindingOutcome.Bound
                || outcome == SubjectBindingOutcome.BindingAvailable
                || outcome == SubjectBindingOutcome.BoundOnFirstUse;
        }

        /// <summary>
        /// Whether this subject may sign in as this account, WITHOUT recording
        /// anything. For the point in a flow where an account may still have to
        /// be created: a subject already bound elsewhere must be refused before
        /// provisioning leaves an orphan account behind, not after.
        ///
        /// A permitted answer here is not a completed sign-in. The caller must
        /// still call <see cref="Bind"/> before it hands out a session.
        /// </summary>
        public SubjectBindingOutcome Check(string subject, string accountName)
        {
            lock (_lock)
            {
                return Load() ? Evaluate(subject, accountName) : SubjectBindingOutcome.StoreUnavailable;
            }
        }

        /// <summary>
        /// Whether this subject may sign in as this account, recording the
        /// binding if it is new. Re-evaluates from scratch under the lock: a
        /// <see cref="Check"/> that passed a moment ago is not carried forward,
        /// because a concurrent first sign-in may have claimed the account in
        /// between.
        ///
        /// Returns <see cref="SubjectBindingOutcome.StoreUnavailable"/> when the
        /// new binding could not be persisted, and does not keep it in memory
        /// either. A binding that survives only until the next restart is worse
        /// than none: it would let this sign-in through and then quietly rebind
        /// the account to whoever signs in first after the restart.
        /// </summary>
        public SubjectBindingOutcome Bind(string subject, string accountName)
        {
            lock (_lock)
            {
                if (!Load())
                {
                    return SubjectBindingOutcome.StoreUnavailable;
                }

                var outcome = Evaluate(subject, accountName);

                if (outcome != SubjectBindingOutcome.BindingAvailable)
                {
                    // Bound, or a refusal. Either way nothing is written.
                    return outcome;
                }

                var binding = new Binding(subject.Trim(), accountName.Trim(), _clock());

                _bySubject[binding.Subject] = binding;
                _byAccount[UsernameMatcher.NormalizeKey(binding.Account)] = binding;

                if (!Save())
                {
                    // Roll the in-memory state back so the process cannot behave
                    // as though a binding exists that no restart will find.
                    _bySubject.Remove(binding.Subject);
                    _byAccount.Remove(UsernameMatcher.NormalizeKey(binding.Account));
                    return SubjectBindingOutcome.StoreUnavailable;
                }

                return SubjectBindingOutcome.BoundOnFirstUse;
            }
        }

        /// <summary>The account this subject is bound to, or null. For log lines only.</summary>
        public string BoundAccountFor(string subject)
        {
            if (string.IsNullOrWhiteSpace(subject))
            {
                return null;
            }

            lock (_lock)
            {
                return Load() && _bySubject.TryGetValue(subject.Trim(), out var binding) ? binding.Account : null;
            }
        }

        // Caller holds _lock.
        private SubjectBindingOutcome Evaluate(string subject, string accountName)
        {
            if (string.IsNullOrWhiteSpace(subject))
            {
                return SubjectBindingOutcome.SubjectMissing;
            }

            if (string.IsNullOrWhiteSpace(accountName))
            {
                return SubjectBindingOutcome.Refused;
            }

            var trimmedSubject = subject.Trim();

            if (_bySubject.TryGetValue(trimmedSubject, out var bySubject))
            {
                return UsernameMatcher.Matches(bySubject.Account, accountName)
                    ? SubjectBindingOutcome.Bound
                    : SubjectBindingOutcome.SubjectBoundToAnotherAccount;
            }

            // The subject is new. The account must be too, or this is somebody
            // else's principal presenting a claim that names it.
            return _byAccount.ContainsKey(UsernameMatcher.NormalizeKey(accountName))
                ? SubjectBindingOutcome.AccountBoundToAnotherSubject
                : SubjectBindingOutcome.BindingAvailable;
        }

        // Caller holds _lock. Returns false when the store cannot be trusted;
        // every caller of this turns that into a refusal.
        private bool Load()
        {
            if (_corrupt)
            {
                // Sticky on purpose. A file this build cannot understand is not
                // retried into an empty store on the next attempt - that would
                // hand out bindings over the top of records nobody has read.
                return false;
            }

            if (_loaded)
            {
                return true;
            }

            if (string.IsNullOrWhiteSpace(_filePath))
            {
                return false;
            }

            string text;

            // Read the file rather than probing with File.Exists first, and
            // keep it that way. File.Exists answers FALSE both for "no such
            // file" and for "there is something there that is not a readable
            // file" - a directory at the path, or a path this process may not
            // traverse - so a pre-check turns those into "first run", which
            // silently discards every recorded binding and reopens the whole
            // trust-on-first-use window for every account at once. The exception
            // TYPE is the only thing that actually distinguishes absent from
            // unreadable. Found by
            // SubjectBindingStoreTests.AnUnreadableStoreRefusesButIsRetriedLater,
            // which failed against the File.Exists version of this method.
            try
            {
                text = File.ReadAllText(_filePath);
            }
            catch (FileNotFoundException)
            {
                // First run. See the class comment: this is the ONE case that
                // is not a failure.
                _loaded = true;
                return true;
            }
            catch (DirectoryNotFoundException)
            {
                // Also a first run - the plugin's data directory has not been
                // created yet. Save() creates it.
                _loaded = true;
                return true;
            }
            catch (Exception)
            {
                // Deliberately broad, and deliberately NOT sticky: a permissions
                // change or a full disk may be fixed between sign-ins. This
                // attempt refuses; the next one tries again.
                return false;
            }

            try
            {
                Parse(text);
            }
            catch (Exception)
            {
                // Anything unparseable, structurally wrong, or duplicated. Made
                // sticky here rather than retried, because none of those get
                // better on their own and re-reading a corrupt file each
                // sign-in only makes the log noisier.
                _corrupt = true;
                _bySubject.Clear();
                _byAccount.Clear();
                return false;
            }

            _loaded = true;
            return true;
        }

        /// <summary>
        /// Throws on anything that is not exactly the shape this build wrote.
        /// Duplicates included: two records claiming one subject, or one
        /// account, mean the file was edited by hand or written by something
        /// else, and choosing which of them to honour would be guessing at an
        /// authentication decision.
        /// </summary>
        private void Parse(string text)
        {
            var root = JObject.Parse(text);
            var version = (int?)root["version"];

            if (version != SchemaVersion)
            {
                throw new FormatException("unexpected subject-binding store version");
            }

            if (!(root["bindings"] is JArray records))
            {
                throw new FormatException("subject-binding store has no bindings array");
            }

            _bySubject.Clear();
            _byAccount.Clear();

            foreach (var record in records)
            {
                var subject = (string)record["subject"];
                var account = (string)record["account"];

                if (string.IsNullOrWhiteSpace(subject) || string.IsNullOrWhiteSpace(account))
                {
                    throw new FormatException("subject-binding record is missing a subject or an account");
                }

                var boundUtc = ParseBoundUtc((string)record["boundUtc"]);
                var binding = new Binding(subject.Trim(), account.Trim(), boundUtc);
                var accountKey = UsernameMatcher.NormalizeKey(binding.Account);

                if (_bySubject.ContainsKey(binding.Subject) || _byAccount.ContainsKey(accountKey))
                {
                    throw new FormatException("subject-binding store contains a duplicate subject or account");
                }

                _bySubject[binding.Subject] = binding;
                _byAccount[accountKey] = binding;
            }
        }

        /// <summary>
        /// The timestamp is a record for an operator reading the file; nothing
        /// decides anything from it. An unreadable one is therefore not worth
        /// refusing every sign-in over - it becomes the epoch and the binding
        /// stands.
        /// </summary>
        private static DateTimeOffset ParseBoundUtc(string value)
        {
            return DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var parsed)
                ? parsed
                : DateTimeOffset.MinValue;
        }

        // Caller holds _lock. Returns false when the store was not durably
        // written; every caller of this turns that into a refusal.
        private bool Save()
        {
            if (string.IsNullOrWhiteSpace(_filePath))
            {
                return false;
            }

            try
            {
                var directory = Path.GetDirectoryName(_filePath);

                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Written to a temporary file and renamed over the real one, so
                // a crash mid-write cannot leave a truncated store behind. A
                // truncated store would parse as corrupt and refuse everybody -
                // fail-closed, but an outage nobody needs to have.
                var temporary = _filePath + ".tmp";
                File.WriteAllText(temporary, Serialize());

                if (File.Exists(_filePath))
                {
                    try
                    {
                        File.Replace(temporary, _filePath, null);
                    }
                    catch (PlatformNotSupportedException)
                    {
                        // Some filesystems do not implement the replace call.
                        // Delete-then-move has a window in which no store file
                        // exists at all; if the process dies inside it the store
                        // reads as a first run and the TOFU window reopens. That
                        // is why it is the fallback and not the mechanism.
                        File.Delete(_filePath);
                        File.Move(temporary, _filePath);
                    }
                }
                else
                {
                    File.Move(temporary, _filePath);
                }

                return true;
            }
            catch (Exception)
            {
                // Broad on purpose: permissions, a read-only mount, a full disk,
                // a path that is not writable. None of them may become a
                // successful sign-in.
                return false;
            }
        }

        // Caller holds _lock.
        private string Serialize()
        {
            var records = new JArray();

            foreach (var binding in _bySubject.Values)
            {
                records.Add(new JObject
                {
                    ["subject"] = binding.Subject,
                    ["account"] = binding.Account,
                    ["boundUtc"] = binding.BoundUtc.ToString("o", CultureInfo.InvariantCulture),
                });
            }

            var root = new JObject
            {
                ["version"] = SchemaVersion,
                ["bindings"] = records,
            };

            return root.ToString(Formatting.Indented);
        }

        private sealed class Binding
        {
            public Binding(string subject, string account, DateTimeOffset boundUtc)
            {
                Subject = subject;
                Account = account;
                BoundUtc = boundUtc;
            }

            public string Subject { get; }

            public string Account { get; }

            public DateTimeOffset BoundUtc { get; }
        }
    }
}

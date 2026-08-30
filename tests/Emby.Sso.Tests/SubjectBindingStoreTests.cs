using System;
using System.IO;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The whole of S1b's decision and durability behaviour. Each test gets its
    /// own temporary directory, so nothing here shares a store.
    ///
    /// What is NOT covered: the two Emby-facing call sites that consult the
    /// store (Auth/SsoAuthenticationProvider and Api/SsoService), which this
    /// project cannot compile.
    /// </summary>
    public sealed class SubjectBindingStoreTests : IDisposable
    {
        private readonly string _directory;
        private readonly string _path;

        public SubjectBindingStoreTests()
        {
            _directory = Path.Combine(Path.GetTempPath(), "emby-sso-tests-" + Guid.NewGuid().ToString("N"));
            _path = Path.Combine(_directory, "bindings", "subject-bindings.json");
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_directory))
                {
                    Directory.Delete(_directory, true);
                }
            }
            catch (IOException)
            {
                // A leftover temp directory is not worth failing a test over.
            }
        }

        private SubjectBindingStore NewStore()
        {
            return new SubjectBindingStore(_path, () => DateTimeOffset.UnixEpoch);
        }

        // ---------------------------------------------------------------
        // Trust on first use
        // ---------------------------------------------------------------

        [Fact]
        public void FirstSignInBindsTheSubjectToTheAccount()
        {
            var store = NewStore();

            Assert.Equal(SubjectBindingOutcome.BindingAvailable, store.Check("sub-1", "alice"));
            Assert.Equal(SubjectBindingOutcome.BoundOnFirstUse, store.Bind("sub-1", "alice"));
            Assert.Equal(SubjectBindingOutcome.Bound, store.Bind("sub-1", "alice"));
            Assert.Equal(SubjectBindingOutcome.Bound, store.Check("sub-1", "alice"));
        }

        [Fact]
        public void ABindingSurvivesARestart()
        {
            // The single property the whole mechanism rests on: a binding made
            // before a restart still refuses an impostor after it.
            Assert.Equal(SubjectBindingOutcome.BoundOnFirstUse, NewStore().Bind("sub-1", "alice"));

            var afterRestart = NewStore();

            Assert.Equal(SubjectBindingOutcome.Bound, afterRestart.Check("sub-1", "alice"));
            Assert.Equal(SubjectBindingOutcome.AccountBoundToAnotherSubject, afterRestart.Check("sub-2", "alice"));
        }

        [Fact]
        public void AMissingFileIsAFirstRunAndNotAFailure()
        {
            // The one non-failure. Refusing here would mean the plugin never
            // works on a fresh install.
            Assert.False(File.Exists(_path));
            Assert.Equal(SubjectBindingOutcome.BindingAvailable, NewStore().Check("sub-1", "alice"));
        }

        // ---------------------------------------------------------------
        // The two mismatches this exists to catch
        // ---------------------------------------------------------------

        [Fact]
        public void AKnownSubjectMayNotSignInAsADifferentAccount()
        {
            var store = NewStore();
            store.Bind("sub-1", "alice");

            // The identity provider user renamed themselves to "bob", or is
            // trying to be bob. Either way the answer is no.
            Assert.Equal(SubjectBindingOutcome.SubjectBoundToAnotherAccount, store.Check("sub-1", "bob"));
            Assert.Equal(SubjectBindingOutcome.SubjectBoundToAnotherAccount, store.Bind("sub-1", "bob"));
        }

        [Fact]
        public void AClaimedAccountRefusesADifferentSubject()
        {
            // The takeover: a second identity provider principal presenting a
            // username claim that names somebody else's Emby account.
            var store = NewStore();
            store.Bind("sub-victim", "alice");

            Assert.Equal(SubjectBindingOutcome.AccountBoundToAnotherSubject, store.Check("sub-attacker", "alice"));
            Assert.Equal(SubjectBindingOutcome.AccountBoundToAnotherSubject, store.Bind("sub-attacker", "alice"));
        }

        [Fact]
        public void ARefusedBindAttemptWritesNothing()
        {
            var store = NewStore();
            store.Bind("sub-victim", "alice");
            store.Bind("sub-attacker", "alice");

            // The attacker's attempt must not have displaced the victim, in
            // memory or on disk.
            Assert.Equal(SubjectBindingOutcome.Bound, NewStore().Check("sub-victim", "alice"));
            Assert.Equal("alice", NewStore().BoundAccountFor("sub-victim"));
            Assert.Null(NewStore().BoundAccountFor("sub-attacker"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void AMissingSubjectIsRefused(string subject)
        {
            // Every OIDC id_token must carry `sub`. One that does not cannot be
            // bound, and a sign-in that cannot be bound must not happen.
            var store = NewStore();

            Assert.Equal(SubjectBindingOutcome.SubjectMissing, store.Check(subject, "alice"));
            Assert.Equal(SubjectBindingOutcome.SubjectMissing, store.Bind(subject, "alice"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void AMissingAccountNameIsRefused(string account)
        {
            var store = NewStore();

            Assert.Equal(SubjectBindingOutcome.Refused, store.Check("sub-1", account));
            Assert.Equal(SubjectBindingOutcome.Refused, store.Bind("sub-1", account));
        }

        // ---------------------------------------------------------------
        // Key comparison
        // ---------------------------------------------------------------

        [Fact]
        public void AccountNamesUseTheSameComparisonAsTheRestOfThePlugin()
        {
            // UsernameMatcher treats "Alice" and " alice " as one account. If
            // the store did not, one person would hold two bindings and the
            // second would silently rebind an account the first already owns.
            var store = NewStore();
            store.Bind("sub-1", "Alice");

            Assert.Equal(SubjectBindingOutcome.Bound, store.Check("sub-1", " alice "));
            Assert.Equal(SubjectBindingOutcome.AccountBoundToAnotherSubject, store.Check("sub-2", "ALICE"));
        }

        [Fact]
        public void SubjectsAreComparedCaseSensitively()
        {
            // A `sub` is an opaque, case-sensitive string. Folding case would
            // merge two distinct principals into one.
            var store = NewStore();
            store.Bind("Sub-1", "alice");

            Assert.Equal(SubjectBindingOutcome.SubjectBoundToAnotherAccount, store.Check("Sub-1", "bob"));
            Assert.Equal(SubjectBindingOutcome.AccountBoundToAnotherSubject, store.Check("sub-1", "alice"));
        }

        [Fact]
        public void SurroundingWhitespaceOnASubjectDoesNotSplitIt()
        {
            var store = NewStore();
            store.Bind(" sub-1 ", "alice");

            Assert.Equal(SubjectBindingOutcome.Bound, store.Check("sub-1", "alice"));
        }

        // ---------------------------------------------------------------
        // Fail closed
        // ---------------------------------------------------------------

        [Fact]
        public void AStoreWithNoPathRefusesEverything()
        {
            var store = new SubjectBindingStore(null, () => DateTimeOffset.UnixEpoch);

            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, store.Check("sub-1", "alice"));
            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, store.Bind("sub-1", "alice"));
            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, SubjectBindingStore.Unavailable.Bind("sub-1", "alice"));
        }

        [Theory]
        [InlineData("this is not json")]
        [InlineData("{}")]
        [InlineData("{\"version\":1}")]
        [InlineData("{\"version\":2,\"bindings\":[]}")]
        [InlineData("{\"version\":1,\"bindings\":{}}")]
        [InlineData("{\"version\":1,\"bindings\":[{\"account\":\"alice\"}]}")]
        [InlineData("{\"version\":1,\"bindings\":[{\"subject\":\"sub-1\"}]}")]
        [InlineData("{\"version\":1,\"bindings\":[{\"subject\":\"  \",\"account\":\"alice\"}]}")]
        public void ACorruptStoreRefusesEverything(string content)
        {
            WriteStoreFile(content);

            var store = NewStore();

            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, store.Check("sub-1", "alice"));
            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, store.Bind("sub-1", "alice"));
        }

        [Fact]
        public void ADuplicateRecordMakesTheStoreCorrupt()
        {
            // Choosing which of two records to honour would be guessing at an
            // authentication decision.
            WriteStoreFile(
                "{\"version\":1,\"bindings\":["
                + "{\"subject\":\"sub-1\",\"account\":\"alice\"},"
                + "{\"subject\":\"sub-2\",\"account\":\"Alice\"}]}");

            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, NewStore().Check("sub-1", "alice"));
        }

        [Fact]
        public void ACorruptStoreIsNeverOverwritten()
        {
            // An operator must still be able to read what the file contained.
            const string content = "{ this is not json";
            WriteStoreFile(content);

            var store = NewStore();
            store.Bind("sub-1", "alice");
            store.Check("sub-1", "alice");

            Assert.Equal(content, File.ReadAllText(_path));
        }

        [Fact]
        public void ACorruptStoreStaysRefusingEvenIfTheFileIsRepairedUnderIt()
        {
            // Sticky on purpose: this process has already decided it cannot
            // trust the file, and a store that re-reads its way back to
            // permissive mid-flight is a store an attacker can race.
            WriteStoreFile("{ not json");

            var store = NewStore();
            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, store.Check("sub-1", "alice"));

            WriteStoreFile("{\"version\":1,\"bindings\":[]}");

            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, store.Check("sub-1", "alice"));

            // A restart is what clears it.
            Assert.Equal(SubjectBindingOutcome.BindingAvailable, NewStore().Check("sub-1", "alice"));
        }

        [Fact]
        public void AnUnwritableStoreRefusesRatherThanBindingInMemoryOnly()
        {
            // A binding that lives only until the next restart would let this
            // sign-in through and then quietly rebind the account to whoever
            // signs in first afterwards.
            Directory.CreateDirectory(Path.GetDirectoryName(_path));

            // A directory where the store file must go: writing the file cannot
            // succeed, on any platform, without touching permissions.
            Directory.CreateDirectory(_path);

            var store = NewStore();

            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, store.Bind("sub-1", "alice"));

            // And nothing was retained in memory either: a later Check must not
            // behave as though the binding had been made.
            Assert.Null(store.BoundAccountFor("sub-1"));
            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, store.Bind("sub-1", "alice"));
        }

        [Fact]
        public void AnUnreadableStoreRefusesButIsRetriedLater()
        {
            // Distinct from corruption: a transient read failure (a permissions
            // change, a full disk) may be fixed between sign-ins, so it refuses
            // THIS attempt and tries again on the next. It must never be
            // mistaken for a first run.
            Directory.CreateDirectory(Path.GetDirectoryName(_path));
            Directory.CreateDirectory(_path);

            var store = NewStore();
            Assert.Equal(SubjectBindingOutcome.StoreUnavailable, store.Check("sub-1", "alice"));

            Directory.Delete(_path);
            File.WriteAllText(_path, "{\"version\":1,\"bindings\":[{\"subject\":\"sub-9\",\"account\":\"zoe\"}]}");

            Assert.Equal(SubjectBindingOutcome.Bound, store.Check("sub-9", "zoe"));
        }

        [Fact]
        public void ZeroIsARefusalAndOnlyThreeOutcomesPermit()
        {
            Assert.Equal(SubjectBindingOutcome.Refused, default(SubjectBindingOutcome));

            foreach (SubjectBindingOutcome outcome in Enum.GetValues(typeof(SubjectBindingOutcome)))
            {
                var expected = outcome == SubjectBindingOutcome.Bound
                    || outcome == SubjectBindingOutcome.BindingAvailable
                    || outcome == SubjectBindingOutcome.BoundOnFirstUse;

                Assert.Equal(expected, SubjectBindingStore.Permits(outcome));
            }
        }

        // ---------------------------------------------------------------
        // On-disk shape
        // ---------------------------------------------------------------

        [Fact]
        public void TheStoredFileIsVersionedAndRoundTrips()
        {
            var store = NewStore();
            store.Bind("sub-1", "alice");
            store.Bind("sub-2", "bob");

            var written = File.ReadAllText(_path);

            Assert.Contains("\"version\": 1", written);
            Assert.Contains("sub-1", written);
            Assert.Contains("alice", written);

            var reloaded = NewStore();

            Assert.Equal(SubjectBindingOutcome.Bound, reloaded.Check("sub-1", "alice"));
            Assert.Equal(SubjectBindingOutcome.Bound, reloaded.Check("sub-2", "bob"));
            Assert.Equal(SubjectBindingOutcome.SubjectBoundToAnotherAccount, reloaded.Check("sub-1", "bob"));
        }

        [Fact]
        public void NoTemporaryFileIsLeftBehind()
        {
            var store = NewStore();
            store.Bind("sub-1", "alice");
            store.Bind("sub-2", "bob");

            Assert.False(File.Exists(_path + ".tmp"));
        }

        [Fact]
        public void TheDirectoryIsCreatedOnDemand()
        {
            Assert.False(Directory.Exists(Path.GetDirectoryName(_path)));

            Assert.Equal(SubjectBindingOutcome.BoundOnFirstUse, NewStore().Bind("sub-1", "alice"));
            Assert.True(File.Exists(_path));
        }

        private void WriteStoreFile(string content)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path));
            File.WriteAllText(_path, content);
        }
    }
}

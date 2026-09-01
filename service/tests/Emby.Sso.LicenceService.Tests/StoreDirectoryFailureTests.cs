using System;
using System.IO;
using Emby.Sso.LicenceService.Storage;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The message an operator gets when the data directory is not writable.
    ///
    /// This is the single most likely first failure of a fresh deployment, and
    /// the version of it that shipped was not good enough: it said "chown the
    /// directory to 5678", which is correct, and is useless to somebody who has
    /// already done exactly that and is looking at the same error again. It
    /// named no uid, so there was no way to tell "you chowned the wrong
    /// directory" from "you chowned the right one and something else is wrong".
    ///
    /// So these hold the message to reporting what was FOUND rather than what is
    /// usually wrong.
    /// </summary>
    public class StoreDirectoryFailureTests
    {
        [Fact]
        public void An_unwritable_directory_is_reported_with_what_was_actually_found()
        {
            if (OperatingSystem.IsWindows() || RunningAsRoot())
            {
                // Windows has no mode bits to clear, and root ignores the ones
                // that are there, so in both cases there is nothing to observe.
                // Skipped rather than faked - a test that quietly asserts
                // nothing is worse than one that is not there.
                return;
            }

            var parent = TestKeys.TempDirectory();
            var directory = Path.Combine(parent, "data");

            Directory.CreateDirectory(directory);

            try
            {
                // Readable and executable, not writable: exactly what a bind
                // mount owned by another user looks like from inside the
                // container.
                File.SetUnixFileMode(
                    directory,
                    UnixFileMode.UserRead | UnixFileMode.UserExecute);

                var store = new LicenceStore(Path.Combine(directory, "licences.db"));

                var ex = Assert.Throws<InvalidOperationException>(() => store.Initialise());

                // The three answers that separate every cause this has.
                Assert.Contains("exists         : yes", ex.Message, StringComparison.Ordinal);
                Assert.Contains("writable by me : NO", ex.Message, StringComparison.Ordinal);
                Assert.Contains("running as uid : ", ex.Message, StringComparison.Ordinal);

                // And it names a real uid, not a hard-coded 5678 that would be
                // wrong the moment anybody runs the image as somebody else.
                Assert.DoesNotContain("running as uid : unknown", ex.Message, StringComparison.Ordinal);

                // The way out that needs no chown at all.
                Assert.Contains("NAMED VOLUME", ex.Message, StringComparison.Ordinal);

                // The original SQLite error is kept rather than swallowed.
                Assert.IsType<Microsoft.Data.Sqlite.SqliteException>(ex.InnerException);
            }
            finally
            {
                File.SetUnixFileMode(
                    directory,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

                Directory.Delete(parent, recursive: true);
            }
        }

        [Fact]
        public void A_writable_directory_creates_the_store_on_the_first_call()
        {
            // The property `docker compose up -d` depends on: nothing has to be
            // created by hand, and Initialise is what brings the database into
            // existence.
            var parent = TestKeys.TempDirectory();
            var path = Path.Combine(parent, "data", "licences.db");

            try
            {
                Assert.False(File.Exists(path));

                new LicenceStore(path).Initialise();

                Assert.True(File.Exists(path), "the database is created by Initialise, not by hand");

                // And again, because Initialise runs on every start.
                new LicenceStore(path).Initialise();

                Assert.True(File.Exists(path));
            }
            finally
            {
                Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                Directory.Delete(parent, recursive: true);
            }
        }

        private static bool RunningAsRoot()
        {
            try
            {
                foreach (var line in File.ReadAllLines("/proc/self/status"))
                {
                    if (line.StartsWith("Uid:", StringComparison.Ordinal))
                    {
                        var fields = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);

                        return fields.Length >= 3 && fields[2] == "0";
                    }
                }
            }
            catch (IOException)
            {
            }

            return false;
        }
    }
}

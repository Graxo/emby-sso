using System;
using System.IO;
using System.Text;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.Backup;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The encrypted backup, and the two things it has to be: readable back with
    /// the right passphrase, and worthless without it.
    ///
    /// It matters because of what is in it. A backup of this store is the
    /// customer list, every activation, every licence signed so far, and the
    /// outbox - which holds redemption codes in the clear, and a redemption code
    /// is a bearer credential. The whole point of taking one is to put it
    /// somewhere less careful than this machine, so it is not enough for the
    /// encryption to be present; it has to be the kind that fails shut.
    /// </summary>
    public class BackupTests
    {
        private const string Passphrase = "a-long-enough-backup-passphrase";
        private const string ServerA = "c5bc6e91458540caa295c4efdda1a58a";

        [Fact]
        public void A_backup_round_trips_every_file_that_was_put_in_it()
        {
            var directory = TestKeys.TempDirectory();

            try
            {
                File.WriteAllText(Path.Combine(directory, "one.txt"), "first");
                File.WriteAllText(Path.Combine(directory, "two.txt"), "second");

                var blob = BackupArchive.Create(
                    Passphrase,
                    new BackupEntry("one.txt", Path.Combine(directory, "one.txt")),
                    new BackupEntry("two.txt", Path.Combine(directory, "two.txt")));

                var restored = Path.Combine(directory, "restored");

                Assert.Equal(2, BackupArchive.Restore(blob, Passphrase, restored));
                Assert.Equal("first", File.ReadAllText(Path.Combine(restored, "one.txt")));
                Assert.Equal("second", File.ReadAllText(Path.Combine(restored, "two.txt")));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void The_contents_are_not_readable_in_the_encrypted_file()
        {
            // The obvious property, asserted anyway: an operator glancing at a
            // backup file should not find a redemption code in it.
            var directory = TestKeys.TempDirectory();

            try
            {
                var path = Path.Combine(directory, "outbox.jsonl");

                File.WriteAllText(path, "{\"code\":\"ABCD-EFGH-JKLM\"}");

                var blob = BackupArchive.Create(Passphrase, new BackupEntry("outbox.jsonl", path));
                var text = Encoding.Latin1.GetString(blob);

                Assert.DoesNotContain("ABCD-EFGH-JKLM", text, StringComparison.Ordinal);
                Assert.DoesNotContain("code", text, StringComparison.Ordinal);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void The_wrong_passphrase_does_not_decrypt_it()
        {
            var directory = TestKeys.TempDirectory();

            try
            {
                var path = Path.Combine(directory, "one.txt");

                File.WriteAllText(path, "first");

                var blob = BackupArchive.Create(Passphrase, new BackupEntry("one.txt", path));

                var ex = Assert.Throws<InvalidOperationException>(
                    () => BackupArchive.Restore(blob, "a-different-long-passphrase", Path.Combine(directory, "out")));

                Assert.Contains("passphrase", ex.Message, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void A_single_altered_byte_is_detected_rather_than_partly_restored()
        {
            // AES-GCM, so this is the authentication tag doing its job. Without
            // it, a corrupted or tampered backup would restore as plausible
            // rubbish - which for a customer list is worse than not restoring.
            var directory = TestKeys.TempDirectory();

            try
            {
                var path = Path.Combine(directory, "one.txt");

                File.WriteAllText(path, "first");

                var blob = BackupArchive.Create(Passphrase, new BackupEntry("one.txt", path));

                blob[blob.Length - 20] ^= 0x01;

                Assert.Throws<InvalidOperationException>(
                    () => BackupArchive.Restore(blob, Passphrase, Path.Combine(directory, "out")));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void The_header_is_authenticated_so_the_iteration_count_cannot_be_lowered()
        {
            // The count is read from the file so that raising it later does not
            // strand old backups. Authenticating it is what stops that
            // flexibility being a downgrade attack.
            var directory = TestKeys.TempDirectory();

            try
            {
                var path = Path.Combine(directory, "one.txt");

                File.WriteAllText(path, "first");

                var blob = BackupArchive.Create(Passphrase, new BackupEntry("one.txt", path));

                // The iteration count lives at offset 11, big-endian.
                blob[12] = 0x01;

                Assert.Throws<InvalidOperationException>(
                    () => BackupArchive.Restore(blob, Passphrase, Path.Combine(directory, "out")));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void Two_backups_of_the_same_data_are_different_files()
        {
            // A fresh salt and nonce every time. Identical ciphertext across
            // backups would leak that nothing changed between them, and would
            // mean a nonce reuse under the same key if the passphrase is the
            // same - which for GCM is catastrophic rather than untidy.
            var directory = TestKeys.TempDirectory();

            try
            {
                var path = Path.Combine(directory, "one.txt");

                File.WriteAllText(path, "first");

                var first = BackupArchive.Create(Passphrase, new BackupEntry("one.txt", path));
                var second = BackupArchive.Create(Passphrase, new BackupEntry("one.txt", path));

                Assert.NotEqual(Convert.ToBase64String(first), Convert.ToBase64String(second));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void A_short_passphrase_is_refused_rather_than_used()
        {
            Assert.Throws<ArgumentException>(() => BackupArchive.Create("short", new BackupEntry("a", "a")));
        }

        [Fact]
        public void Something_that_is_not_a_backup_is_refused_by_name()
        {
            var ex = Assert.Throws<InvalidOperationException>(
                () => BackupArchive.Restore(
                    Encoding.UTF8.GetBytes("this is not a backup, it is a text file that is long enough"),
                    Passphrase,
                    Path.Combine(TestKeys.TempDirectory(), "out")));

            Assert.Contains("not an Emby SSO backup", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_restore_never_writes_into_a_directory_that_has_anything_in_it()
        {
            // The one operation that could destroy a live store. It refuses
            // instead, and moving the files into place is the operator's own
            // deliberate step.
            var directory = TestKeys.TempDirectory();

            try
            {
                var path = Path.Combine(directory, "one.txt");

                File.WriteAllText(path, "first");

                var blob = BackupArchive.Create(Passphrase, new BackupEntry("one.txt", path));

                Assert.Throws<InvalidOperationException>(() => BackupArchive.Restore(blob, Passphrase, directory));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void An_entry_that_would_escape_the_destination_is_refused()
        {
            // Zip-slip. The archive is one this service wrote, but a backup file
            // arrives from wherever the operator kept it, and "the input is
            // ours" is exactly the assumption that keeps this bug alive.
            var directory = TestKeys.TempDirectory();

            try
            {
                var path = Path.Combine(directory, "one.txt");

                File.WriteAllText(path, "nope");

                var blob = BackupArchive.Create(Passphrase, new BackupEntry("../escaped.txt", path));

                var ex = Assert.Throws<InvalidOperationException>(
                    () => BackupArchive.Restore(blob, Passphrase, Path.Combine(directory, "out")));

                Assert.Contains("outside", ex.Message, StringComparison.OrdinalIgnoreCase);
                Assert.False(File.Exists(Path.Combine(directory, "escaped.txt")));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void A_backup_of_a_live_service_restores_to_a_working_store()
        {
            // The end-to-end claim: the file that comes off /admin/backup is one
            // an operator can actually rebuild from, including the WAL-mode
            // database that a plain file copy would silently truncate.
            using var service = new TestService(options => options.BackupPassphrase = Passphrase);

            var code = service.GiveOutACode();

            service.ActivateAndSign(
                new ActivationRequest { Code = code, ServerId = ServerA, PluginVersion = "1.4.0" },
                "10.0.0.1");

            var backups = new BackupService(
                service.Store,
                service.Options,
                service.Clock,
                NullLogger<BackupService>.Instance);

            Assert.True(backups.IsConfigured);

            var blob = backups.Create();
            var restored = Path.Combine(service.Directory, "restored");

            BackupArchive.Restore(blob, Passphrase, restored);

            Assert.True(File.Exists(Path.Combine(restored, "licences.db")));
            Assert.True(File.Exists(Path.Combine(restored, LicenceFormat.LedgerFileName)));

            // And the restored database really opens and holds the activation.
            var reopened = new Storage.LicenceStore(Path.Combine(restored, "licences.db"));

            Assert.Single(reopened.ListCodes());
            Assert.Equal(0, reopened.CountWaitingToBeSigned());
        }

        [Fact]
        public void With_no_passphrase_there_is_no_backup_rather_than_a_plain_one()
        {
            using var service = new TestService();

            var backups = new BackupService(
                service.Store,
                service.Options,
                service.Clock,
                NullLogger<BackupService>.Instance);

            Assert.False(backups.IsConfigured);
            Assert.Throws<InvalidOperationException>(() => backups.Create());
        }

        [Fact]
        public void A_short_backup_passphrase_stops_the_service_starting()
        {
            var options = new Configuration.ServiceOptions { BackupPassphrase = "tooshort" };

            Assert.Contains(
                options.Problems(),
                p => p.Contains("LICENCE_BACKUP_PASSPHRASE", StringComparison.Ordinal));
        }

    }
}

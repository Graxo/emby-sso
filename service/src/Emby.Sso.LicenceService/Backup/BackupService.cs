using System;
using System.Globalization;
using System.IO;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;

namespace Emby.Sso.LicenceService.Backup
{
    /// <summary>
    /// Gathers everything on the volume that cannot be rebuilt and hands it back
    /// as one encrypted file.
    ///
    /// WHAT IS IRREPLACEABLE HERE, which is the whole reason this exists: who
    /// bought what, which servers each code has been activated onto, which
    /// licences have been signed and what they were, the outbox of codes that
    /// have not been delivered, and the admin audit trail. None of it can be
    /// reconstructed from PayPal, from the plugin, or from the signing machine.
    /// If this volume is lost, the vendor cannot answer "did this person pay?"
    /// for anybody, ever again.
    ///
    /// Present only when LICENCE_BACKUP_PASSPHRASE is set. There is no
    /// unencrypted path - see <see cref="BackupArchive"/>.
    /// </summary>
    public sealed class BackupService
    {
        private readonly LicenceStore _store;
        private readonly ServiceOptions _options;
        private readonly TimeProvider _time;
        private readonly ILogger<BackupService> _log;

        public BackupService(LicenceStore store, ServiceOptions options, TimeProvider time, ILogger<BackupService> log)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _time = time ?? throw new ArgumentNullException(nameof(time));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public bool IsConfigured => !string.IsNullOrEmpty(_options.BackupPassphrase);

        /// <summary>The name the download is offered under. Sortable, and says what it is.</summary>
        public string FileName()
        {
            return "emby-sso-licences-"
                + _time.GetUtcNow().UtcDateTime.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)
                + ".backup";
        }

        /// <summary>
        /// The encrypted archive. The database goes in as a VACUUM INTO snapshot
        /// rather than a file copy, because this store runs in WAL mode and the
        /// .db file on its own is an older database than the one being served.
        /// </summary>
        public byte[] Create()
        {
            if (!IsConfigured)
            {
                throw new InvalidOperationException(
                    "No LICENCE_BACKUP_PASSPHRASE is set, so there is nothing to encrypt a backup with.");
            }

            // A temporary directory, not a temporary name beside the store: the
            // snapshot is a complete copy of the customer list, and it should not
            // spend even a moment in a directory somebody might be syncing.
            var scratch = Path.Combine(Path.GetTempPath(), "emby-sso-backup-" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(scratch);

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    scratch,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            try
            {
                var snapshot = Path.Combine(scratch, "licences.db");

                _store.SnapshotTo(snapshot);

                var blob = BackupArchive.Create(
                    _options.BackupPassphrase,
                    new BackupEntry("licences.db", snapshot),
                    new BackupEntry(LicenceFormat.LedgerFileName, _options.LedgerPath),
                    new BackupEntry("codes-outbox.jsonl", _options.OutboxPath),
                    new BackupEntry("admin-audit.jsonl", _options.AdminAuditPath));

                _log.LogInformation(
                    "backup taken: {Bytes} bytes encrypted, from {Store}",
                    blob.Length,
                    _store.Path);

                return blob;
            }
            finally
            {
                try
                {
                    Directory.Delete(scratch, recursive: true);
                }
                catch (IOException ex)
                {
                    // Loud, because what is left behind is a plaintext copy of
                    // the customer store in the temp directory.
                    _log.LogError(
                        ex,
                        "backup: the temporary snapshot at {Path} could not be deleted. It is an UNENCRYPTED copy "
                        + "of the store - delete it by hand.",
                        scratch);
                }
            }
        }
    }
}

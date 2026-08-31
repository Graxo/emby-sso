using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Emby.Sso.Licensing
{
    /// <summary>
    /// Appends to the same <c>licences-issued.jsonl</c> the vendor's offline tool
    /// writes, in the same shape, so that `licencetool list` and `licencetool
    /// show` work on licences this service issued without knowing the service
    /// exists.
    ///
    /// THE FIELD NAMES BELOW ARE A WIRE FORMAT. The tool's `list` reads
    /// licensee, server_id, issued_at, expires_at and fingerprint by name and
    /// skips - loudly - any line missing one. LicenceToolCompatibilityTests
    /// fails if they stop matching.
    /// </summary>
    public sealed class LicenceLedger
    {
        private readonly object _gate = new object();

        public LicenceLedger(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("the ledger needs a path", nameof(path));
            }

            Path = System.IO.Path.GetFullPath(path);
        }

        public string Path { get; }

        /// <summary>
        /// Appends one record, returning false and the reason rather than
        /// throwing.
        ///
        /// A ledger failure is never allowed to fail an activation. The tool
        /// takes the same line ("losing the record of a licence is bad, failing
        /// to issue one because a log file is wrong is worse") but it has more
        /// riding on it there, because the tool's ledger is the ONLY record. Here
        /// it is the second one: the activation is already committed to the
        /// SQLite store inside the transaction that consumed it, so a failed
        /// append costs the vendor the convenience of `licencetool list`, not the
        /// knowledge of who holds what. The caller logs the reason at warning.
        /// </summary>
        public bool TryAppend(LedgerRecord record, out string error)
        {
            if (record == null)
            {
                throw new ArgumentNullException(nameof(record));
            }

            try
            {
                var line = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Dictionary<string, object>
                {
                    ["issued_at"] = LicenceFormat.Iso(record.IssuedAt),
                    ["expires_at"] = LicenceFormat.Iso(record.ExpiresAt),
                    ["days"] = record.Days,
                    ["licensee"] = record.Licensee,
                    ["server_id"] = record.ServerId,
                    ["fingerprint"] = record.Fingerprint,
                }) + "\n");

                var directory = System.IO.Path.GetDirectoryName(Path);

                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var options = new FileStreamOptions
                {
                    Mode = FileMode.Append,
                    Access = FileAccess.Write,

                    // The vendor's tool may be appending to the same file from
                    // the same host at the same moment. Append mode plus a single
                    // write of one short line is what keeps the two from
                    // interleaving; the file is never opened for truncation, so a
                    // concurrent writer cannot cost more than its own record. The
                    // lock below only serialises this process with itself.
                    Share = FileShare.ReadWrite,
                };

                if (!OperatingSystem.IsWindows())
                {
                    // Set at creation rather than chmod-ed afterwards, so there is
                    // no moment when a list of who holds a licence for which
                    // server exists at the umask default.
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                }

                lock (_gate)
                {
                    using var file = new FileStream(Path, options);

                    file.Write(line, 0, line.Length);
                }

                error = null;

                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is NotSupportedException)
            {
                error = ex.Message;

                return false;
            }
        }
    }

    /// <summary>One line of the ledger.</summary>
    public sealed class LedgerRecord
    {
        public LedgerRecord(IssuedLicence licence)
        {
            if (licence == null)
            {
                throw new ArgumentNullException(nameof(licence));
            }

            IssuedAt = licence.IssuedAt;
            ExpiresAt = licence.ExpiresAt;
            Licensee = licence.Licensee;
            ServerId = licence.ServerId;
            Fingerprint = licence.Fingerprint;

            // The tool writes the `--days` it was given. The service is not
            // given days, it is given the code's fixed expiry, so this is the
            // licence's own lifetime rounded to whole days - which for a
            // re-issue onto the same server is the REMAINING term, not the
            // original one. That is the honest number: a re-issue does not
            // extend anything.
            Days = (int)Math.Round((ExpiresAt - IssuedAt).TotalDays, MidpointRounding.AwayFromZero);
        }

        public DateTimeOffset IssuedAt { get; }

        public DateTimeOffset ExpiresAt { get; }

        public int Days { get; }

        public string Licensee { get; }

        public string ServerId { get; }

        public string Fingerprint { get; }
    }
}

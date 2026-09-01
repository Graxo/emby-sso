using System;
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Emby.Sso.LicenceService.Backup
{
    /// <summary>
    /// An encrypted copy of everything on the volume that cannot be rebuilt.
    ///
    /// WHY IT IS ENCRYPTED AND THERE IS NO PLAIN OPTION. What is in here is the
    /// customer list, every activation, every licence that has been signed, the
    /// outbox of redemption codes, and the admin audit trail. A redemption code
    /// is a bearer credential and a licence is a live one. The entire reason for
    /// taking a backup is to put it somewhere that is not this box - a laptop, a
    /// cloud drive, an email to yourself - which is to say somewhere less
    /// careful than this box. A plaintext option would be used, and it would be
    /// the worst file in the vendor's possession.
    ///
    /// THE FORMAT, deliberately boring and readable from this file alone:
    ///
    ///     magic       12 bytes  "EMBYSSOBAK\0" and a format byte
    ///     iterations   4 bytes  big-endian, the PBKDF2 count actually used
    ///     salt        32 bytes
    ///     nonce       12 bytes
    ///     ciphertext   n bytes  AES-256-GCM of a ZIP archive
    ///     tag         16 bytes
    ///
    /// The header is the GCM associated data, so an attacker cannot lower the
    /// iteration count in the file and have it still authenticate - the count is
    /// read from the file rather than assumed, which is what lets it be raised
    /// later without stranding old backups, and authenticating it is what stops
    /// that flexibility becoming a downgrade.
    ///
    /// AES-GCM in one shot, over the whole archive. That caps what this can back
    /// up at what fits in memory twice, which is why <see cref="MaximumBytes"/>
    /// exists and refuses rather than thrashing. For a store that is a few
    /// megabytes of a one-person vendor's sales it is the right trade: chunked
    /// framing is more code, and more code between a person and their only copy
    /// of their customer list is not obviously a win.
    ///
    /// NOT A SUBSTITUTE FOR THE SIGNING KEY'S OWN BACKUP. The key is not on this
    /// host and is not in here. Losing it is unrecoverable in a way losing this
    /// is not.
    /// </summary>
    public static class BackupArchive
    {
        /// <summary>11 bytes of magic and one format byte, so a wrong file is refused by name.</summary>
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("EMBYSSOBAK\0");

        private const byte Format = 1;

        private const int SaltBytes = 32;
        private const int NonceBytes = 12;
        private const int TagBytes = 16;
        private const int KeyBytes = 32;

        private static readonly int HeaderBytes = Magic.Length + 1 + 4 + SaltBytes + NonceBytes;

        /// <summary>
        /// PBKDF2-HMAC-SHA256, at the count OWASP recommends for this function.
        /// Read from the file on the way back in, so raising it here does not
        /// strand a backup taken before the change.
        /// </summary>
        public const int Iterations = 600_000;

        /// <summary>
        /// The most this will encrypt or decrypt in one go. It is a refusal, not
        /// a truncation: a backup that quietly stopped early is worse than no
        /// backup at all, and finding out at restore time is the worst possible
        /// moment.
        /// </summary>
        public const int MaximumBytes = 128 * 1024 * 1024;

        /// <summary>
        /// The shortest passphrase this will accept. Enforced here as well as in
        /// the configuration check, because this is the function that would
        /// otherwise happily encrypt the customer list under "hunter2".
        /// </summary>
        public const int MinimumPassphrase = 16;

        /// <summary>
        /// Packs the named files into an encrypted archive. A file that is not
        /// there is skipped rather than failing: an outbox only exists once a
        /// code has been sold, and an audit trail only once somebody has logged
        /// in, and refusing to back up a young deployment would mean the backup
        /// starts working on the day it stops being easy to recreate.
        /// </summary>
        public static byte[] Create(string passphrase, params BackupEntry[] entries)
        {
            RequireUsablePassphrase(passphrase);

            if (entries == null || entries.Length == 0)
            {
                throw new ArgumentException("a backup with nothing in it is not a backup", nameof(entries));
            }

            byte[] archive;

            using (var buffer = new MemoryStream())
            {
                using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
                {
                    foreach (var entry in entries)
                    {
                        if (entry?.Path == null || !File.Exists(entry.Path))
                        {
                            continue;
                        }

                        var written = zip.CreateEntry(entry.Name, CompressionLevel.Optimal);

                        using var source = File.OpenRead(entry.Path);
                        using var target = written.Open();

                        source.CopyTo(target);
                    }
                }

                archive = buffer.ToArray();
            }

            if (archive.Length > MaximumBytes)
            {
                throw new InvalidOperationException(
                    "This store is " + (archive.Length / (1024 * 1024)).ToString(CultureInfo.InvariantCulture)
                    + " MB compressed, which is past the " + (MaximumBytes / (1024 * 1024)).ToString(CultureInfo.InvariantCulture)
                    + " MB this backup format handles in one piece. Copy the volume directly instead, and encrypt it "
                    + "yourself - do not leave it lying about.");
            }

            var salt = RandomNumberGenerator.GetBytes(SaltBytes);
            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            var header = Header(salt, nonce, Iterations);
            var key = DeriveKey(passphrase, salt, Iterations);

            var cipher = new byte[archive.Length];
            var tag = new byte[TagBytes];

            try
            {
                using var aes = new AesGcm(key, TagBytes);

                aes.Encrypt(nonce, archive, cipher, tag, header);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(archive);
            }

            var result = new byte[header.Length + cipher.Length + tag.Length];

            Buffer.BlockCopy(header, 0, result, 0, header.Length);
            Buffer.BlockCopy(cipher, 0, result, header.Length, cipher.Length);
            Buffer.BlockCopy(tag, 0, result, header.Length + cipher.Length, tag.Length);

            return result;
        }

        /// <summary>
        /// Unpacks an archive into <paramref name="directory"/>, which must be
        /// empty or not exist.
        ///
        /// A wrong passphrase and a tampered file are the same failure here, and
        /// that is not a limitation: GCM cannot tell them apart, and pretending
        /// otherwise would mean trusting a partial decryption to say which. Both
        /// get the same sentence, which names the likely cause first.
        /// </summary>
        public static int Restore(byte[] blob, string passphrase, string directory)
        {
            RequireUsablePassphrase(passphrase);

            if (blob == null || blob.Length < HeaderBytes + TagBytes)
            {
                throw new InvalidOperationException("That is not an Emby SSO backup: it is too short to be one.");
            }

            for (var i = 0; i < Magic.Length; i++)
            {
                if (blob[i] != Magic[i])
                {
                    throw new InvalidOperationException(
                        "That is not an Emby SSO backup - it does not start the way one does.");
                }
            }

            if (blob[Magic.Length] != Format)
            {
                throw new InvalidOperationException(
                    "That backup is format " + blob[Magic.Length].ToString(CultureInfo.InvariantCulture)
                    + " and this build reads format " + Format.ToString(CultureInfo.InvariantCulture)
                    + ". Use the version of the service that wrote it.");
            }

            var iterations = BinaryPrimitives.ReadInt32BigEndian(blob.AsSpan(Magic.Length + 1, 4));

            if (iterations < 100_000 || iterations > 10_000_000)
            {
                // Authenticated as associated data, so this cannot be forced by
                // an attacker without failing the tag - but a corrupt file could
                // still name an absurd count, and spending an hour on PBKDF2
                // before reporting that is not a useful failure mode.
                throw new InvalidOperationException(
                    "That backup names an implausible key-derivation count (" + iterations.ToString(CultureInfo.InvariantCulture)
                    + "). It is corrupt.");
            }

            var salt = blob.AsSpan(Magic.Length + 5, SaltBytes).ToArray();
            var nonce = blob.AsSpan(Magic.Length + 5 + SaltBytes, NonceBytes).ToArray();
            var header = blob.AsSpan(0, HeaderBytes).ToArray();

            var cipherLength = blob.Length - HeaderBytes - TagBytes;

            if (cipherLength > MaximumBytes)
            {
                throw new InvalidOperationException("That backup is larger than this build will decrypt in one piece.");
            }

            var cipher = blob.AsSpan(HeaderBytes, cipherLength).ToArray();
            var tag = blob.AsSpan(HeaderBytes + cipherLength, TagBytes).ToArray();
            var key = DeriveKey(passphrase, salt, iterations);
            var plain = new byte[cipherLength];

            try
            {
                using var aes = new AesGcm(key, TagBytes);

                aes.Decrypt(nonce, cipher, tag, plain, header);
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(plain);

                throw new InvalidOperationException(
                    "That backup did not decrypt. Almost always this is the wrong passphrase - it has to be the "
                    + "LICENCE_BACKUP_PASSPHRASE that was set WHEN THE BACKUP WAS TAKEN, not the one set now. "
                    + "Otherwise the file has been damaged or altered in transit.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }

            try
            {
                return Unpack(plain, directory);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }

        private static int Unpack(byte[] archive, string directory)
        {
            var target = Path.GetFullPath(directory);

            if (Directory.Exists(target) && Directory.GetFileSystemEntries(target).Length > 0)
            {
                throw new InvalidOperationException(
                    target + " is not empty. Restore into a new directory and move the files yourself, so that a "
                    + "restore can never quietly overwrite a live store.");
            }

            Directory.CreateDirectory(target);

            using var buffer = new MemoryStream(archive, writable: false);
            using var zip = new ZipArchive(buffer, ZipArchiveMode.Read);

            var restored = 0;

            foreach (var entry in zip.Entries)
            {
                // Zip-slip, refused on the plainest possible rule: this format's
                // archives are FLAT - four files, no directories - so an entry
                // with any path in its name is not one this service wrote, and
                // there is nothing to weigh up. Extracting by Name rather than
                // FullName would already discard the path, but a guard that
                // works by accident of which property was used is one an
                // innocent-looking edit turns off.
                //
                // A backup file arrives from wherever the operator kept it. "The
                // input is ours" is exactly the assumption that keeps this class
                // of bug alive.
                if (!string.Equals(entry.FullName, entry.Name, StringComparison.Ordinal)
                    || entry.Name.Length == 0)
                {
                    throw new InvalidOperationException(
                        "That backup contains an entry named '" + entry.FullName
                        + "', which would be written outside " + target + ". Refusing to unpack it.");
                }

                var destination = Path.GetFullPath(Path.Combine(target, entry.Name));

                if (!destination.StartsWith(target + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "That backup contains an entry that would be written outside " + target
                        + ". Refusing to unpack it.");
                }

                entry.ExtractToFile(destination, overwrite: false);

                if (!OperatingSystem.IsWindows())
                {
                    // Everything in here is either a credential or a customer
                    // list. Owner-only, whatever the umask says.
                    File.SetUnixFileMode(destination, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }

                restored++;
            }

            return restored;
        }

        private static void RequireUsablePassphrase(string passphrase)
        {
            if (passphrase == null || passphrase.Length < MinimumPassphrase)
            {
                throw new ArgumentException(
                    "The backup passphrase must be at least " + MinimumPassphrase.ToString(CultureInfo.InvariantCulture)
                    + " characters. It is the only thing protecting a copy of the whole customer store.",
                    nameof(passphrase));
            }
        }

        private static byte[] Header(byte[] salt, byte[] nonce, int iterations)
        {
            var header = new byte[HeaderBytes];

            Buffer.BlockCopy(Magic, 0, header, 0, Magic.Length);
            header[Magic.Length] = Format;
            BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(Magic.Length + 1, 4), iterations);
            Buffer.BlockCopy(salt, 0, header, Magic.Length + 5, SaltBytes);
            Buffer.BlockCopy(nonce, 0, header, Magic.Length + 5 + SaltBytes, NonceBytes);

            return header;
        }

        private static byte[] DeriveKey(string passphrase, byte[] salt, int iterations)
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(passphrase),
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                KeyBytes);
        }
    }

    /// <summary>One file to put in the archive, and the name it takes inside it.</summary>
    public sealed class BackupEntry
    {
        public BackupEntry(string name, string path)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Path = path;
        }

        public string Name { get; }

        public string Path { get; }
    }
}

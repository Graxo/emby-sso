using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Licensing
{
    /// <summary>
    /// Loads the private signing key off disk, and refuses to load one that is
    /// stored carelessly.
    ///
    /// THIS IS THE ONE THING THE WHOLE SCHEME RESTS ON. Until this service
    /// existed the key lived offline on the vendor's laptop and touched the
    /// network never; it now sits on a box with a port open to the internet.
    /// Everything this class refuses to do is refused loudly and at startup,
    /// because a licence service that has quietly fallen back to something
    /// weaker is worse than one that will not start.
    /// </summary>
    public static class SigningKeyFile
    {
        /// <summary>
        /// Thrown for every refusal below. The host catches it at startup, logs
        /// it, and exits non-zero rather than serving without a key.
        /// </summary>
        public sealed class SigningKeyException : Exception
        {
            public SigningKeyException(string message)
                : base(message)
            {
            }
        }

        /// <summary>
        /// Reads and checks the key at <paramref name="path"/>.
        ///
        /// The checks, in order, and why each one is fatal:
        ///
        ///   * missing - the operator mounted the wrong path, or forgot the
        ///     volume. Starting anyway would mean every activation failing at
        ///     the last step, after the customer's money has already moved.
        ///   * not readable - same, one layer down.
        ///   * readable by anyone but its owner - the key is one `cat` away from
        ///     any other account or container on that host. This is checked
        ///     rather than fixed: silently chmod-ing a file the operator may
        ///     have deliberately shared is not this code's decision, and a key
        ///     that has already been group-readable on a shared box has to be
        ///     treated as leaked, not tidied up.
        ///   * public half only - a JWK with no `d` cannot sign. Caught here so
        ///     the message says so, rather than a cryptic library error on the
        ///     first sale.
        ///   * inside a git working tree - one `git add -A` from being
        ///     published, and there is no undoing that. The tool refuses this
        ///     too; see tools/Emby.Sso.LicenceTool/README.md.
        /// </summary>
        public static SigningKey Load(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new SigningKeyException(
                    "No signing key path configured. Set LICENCE_SIGNING_KEY_PATH to the "
                    + LicenceFormat.PrivateKeyFileName + " that was mounted read-only into this container.");
            }

            var full = Path.GetFullPath(path);

            if (!File.Exists(full))
            {
                throw new SigningKeyException(
                    "No signing key at " + full + "." + Environment.NewLine
                    + "Nothing can be issued without it. Check the read-only bind mount in docker-compose.yml, "
                    + "and that LICENCE_SIGNING_KEY_PATH names the file rather than the directory it is in.");
            }

            RefuseAGitWorkingTree(full);
            RefuseWiderThanOwnerOnly(full);

            string text;

            try
            {
                text = File.ReadAllText(full);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                throw new SigningKeyException(
                    "Cannot read the signing key at " + full + ": " + ex.Message + Environment.NewLine
                    + "The mount has to be readable by the uid this container runs as.");
            }

            JsonWebKey key;

            try
            {
                key = new JsonWebKey(text);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is JsonException)
            {
                throw new SigningKeyException(
                    full + " is not a JWK. It should be the single-line JSON file that "
                    + "`licencetool keygen` wrote: " + ex.Message);
            }

            if (string.IsNullOrEmpty(key.N) || string.IsNullOrEmpty(key.E))
            {
                throw new SigningKeyException(
                    full + " is not an RSA JWK - it carries no modulus and exponent.");
            }

            if (string.IsNullOrEmpty(key.D))
            {
                throw new SigningKeyException(
                    full + " carries no private key material - this is the PUBLIC half, which cannot sign. "
                    + "The private half is the file `licencetool keygen` wrote, named "
                    + LicenceFormat.PrivateKeyFileName + ".");
            }

            return new SigningKey(key, full);
        }

        /// <summary>
        /// Owner-only, or nothing. Group and other are treated the same: on a
        /// host where the key is group-readable, "the group" is an account the
        /// vendor is not thinking about.
        ///
        /// Windows has no mode bits to check and this service is only ever run
        /// in the Linux image, so the check is skipped there rather than faked.
        /// </summary>
        private static void RefuseWiderThanOwnerOnly(string path)
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            const UnixFileMode BeyondOwner =
                UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

            var mode = File.GetUnixFileMode(path);

            if ((mode & BeyondOwner) != 0)
            {
                throw new SigningKeyException(
                    "REFUSING TO START: the signing key at " + path + " is readable or writable by accounts "
                    + "other than its owner (mode " + Describe(mode) + ")." + Environment.NewLine
                    + "This key mints licences for every customer you have. `chmod 600` it on the host, and if it "
                    + "has been sitting like that on a machine other people can reach, treat it as leaked: new "
                    + "keypair, new plugin build, reissue everybody.");
            }
        }

        private static void RefuseAGitWorkingTree(string path)
        {
            for (var directory = new DirectoryInfo(Path.GetDirectoryName(path)); directory != null; directory = directory.Parent)
            {
                var git = Path.Combine(directory.FullName, ".git");

                if (!Directory.Exists(git) && !File.Exists(git))
                {
                    continue;
                }

                throw new SigningKeyException(
                    "REFUSING TO START: the signing key at " + path + " is inside the git working tree at "
                    + directory.FullName + "." + Environment.NewLine
                    + "It is one `git add -A` from being published, and a key that reaches any commit that ever "
                    + "left the machine has to be treated as leaked. Mount it from somewhere outside every "
                    + "repository.");
            }
        }

        private static string Describe(UnixFileMode mode)
        {
            var text = new StringBuilder(9);

            text.Append((mode & UnixFileMode.UserRead) != 0 ? 'r' : '-');
            text.Append((mode & UnixFileMode.UserWrite) != 0 ? 'w' : '-');
            text.Append((mode & UnixFileMode.UserExecute) != 0 ? 'x' : '-');
            text.Append((mode & UnixFileMode.GroupRead) != 0 ? 'r' : '-');
            text.Append((mode & UnixFileMode.GroupWrite) != 0 ? 'w' : '-');
            text.Append((mode & UnixFileMode.GroupExecute) != 0 ? 'x' : '-');
            text.Append((mode & UnixFileMode.OtherRead) != 0 ? 'r' : '-');
            text.Append((mode & UnixFileMode.OtherWrite) != 0 ? 'w' : '-');
            text.Append((mode & UnixFileMode.OtherExecute) != 0 ? 'x' : '-');

            return text.ToString();
        }

        /// <summary>
        /// A loaded signing key, and the one safe thing that can be said about it
        /// out loud.
        /// </summary>
        public sealed class SigningKey
        {
            internal SigningKey(JsonWebKey key, string path)
            {
                Key = key;
                Path = path;
                PublicJwk = JsonSerializer.Serialize(new Dictionary<string, string>
                {
                    ["kty"] = "RSA",
                    ["n"] = key.N,
                    ["e"] = key.E,
                });

                var hash = SHA256.HashData(Encoding.UTF8.GetBytes(PublicJwk));

                Thumbprint = Convert.ToHexString(hash).ToLowerInvariant().Substring(0, 16);
            }

            /// <summary>The key itself, private half included. Never log this.</summary>
            public JsonWebKey Key { get; }

            public string Path { get; }

            /// <summary>The public half, as the plugin embeds it. Not a secret.</summary>
            public string PublicJwk { get; }

            /// <summary>
            /// A short SHA-256 of the PUBLIC half, so a startup log line and the
            /// health endpoint can say <em>which</em> key is loaded - "did I mount
            /// last year's key?" is a real question - without any of it being
            /// derived from the private material.
            /// </summary>
            public string Thumbprint { get; }
        }
    }
}

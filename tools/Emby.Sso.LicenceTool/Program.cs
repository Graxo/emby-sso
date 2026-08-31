using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.LicenceTool
{
    /// <summary>
    /// Mints the licences the plugin checks. The vendor runs this; an operator
    /// never sees it.
    ///
    /// It is a separate program on purpose. The private key it holds is the only
    /// thing the whole scheme rests on, and the smallest possible amount of code
    /// should be able to touch it - certainly not a plugin that gets copied onto
    /// other people's servers.
    ///
    /// The two constants below are duplicated from
    /// <c>Emby.Sso.Protocol.LicenceCheck</c> rather than shared, because sharing
    /// them would mean this project referencing the plugin and the plugin's
    /// dependency graph. They must stay character-identical to it: a mismatch
    /// makes every licence this tool issues fail validation with "wrong issuer",
    /// which is at least a loud failure rather than a quiet one.
    /// </summary>
    internal static class Program
    {
        private const string Issuer = "urn:emby-sso:licence";
        private const string Algorithm = SecurityAlgorithms.RsaSha256;

        private const string PrivateKeyFileName = "licence-signing-key.private.json";

        private const string Usage = @"Emby SSO licence tool

  keygen --out <directory> [--allow-git]
      Generates a 3072-bit RSA signing keypair. Writes the PRIVATE key to
      <directory>/" + PrivateKeyFileName + @" and prints the PUBLIC key as a
      one-line JWK to paste into src/Emby.Sso/Protocol/LicencePublicKey.cs.
      Run this ONCE. Every licence already issued dies with the key.

  issue --key <private key file> --server-id <id> --licensee <name> --days <n>
      Prints a licence for one Emby server. The server id is the ServerId
      Emby logs at startup (IApplicationHost.SystemId).

See README.md in this directory for where the private key should live.";

        private static int Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    Console.WriteLine(Usage);
                    return 1;
                }

                switch (args[0])
                {
                    case "keygen":
                        return KeyGen(Parse(args));

                    case "issue":
                        return Issue(Parse(args));

                    default:
                        Console.Error.WriteLine("unknown command '" + args[0] + "'");
                        Console.WriteLine(Usage);
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        }

        private static int KeyGen(IDictionary<string, string> options)
        {
            var directory = Required(options, "out");

            // 3072 bits, not 2048. This key signs for years, it is verified on a
            // machine that does it once per sign-in, and the only cost of the
            // larger key is a longer licence string - which an operator pastes
            // once. There is no reason to pick the smaller one.
            using var rsa = RSA.Create(3072);

            var path = Path.GetFullPath(Path.Combine(directory, PrivateKeyFileName));

            RefuseToWriteInsideAGitRepository(path, options.ContainsKey("allow-git"));

            if (File.Exists(path))
            {
                // Never overwrite. Every licence ever issued is verified against
                // the public half of the key that is already there; replacing it
                // by accident invalidates all of them at once.
                throw new InvalidOperationException(
                    path + " already exists. Refusing to overwrite a signing key - "
                    + "every licence issued with it would stop validating.");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path));

            var p = rsa.ExportParameters(true);

            File.WriteAllText(path, Json(new Dictionary<string, string>
            {
                ["kty"] = "RSA",
                ["n"] = Base64UrlEncoder.Encode(p.Modulus),
                ["e"] = Base64UrlEncoder.Encode(p.Exponent),
                ["d"] = Base64UrlEncoder.Encode(p.D),
                ["p"] = Base64UrlEncoder.Encode(p.P),
                ["q"] = Base64UrlEncoder.Encode(p.Q),
                ["dp"] = Base64UrlEncoder.Encode(p.DP),
                ["dq"] = Base64UrlEncoder.Encode(p.DQ),
                ["qi"] = Base64UrlEncoder.Encode(p.InverseQ),
            }));

            // Owner-only. Not a substitute for keeping the file somewhere
            // sensible, but it stops the obvious accident of a world-readable
            // signing key in a shared home directory.
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            var publicKey = Json(new Dictionary<string, string>
            {
                ["kty"] = "RSA",
                ["n"] = Base64UrlEncoder.Encode(p.Modulus),
                ["e"] = Base64UrlEncoder.Encode(p.Exponent),
            });

            Console.WriteLine("Private key written to " + path);
            Console.WriteLine("  Back it up. Losing it means no further licence can ever be issued");
            Console.WriteLine("  for the builds that carry the matching public key.");
            Console.WriteLine();
            Console.WriteLine("Paste this PUBLIC key into src/Emby.Sso/Protocol/LicencePublicKey.cs:");
            Console.WriteLine();
            Console.WriteLine(publicKey);
            Console.WriteLine();

            return 0;
        }

        private static int Issue(IDictionary<string, string> options)
        {
            var keyFile = Required(options, "key");
            var serverId = Required(options, "server-id").Trim();
            var licensee = Required(options, "licensee").Trim();
            var days = int.Parse(Required(options, "days"), CultureInfo.InvariantCulture);

            if (days <= 0)
            {
                throw new ArgumentException("--days must be a positive number; a licence must expire");
            }

            if (serverId.Length == 0 || licensee.Length == 0)
            {
                throw new ArgumentException("--server-id and --licensee must not be empty");
            }

            var key = new JsonWebKey(File.ReadAllText(keyFile));

            if (string.IsNullOrEmpty(key.D))
            {
                throw new ArgumentException(
                    keyFile + " carries no private key material - this is the PUBLIC half, which cannot sign.");
            }

            var now = DateTime.UtcNow;

            // `sub` is the licensee, `aud` the one server this is good for, and
            // exp/iat/nbf are the standard lifetime claims - all of them
            // registered claims, so the plugin's validator enforces them through
            // the library rather than by re-reading the payload itself.
            var payload = Json(new Dictionary<string, object>
            {
                ["iss"] = Issuer,
                ["sub"] = licensee,
                ["aud"] = serverId,
                ["iat"] = EpochTime.GetIntDate(now),
                ["nbf"] = EpochTime.GetIntDate(now),
                ["exp"] = EpochTime.GetIntDate(now.AddDays(days)),
            });

            var licence = new JsonWebTokenHandler().CreateToken(
                payload,
                new SigningCredentials(key, Algorithm));

            Console.Error.WriteLine("Licensee : " + licensee);
            Console.Error.WriteLine("Server   : " + serverId);
            Console.Error.WriteLine("Expires  : " + now.AddDays(days).ToString("u", CultureInfo.InvariantCulture));
            Console.Error.WriteLine();

            // The licence itself goes to stdout alone, so it can be redirected
            // to a file or piped without the summary above coming with it.
            Console.WriteLine(licence);

            return 0;
        }

        /// <summary>
        /// A signing key inside a git working tree is one <c>git add -A</c> away
        /// from being published, and there is no undoing that - a key in any
        /// commit that ever left the machine has to be treated as leaked, and
        /// every licence issued with it reissued. So this refuses rather than
        /// warns.
        ///
        /// <c>--allow-git</c> exists for the one legitimate case: a home
        /// directory that is itself a dotfiles repository. It is not an
        /// override to reach for otherwise, and the repository's own .gitignore
        /// covers the file name either way.
        /// </summary>
        private static void RefuseToWriteInsideAGitRepository(string path, bool allowed)
        {
            if (allowed)
            {
                return;
            }

            for (var directory = new DirectoryInfo(Path.GetDirectoryName(path)); directory != null; directory = directory.Parent)
            {
                var git = Path.Combine(directory.FullName, ".git");

                if (!Directory.Exists(git) && !File.Exists(git))
                {
                    continue;
                }

                throw new InvalidOperationException(
                    "Refusing to write a signing key inside the git working tree at " + directory.FullName + "."
                    + Environment.NewLine
                    + "A private key that reaches a commit has to be treated as leaked. Choose a directory "
                    + "outside any repository - see tools/Emby.Sso.LicenceTool/README.md - or pass --allow-git "
                    + "if this directory really is not tracked.");
            }
        }

        private static string Json<T>(IDictionary<string, T> values)
        {
            return JsonSerializer.Serialize(values);
        }

        /// <summary>
        /// The smallest thing that reads <c>--name value</c> pairs. Flags with no
        /// value (<c>--allow-git</c>) are recorded as present with an empty
        /// value. Deliberately not a command-line library: one more dependency
        /// on the machine that holds the signing key is one more than this needs.
        /// </summary>
        private static IDictionary<string, string> Parse(string[] args)
        {
            var options = new Dictionary<string, string>(StringComparer.Ordinal);

            for (var i = 1; i < args.Length; i++)
            {
                if (!args[i].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException("unexpected argument '" + args[i] + "'");
                }

                var name = args[i].Substring(2);
                var hasValue = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal);

                options[name] = hasValue ? args[++i] : string.Empty;
            }

            return options;
        }

        private static string Required(IDictionary<string, string> options, string name)
        {
            if (!options.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("--" + name + " is required" + Environment.NewLine + Environment.NewLine + Usage);
            }

            return value;
        }
    }
}

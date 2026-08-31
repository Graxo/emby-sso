using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// A signing key for tests, written in exactly the shape
    /// `licencetool keygen` writes - same field names, same encoding, same
    /// owner-only mode - so a test that loads one is testing the loader against
    /// the file the vendor really has.
    ///
    /// 2048 bits here rather than the tool's 3072: this generates a key per test
    /// class and key generation is the slowest thing in the suite. Nothing under
    /// test depends on the modulus size.
    /// </summary>
    internal static class TestKeys
    {
        public static string WritePrivateKey(string directory, bool ownerOnly = true)
        {
            Directory.CreateDirectory(directory);

            using var rsa = RSA.Create(2048);

            var p = rsa.ExportParameters(true);
            var path = Path.Combine(directory, "licence-signing-key.private.json");

            File.WriteAllText(path, JsonSerializer.Serialize(new Dictionary<string, string>
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

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    path,
                    ownerOnly
                        ? UnixFileMode.UserRead | UnixFileMode.UserWrite
                        : UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            }

            return path;
        }

        public static string WritePublicKeyOnly(string directory)
        {
            Directory.CreateDirectory(directory);

            using var rsa = RSA.Create(2048);

            var p = rsa.ExportParameters(false);
            var path = Path.Combine(directory, "licence-signing-key.private.json");

            File.WriteAllText(path, JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["kty"] = "RSA",
                ["n"] = Base64UrlEncoder.Encode(p.Modulus),
                ["e"] = Base64UrlEncoder.Encode(p.Exponent),
            }));

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            return path;
        }

        /// <summary>
        /// A directory under the system temp path. Deliberately NOT under the
        /// repository: the key loader refuses to load a key from inside a git
        /// working tree, which is a rule the tests have to live with rather than
        /// work around.
        /// </summary>
        public static string TempDirectory()
        {
            var path = Path.Combine(Path.GetTempPath(), "emby-sso-licence-tests", Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(path);

            return path;
        }
    }
}

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
        /// <summary>
        /// A fixed RSA PUBLIC key in the canonical shape LICENCE_PUBLIC_KEYS
        /// takes, for the tests that build a configuration out of environment
        /// strings and never sign anything. Generating one per test would cost
        /// seconds across the suite and prove nothing more.
        ///
        /// It is a public key with no private half anywhere, so it is not a
        /// secret and nothing can be signed with it.
        /// </summary>
        public const string SamplePublicJwk =
            "{\"kty\":\"RSA\",\"n\":\"4MRfQ1GfRQHBCePuyRQs_4SrzClGhThYs4od4YOWSffORiWjQhpm0vJXtDVbRYu1d0kzE-xt"
            + "CIzwM5GJJzNtyYvoldijecmwuBfM1XVEdmVZIdx38EWWxoYQVwrvTB_cC8fb1uziHes0Msu_VlGf59cJSTiqHUL8oWS-0ZA63OUv"
            + "6ULclFr49pHsWJJZVaRXm2ADjnidxMkreMm30kD_0dvG8K83F197dXgDMqbXr_af9B25X1eLncgikadZDW-rjGxPLg8r2Rs5aoF-"
            + "XWqZQiwToJsbLBTgSM4uBHnEjDOS-RdmtfooYdas-a1n34AuXLj2dxqOsLsG93Wc0jE0d6sDK6nNpy4K1MPcRuyqvrHSIC_sXUxE"
            + "PlLMdhVBGKKZpLVYO0LAzXPelN_AErYCw21CNaVxTY3mlsx5T1O3vTaoRjG0O_ySW54PXt8hhAznWKckrf6MC0KCsAoW9K45gWZc"
            + "NP4PuwLaY4dSh6mDBv2XWnDDfsXHb-jTditdyYyn\",\"e\":\"AQAB\"}";

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

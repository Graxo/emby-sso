using System;
using System.IO;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The brief's "loud failure if missing or world-readable", asserted.
    ///
    /// Each of these is a refusal to start. A licence service that starts
    /// without a usable key takes money and then fails at the last step, and one
    /// that starts with a key every account on the box can read has already lost
    /// the only thing it was protecting.
    /// </summary>
    public class SigningKeyFileTests : IDisposable
    {
        private readonly string _directory = TestKeys.TempDirectory();

        public void Dispose()
        {
            Directory.Delete(_directory, recursive: true);
        }

        [Fact]
        public void A_good_key_loads_and_reports_a_thumbprint_of_its_public_half()
        {
            var path = TestKeys.WritePrivateKey(_directory);

            var key = SigningKeyFile.Load(path);

            Assert.Equal(path, key.Path);
            Assert.Equal(16, key.Thumbprint.Length);
            Assert.Contains("\"kty\":\"RSA\"", key.PublicJwk, StringComparison.Ordinal);

            // The public JWK is handed to /healthz and to logs. It must not carry
            // the private half.
            Assert.DoesNotContain("\"d\":", key.PublicJwk, StringComparison.Ordinal);
            Assert.DoesNotContain("\"p\":", key.PublicJwk, StringComparison.Ordinal);
        }

        [Fact]
        public void The_same_key_always_has_the_same_thumbprint()
        {
            var path = TestKeys.WritePrivateKey(_directory);

            Assert.Equal(SigningKeyFile.Load(path).Thumbprint, SigningKeyFile.Load(path).Thumbprint);
        }

        [Fact]
        public void A_missing_key_refuses_to_start_and_says_where_it_looked()
        {
            var missing = Path.Combine(_directory, "not-there.json");

            var ex = Assert.Throws<SigningKeyFile.SigningKeyException>(() => SigningKeyFile.Load(missing));

            Assert.Contains(missing, ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void No_configured_path_refuses_to_start()
        {
            Assert.Throws<SigningKeyFile.SigningKeyException>(() => SigningKeyFile.Load(null));
            Assert.Throws<SigningKeyFile.SigningKeyException>(() => SigningKeyFile.Load("   "));
        }

        [Fact]
        public void A_key_anyone_can_read_refuses_to_start()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            var path = TestKeys.WritePrivateKey(_directory, ownerOnly: false);

            var ex = Assert.Throws<SigningKeyFile.SigningKeyException>(() => SigningKeyFile.Load(path));

            Assert.Contains("readable or writable by accounts", ex.Message, StringComparison.Ordinal);
            Assert.Contains("treat it as leaked", ex.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead)]
        [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead)]
        [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite)]
        [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupWrite)]
        public void Every_bit_beyond_the_owner_refuses_to_start(UnixFileMode mode)
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            var path = TestKeys.WritePrivateKey(_directory);

            File.SetUnixFileMode(path, mode);

            Assert.Throws<SigningKeyFile.SigningKeyException>(() => SigningKeyFile.Load(path));
        }

        [Fact]
        public void The_public_half_alone_refuses_to_start_and_says_so_plainly()
        {
            var path = TestKeys.WritePublicKeyOnly(_directory);

            var ex = Assert.Throws<SigningKeyFile.SigningKeyException>(() => SigningKeyFile.Load(path));

            Assert.Contains("PUBLIC half", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Something_that_is_not_a_key_refuses_to_start()
        {
            var path = Path.Combine(_directory, "licence-signing-key.private.json");

            File.WriteAllText(path, "this is not a JWK");

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            Assert.Throws<SigningKeyFile.SigningKeyException>(() => SigningKeyFile.Load(path));
        }

        [Fact]
        public void A_key_inside_a_git_working_tree_refuses_to_start()
        {
            var repository = Path.Combine(_directory, "repo");

            Directory.CreateDirectory(Path.Combine(repository, ".git"));

            var path = TestKeys.WritePrivateKey(repository);

            var ex = Assert.Throws<SigningKeyFile.SigningKeyException>(() => SigningKeyFile.Load(path));

            Assert.Contains("git working tree", ex.Message, StringComparison.Ordinal);
        }
    }
}

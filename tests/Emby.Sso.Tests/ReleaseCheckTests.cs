using System;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The release manifest check - the gate in front of code execution.
    ///
    /// Whatever passes here gets downloaded and written into Emby's plugins
    /// directory, and then runs. So the bar is the highest in this project: a
    /// manifest must be signed by the RELEASE key, name a plausible hash, name
    /// an https address, and offer a version STRICTLY NEWER than the one
    /// running. Anything else returns null and nothing happens.
    ///
    /// The downgrade case is the subtle one and has its own tests. An old
    /// manifest never stops being genuine - it really was signed, and it really
    /// does describe a real build - so replaying one is the cheapest way to put
    /// a version with a known hole back onto a server. Only the version
    /// comparison prevents it.
    /// </summary>
    public class ReleaseCheckTests
    {
        private static readonly Version Running = new Version(1, 0, 2);
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);
        private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private const string Url = "https://license.koper.cloud/releases/1.0.3/Emby.Sso.dll";

        private readonly LicenceFactory _vendor = new LicenceFactory();

        [Fact]
        public async Task A_signed_newer_release_is_offered()
        {
            var release = await Read(Manifest("1.0.3"));

            Assert.NotNull(release);
            Assert.Equal(new Version(1, 0, 3), release.Version);
            Assert.Equal(Hash, release.Sha256);
            Assert.Equal(Url, release.Url);
        }

        [Theory]
        [InlineData("1.0.2")]
        [InlineData("1.0.1")]
        [InlineData("0.9.0")]
        public async Task A_version_that_is_not_newer_is_never_offered(string version)
        {
            // Including the running version itself: there is nothing to install.
            Assert.Null(await Read(Manifest(version)));
        }

        [Fact]
        public async Task An_old_manifest_replayed_later_cannot_downgrade_anything()
        {
            // Signed a year ago, genuinely, for a real build. Still refused,
            // because it is not newer - and expiry could never have caught this,
            // since a manifest has to outlive the release it describes.
            var old = Manifest("1.0.1", issuedAt: Now.AddYears(-1));

            Assert.Null(await Read(old));
        }

        [Fact]
        public async Task A_manifest_signed_by_a_stranger_is_refused()
        {
            var stranger = new LicenceFactory();

            Assert.Null(await Read(Manifest("1.0.3", signer: stranger)));
        }

        [Fact]
        public async Task A_manifest_signed_by_the_LICENCE_key_is_refused()
        {
            // The separation that matters most. The licence key lives on an
            // internet-facing service; if it could sign releases, breaking into
            // that service would mean shipping code to every customer.
            var licenceKeyOnly = new[] { _vendor.PublicKeyJwk };
            var stranger = new LicenceFactory();

            var signedByLicenceKey = Manifest("1.0.3", signer: stranger);

            var release = await ReleaseCheck.ReadAsync(signedByLicenceKey, licenceKeyOnly, Running, Now);

            Assert.Null(release);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("not-a-manifest")]
        [InlineData("a.b.c")]
        public async Task Nothing_that_is_not_a_manifest_is_offered(string manifest)
        {
            Assert.Null(await Read(manifest));
        }

        [Theory]
        [InlineData("")]
        [InlineData("nothex")]
        [InlineData("0123456789abcdef")]
        [InlineData("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEG")]
        public async Task A_manifest_without_a_usable_hash_is_refused(string hash)
        {
            Assert.Null(await Read(Manifest("1.0.3", hash: hash)));
        }

        [Theory]
        [InlineData("")]
        [InlineData("http://license.koper.cloud/x.dll")]
        [InlineData("file:///etc/passwd")]
        [InlineData("not a url")]
        public async Task A_manifest_without_an_https_address_is_refused(string url)
        {
            Assert.Null(await Read(Manifest("1.0.3", url: url)));
        }

        [Fact]
        public async Task A_licence_presented_as_a_manifest_is_refused()
        {
            Assert.Null(await Read(_vendor.Issue()));
        }

        [Fact]
        public async Task With_no_release_key_nothing_is_ever_offered()
        {
            // The fail-closed direction: a build that cannot verify a manifest
            // must never install anything.
            Assert.Null(await ReleaseCheck.ReadAsync(Manifest("1.0.3"), new string[0], Running, Now));
        }

        [Fact]
        public void The_build_ships_a_release_key_and_it_is_not_the_licence_key()
        {
            Assert.NotEmpty(ReleasePublicKey.TrustedJwks);

            foreach (var release in ReleasePublicKey.TrustedJwks)
            {
                Assert.False(string.IsNullOrWhiteSpace(release));
                Assert.DoesNotContain("\"d\"", release, StringComparison.Ordinal);

                foreach (var licence in LicencePublicKey.TrustedJwks)
                {
                    Assert.NotEqual(licence, release);
                }
            }
        }

        private Task<SignedRelease> Read(string manifest)
        {
            return ReleaseCheck.ReadAsync(manifest, new[] { _vendor.PublicKeyJwk }, Running, Now);
        }

        private string Manifest(
            string version,
            LicenceFactory signer = null,
            string hash = Hash,
            string url = Url,
            DateTimeOffset? issuedAt = null)
        {
            var at = issuedAt ?? Now;

            var payload = "{"
                + "\"iss\":\"" + ReleaseCheck.Issuer + "\","
                + "\"sub\":\"" + version + "\","
                + "\"" + ReleaseCheck.HashClaim + "\":\"" + hash + "\","
                + "\"" + ReleaseCheck.UrlClaim + "\":\"" + url + "\","
                + "\"iat\":" + EpochTime.GetIntDate(at.UtcDateTime) + ","
                + "\"nbf\":" + EpochTime.GetIntDate(at.UtcDateTime) + ","
                + "\"exp\":" + EpochTime.GetIntDate(at.AddYears(10).UtcDateTime)
                + "}";

            return new JsonWebTokenHandler().CreateToken(
                payload,
                new SigningCredentials((signer ?? _vendor).SigningKey, SecurityAlgorithms.RsaSha256));
        }
    }
}

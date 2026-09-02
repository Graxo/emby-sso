using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Release;
using Emby.Sso.Licensing;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The release store, which is the only thing in this service that decides
    /// what code other people's servers are offered.
    ///
    /// The tests worth having here are all refusals. A manifest that verifies is
    /// the easy case and the plugin checks it again anyway; what matters is that
    /// the pairs which would LOOK published and then fail on every customer's
    /// server at once are refused on the vendor's own screen instead.
    /// </summary>
    public sealed class ReleaseStoreTests : IDisposable
    {
        private const string PublicBase = "https://licence.example.com";

        private readonly string _directory = TestKeys.TempDirectory();
        private readonly RSA _release = RSA.Create(2048);
        private readonly RSA _somethingElse = RSA.Create(2048);

        public void Dispose()
        {
            _release.Dispose();
            _somethingElse.Dispose();

            try
            {
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
                // A leftover temporary directory is not a failed test.
            }
        }

        [Fact]
        public async Task Publishes_a_manifest_and_the_file_it_names()
        {
            var store = Store();
            var dll = Bytes("a plugin build");

            Assert.Null(await store.PublishAsync(Manifest("1.0.3", dll, HostedUrl), dll));

            Assert.Equal("1.0.3", store.PublishedVersion());
            Assert.Equal(Sha256(dll), store.PublishedHash());

            using var served = store.OpenFile();

            Assert.NotNull(served);
            Assert.Equal(dll, Read(served));
        }

        /// <summary>
        /// The mistake this exists for: signing one build and uploading another.
        /// Both files are called Emby.Sso.dll and one of them is in the
        /// downloads folder from last time.
        /// </summary>
        [Fact]
        public async Task Refuses_a_file_that_is_not_the_one_signed_for()
        {
            var store = Store();
            var signed = Bytes("the build that was signed");
            var uploaded = Bytes("a different build entirely");

            var problem = await store.PublishAsync(Manifest("1.0.3", signed, HostedUrl), uploaded);

            Assert.NotNull(problem);
            Assert.Contains("not the one the manifest was signed for", problem);

            // Nothing at all, rather than a manifest without its file.
            Assert.Null(store.PublishedVersion());
            Assert.Null(store.OpenFile());
        }

        /// <summary>
        /// The failure that looks like success: the manifest verifies, the page
        /// says published, and every server then reports the download
        /// unreachable because nothing was ever put at that address.
        /// </summary>
        [Fact]
        public async Task Refuses_a_manifest_pointing_here_with_no_file()
        {
            var store = Store();
            var dll = Bytes("a plugin build");

            var problem = await store.PublishAsync(Manifest("1.0.3", dll, HostedUrl));

            Assert.NotNull(problem);
            Assert.Contains("no plugin file has been uploaded", problem);
            Assert.Null(store.PublishedVersion());
        }

        [Fact]
        public async Task Refuses_a_file_when_the_manifest_points_somewhere_else()
        {
            var store = Store();
            var dll = Bytes("a plugin build");

            var problem = await store.PublishAsync(
                Manifest("1.0.3", dll, "https://downloads.example.com/Emby.Sso.dll"),
                dll);

            Assert.NotNull(problem);
            Assert.Contains("would never be fetched", problem);
            Assert.Null(store.PublishedVersion());
        }

        /// <summary>
        /// A build hosted elsewhere means the copy here belongs to a version
        /// nobody is offered any more. Left in place it would be served, by hand
        /// or by habit, as if it were current.
        /// </summary>
        [Fact]
        public async Task Forgets_the_stored_file_when_the_next_release_lives_elsewhere()
        {
            var store = Store();
            var first = Bytes("the first build");

            Assert.Null(await store.PublishAsync(Manifest("1.0.3", first, HostedUrl), first));
            Assert.NotNull(store.OpenFile());

            var second = Bytes("the second build");

            Assert.Null(await store.PublishAsync(
                Manifest("1.0.4", second, "https://downloads.example.com/Emby.Sso.dll")));

            Assert.Equal("1.0.4", store.PublishedVersion());
            Assert.Null(store.OpenFile());
        }

        [Fact]
        public async Task Refuses_a_manifest_signed_by_a_key_it_does_not_trust()
        {
            var store = Store();
            var dll = Bytes("a plugin build");

            var problem = await store.PublishAsync(
                Manifest("1.0.3", dll, HostedUrl, _somethingElse),
                dll);

            Assert.NotNull(problem);
            Assert.Contains("did not verify", problem);
            Assert.Null(store.OpenFile());
        }

        /// <summary>
        /// Already enforced before this change and worth keeping enforced: it is
        /// what stops an old manifest being replayed by anybody who takes this
        /// host, and every plugin refuses a version that is not newer anyway.
        /// </summary>
        [Fact]
        public async Task Refuses_a_version_that_is_not_newer()
        {
            var store = Store();
            var current = Bytes("the current build");

            Assert.Null(await store.PublishAsync(Manifest("1.0.4", current, HostedUrl), current));

            var older = Bytes("an older build");
            var problem = await store.PublishAsync(Manifest("1.0.3", older, HostedUrl), older);

            Assert.NotNull(problem);
            Assert.Contains("already published", problem);

            // And the file that IS published is untouched.
            using var served = store.OpenFile();

            Assert.Equal(current, Read(served));
        }

        [Fact]
        public async Task Accepts_nothing_at_all_without_a_release_public_key()
        {
            var store = new ReleaseStore(Options(), null, new RecordingLogger<ReleaseStore>());
            var dll = Bytes("a plugin build");

            var problem = await store.PublishAsync(Manifest("1.0.3", dll, HostedUrl), dll);

            Assert.NotNull(problem);
            Assert.Contains("LICENCE_RELEASE_PUBLIC_KEYS", problem);
            Assert.False(store.CanAccept);
        }

        [Fact]
        public void Names_its_own_download_address()
        {
            Assert.Equal(HostedUrl, Store().HostedUrl);
        }

        /// <summary>
        /// Without a public base URL the service does not know what address to
        /// tell anybody to sign for, so it hosts nothing rather than guessing.
        /// </summary>
        [Fact]
        public void Hosts_nothing_when_it_does_not_know_its_own_address()
        {
            var options = Options();

            options.PublicBaseUrl = null;

            Assert.Null(new ReleaseStore(options, Trusted(), new RecordingLogger<ReleaseStore>()).HostedUrl);
        }

        private static string HostedUrl => PublicBase + ReleaseStore.DownloadPath;

        private ServiceOptions Options()
        {
            return new ServiceOptions
            {
                DataDirectory = _directory,
                PublicBaseUrl = PublicBase,
            };
        }

        private ReleaseStore Store()
        {
            return new ReleaseStore(Options(), Trusted(), new RecordingLogger<ReleaseStore>());
        }

        private TrustedKeys Trusted()
        {
            var parameters = _release.ExportParameters(false);

            return TrustedKeys.Parse(LicenceFormat.PublicJwk(
                Base64UrlEncoder.Encode(parameters.Modulus),
                Base64UrlEncoder.Encode(parameters.Exponent)));
        }

        private string Manifest(string version, byte[] file, string url, RSA key = null)
        {
            var parameters = (key ?? _release).ExportParameters(true);

            var jwk = new JsonWebKey
            {
                Kty = "RSA",
                N = Base64UrlEncoder.Encode(parameters.Modulus),
                E = Base64UrlEncoder.Encode(parameters.Exponent),
                D = Base64UrlEncoder.Encode(parameters.D),
                P = Base64UrlEncoder.Encode(parameters.P),
                Q = Base64UrlEncoder.Encode(parameters.Q),
                DP = Base64UrlEncoder.Encode(parameters.DP),
                DQ = Base64UrlEncoder.Encode(parameters.DQ),
                QI = Base64UrlEncoder.Encode(parameters.InverseQ),
            };

            return ReleaseManifest.Issue(jwk, version, Sha256(file), url, DateTimeOffset.UtcNow);
        }

        private static byte[] Bytes(string content) => Encoding.UTF8.GetBytes(content);

        private static string Sha256(byte[] content)
        {
            return Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        }

        private static byte[] Read(Stream stream)
        {
            using var buffer = new MemoryStream();

            stream.CopyTo(buffer);

            return buffer.ToArray();
        }
    }
}

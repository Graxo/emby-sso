using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// Downloading a release, and the single rule that makes it safe: THE HASH
    /// DECIDES, NOT THE ADDRESS.
    ///
    /// The address comes out of a signed manifest, but an address is not a
    /// guarantee - the download host can be compromised, the DNS entry hijacked,
    /// a proxy interposed, a cache poisoned. Every one of those arrives here as
    /// "bytes that do not hash to what the vendor signed", and every one of them
    /// must end with nothing written.
    ///
    /// So the interesting tests are the ones where something plausible comes
    /// back and is refused anyway.
    /// </summary>
    public class ReleaseDownloadTests
    {
        private static readonly byte[] RealBytes = Encoding.UTF8.GetBytes("this is the real plugin, pretend it is a DLL");
        private const string Url = "https://license.koper.cloud/releases/1.0.3/Emby.Sso.dll";

        [Fact]
        public async Task Bytes_that_match_the_signed_hash_are_returned()
        {
            var result = await Fetch(RealBytes, ReleaseDownload.Sha256(RealBytes));

            Assert.Equal(ReleaseDownloadOutcome.Verified, result.Outcome);
            Assert.Equal(RealBytes, result.Content);
        }

        [Fact]
        public async Task Bytes_that_do_not_match_are_refused_and_nothing_comes_back()
        {
            // The compromised-host case. A perfectly good HTTP 200, a plausible
            // file, and the wrong bytes.
            var swapped = Encoding.UTF8.GetBytes("this is NOT the real plugin, it is somebody else's");

            var result = await Fetch(swapped, ReleaseDownload.Sha256(RealBytes));

            Assert.Equal(ReleaseDownloadOutcome.WrongBytes, result.Outcome);
            Assert.Null(result.Content);
        }

        [Fact]
        public async Task A_single_flipped_byte_is_refused()
        {
            var tampered = (byte[])RealBytes.Clone();

            tampered[0] ^= 0x01;

            var result = await Fetch(tampered, ReleaseDownload.Sha256(RealBytes));

            Assert.Equal(ReleaseDownloadOutcome.WrongBytes, result.Outcome);
            Assert.Null(result.Content);
        }

        [Fact]
        public async Task An_empty_body_is_refused()
        {
            var result = await Fetch(new byte[0], ReleaseDownload.Sha256(RealBytes));

            Assert.Equal(ReleaseDownloadOutcome.WrongBytes, result.Outcome);
            Assert.Null(result.Content);
        }

        [Theory]
        [InlineData(HttpStatusCode.NotFound)]
        [InlineData(HttpStatusCode.Forbidden)]
        [InlineData(HttpStatusCode.InternalServerError)]
        [InlineData(HttpStatusCode.MovedPermanently)]
        public async Task A_release_address_that_does_not_serve_the_file_is_unreachable(HttpStatusCode status)
        {
            var result = await Fetch(RealBytes, ReleaseDownload.Sha256(RealBytes), status);

            Assert.Equal(ReleaseDownloadOutcome.Unreachable, result.Outcome);
            Assert.Null(result.Content);
        }

        [Fact]
        public async Task A_network_failure_is_unreachable_and_names_no_remote_text()
        {
            using var client = new HttpClient(new ThrowingHandler());

            var result = await ReleaseDownload.FetchAsync(client, Release(ReleaseDownload.Sha256(RealBytes)), CancellationToken.None);

            Assert.Equal(ReleaseDownloadOutcome.Unreachable, result.Outcome);
            Assert.Null(result.Content);

            // The exception TYPE only. A message chosen by whatever answered has
            // no business in a server log.
            Assert.DoesNotContain("teapot", result.Detail, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task A_body_past_the_cap_is_refused_rather_than_buffered()
        {
            var huge = new byte[ReleaseDownload.MaximumBytes + 1];

            var result = await Fetch(huge, ReleaseDownload.Sha256(RealBytes));

            Assert.Equal(ReleaseDownloadOutcome.TooLarge, result.Outcome);
            Assert.Null(result.Content);
        }

        [Fact]
        public async Task Nothing_to_fetch_is_a_refusal_rather_than_a_crash()
        {
            using var client = new HttpClient(new StubHandler(RealBytes, HttpStatusCode.OK));

            Assert.Equal(
                ReleaseDownloadOutcome.Failed,
                (await ReleaseDownload.FetchAsync(client, null, CancellationToken.None)).Outcome);

            Assert.Equal(
                ReleaseDownloadOutcome.Failed,
                (await ReleaseDownload.FetchAsync(null, Release("aa"), CancellationToken.None)).Outcome);
        }

        private static Task<ReleaseDownloadResult> Fetch(byte[] served, string expectedHash, HttpStatusCode status = HttpStatusCode.OK)
        {
            var client = new HttpClient(new StubHandler(served, status));

            return ReleaseDownload.FetchAsync(client, Release(expectedHash), CancellationToken.None);
        }

        private static SignedRelease Release(string hash)
        {
            return new SignedRelease(new Version(1, 0, 3), "1.0.3", hash, Url);
        }

        private sealed class StubHandler : HttpMessageHandler
        {
            private readonly byte[] _body;
            private readonly HttpStatusCode _status;

            public StubHandler(byte[] body, HttpStatusCode status)
            {
                _body = body;
                _status = status;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromResult(new HttpResponseMessage(_status)
                {
                    Content = new ByteArrayContent(_body),
                });
            }
        }

        private sealed class ThrowingHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                throw new HttpRequestException("I am a teapot and this text must not reach a log");
            }
        }
    }
}

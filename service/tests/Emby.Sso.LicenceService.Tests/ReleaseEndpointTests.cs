using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Release;
using Emby.Sso.Licensing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// POST /v1/release, the route release.sh publishes through. It has no
    /// password: the release-key signature is the credential, so what is worth
    /// testing is that nothing without one - or with one for another file, or an
    /// older version - changes what plugins are offered. ReleaseStoreTests holds
    /// every refusal the store makes; these hold the wire around it.
    /// </summary>
    public sealed class ReleaseEndpointTests : IAsyncLifetime
    {
        private const string PublicBase = "https://licence.example.com";

        private readonly RSA _release = RSA.Create(2048);
        private readonly RSA _somethingElse = RSA.Create(2048);

        private TestService _service;
        private WebApplication _app;
        private HttpClient _client;

        public async Task InitializeAsync()
        {
            var parameters = _release.ExportParameters(false);
            var publicJwk = LicenceFormat.PublicJwk(
                Base64UrlEncoder.Encode(parameters.Modulus),
                Base64UrlEncoder.Encode(parameters.Exponent));

            _service = new TestService(options =>
            {
                options.PayPal.ClientId = null;
                options.PayPal.ClientSecret = null;
                options.PublicBaseUrl = PublicBase;
                options.ReleasePublicKeys = publicJwk;
            });

            _app = Program.BuildApp(_service.Options, builder => builder.WebHost.UseTestServer());

            await _app.StartAsync();

            _client = _app.GetTestClient();
        }

        public async Task DisposeAsync()
        {
            _client?.Dispose();

            if (_app != null)
            {
                await _app.StopAsync();
                await _app.DisposeAsync();
            }

            _service?.Dispose();
            _release.Dispose();
            _somethingElse.Dispose();
        }

        [Fact]
        public async Task A_signed_build_is_published_and_served()
        {
            var dll = Bytes("the 1.0.5 build");

            var response = await Publish(Manifest("1.0.5", dll), dll);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
            {
                Assert.Equal("1.0.5", body.RootElement.GetProperty("version").GetString());
                Assert.Equal(Sha256(dll), body.RootElement.GetProperty("sha256").GetString());
            }

            Assert.Equal(dll, await _client.GetByteArrayAsync(ReleaseStore.DownloadPath));
            Assert.Contains("manifest", await _client.GetStringAsync("/v1/release"));
        }

        [Fact]
        public async Task A_manifest_signed_by_any_other_key_publishes_nothing()
        {
            var dll = Bytes("a build somebody else signed");

            var response = await Publish(Manifest("9.9.9", dll, _somethingElse), dll);

            Assert.Equal((HttpStatusCode)422, response.StatusCode);
            Assert.Contains("did not verify", await response.Content.ReadAsStringAsync());
            Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync("/v1/release")).StatusCode);
        }

        [Fact]
        public async Task A_genuine_manifest_with_another_file_publishes_nothing()
        {
            var response = await Publish(Manifest("1.0.5", Bytes("the build that was signed")), Bytes("a swapped file"));

            Assert.Equal((HttpStatusCode)422, response.StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync(ReleaseStore.DownloadPath)).StatusCode);
        }

        [Fact]
        public async Task An_older_release_cannot_be_published_over_a_newer_one()
        {
            var newer = Bytes("1.0.5");
            var older = Bytes("1.0.4");
            var replay = Manifest("1.0.4", older);

            Assert.Equal(HttpStatusCode.OK, (await Publish(Manifest("1.0.5", newer), newer)).StatusCode);
            Assert.Equal((HttpStatusCode)422, (await Publish(replay, older)).StatusCode);

            Assert.Equal(newer, await _client.GetByteArrayAsync(ReleaseStore.DownloadPath));
        }

        [Fact]
        public async Task A_request_without_the_file_is_a_400()
        {
            using var form = new MultipartFormDataContent { { new StringContent("x"), "manifest" } };

            Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsync("/v1/release", form)).StatusCode);
            Assert.Equal(
                HttpStatusCode.BadRequest,
                (await _client.PostAsync("/v1/release", new StringContent("{}", Encoding.UTF8, "application/json"))).StatusCode);
        }

        private async Task<HttpResponseMessage> Publish(string manifest, byte[] dll)
        {
            using var form = new MultipartFormDataContent
            {
                { new StringContent(manifest), "manifest" },
                { new ByteArrayContent(dll), "plugin", "Emby.Sso.dll" },
            };

            return await _client.PostAsync("/v1/release", form);
        }

        private string Manifest(string version, byte[] file, RSA key = null)
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

            return ReleaseManifest.Issue(jwk, version, Sha256(file), PublicBase + ReleaseStore.DownloadPath, DateTimeOffset.UtcNow);
        }

        private static byte[] Bytes(string content) => Encoding.UTF8.GetBytes(content);

        private static string Sha256(byte[] content)
        {
            return Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        }
    }
}

using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.Licensing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The vendor API over the real routes: the portal's Go client is written
    /// against exactly these field names and status codes.
    /// </summary>
    public sealed class VendorEndpointTests : IAsyncLifetime
    {
        private const string Token = "vendor-token-for-tests-only";
        private const string Server = "c5bc6e91458540caa295c4efdda1a58a";

        private TestService _service;
        private WebApplication _app;
        private HttpClient _client;

        public Task InitializeAsync()
        {
            return StartAsync(Token);
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
        }

        private async Task StartAsync(string token)
        {
            if (_app != null)
            {
                await DisposeAsync();
            }

            _service = new TestService(o =>
            {
                o.PayPal.ClientId = null;
                o.PayPal.ClientSecret = null;
                o.VendorToken = token;
            });

            _app = Program.BuildApp(_service.Options, builder => builder.WebHost.UseTestServer());

            await _app.StartAsync();

            _client = _app.GetTestClient();
        }

        [Fact]
        public async Task Without_a_configured_token_the_routes_do_not_exist()
        {
            await StartAsync(null);

            var response = await Send(HttpMethod.Get, "/v1/vendor/licences/a", null, Token);

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("wrong")]
        [InlineData("vendor-token-for-tests-onl")]
        public async Task A_missing_or_wrong_bearer_is_401_with_no_detail(string bearer)
        {
            foreach (var (method, path) in new[]
            {
                (HttpMethod.Get, "/v1/vendor/licences/a"),
                (HttpMethod.Put, "/v1/vendor/licences/a"),
                (HttpMethod.Delete, "/v1/vendor/licences/a/activations/" + Server),
            })
            {
                var response = await Send(method, path, method == HttpMethod.Put ? Body(Hash()) : null, bearer);

                Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync());
            }
        }

        [Fact]
        public async Task Put_creates_then_updates_and_answers_the_get_shape()
        {
            var hash = Hash();

            var created = await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(hash), Token);

            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            Assert.StartsWith("application/json", created.Content.Headers.ContentType.MediaType);

            var json = await Json(created);

            Assert.Equal("order-1", json.GetProperty("ref").GetString());
            Assert.Equal("active", json.GetProperty("status").GetString());
            Assert.Equal(3, json.GetProperty("seats").GetInt32());
            Assert.Equal("2027-10-26T00:00:00Z", json.GetProperty("expiresUtc").GetString());
            Assert.Equal(0, json.GetProperty("activations").GetArrayLength());

            Assert.Equal(HttpStatusCode.OK, (await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(hash), Token)).StatusCode);

            var updated = await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(hash, seats: 5, status: "void", reason: "refunded"), Token);

            Assert.Equal(HttpStatusCode.OK, updated.StatusCode);

            var row = await Json(updated);

            Assert.Equal(5, row.GetProperty("seats").GetInt32());
            Assert.Equal("void", row.GetProperty("status").GetString());
        }

        [Fact]
        public async Task A_different_hash_for_the_same_ref_is_409()
        {
            await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(Hash()), Token);

            var response = await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(Hash()), Token);

            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            Assert.Equal("hash_conflict", (await Json(response)).GetProperty("error").GetString());
        }

        [Theory]
        [InlineData("Bad_Ref", null)]
        [InlineData("order-1", "{not json")]
        [InlineData("order-1", "{\"codeHash\":\"ABC\",\"licensee\":\"x\",\"seats\":3,\"expiresUtc\":\"2027-10-26T00:00:00Z\",\"status\":\"active\"}")]
        [InlineData("order-1", "{\"codeHash\":\"H\",\"licensee\":\"x\",\"seats\":0,\"expiresUtc\":\"2027-10-26T00:00:00Z\",\"status\":\"active\"}")]
        [InlineData("order-1", "{\"codeHash\":\"H\",\"licensee\":\"x\",\"seats\":101,\"expiresUtc\":\"2027-10-26T00:00:00Z\",\"status\":\"active\"}")]
        [InlineData("order-1", "{\"codeHash\":\"H\",\"licensee\":\"x\",\"seats\":3,\"expiresUtc\":\"2027-10-26T00:00:00Z\",\"status\":\"paused\"}")]
        [InlineData("order-1", "{\"codeHash\":\"H\",\"licensee\":\"x\",\"seats\":3,\"status\":\"active\"}")]
        [InlineData("order-1", "{\"codeHash\":\"H\",\"seats\":3,\"expiresUtc\":\"2027-10-26T00:00:00Z\",\"status\":\"active\"}")]
        public async Task Bad_input_is_400(string vendorRef, string body)
        {
            body = body?.Replace("\"H\"", "\"" + Hash() + "\"") ?? Body(Hash());

            var response = await Send(HttpMethod.Put, "/v1/vendor/licences/" + vendorRef, body, Token);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task A_licensee_over_200_characters_is_400()
        {
            var response = await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(Hash(), licensee: new string('a', 201)), Token);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task Get_is_404_for_an_unknown_ref_and_lists_activations_otherwise()
        {
            Assert.Equal(HttpStatusCode.NotFound, (await Send(HttpMethod.Get, "/v1/vendor/licences/nope", null, Token)).StatusCode);

            var code = RedemptionCode.Generate();

            await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(RedemptionCode.Hash(code)), Token);

            _service.ActivateAndSign(
                new ActivationRequest { Code = RedemptionCode.Format(code), ServerId = Server, PluginVersion = "1.4.0" },
                "10.0.0.1");

            var json = await Json(await Send(HttpMethod.Get, "/v1/vendor/licences/order-1", null, Token));
            var activation = json.GetProperty("activations")[0];

            Assert.Equal(Server, activation.GetProperty("serverId").GetString());
            Assert.Equal("1.4.0", activation.GetProperty("pluginVersion").GetString());
            Assert.Equal(JsonValueKind.String, activation.GetProperty("firstSeenUtc").ValueKind);
            Assert.Equal(JsonValueKind.String, activation.GetProperty("lastSeenUtc").ValueKind);
            Assert.Equal(JsonValueKind.Null, activation.GetProperty("releasedUtc").ValueKind);
        }

        [Fact]
        public async Task Delete_releases_idempotently_and_404s_for_unknowns()
        {
            var code = RedemptionCode.Generate();

            await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(RedemptionCode.Hash(code)), Token);

            _service.ActivateAndSign(
                new ActivationRequest { Code = RedemptionCode.Format(code), ServerId = Server, PluginVersion = "1.4.0" },
                "10.0.0.1");

            var path = "/v1/vendor/licences/order-1/activations/" + Server;

            Assert.Equal(HttpStatusCode.NoContent, (await Send(HttpMethod.Delete, path, null, Token)).StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, (await Send(HttpMethod.Delete, path, null, Token)).StatusCode);

            var json = await Json(await Send(HttpMethod.Get, "/v1/vendor/licences/order-1", null, Token));

            Assert.Equal(JsonValueKind.String, json.GetProperty("activations")[0].GetProperty("releasedUtc").ValueKind);

            Assert.Equal(HttpStatusCode.NotFound, (await Send(HttpMethod.Delete, "/v1/vendor/licences/order-1/activations/ffff", null, Token)).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await Send(HttpMethod.Delete, "/v1/vendor/licences/nope/activations/" + Server, null, Token)).StatusCode);
        }

        private static string Hash()
        {
            return RedemptionCode.Hash(RedemptionCode.Generate());
        }

        private static string Body(string hash, int seats = 3, string status = "active", string reason = "", string licensee = "Robin")
        {
            return JsonSerializer.Serialize(new
            {
                codeHash = hash,
                licensee,
                seats,
                expiresUtc = "2027-10-26T00:00:00Z",
                status,
                voidReason = reason,
            });
        }

        private async Task<HttpResponseMessage> Send(HttpMethod method, string path, string body, string bearer)
        {
            var request = new HttpRequestMessage(method, path);

            if (bearer != null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }

            if (body != null)
            {
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }

            return await _client.SendAsync(request);
        }

        private static async Task<JsonElement> Json(HttpResponseMessage response)
        {
            return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
        }
    }
}

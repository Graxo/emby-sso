using System;
using System.Linq;
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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
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

        private async Task StartAsync(string token, Action<WebApplicationBuilder> configure = null)
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

            _app = Program.BuildApp(_service.Options, builder =>
            {
                builder.WebHost.UseTestServer();
                configure?.Invoke(builder);
            });

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
                (HttpMethod.Get, "/v1/vendor/unmanaged"),
                (HttpMethod.Post, "/v1/vendor/licences/a/adopt"),
            })
            {
                var body = method == HttpMethod.Put ? Body(Hash()) : method == HttpMethod.Post ? Adopt(Hash()) : null;
                var response = await Send(method, path, body, bearer);

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
        public async Task A_void_reason_over_500_characters_is_400_naming_the_field()
        {
            var response = await Send(
                HttpMethod.Put,
                "/v1/vendor/licences/order-1",
                Body(Hash(), status: "void", reason: new string('r', 501)),
                Token);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("voidReason", (await Json(response)).GetProperty("field").GetString());

            var atTheLimit = await Send(
                HttpMethod.Put,
                "/v1/vendor/licences/order-2",
                Body(Hash(), status: "void", reason: new string('r', 500)),
                Token);

            Assert.Equal(HttpStatusCode.Created, atTheLimit.StatusCode);
        }

        [Fact]
        public async Task A_refused_token_is_logged_once_as_a_warning_without_the_token()
        {
            var log = new RecordingLogger<object>();

            await StartAsync(Token, builder => builder.Logging.AddProvider(new RecordingProvider(log)));

            await Send(HttpMethod.Get, "/v1/vendor/licences/order-1", null, "wrong-token-value");

            var warnings = log.At(LogLevel.Warning).ToList();

            Assert.Single(warnings);
            Assert.DoesNotContain("wrong-token-value", log.Everything);
            Assert.DoesNotContain(Token, log.Everything);
            Assert.DoesNotContain("order-1", log.Everything);

            // An authorised call adds none.
            await Send(HttpMethod.Get, "/v1/vendor/licences/order-1", null, Token);

            Assert.Single(log.At(LogLevel.Warning));
        }

        private sealed class RecordingProvider : ILoggerProvider
        {
            private readonly RecordingLogger<object> _log;

            public RecordingProvider(RecordingLogger<object> log)
            {
                _log = log;
            }

            public ILogger CreateLogger(string categoryName)
            {
                // Only the vendor API's own category: the host logs plenty of
                // its own at startup and that is not what is being counted.
                return categoryName.EndsWith(".Vendor", StringComparison.Ordinal)
                    ? _log
                    : NullLogger.Instance;
            }

            public void Dispose()
            {
            }
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

        [Fact]
        public async Task Unmanaged_lists_only_codes_without_a_ref_with_activations_void_ones_and_null_expiry()
        {
            Assert.Equal(
                "{\"codes\":[]}",
                await (await Send(HttpMethod.Get, "/v1/vendor/unmanaged", null, Token)).Content.ReadAsStringAsync());

            var activated = RedemptionCode.Generate();
            var store = _service.Store;
            var now = _service.Clock.GetUtcNow();

            store.RecordPayment(
                "evt-1", "tx-1", "PAYMENT.CAPTURE.COMPLETED", "cap-1", "buyer@example.com", "Buyer",
                null, RedemptionCode.Hash(activated), 2, 365, now);

            _service.Clock.Advance(TimeSpan.FromMinutes(1));

            var comp = Hash();
            store.CreateManualCode(comp, "Tester", 1, 30, "comp for a tester", _service.Clock.GetUtcNow());

            _service.Clock.Advance(TimeSpan.FromMinutes(1));

            var voided = Hash();
            store.CreateManualCode(voided, "Leaked", 1, 365, null, _service.Clock.GetUtcNow());
            store.VoidCodeByHash(voided, "leaked", _service.Clock.GetUtcNow());

            // The portal's own code is managed already and must not be offered.
            await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(Hash()), Token);

            _service.ActivateAndSign(
                new ActivationRequest { Code = RedemptionCode.Format(activated), ServerId = Server, PluginVersion = "1.4.0" },
                "10.0.0.1");

            var response = await Send(HttpMethod.Get, "/v1/vendor/unmanaged", null, Token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var codes = (await Json(response)).GetProperty("codes");

            Assert.Equal(3, codes.GetArrayLength());

            var paypal = codes[0];

            Assert.Equal(RedemptionCode.Hash(activated), paypal.GetProperty("codeHash").GetString());
            Assert.Equal("Buyer", paypal.GetProperty("licensee").GetString());
            Assert.Equal("buyer@example.com", paypal.GetProperty("buyerEmail").GetString());
            Assert.Equal(2, paypal.GetProperty("seats").GetInt32());
            Assert.Equal("active", paypal.GetProperty("status").GetString());
            Assert.Equal("paypal", paypal.GetProperty("source").GetString());
            Assert.Equal(LicenceFormat.Iso(now), paypal.GetProperty("createdUtc").GetString());
            Assert.Equal(JsonValueKind.String, paypal.GetProperty("expiresUtc").ValueKind);
            Assert.Equal(365, paypal.GetProperty("licenceDays").GetInt32());

            var activation = paypal.GetProperty("activations")[0];

            Assert.Equal(Server, activation.GetProperty("serverId").GetString());
            Assert.Equal("1.4.0", activation.GetProperty("pluginVersion").GetString());
            Assert.Equal(JsonValueKind.String, activation.GetProperty("firstSeenUtc").ValueKind);
            Assert.Equal(JsonValueKind.String, activation.GetProperty("lastSeenUtc").ValueKind);
            Assert.Equal(JsonValueKind.Null, activation.GetProperty("releasedUtc").ValueKind);

            var manual = codes[1];

            Assert.Equal(comp, manual.GetProperty("codeHash").GetString());
            Assert.Equal("manual", manual.GetProperty("source").GetString());
            Assert.Equal(JsonValueKind.Null, manual.GetProperty("expiresUtc").ValueKind);
            Assert.Equal(30, manual.GetProperty("licenceDays").GetInt32());
            Assert.Equal(0, manual.GetProperty("activations").GetArrayLength());

            // The note `issue-code` keeps in buyer_email is not an address.
            Assert.Equal(JsonValueKind.Null, manual.GetProperty("buyerEmail").ValueKind);
            Assert.Equal("comp for a tester", manual.GetProperty("note").GetString());

            Assert.Equal(voided, codes[2].GetProperty("codeHash").GetString());
            Assert.Equal("void", codes[2].GetProperty("status").GetString());
        }

        [Fact]
        public async Task Adopt_attaches_the_ref_and_changes_nothing_else()
        {
            var hash = Hash();
            _service.Store.CreateManualCode(hash, "Old customer", 2, 365, null, _service.Clock.GetUtcNow());

            var before = _service.Store.FindCodeByHash(hash);
            var response = await Send(HttpMethod.Post, "/v1/vendor/licences/order-7/adopt", Adopt(hash), Token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var json = await Json(response);

            Assert.Equal("order-7", json.GetProperty("ref").GetString());
            Assert.Equal("active", json.GetProperty("status").GetString());
            Assert.Equal(2, json.GetProperty("seats").GetInt32());
            Assert.Equal(JsonValueKind.Null, json.GetProperty("expiresUtc").ValueKind);

            var after = _service.Store.FindCodeByHash(hash);

            Assert.Equal(before.Status, after.Status);
            Assert.Equal(before.Licensee, after.Licensee);
            Assert.Equal(before.ActivationsAllowed, after.ActivationsAllowed);
            Assert.Equal(before.ExpiresUtc, after.ExpiresUtc);
            Assert.Equal(before.LicenceDays, after.LicenceDays);
            Assert.Equal("manual", after.Source);

            var unmanaged = (await Json(await Send(HttpMethod.Get, "/v1/vendor/unmanaged", null, Token))).GetProperty("codes");

            Assert.Equal(0, unmanaged.GetArrayLength());
        }

        [Fact]
        public async Task Adopting_again_with_the_same_ref_is_200()
        {
            var hash = Hash();
            _service.Store.CreateManualCode(hash, "Old customer", 2, 365, null, _service.Clock.GetUtcNow());

            Assert.Equal(HttpStatusCode.OK, (await Send(HttpMethod.Post, "/v1/vendor/licences/order-7/adopt", Adopt(hash), Token)).StatusCode);

            var again = await Send(HttpMethod.Post, "/v1/vendor/licences/order-7/adopt", Adopt(hash), Token);

            Assert.Equal(HttpStatusCode.OK, again.StatusCode);
            Assert.Equal("order-7", (await Json(again)).GetProperty("ref").GetString());
        }

        [Fact]
        public async Task Adopting_a_code_that_has_another_ref_is_409_already_managed()
        {
            var adopted = Hash();
            _service.Store.CreateManualCode(adopted, "Old customer", 2, 365, null, _service.Clock.GetUtcNow());
            await Send(HttpMethod.Post, "/v1/vendor/licences/order-7/adopt", Adopt(adopted), Token);

            var created = Hash();
            await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(created), Token);

            foreach (var hash in new[] { adopted, created })
            {
                var response = await Send(HttpMethod.Post, "/v1/vendor/licences/order-9/adopt", Adopt(hash), Token);

                Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
                Assert.Equal("already_managed", (await Json(response)).GetProperty("error").GetString());
            }

            Assert.Equal(HttpStatusCode.NotFound, (await Send(HttpMethod.Get, "/v1/vendor/licences/order-9", null, Token)).StatusCode);
        }

        [Fact]
        public async Task Adopting_with_a_ref_another_code_has_is_409_ref_in_use()
        {
            await Send(HttpMethod.Put, "/v1/vendor/licences/order-1", Body(Hash()), Token);

            var hash = Hash();
            _service.Store.CreateManualCode(hash, "Old customer", 2, 365, null, _service.Clock.GetUtcNow());

            var response = await Send(HttpMethod.Post, "/v1/vendor/licences/order-1/adopt", Adopt(hash), Token);

            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            Assert.Equal("ref_in_use", (await Json(response)).GetProperty("error").GetString());

            // Still unmanaged.
            var unmanaged = (await Json(await Send(HttpMethod.Get, "/v1/vendor/unmanaged", null, Token))).GetProperty("codes");

            Assert.Equal(hash, unmanaged[0].GetProperty("codeHash").GetString());
        }

        [Fact]
        public async Task Adopting_an_unknown_hash_is_404()
        {
            var response = await Send(HttpMethod.Post, "/v1/vendor/licences/order-7/adopt", Adopt(Hash()), Token);

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("not_found", (await Json(response)).GetProperty("error").GetString());
        }

        [Theory]
        [InlineData("Bad_Ref", null, "ref")]
        [InlineData("order-7", "{not json", "body")]
        [InlineData("order-7", "null", "body")]
        [InlineData("order-7", "{}", "codeHash")]
        [InlineData("order-7", "{\"codeHash\":\"ABC\"}", "codeHash")]
        [InlineData("order-7", "{\"codeHash\":\"0123\"}", "codeHash")]
        public async Task Bad_adopt_input_is_400_naming_the_field(string vendorRef, string body, string field)
        {
            var response = await Send(HttpMethod.Post, "/v1/vendor/licences/" + vendorRef + "/adopt", body ?? Adopt(Hash()), Token);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

            var json = await Json(response);

            Assert.Equal("invalid", json.GetProperty("error").GetString());
            Assert.Equal(field, json.GetProperty("field").GetString());
        }

        [Fact]
        public async Task An_adopted_code_is_managed_by_get_and_put_and_keeps_its_activations()
        {
            var code = RedemptionCode.Generate();
            var hash = RedemptionCode.Hash(code);

            _service.Store.RecordPayment(
                "evt-1", "tx-1", "PAYMENT.CAPTURE.COMPLETED", "cap-1", "buyer@example.com", "Buyer",
                null, hash, 2, 365, _service.Clock.GetUtcNow());

            _service.ActivateAndSign(
                new ActivationRequest { Code = RedemptionCode.Format(code), ServerId = Server, PluginVersion = "1.4.0" },
                "10.0.0.1");

            Assert.Equal(HttpStatusCode.OK, (await Send(HttpMethod.Post, "/v1/vendor/licences/order-7/adopt", Adopt(hash), Token)).StatusCode);

            var got = await Json(await Send(HttpMethod.Get, "/v1/vendor/licences/order-7", null, Token));

            Assert.Equal(2, got.GetProperty("seats").GetInt32());
            Assert.Equal(1, got.GetProperty("activations").GetArrayLength());

            // The update path, not hash_conflict: the code is this ref's now.
            var put = await Send(HttpMethod.Put, "/v1/vendor/licences/order-7", Body(hash, seats: 5, licensee: "Robin"), Token);

            Assert.Equal(HttpStatusCode.OK, put.StatusCode);

            var json = await Json(put);

            Assert.Equal(5, json.GetProperty("seats").GetInt32());
            Assert.Equal("2027-10-26T00:00:00Z", json.GetProperty("expiresUtc").GetString());
            Assert.Equal(Server, json.GetProperty("activations")[0].GetProperty("serverId").GetString());

            var summary = _service.Store.FindCodeByHash(hash);

            Assert.Equal("Robin", summary.Licensee);
            Assert.Equal("paypal", summary.Source);
            Assert.Equal(1, summary.ActivationsUsed);

            // And the seat can be released by ref like any vendor code's.
            Assert.Equal(
                HttpStatusCode.NoContent,
                (await Send(HttpMethod.Delete, "/v1/vendor/licences/order-7/activations/" + Server, null, Token)).StatusCode);
        }

        [Fact]
        public async Task An_adopted_code_that_was_never_activated_answers_a_null_expiry_until_its_first_put()
        {
            var hash = Hash();
            _service.Store.CreateManualCode(hash, "Old customer", 2, 365, null, _service.Clock.GetUtcNow());

            await Send(HttpMethod.Post, "/v1/vendor/licences/order-7/adopt", Adopt(hash), Token);

            var got = await Send(HttpMethod.Get, "/v1/vendor/licences/order-7", null, Token);

            Assert.Equal(HttpStatusCode.OK, got.StatusCode);
            Assert.Equal(JsonValueKind.Null, (await Json(got)).GetProperty("expiresUtc").ValueKind);

            var put = await Send(HttpMethod.Put, "/v1/vendor/licences/order-7", Body(hash), Token);

            Assert.Equal(HttpStatusCode.OK, put.StatusCode);
            Assert.Equal("2027-10-26T00:00:00Z", (await Json(put)).GetProperty("expiresUtc").GetString());
        }

        [Fact]
        public async Task Adopt_logs_one_line_with_the_tag_and_never_the_whole_hash()
        {
            var log = new RecordingLogger<object>();

            await StartAsync(Token, builder => builder.Logging.AddProvider(new RecordingProvider(log)));

            var hash = Hash();
            _service.Store.CreateManualCode(hash, "Old customer", 2, 365, null, _service.Clock.GetUtcNow());

            await Send(HttpMethod.Post, "/v1/vendor/licences/order-7/adopt", Adopt(hash), Token);

            var lines = log.At(LogLevel.Information).ToList();

            Assert.Single(lines);
            Assert.DoesNotContain(hash, log.Everything);
            Assert.Contains(RedemptionCode.LogTag(hash), log.Everything);
            Assert.Contains("Adopted", log.Everything);
        }

        private static string Adopt(string hash)
        {
            return JsonSerializer.Serialize(new { codeHash = hash });
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

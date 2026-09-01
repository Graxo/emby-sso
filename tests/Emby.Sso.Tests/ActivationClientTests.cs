using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// Redeeming a code at the vendor's activation service.
    ///
    /// THE TESTS THAT MATTER ARE THE REFUSALS. The activation service is the
    /// vendor's, but it is not trusted, and it must not be: the licence is a
    /// JWT signed by a key that never leaves the vendor and bound to one Emby
    /// server, and that self-verification is the entire licensing model. A
    /// plugin that stored whatever the service handed it would turn a spoofed
    /// or compromised service - or an operator-supplied service address - into
    /// a complete bypass. So every forgery this file can build is presented in
    /// a 200 answer, and every one of them must come back
    /// <see cref="ActivationOutcome.LicenceRejected"/> with nothing to store.
    ///
    /// The forgeries are the same ones <c>LicenceCheckTests</c> uses, built by
    /// <see cref="LicenceFactory"/> rather than pasted, so they stay valid as
    /// the licence format moves.
    /// </summary>
    public class ActivationClientTests : IDisposable
    {
        private const string Code = "SSOX-7Q2M-VVAB-31KD";
        private const string ServiceBase = "https://licence.test";
        private const string ActivateUrl = "https://licence.test/v1/activate";

        private readonly LicenceFactory _licences = new LicenceFactory();
        private readonly ScriptedService _service = new ScriptedService();

        public void Dispose()
        {
            _licences.Dispose();
            _service.Dispose();
        }

        /// <summary>
        /// Answers from a script and records everything it was asked to send,
        /// so "refused before sending" can be told apart from "sent and then
        /// complained about" - the distinction several tests here turn on.
        /// </summary>
        private sealed class ScriptedService : HttpMessageHandler
        {
            public List<string> Urls { get; } = new List<string>();

            public List<string> Bodies { get; } = new List<string>();

            public List<string> Methods { get; } = new List<string>();

            public List<string> ContentTypes { get; } = new List<string>();

            public HttpResponseMessage Response { get; set; }

            public Exception Throws { get; set; }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Urls.Add(request.RequestUri.ToString());
                Methods.Add(request.Method.Method);
                ContentTypes.Add(request.Content?.Headers?.ContentType?.MediaType);
                Bodies.Add(request.Content == null ? null : await request.Content.ReadAsStringAsync().ConfigureAwait(false));

                if (Throws != null)
                {
                    throw Throws;
                }

                return Response ?? Ok("{}");
            }
        }

        private static HttpResponseMessage Ok(string body)
        {
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
        }

        private static HttpResponseMessage Fails(HttpStatusCode status, string body, string retryAfter = null)
        {
            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };

            if (retryAfter != null)
            {
                response.Headers.TryAddWithoutValidation("Retry-After", retryAfter);
            }

            return response;
        }

        private static HttpResponseMessage Issued(string licence)
        {
            return Ok(new JObject
            {
                ["licence"] = licence,
                ["expiresUtc"] = "2027-08-31T00:00:00Z",
                ["activationsUsed"] = 1,
                ["activationsAllowed"] = 3,
            }.ToString());
        }

        private Task<ActivationResult> ActivateAsync(
            string serviceBase = ServiceBase,
            string code = Code,
            string serverId = LicenceFactory.ServerId,
            string publicKeyJwk = null,
            DateTimeOffset? now = null)
        {
            return ActivationClient.ActivateAsync(
                new HttpClient(_service),
                serviceBase,
                code,
                serverId,
                "1.5.0",
                new[] { publicKeyJwk ?? _licences.PublicKeyJwk },
                now ?? DateTimeOffset.UtcNow,
                CancellationToken.None);
        }

        // ------------------------------------------------------------------
        // The happy path, so the refusals below mean something.
        // ------------------------------------------------------------------

        [Fact]
        public async Task ActivatesOnALicenceThatVerifies()
        {
            var licence = _licences.Issue();
            _service.Response = Issued(licence);

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.Activated, result.Outcome);
            Assert.True(ActivationResult.Succeeded(result));
            Assert.Equal(licence, result.Licence);
            Assert.Equal("2027-08-31T00:00:00Z", result.ExpiresUtc);
            Assert.Equal(1, result.ActivationsUsed);
            Assert.Equal(3, result.ActivationsAllowed);
        }

        [Fact]
        public async Task PostsTheContractRequestToTheContractPath()
        {
            _service.Response = Issued(_licences.Issue());

            await ActivateAsync();

            Assert.Equal(ActivateUrl, Assert.Single(_service.Urls));
            Assert.Equal("POST", Assert.Single(_service.Methods));
            Assert.Equal("application/json", Assert.Single(_service.ContentTypes));

            var body = JObject.Parse(Assert.Single(_service.Bodies));

            Assert.Equal(Code, (string)body["code"]);
            Assert.Equal(LicenceFactory.ServerId, (string)body["serverId"]);
            Assert.Equal("1.5.0", (string)body["pluginVersion"]);
        }

        [Fact]
        public async Task TheCodeNeverAppearsInTheUrl()
        {
            // A query string is written to access logs, proxy logs and Referer
            // headers. The code is a bearer secret and belongs in the body.
            _service.Response = Issued(_licences.Issue());

            await ActivateAsync();

            Assert.DoesNotContain(Code, Assert.Single(_service.Urls));
        }

        // ------------------------------------------------------------------
        // P2. The service is not trusted. Every forgery, in a 200 answer.
        // ------------------------------------------------------------------

        [Fact]
        public async Task RefusesALicenceSignedByAnybodyButTheVendor()
        {
            // The whole attack: stand up a service, answer 200, hand over a
            // perfectly formed licence for this exact server signed with a key
            // you generated yourself.
            _service.Response = Issued(_licences.Issue(signedByAStranger: true));

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.LicenceRejected, result.Outcome);
            Assert.False(ActivationResult.Succeeded(result));
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task RefusesAnUnsignedLicence()
        {
            _service.Response = Issued(LicenceFactory.Unsigned());

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.LicenceRejected, result.Outcome);
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task RefusesTheAlgorithmConfusionForgery()
        {
            // An HS256 token whose HMAC secret is the public key material that
            // ships inside the plugin - which anybody holding the DLL holds.
            _service.Response = Issued(_licences.HmacSignedWithThePublicKey());

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.LicenceRejected, result.Outcome);
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task RefusesALicenceTamperedWithAfterSigning()
        {
            _service.Response = Issued(LicenceFactory.Tamper(_licences.Issue(), "sub", "Somebody Else"));

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.LicenceRejected, result.Outcome);
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task RefusesAGenuineLicenceForADifferentServer()
        {
            // Signed by the real key, entirely valid - for somebody else's
            // Emby server. The server binding is checked here, not just at
            // sign-in, so it cannot be stored and puzzled over later.
            _service.Response = Issued(_licences.Issue(serverId: "a-different-server"));

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.LicenceRejected, result.Outcome);
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task RefusesAnExpiredLicence()
        {
            _service.Response = Issued(_licences.Issue(
                issuedAt: DateTime.UtcNow.AddDays(-400),
                expires: DateTime.UtcNow.AddDays(-1)));

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.LicenceRejected, result.Outcome);
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task RefusesALicenceForTheWrongIssuer()
        {
            _service.Response = Issued(_licences.Issue(issuer: "urn:somebody-else"));

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.LicenceRejected, result.Outcome);
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task RefusesALicenceWhenThisBuildCarriesNoPublicKey()
        {
            // Fail closed: a build that cannot verify anything must not accept
            // anything, exactly as the sign-in check does not.
            _service.Response = Issued(_licences.Issue());

            var result = await ActivateAsync(publicKeyJwk: string.Empty);

            Assert.Equal(ActivationOutcome.LicenceRejected, result.Outcome);
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task RefusalNamesWhatToLookAtWithoutLeakingTheCode()
        {
            _service.Response = Issued(_licences.Issue(signedByAStranger: true));

            var result = await ActivateAsync();

            Assert.Contains("NOTHING WAS SAVED", result.Message);
            Assert.DoesNotContain(Code, result.Message);
            Assert.DoesNotContain(Code, result.LogDetail);
        }

        // ------------------------------------------------------------------
        // Nothing leaves this process unless it can leave it safely.
        // ------------------------------------------------------------------

        [Theory]
        [InlineData("http://licence.test")]
        [InlineData("licence.test")]
        [InlineData("")]
        [InlineData(null)]
        public async Task SendsNothingToAnAddressItRefuses(string serviceBase)
        {
            var result = await ActivateAsync(serviceBase: serviceBase);

            Assert.Equal(ActivationOutcome.NotAttempted, result.Outcome);
            Assert.Empty(_service.Urls);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task SendsNothingWithoutACode(string code)
        {
            var result = await ActivateAsync(code: code);

            Assert.Equal(ActivationOutcome.NotAttempted, result.Outcome);
            Assert.Empty(_service.Urls);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("  ")]
        public async Task SendsNothingWithoutAServerId(string serverId)
        {
            // A licence whose binding cannot be checked is a licence that was
            // not checked, so there is no point asking for one.
            var result = await ActivateAsync(serverId: serverId);

            Assert.Equal(ActivationOutcome.NotAttempted, result.Outcome);
            Assert.Empty(_service.Urls);
        }

        [Fact]
        public async Task ADestinationTheOutboundGuardRefusedIsNotAnUnreachableService()
        {
            // Nothing left this process, and the fix is a setting rather than a
            // network - so the operator is told the rule that fired.
            _service.Throws = new HttpRequestException(
                "wrapped",
                new OutboundRefusedException("that address is inside this server's own network"));

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.NotAttempted, result.Outcome);
            Assert.Contains("inside this server's own network", result.Message);
        }

        // ------------------------------------------------------------------
        // What the service said, when it managed to say anything.
        // ------------------------------------------------------------------

        [Fact]
        public async Task AnUnreachableServiceSaysSoAndSaysSignInsAreFine()
        {
            _service.Throws = new HttpRequestException("no route to host");

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.Unreachable, result.Outcome);
            Assert.Contains("does not affect sign-ins", result.Message);
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task ATimeoutIsAnUnreachableService()
        {
            _service.Throws = new TaskCanceledException("timed out");

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.Unreachable, result.Outcome);
        }

        [Fact]
        public async Task ReportsAnExhaustedCodeAsSomethingToActOn()
        {
            _service.Response = Fails(HttpStatusCode.Conflict, "{\"error\":\"code_exhausted\"}");

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.CodeExhausted, result.Outcome);
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task ReportsAnUnknownCodeAsSomethingElseToActOn()
        {
            _service.Response = Fails(HttpStatusCode.BadRequest, "{\"error\":\"invalid_code\"}");

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.InvalidCode, result.Outcome);
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task ReadsRetryAfterOffARateLimitedAnswer()
        {
            _service.Response = Fails((HttpStatusCode)429, "{\"error\":\"rate_limited\"}", "120");

            var result = await ActivateAsync();

            Assert.Equal(ActivationOutcome.RateLimited, result.Outcome);
            Assert.Contains("2 minutes", result.Message);
        }

        [Fact]
        public async Task ARedirectIsNotAnActivation()
        {
            // The transport does not follow redirects, so a 302 arrives here as
            // itself. It is not 200 and carries no licence: refuse.
            _service.Response = new HttpResponseMessage(HttpStatusCode.Found)
            {
                Content = new StringContent(string.Empty),
            };

            var result = await ActivateAsync();

            Assert.False(ActivationResult.Succeeded(result));
            Assert.Null(result.Licence);
        }

        [Fact]
        public async Task DoesNotReadAnUnboundedBody()
        {
            // A service having a very bad day, or trying something. The cap is
            // what stops it becoming this process's problem.
            var padding = new string('x', ActivationClient.MaxResponseBytes * 2);
            _service.Response = Ok("{\"licence\":\"" + padding + "\"}");

            var result = await ActivateAsync();

            // Truncated to the cap, so it is not valid JSON any more, and in any
            // case would never have verified. Either way: refused, nothing
            // stored.
            Assert.False(ActivationResult.Succeeded(result));
            Assert.Null(result.Licence);
        }

        /// <summary>
        /// The redemption code is a bearer secret and is treated the way the
        /// client secret is: it goes into the request body and nowhere else.
        /// Nothing the page shows and nothing the log records may carry it, on
        /// ANY path - including the ones where the code itself was the problem.
        /// </summary>
        [Fact]
        public async Task NoOutcomeEverCarriesTheCodeIntoAMessageOrALog()
        {
            var answers = new List<Func<HttpResponseMessage>>
            {
                () => Issued(_licences.Issue()),
                () => Issued(_licences.Issue(signedByAStranger: true)),
                () => Issued(_licences.Issue(serverId: "elsewhere")),
                () => Issued(LicenceFactory.Unsigned()),
                () => Ok("{}"),
                () => Ok("not json"),
                () => Fails(HttpStatusCode.BadRequest, "{\"error\":\"invalid_code\"}"),
                () => Fails(HttpStatusCode.Conflict, "{\"error\":\"code_exhausted\"}"),
                () => Fails((HttpStatusCode)429, "{\"error\":\"rate_limited\"}", "60"),
                () => Fails(HttpStatusCode.InternalServerError, "{\"error\":\"server_error\"}"),
                () => Fails(HttpStatusCode.BadGateway, "{\"error\":\"" + Code + "\"}"),
            };

            foreach (var answer in answers)
            {
                using (var service = new ScriptedService { Response = answer() })
                {
                    var result = await ActivationClient.ActivateAsync(
                        new HttpClient(service),
                        ServiceBase,
                        Code,
                        LicenceFactory.ServerId,
                        "1.5.0",
                        new[] { _licences.PublicKeyJwk },
                        DateTimeOffset.UtcNow,
                        CancellationToken.None);

                    Assert.DoesNotContain(Code, result.Message);
                    Assert.DoesNotContain(Code, result.LogDetail ?? string.Empty);
                }
            }

            // And the refusals that never send anything at all.
            foreach (var serviceBase in new[] { "http://licence.test", "not-a-url" })
            {
                var result = await ActivateAsync(serviceBase: serviceBase);

                Assert.DoesNotContain(Code, result.Message);
                Assert.DoesNotContain(Code, result.LogDetail ?? string.Empty);
            }
        }
    }
}

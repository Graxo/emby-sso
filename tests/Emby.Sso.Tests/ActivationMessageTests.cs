using Emby.Sso.Protocol;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The wire format from <c>contract.md</c>, both directions: what this
    /// plugin sends, and what it makes of every answer the contract allows.
    ///
    /// The error mapping is tested one code at a time because the whole point
    /// of it is that an administrator can tell an unknown code from an
    /// exhausted one - those need different actions from them, and a single
    /// "activation failed" would hide the difference.
    /// </summary>
    public class ActivationMessageTests
    {
        private const string Code = "AAAA-BBBB-CCCC-DDDD";

        private static ActivationResult Read(int status, string body, string retryAfter = null)
        {
            return ActivationMessage.ReadResponse(status, body, retryAfter, out _, out _, out _, out _);
        }

        [Fact]
        public void TheRequestCarriesTheThreeFieldsTheContractNames()
        {
            var body = JObject.Parse(ActivationMessage.BuildRequest(Code, "server-1", "1.5.0"));

            Assert.Equal(Code, (string)body["code"]);
            Assert.Equal("server-1", (string)body["serverId"]);
            Assert.Equal("1.5.0", (string)body["pluginVersion"]);
        }

        [Fact]
        public void TheCodeIsSentAsTypedApartFromSurroundingSpace()
        {
            // The contract makes the SERVICE responsible for case and
            // separators. Normalising here would be a second implementation of
            // a rule that already has one owner, and the two would drift.
            var body = JObject.Parse(ActivationMessage.BuildRequest("  aaaa bbbb  ", "server-1", "1.0.0"));

            Assert.Equal("aaaa bbbb", (string)body["code"]);
        }

        [Fact]
        public void AnAbsentVersionIsStatedRatherThanOmitted()
        {
            var body = JObject.Parse(ActivationMessage.BuildRequest(Code, "server-1", null));

            Assert.Equal("unknown", (string)body["pluginVersion"]);
        }

        [Fact]
        public void ReadsALicenceOutOfASuccessfulAnswer()
        {
            var refusal = ActivationMessage.ReadResponse(
                200,
                "{\"licence\":\"a.b.c\",\"expiresUtc\":\"2027-08-31T00:00:00Z\",\"activationsUsed\":1,\"activationsAllowed\":3}",
                null,
                out var licence,
                out var expiresUtc,
                out var used,
                out var allowed);

            // Null, not a success: this method deliberately cannot decide an
            // activation succeeded. Only ActivationClient can, and only after
            // it has verified the licence.
            Assert.Null(refusal);
            Assert.Equal("a.b.c", licence);
            Assert.Equal("2027-08-31T00:00:00Z", expiresUtc);
            Assert.Equal(1, used);
            Assert.Equal(3, allowed);
        }

        [Fact]
        public void ASuccessWithNoLicenceIsARefusal()
        {
            var result = ActivationMessage.ReadResponse(200, "{\"expiresUtc\":\"2027-08-31T00:00:00Z\"}", null, out var licence, out _, out _, out _);

            Assert.Equal(ActivationOutcome.UnreadableResponse, result.Outcome);
            Assert.Null(licence);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("not json at all")]
        [InlineData("[\"an array\"]")]
        [InlineData(null)]
        public void ASuccessThatIsNotAnActivationResponseIsARefusal(string body)
        {
            var result = Read(200, body);

            Assert.Equal(ActivationOutcome.UnreadableResponse, result.Outcome);
        }

        [Fact]
        public void ASuccessWithABlankLicenceIsARefusal()
        {
            var result = ActivationMessage.ReadResponse(200, "{\"licence\":\"   \"}", null, out var licence, out _, out _, out _);

            Assert.Equal(ActivationOutcome.UnreadableResponse, result.Outcome);
            Assert.Null(licence);
        }

        [Fact]
        public void CountsItCannotReadDoNotSinkAnOtherwiseGoodAnswer()
        {
            // They are display only. The licence's own claims are what is
            // enforced.
            var refusal = ActivationMessage.ReadResponse(
                200,
                "{\"licence\":\"a.b.c\",\"activationsUsed\":\"lots\",\"activationsAllowed\":null}",
                null,
                out var licence,
                out _,
                out var used,
                out var allowed);

            Assert.Null(refusal);
            Assert.Equal("a.b.c", licence);
            Assert.Null(used);
            Assert.Null(allowed);
        }

        // The expected outcome is named as a string because xunit theory
        // methods must be public and ActivationOutcome is internal.
        [Theory]
        [InlineData(400, "invalid_code", "InvalidCode")]
        [InlineData(409, "code_exhausted", "CodeExhausted")]
        [InlineData(400, "malformed_request", "MalformedRequest")]
        [InlineData(429, "rate_limited", "RateLimited")]
        [InlineData(500, "server_error", "ServiceError")]
        public void MapsEveryErrorCodeTheContractDefines(int status, string code, string expected)
        {
            var result = Read(status, "{\"error\":\"" + code + "\",\"message\":\"whatever\"}");

            Assert.Equal(expected, result.Outcome.ToString());
            Assert.False(string.IsNullOrWhiteSpace(result.Message));
        }

        [Fact]
        public void AnUnknownCodeAndAnExhaustedOneReadDifferently()
        {
            // The one distinction this mapping exists for: they need different
            // actions from the administrator.
            var unknown = Read(400, "{\"error\":\"invalid_code\"}");
            var exhausted = Read(409, "{\"error\":\"code_exhausted\"}");

            Assert.NotEqual(unknown.Message, exhausted.Message);
        }

        [Theory]
        [InlineData("{\"error\":\"teapot\"}")]
        [InlineData("{\"message\":\"no code at all\"}")]
        [InlineData("not json")]
        [InlineData("")]
        public void AnErrorThisBuildDoesNotKnowIsStillARefusal(string body)
        {
            var result = Read(503, body);

            Assert.NotEqual(ActivationOutcome.Activated, result.Outcome);
            Assert.False(ActivationResult.Succeeded(result));
        }

        [Fact]
        public void ANumericRetryAfterBecomesAdvice()
        {
            var result = Read(429, "{\"error\":\"rate_limited\"}", "300");

            Assert.Equal(ActivationOutcome.RateLimited, result.Outcome);
            Assert.Contains("5 minutes", result.Message);
        }

        [Theory]
        [InlineData("Wed, 21 Oct 2026 07:28:00 GMT")]
        [InlineData("nonsense")]
        [InlineData("-1")]
        [InlineData(null)]
        public void ARetryAfterThisBuildCannotReadIsLeftOutRatherThanGuessedAt(string retryAfter)
        {
            var result = Read(429, "{\"error\":\"rate_limited\"}", retryAfter);

            Assert.Equal(ActivationOutcome.RateLimited, result.Outcome);
            Assert.Contains("Wait a few minutes", result.Message);
        }

        [Fact]
        public void AServiceSuppliedErrorCodeCannotForgeLogLines()
        {
            var result = Read(400, "{\"error\":\"invalid_code\\nFATAL: everything is fine\"}");

            Assert.DoesNotContain("\n", result.LogDetail);
            Assert.DoesNotContain("\r", result.LogDetail);
        }
    }
}

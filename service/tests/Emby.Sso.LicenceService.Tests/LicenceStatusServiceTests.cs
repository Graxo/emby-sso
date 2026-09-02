using System;
using System.Linq;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.RateLimiting;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The daily "is this licence still good?" endpoint.
    ///
    /// Two properties matter. The answer must be SIGNED and bound to one server
    /// and one licence, or anyone between a customer and this service could
    /// switch off their plugin. And a licence this service does not recognise
    /// must answer "unknown" rather than "revoked" - a restored backup looks
    /// exactly like a stranger, and disabling a paying customer over that would
    /// be far worse than failing to disable a refunded one.
    /// </summary>
    public class LicenceStatusServiceTests : IDisposable
    {
        private const string ServerA = "c5bc6e91458540caa295c4efdda1a58a";

        private readonly TestService _service = new TestService();

        public void Dispose()
        {
            _service.Dispose();

            GC.SuppressFinalize(this);
        }

        [Fact]
        public async Task An_active_licence_is_answered_valid_and_signed()
        {
            var fingerprint = await ActivatedLicence();
            var reply = Statuses().Check(Ask(fingerprint), "10.0.0.1");

            Assert.True(reply.IsAnswered);
            Assert.Equal(200, reply.StatusCode);
            Assert.Equal(LicenceStatusToken.Valid, StatusOf(reply.Token));

            // Bound to this server and this licence, so it cannot be replayed
            // at another server or about another licence.
            var claims = Claims(reply.Token);

            Assert.Equal(LicenceStatusToken.Issuer, claims.Issuer);
            Assert.Equal(fingerprint, claims.Subject);
            Assert.Contains(ServerA, claims.Audiences);
        }

        [Fact]
        public async Task A_voided_code_is_answered_revoked()
        {
            var code = _service.GiveOutACode();
            var fingerprint = await ActivatedLicence(code);

            _service.Store.VoidCodeByHash(RedemptionCode.Hash(Normalise(code)), "refunded", _service.Clock.GetUtcNow());

            Assert.Equal(LicenceStatusToken.Revoked, StatusOf(Statuses().Check(Ask(fingerprint), "10.0.0.1").Token));
        }

        [Fact]
        public void A_licence_this_service_never_issued_is_unknown_and_not_revoked()
        {
            // A restored backup, or a store rebuilt without this activation in
            // it, is indistinguishable from a stranger. Answering "revoked"
            // would disable a paying customer over a bookkeeping accident.
            var fingerprint = "sha256:" + new string('a', 64);

            Assert.Equal(LicenceStatusToken.Unknown, StatusOf(Statuses().Check(Ask(fingerprint), "10.0.0.1").Token));
        }

        [Theory]
        [InlineData(null, "sha256:aaaa")]
        [InlineData("", "sha256:aaaa")]
        [InlineData(ServerA, null)]
        [InlineData(ServerA, "")]
        [InlineData(ServerA, "not-a-fingerprint")]
        [InlineData(ServerA, "sha256:tooshort")]
        [InlineData("not a server id!", "sha256:aaaa")]
        public void A_malformed_question_gets_no_answer(string serverId, string fingerprint)
        {
            var reply = Statuses().Check(
                new LicenceStatusRequest { ServerId = serverId, Fingerprint = fingerprint },
                "10.0.0.1");

            Assert.False(reply.IsAnswered);
            Assert.Equal(400, reply.StatusCode);
        }

        [Fact]
        public void With_no_signing_key_it_says_it_cannot_answer_rather_than_answering_unsigned()
        {
            // A deployment that signs offline has no key here, so it cannot
            // produce a signed answer. An unsigned one would be worse than
            // none: the plugin refuses it anyway, and the service would have
            // published something that looks like an answer.
            var statuses = new LicenceStatusService(
                _service.Store,
                _service.Limiter,
                null,
                _service.Clock,
                NullLogger<LicenceStatusService>.Instance);

            Assert.False(statuses.CanAnswer);

            var reply = statuses.Check(Ask("sha256:" + new string('a', 64)), "10.0.0.1");

            Assert.False(reply.IsAnswered);
            Assert.Equal(501, reply.StatusCode);
            Assert.Null(reply.Token);
        }

        [Fact]
        public void The_rate_limiter_is_spent_before_anything_is_looked_up()
        {
            using var service = new TestService(options =>
            {
                options.RateLimit.PerClientBurst = 1;
                options.RateLimit.PerClientPerMinute = 1;
            });

            var statuses = new LicenceStatusService(
                service.Store,
                service.Limiter,
                service.Key.Key,
                service.Clock,
                NullLogger<LicenceStatusService>.Instance);

            var question = Ask("sha256:" + new string('a', 64));

            Assert.True(statuses.Check(question, "1.2.3.4").IsAnswered);

            var refused = statuses.Check(question, "1.2.3.4");

            Assert.False(refused.IsAnswered);
            Assert.Equal(429, refused.StatusCode);
        }

        [Fact]
        public async Task The_answer_is_about_the_licence_that_was_asked_about()
        {
            // Two licences from one code, on two servers. An answer about one
            // must not carry the other's fingerprint.
            var code = _service.GiveOutACode();
            var first = await ActivatedLicence(code, ServerA);
            var second = await ActivatedLicence(code, "0b3d0f8fd4d9412e9c4e5ba0d09a3f77");

            Assert.NotEqual(first, second);
            Assert.Equal(first, Claims(Statuses().Check(Ask(first), "10.0.0.1").Token).Subject);
            Assert.Equal(second, Claims(Statuses().Check(Ask(second, "0b3d0f8fd4d9412e9c4e5ba0d09a3f77"), "10.0.0.1").Token).Subject);
        }

        private LicenceStatusService Statuses()
        {
            return new LicenceStatusService(
                _service.Store,
                _service.Limiter,
                _service.Key.Key,
                _service.Clock,
                NullLogger<LicenceStatusService>.Instance);
        }

        private static LicenceStatusRequest Ask(string fingerprint, string serverId = ServerA)
        {
            return new LicenceStatusRequest { ServerId = serverId, Fingerprint = fingerprint };
        }

        private async Task<string> ActivatedLicence(string code = null, string serverId = ServerA)
        {
            code ??= _service.GiveOutACode();

            var reply = _service.ActivateAndSign(
                new ActivationRequest { Code = code, ServerId = serverId, PluginVersion = "1.4.0" },
                "10.0.0.1");

            Assert.True(reply.IsSuccess);

            await Task.CompletedTask;

            return LicenceFormat.Fingerprint(reply.Licence);
        }

        private static string Normalise(string code)
        {
            Assert.True(RedemptionCode.TryNormalise(code, out var normalised));

            return normalised;
        }

        private static string StatusOf(string token)
        {
            return Claims(token).Claims.First(c => c.Type == LicenceStatusToken.StatusClaim).Value;
        }

        private static Microsoft.IdentityModel.JsonWebTokens.JsonWebToken Claims(string token)
        {
            Assert.False(string.IsNullOrEmpty(token));

            return new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(token);
        }
    }
}

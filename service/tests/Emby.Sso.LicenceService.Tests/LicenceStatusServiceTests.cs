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

        [Fact]
        public async Task An_unchanged_expiry_hands_back_no_licence()
        {
            var fingerprint = await ActivatedLicence();
            var reply = Statuses().Check(Ask(fingerprint), "10.0.0.1");

            Assert.Equal(LicenceStatusToken.Valid, StatusOf(reply.Token));
            Assert.Null(reply.Licence);
        }

        [Fact]
        public async Task A_vendor_code_extended_after_activation_hands_back_a_licence_to_the_new_expiry()
        {
            // The renewal case: the portal moved paid-until a year on, and the
            // licence on the server still says the old date.
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = await HeldLicence(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));
            _service.Clock.Advance(TimeSpan.FromDays(30));

            var reply = Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1");

            Assert.Equal(LicenceStatusToken.Valid, StatusOf(reply.Token));

            // The status token is still about the licence that was asked about,
            // not the one being handed back.
            Assert.Equal(LicenceFormat.Fingerprint(held), Claims(reply.Token).Subject);

            await AssertRenewed(reply.Licence, held, PaidUntil.AddYears(1));
        }

        [Fact]
        public async Task The_renewed_licence_answers_valid_without_another_licence()
        {
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = await HeldLicence(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));

            var renewed = Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1").Licence;

            Assert.NotNull(renewed);

            var reply = Statuses().Check(Ask(LicenceFormat.Fingerprint(renewed)), "10.0.0.1");

            Assert.Equal(LicenceStatusToken.Valid, StatusOf(reply.Token));
            Assert.Equal(LicenceFormat.Fingerprint(renewed), Claims(reply.Token).Subject);
            Assert.Null(reply.Licence);
        }

        [Fact]
        public async Task The_old_licence_is_renewed_again_when_the_server_did_not_keep_the_new_one()
        {
            // A plugin that crashed before saving what it was handed asks with
            // the old fingerprint again tomorrow. That must still be recognised
            // and still renew, or the customer is stuck on the old date.
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = await HeldLicence(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));

            Assert.NotNull(Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1").Licence);

            _service.Clock.Advance(TimeSpan.FromDays(1));

            var again = Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1");

            Assert.Equal(LicenceStatusToken.Valid, StatusOf(again.Token));
            await AssertRenewed(again.Licence, held, PaidUntil.AddYears(1));
        }

        [Fact]
        public async Task The_same_licence_renewed_twice_in_one_second_is_handed_back_both_times()
        {
            // RS256 PKCS#1 v1.5 is deterministic: the same claims in the same
            // second are the same licence, with the same fingerprint, which is
            // the renewed_licences primary key. Two status checks with the old
            // fingerprint in one second (a retry, two servers behind one
            // activation) must not turn the second into a failed renewal.
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = await HeldLicence(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));

            var first = Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1").Licence;
            var second = Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1").Licence;

            Assert.NotNull(first);
            Assert.Equal(first, second);
            await AssertRenewed(second, held, PaidUntil.AddYears(1));
        }

        [Fact]
        public async Task A_licence_renewed_twice_keeps_every_step_recognised()
        {
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = await HeldLicence(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));

            var second = Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1").Licence;

            Extend("ref-1", hash, PaidUntil.AddYears(2));

            var reply = Statuses().Check(Ask(LicenceFormat.Fingerprint(second)), "10.0.0.1");

            Assert.Equal(LicenceStatusToken.Valid, StatusOf(reply.Token));
            await AssertRenewed(reply.Licence, held, PaidUntil.AddYears(2));
        }

        [Fact]
        public async Task A_voided_code_is_revoked_and_hands_back_no_licence_even_when_extended()
        {
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = await HeldLicence(code);

            _service.Store.UpsertVendorCode(
                "ref-1", hash, "test", 3, PaidUntil.AddYears(1), true, "refunded", _service.Clock.GetUtcNow());

            var reply = Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1");

            Assert.Equal(LicenceStatusToken.Revoked, StatusOf(reply.Token));
            Assert.Null(reply.Licence);
        }

        [Fact]
        public async Task A_released_activation_is_revoked_and_hands_back_no_licence_even_when_extended()
        {
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = await HeldLicence(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));

            var renewed = Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1").Licence;

            _service.Store.ReleaseVendorActivation("ref-1", ServerA, _service.Clock.GetUtcNow());
            Extend("ref-1", hash, PaidUntil.AddYears(2));

            // Both the original and the renewed licence belong to the released
            // activation, and both must stop.
            foreach (var licence in new[] { held, renewed })
            {
                var reply = Statuses().Check(Ask(LicenceFormat.Fingerprint(licence)), "10.0.0.1");

                Assert.Equal(LicenceStatusToken.Revoked, StatusOf(reply.Token));
                Assert.Null(reply.Licence);
            }
        }

        [Fact]
        public async Task A_reopened_activation_still_handed_its_original_licence_is_renewed_to_the_code_expiry()
        {
            // Without a signing key (the offline-signing service here),
            // re-activating a released server hands back the licence signed for
            // its first activation, with that activation's expiry, because
            // nothing on the activation path can sign a longer one. The status
            // check is what brings it up to date. A self-signing service renews
            // on the activation itself: see ReactivationRenewalTests.
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = await HeldLicence(code);

            _service.Store.ReleaseVendorActivation("ref-1", ServerA, _service.Clock.GetUtcNow());
            Extend("ref-1", hash, PaidUntil.AddYears(1));

            var reopened = _service.Activations.Activate(
                new ActivationRequest { Code = code, ServerId = ServerA, PluginVersion = "1.4.0" },
                "10.0.0.1");

            Assert.True(reopened.IsSuccess);
            Assert.Equal(held, reopened.Licence);

            var reply = Statuses().Check(Ask(LicenceFormat.Fingerprint(reopened.Licence)), "10.0.0.1");

            Assert.Equal(LicenceStatusToken.Valid, StatusOf(reply.Token));
            await AssertRenewed(reply.Licence, held, PaidUntil.AddYears(1));
        }

        [Fact]
        public async Task Any_active_code_whose_expiry_moved_is_renewed_not_only_vendor_codes()
        {
            var code = _service.GiveOutACode();
            var held = await HeldLicence(code);
            var moved = _service.Clock.GetUtcNow().AddDays(365 + 90);

            // There is no command that moves a manual code's expiry; an operator
            // doing it by hand in the database is exactly the case this covers.
            using (var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + _service.Options.DatabasePath))
            {
                connection.Open();

                using var command = connection.CreateCommand();

                command.CommandText = "UPDATE codes SET expires_utc = $e WHERE code_hash = $h;";
                command.Parameters.AddWithValue("$e", LicenceFormat.Iso(moved));
                command.Parameters.AddWithValue("$h", RedemptionCode.Hash(Normalise(code)));

                Assert.Equal(1, command.ExecuteNonQuery());
            }

            var reply = Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1");

            await AssertRenewed(reply.Licence, held, moved);
        }

        [Fact]
        public async Task A_question_from_a_different_server_gets_its_answer_but_no_licence()
        {
            // The renewed licence is for the server the activation was made
            // for. Knowing a fingerprint must not be a way to obtain a licence
            // on the caller's say-so about which server it is.
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = await HeldLicence(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));

            var reply = Statuses().Check(
                Ask(LicenceFormat.Fingerprint(held), "0b3d0f8fd4d9412e9c4e5ba0d09a3f77"),
                "10.0.0.1");

            Assert.True(reply.IsAnswered);
            Assert.Null(reply.Licence);
        }

        private static readonly DateTimeOffset PaidUntil = new DateTimeOffset(2027, 3, 1, 0, 0, 0, TimeSpan.Zero);

        private string VendorCode(string vendorRef, DateTimeOffset expires, out string code)
        {
            var raw = RedemptionCode.Generate();
            var hash = RedemptionCode.Hash(raw);

            _service.Store.UpsertVendorCode(vendorRef, hash, "test", 3, expires, false, null, _service.Clock.GetUtcNow());

            code = RedemptionCode.Format(raw);

            return hash;
        }

        private void Extend(string vendorRef, string hash, DateTimeOffset expires)
        {
            _service.Store.UpsertVendorCode(vendorRef, hash, "test", 3, expires, false, null, _service.Clock.GetUtcNow());
        }

        private async Task<string> HeldLicence(string code, string serverId = ServerA)
        {
            var reply = _service.ActivateAndSign(
                new ActivationRequest { Code = code, ServerId = serverId, PluginVersion = "1.4.0" },
                "10.0.0.1");

            Assert.True(reply.IsSuccess);

            await Task.CompletedTask;

            return reply.Licence;
        }

        /// <summary>
        /// The licence handed back is a real one: signed by the service's key,
        /// for the same licensee and server as the one it replaces, issued now
        /// and expiring exactly at the code's expiry.
        /// </summary>
        private async Task AssertRenewed(string renewed, string held, DateTimeOffset expires)
        {
            Assert.False(string.IsNullOrEmpty(renewed));
            Assert.NotEqual(held, renewed);

            var verdict = await LicenceVerifier.VerifyAsync(
                renewed,
                Configuration.TrustedKeys.Parse(_service.Key.PublicJwk).Keys,
                new SigningRequest
                {
                    Licensee = Claims(held).Subject,
                    ServerId = ServerA,
                    IssuedAt = LicenceFormat.Iso(_service.Clock.GetUtcNow()),
                    Expires = LicenceFormat.Iso(expires),
                });

            Assert.True(verdict.IsValid, verdict.Problem);
            Assert.Contains(ServerA, Claims(renewed).Audiences);
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

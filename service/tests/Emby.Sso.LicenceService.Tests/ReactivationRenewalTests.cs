using System;
using System.Linq;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// A repeat activation hands a licence to a server just as the daily status
    /// check does, so it must never hand back one that runs out before the code
    /// it was activated with. The licence signed at first activation keeps its
    /// first expiry for ever; once the code has been renewed, a server that
    /// re-activates (reinstalled, re-opened after a release, or a 1.0.x plugin
    /// that cannot take a renewal from the status check) needs a new one.
    ///
    /// And a code that has run out is refused before it costs anything: no seat,
    /// no signing request, no licence that is dead on arrival.
    /// </summary>
    public class ReactivationRenewalTests : IDisposable
    {
        private const string ServerA = "c5bc6e91458540caa295c4efdda1a58a";
        private const string ServerB = "0b3d0f8fd4d9412e9c4e5ba0d09a3f77";

        private static readonly DateTimeOffset PaidUntil = new DateTimeOffset(2027, 3, 1, 0, 0, 0, TimeSpan.Zero);

        private readonly TestService _service = new TestService();

        public void Dispose()
        {
            _service.Dispose();

            GC.SuppressFinalize(this);
        }

        [Fact]
        public async Task A_repeat_activation_after_the_code_was_extended_hands_back_a_licence_to_the_new_expiry()
        {
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = Activated(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));
            _service.Clock.Advance(TimeSpan.FromDays(30));

            var reply = _service.SelfSigningActivations().Activate(Request(code), "10.0.0.1");

            Assert.True(reply.IsSuccess);
            await AssertLicence(reply.Licence, held, PaidUntil.AddYears(1));
            Assert.Equal(PaidUntil.AddYears(1), reply.ExpiresUtc);

            // Recorded like a status-check renewal: the status check knows it,
            // answers valid, and has nothing further to hand back.
            var status = Statuses().Check(Ask(LicenceFormat.Fingerprint(reply.Licence)), "10.0.0.1");

            Assert.Equal(LicenceStatusToken.Valid, StatusOf(status.Token));
            Assert.Null(status.Licence);
            Assert.Equal(LicenceFormat.Fingerprint(reply.Licence), Activation(hash, ServerA).LastFingerprint);
        }

        [Fact]
        public async Task A_repeat_activation_after_the_first_licence_expired_is_licensed_to_the_code_expiry()
        {
            // The lock-out: the first licence has run out, the code was paid
            // for again. Before the fix the expired first licence came back and
            // the plugin refused to store it.
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = Activated(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));
            _service.Clock.Set(PaidUntil.AddDays(10));

            var reply = _service.SelfSigningActivations().Activate(Request(code), "10.0.0.1");

            Assert.True(reply.IsSuccess);
            await AssertLicence(reply.Licence, held, PaidUntil.AddYears(1));
        }

        [Fact]
        public async Task A_server_reopened_after_release_and_extension_is_licensed_to_the_code_expiry()
        {
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = Activated(code);

            _service.Store.ReleaseVendorActivation("ref-1", ServerA, _service.Clock.GetUtcNow());
            Extend("ref-1", hash, PaidUntil.AddYears(1));
            _service.Clock.Set(PaidUntil.AddDays(10));

            var reply = _service.SelfSigningActivations().Activate(Request(code), "10.0.0.1");

            Assert.True(reply.IsSuccess);
            Assert.Equal(1, reply.ActivationsUsed);
            await AssertLicence(reply.Licence, held, PaidUntil.AddYears(1));

            var fingerprint = LicenceFormat.Fingerprint(reply.Licence);

            Assert.Equal(LicenceStatusToken.Valid, StatusOf(Statuses().Check(Ask(fingerprint), "10.0.0.1").Token));

            // Releasing again revokes the licence the re-activation handed out.
            _service.Store.ReleaseVendorActivation("ref-1", ServerA, _service.Clock.GetUtcNow());

            Assert.Equal(LicenceStatusToken.Revoked, StatusOf(Statuses().Check(Ask(fingerprint), "10.0.0.1").Token));
        }

        [Fact]
        public async Task Re_activating_a_server_that_holds_a_renewed_licence_never_hands_back_a_shorter_one()
        {
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = Activated(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));

            var renewed = Statuses().Check(Ask(LicenceFormat.Fingerprint(held)), "10.0.0.1").Licence;

            Assert.NotNull(renewed);

            _service.Clock.Advance(TimeSpan.FromDays(1));

            var reply = _service.SelfSigningActivations().Activate(Request(code), "10.0.0.1");

            Assert.True(reply.IsSuccess);
            Assert.True(Claims(reply.Licence).ValidTo >= Claims(renewed).ValidTo);
            await AssertLicence(reply.Licence, held, PaidUntil.AddYears(1));
        }

        [Fact]
        public void A_repeat_activation_of_an_unchanged_code_hands_back_the_licence_it_already_has()
        {
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = Activated(code);

            _service.Clock.Advance(TimeSpan.FromDays(30));

            var reply = _service.SelfSigningActivations().Activate(Request(code), "10.0.0.1");

            Assert.True(reply.IsSuccess);
            Assert.Equal(held, reply.Licence);
            Assert.Equal(LicenceFormat.Fingerprint(held), Activation(hash, ServerA).LastFingerprint);
        }

        [Fact]
        public void Without_a_signing_key_a_repeat_activation_hands_back_what_was_signed_and_says_so()
        {
            // An offline-signing deployment has nothing that can sign a longer
            // licence here - the status check cannot renew either (501). It
            // hands back the licence that was signed, reports that licence's
            // own expiry rather than the code's, and logs a warning.
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = Activated(code);

            Extend("ref-1", hash, PaidUntil.AddYears(1));

            var log = new RecordingLogger<ActivationService>();
            var offline = new ActivationService(
                _service.Store,
                _service.Limiter,
                _service.Options,
                _service.Clock,
                log);

            var reply = offline.Activate(Request(code), "10.0.0.1");

            Assert.True(reply.IsSuccess);
            Assert.Equal(held, reply.Licence);
            Assert.Equal(PaidUntil, reply.ExpiresUtc);
            Assert.Contains(log.At(LogLevel.Warning), l => l.Rendered.Contains("no signing key", StringComparison.Ordinal));
        }

        [Fact]
        public void A_lapsed_code_is_refused_on_a_new_server_without_taking_a_seat()
        {
            var hash = VendorCode("ref-1", PaidUntil, out var code);

            _service.Clock.Set(PaidUntil.AddDays(1));

            var reply = _service.SelfSigningActivations().Activate(Request(code), "10.0.0.1");

            Assert.False(reply.IsSuccess);
            Assert.Equal(ActivationError.InvalidCode, reply.Error);
            Assert.Empty(_service.Store.ActivationsFor(_service.Store.FindCode(hash).Id));
            Assert.Equal(0, _service.Store.CountWaitingToBeSigned());
        }

        [Fact]
        public void A_code_expiring_this_instant_is_refused()
        {
            VendorCode("ref-1", PaidUntil, out var code);

            _service.Clock.Set(PaidUntil);

            var reply = _service.Activations.Activate(Request(code), "10.0.0.1");

            Assert.Equal(ActivationError.InvalidCode, reply.Error);
        }

        [Fact]
        public void A_lapsed_code_is_refused_for_a_server_already_activated_and_its_seat_is_unchanged()
        {
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = Activated(code);

            _service.Clock.Set(PaidUntil.AddDays(1));

            var before = Activation(hash, ServerA);
            var reply = _service.SelfSigningActivations().Activate(Request(code), "10.0.0.1");

            Assert.Equal(ActivationError.InvalidCode, reply.Error);

            var after = Activation(hash, ServerA);

            Assert.Equal(before.IssueCount, after.IssueCount);
            Assert.Equal(LicenceFormat.Fingerprint(held), after.LastFingerprint);
            Assert.Single(_service.Store.ActivationsFor(_service.Store.FindCode(hash).Id));
        }

        [Fact]
        public void A_shop_code_past_its_licence_days_is_refused_on_another_server()
        {
            var code = _service.GiveOutACode(licenceDays: 365);

            Activated(code);
            _service.Clock.Advance(TimeSpan.FromDays(366));

            var reply = _service.Activations.Activate(Request(code, ServerB), "10.0.0.1");

            Assert.Equal(ActivationError.InvalidCode, reply.Error);
            Assert.Equal(0, _service.Store.CountWaitingToBeSigned());
        }

        [Fact]
        public async Task A_lapsed_code_that_is_paid_again_licenses_the_server_to_the_new_expiry()
        {
            // I1 and C1 together: the grace period ran out, the customer tried
            // (refused, nothing spent), paid, and tried again.
            var hash = VendorCode("ref-1", PaidUntil, out var code);
            var held = Activated(code);

            _service.Clock.Set(PaidUntil.AddDays(20));

            Assert.Equal(ActivationError.InvalidCode, _service.SelfSigningActivations().Activate(Request(code), "10.0.0.1").Error);

            Extend("ref-1", hash, PaidUntil.AddYears(1));

            var reply = _service.SelfSigningActivations().Activate(Request(code), "10.0.0.1");

            Assert.True(reply.IsSuccess);
            await AssertLicence(reply.Licence, held, PaidUntil.AddYears(1));
        }

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

        /// <summary>First activation, signed: the licence the server holds from then on.</summary>
        private string Activated(string code, string serverId = ServerA)
        {
            var reply = _service.ActivateAndSign(Request(code, serverId), "10.0.0.1");

            Assert.True(reply.IsSuccess);

            return reply.Licence;
        }

        private Storage.ActivationRow Activation(string hash, string serverId)
        {
            return _service.Store.ActivationsFor(_service.Store.FindCode(hash).Id)
                .Single(a => string.Equals(a.ServerId, serverId, StringComparison.Ordinal));
        }

        /// <summary>
        /// A real licence: signed by the service's key, for the same licensee and
        /// server as the first one, expiring exactly at <paramref name="expires"/>.
        /// </summary>
        private async Task AssertLicence(string licence, string first, DateTimeOffset expires)
        {
            Assert.False(string.IsNullOrEmpty(licence));
            Assert.NotEqual(first, licence);

            var verdict = await LicenceVerifier.VerifyAsync(
                licence,
                Configuration.TrustedKeys.Parse(_service.Key.PublicJwk).Keys,
                new SigningRequest
                {
                    Licensee = Claims(first).Subject,
                    ServerId = ServerA,
                    IssuedAt = LicenceFormat.Iso(_service.Clock.GetUtcNow()),
                    Expires = LicenceFormat.Iso(expires),
                });

            Assert.True(verdict.IsValid, verdict.Problem);
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

        private static ActivationRequest Request(string code, string serverId = ServerA)
        {
            return new ActivationRequest { Code = code, ServerId = serverId, PluginVersion = "1.0.3" };
        }

        private static LicenceStatusRequest Ask(string fingerprint, string serverId = ServerA)
        {
            return new LicenceStatusRequest { ServerId = serverId, Fingerprint = fingerprint };
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

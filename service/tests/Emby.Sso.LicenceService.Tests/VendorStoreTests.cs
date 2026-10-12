using System;
using System.Linq;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// Vendor-managed codes: the reseller's reference, seats and paid-until
    /// decide the code, and an activation can be released to free its seat.
    /// Real store, real activation path - the seat count IS the database.
    /// </summary>
    public sealed class VendorStoreTests : IDisposable
    {
        private const string ServerA = "c5bc6e91458540caa295c4efdda1a58a";
        private const string ServerB = "aaaa1111bbbb2222cccc3333dddd4444";
        private const string ServerC = "9999aaaa8888bbbb7777cccc6666dddd";
        private const string ServerD = "11112222333344445555666677778888";

        private readonly TestService _service = new TestService();
        private readonly DateTimeOffset _paidUntil = new DateTimeOffset(2027, 3, 1, 0, 0, 0, TimeSpan.Zero);

        public void Dispose()
        {
            _service.Dispose();
        }

        [Fact]
        public void Upsert_creates_then_reports_unchanged_then_updates()
        {
            var hash = NewHash();
            var now = _service.Clock.GetUtcNow();

            Assert.Equal(VendorUpsertResult.Created, Upsert("ref-1", hash, 3, _paidUntil));
            Assert.Equal(VendorUpsertResult.Unchanged, Upsert("ref-1", hash, 3, _paidUntil));
            Assert.Equal(VendorUpsertResult.Updated, Upsert("ref-1", hash, 5, _paidUntil.AddYears(1)));

            var row = _service.Store.FindVendorCode("ref-1");

            Assert.Equal(5, row.Seats);
            Assert.Equal(_paidUntil.AddYears(1), row.ExpiresUtc);
            Assert.Equal(CodeStatus.Active, row.Status);

            var summary = _service.Store.FindCodeByHash(hash);

            Assert.Equal("vendor", summary.Source);
            Assert.Null(summary.FirstActivatedUtc);
            Assert.Equal(now, summary.CreatedUtc);
        }

        [Fact]
        public void Voiding_and_restoring_goes_through_update()
        {
            var hash = NewHash();

            Upsert("ref-1", hash, 3, _paidUntil);

            Assert.Equal(
                VendorUpsertResult.Updated,
                _service.Store.UpsertVendorCode("ref-1", hash, "test", 3, _paidUntil, true, "refunded", _service.Clock.GetUtcNow()));
            Assert.Equal(CodeStatus.Void, _service.Store.FindVendorCode("ref-1").Status);
            Assert.Equal("refunded", _service.Store.FindCodeByHash(hash).VoidReason);

            Assert.Equal(VendorUpsertResult.Updated, Upsert("ref-1", hash, 3, _paidUntil));
            Assert.Equal(CodeStatus.Active, _service.Store.FindVendorCode("ref-1").Status);
        }

        [Fact]
        public void A_different_hash_for_a_reference_or_a_taken_hash_is_a_conflict()
        {
            var hash = NewHash();

            Upsert("ref-1", hash, 3, _paidUntil);

            Assert.Equal(VendorUpsertResult.HashConflict, Upsert("ref-1", NewHash(), 3, _paidUntil));
            Assert.Equal(VendorUpsertResult.HashConflict, Upsert("ref-2", hash, 3, _paidUntil));
            Assert.Null(_service.Store.FindVendorCode("ref-2"));
        }

        [Fact]
        public void An_unknown_reference_finds_nothing()
        {
            Assert.Null(_service.Store.FindVendorCode("nope"));
        }

        [Fact]
        public void Find_lists_activations_including_released_ones()
        {
            var code = NewVendorCode("ref-1", 3);

            Activate(code, ServerA);
            Activate(code, ServerB);

            Assert.Equal(ReleaseResult.Released, _service.Store.ReleaseVendorActivation("ref-1", ServerB, _service.Clock.GetUtcNow()));

            var row = _service.Store.FindVendorCode("ref-1");

            Assert.Equal(2, row.Activations.Count);
            Assert.Null(row.Activations.Single(a => a.ServerId == ServerA).ReleasedUtc);
            Assert.NotNull(row.Activations.Single(a => a.ServerId == ServerB).ReleasedUtc);
            Assert.Equal("1.4.0", row.Activations[0].PluginVersion);
        }

        [Fact]
        public void Release_reports_already_released_and_not_found()
        {
            var code = NewVendorCode("ref-1", 3);
            var now = _service.Clock.GetUtcNow();

            Activate(code, ServerA);

            Assert.Equal(ReleaseResult.NotFound, _service.Store.ReleaseVendorActivation("ref-1", ServerD, now));
            Assert.Equal(ReleaseResult.NotFound, _service.Store.ReleaseVendorActivation("ref-9", ServerA, now));
            Assert.Equal(ReleaseResult.Released, _service.Store.ReleaseVendorActivation("ref-1", ServerA.ToUpperInvariant(), now));
            Assert.Equal(ReleaseResult.AlreadyReleased, _service.Store.ReleaseVendorActivation("ref-1", ServerA, now));
        }

        [Fact]
        public void Release_frees_a_slot_and_the_released_server_cannot_come_back_into_a_full_code()
        {
            var code = NewVendorCode("ref-1", 3);

            Assert.True(Activate(code, ServerA).IsSuccess);
            Assert.True(Activate(code, ServerB).IsSuccess);
            Assert.True(Activate(code, ServerC).IsSuccess);
            Assert.Equal(ActivationError.CodeExhausted, Activate(code, ServerD).Error);

            _service.Store.ReleaseVendorActivation("ref-1", ServerA, _service.Clock.GetUtcNow());

            var fourth = Activate(code, ServerD);

            Assert.True(fourth.IsSuccess);
            Assert.Equal(3, fourth.ActivationsUsed);

            // Seats are full again, so the released server is refused.
            Assert.Equal(ActivationError.CodeExhausted, Activate(code, ServerA).Error);
        }

        [Fact]
        public void A_released_server_is_reopened_when_a_seat_is_free()
        {
            var code = NewVendorCode("ref-1", 3);

            Activate(code, ServerA);
            _service.Store.ReleaseVendorActivation("ref-1", ServerA, _service.Clock.GetUtcNow());

            var again = Activate(code, ServerA);

            Assert.True(again.IsSuccess);
            Assert.Equal(1, again.ActivationsUsed);
            Assert.Null(_service.Store.FindVendorCode("ref-1").Activations.Single().ReleasedUtc);
        }

        [Fact]
        public void A_vendor_code_expires_when_the_vendor_says_not_a_year_after_first_activation()
        {
            var code = NewVendorCode("ref-1", 3);

            // Activated long before paid-until; 365 days later would be 2027-01-05.
            // Not signed yet, so the request that is waiting carries the terms.
            _service.Activations.Activate(
                new ActivationRequest { Code = code, ServerId = ServerA, PluginVersion = "1.4.0" },
                "10.0.0.1");

            var request = _service.Store.WaitingToBeSigned(10).Single();

            Assert.Equal(LicenceFormat.Iso(_paidUntil), request.Expires);
            Assert.Equal(_paidUntil, _service.Store.FindVendorCode("ref-1").ExpiresUtc);
            Assert.Null(_service.Store.FindCodeByHash(RedemptionCode.Hash(Normalise(code))).FirstActivatedUtc);
        }

        [Fact]
        public void Status_for_a_released_activation_is_revoked_and_for_the_others_valid()
        {
            var code = NewVendorCode("ref-1", 3);

            var a = Licence(code, ServerA);
            var b = Licence(code, ServerB);

            var statuses = new LicenceStatusService(
                _service.Store,
                _service.Limiter,
                _service.Key.Key,
                _service.Clock,
                NullLogger<LicenceStatusService>.Instance);

            Assert.Equal(LicenceStatusToken.Valid, StatusOf(statuses, a, ServerA));

            _service.Store.ReleaseVendorActivation("ref-1", ServerA, _service.Clock.GetUtcNow());

            Assert.Equal(LicenceStatusToken.Revoked, StatusOf(statuses, a, ServerA));
            Assert.Equal(LicenceStatusToken.Valid, StatusOf(statuses, b, ServerB));
        }

        [Fact]
        public void Seats_in_use_ignores_released_activations_in_the_code_list()
        {
            var code = NewVendorCode("ref-1", 3);

            Activate(code, ServerA);
            Activate(code, ServerB);
            _service.Store.ReleaseVendorActivation("ref-1", ServerB, _service.Clock.GetUtcNow());

            Assert.Equal(1, _service.Store.FindCodeByHash(RedemptionCode.Hash(Normalise(code))).ActivationsUsed);
        }

        private string StatusOf(LicenceStatusService statuses, string fingerprint, string serverId)
        {
            var reply = statuses.Check(
                new LicenceStatusRequest { ServerId = serverId, Fingerprint = fingerprint },
                "10.0.0.1");

            Assert.True(reply.IsAnswered);

            return new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(reply.Token)
                .Claims.First(c => c.Type == LicenceStatusToken.StatusClaim).Value;
        }

        private string Licence(string code, string serverId)
        {
            var reply = _service.ActivateAndSign(
                new ActivationRequest { Code = code, ServerId = serverId, PluginVersion = "1.4.0" },
                "10.0.0.1");

            Assert.True(reply.IsSuccess);

            return LicenceFormat.Fingerprint(reply.Licence);
        }

        private VendorUpsertResult Upsert(string vendorRef, string hash, int seats, DateTimeOffset expires)
        {
            return _service.Store.UpsertVendorCode(vendorRef, hash, "test", seats, expires, false, null, _service.Clock.GetUtcNow());
        }

        private static string NewHash()
        {
            return RedemptionCode.Hash(RedemptionCode.Generate());
        }

        private string NewVendorCode(string vendorRef, int seats)
        {
            var code = RedemptionCode.Generate();

            Upsert(vendorRef, RedemptionCode.Hash(code), seats, _paidUntil);

            return RedemptionCode.Format(code);
        }

        private ActivationReply Activate(string code, string serverId)
        {
            return _service.ActivateAndSign(
                new ActivationRequest { Code = code, ServerId = serverId, PluginVersion = "1.4.0" },
                "10.0.0.1");
        }

        private static string Normalise(string code)
        {
            Assert.True(RedemptionCode.TryNormalise(code, out var normalised));

            return normalised;
        }
    }
}

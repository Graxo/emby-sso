using System;
using System.Linq;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The per-day check-in counts behind the portal's "check-ins over time"
    /// chart: what counts as a check-in, what does not, and how long it is
    /// kept. Real store, real activation and status paths - the count is
    /// written inside their transactions, so a fake would test nothing.
    /// </summary>
    public sealed class CheckinTests : IDisposable
    {
        private const string ServerA = "c5bc6e91458540caa295c4efdda1a58a";
        private const string ServerB = "aaaa1111bbbb2222cccc3333dddd4444";

        private static readonly DateTimeOffset PaidUntil = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

        private readonly TestService _service = new TestService();

        public void Dispose()
        {
            _service.Dispose();
        }

        [Fact]
        public void An_activation_counts_once_per_request_and_a_new_day_starts_a_new_row()
        {
            var code = VendorCode("ref-1");

            // The first one is answered "waiting for a signature", and is still
            // a check-in: the activation was recorded and last_seen_utc moved.
            Activate(code, ServerA);
            Activate(code, ServerA);

            Assert.Equal(new[] { ("2026-01-05", ServerA, 2) }, Rows("ref-1"));

            _service.Clock.Advance(TimeSpan.FromDays(1));
            Activate(code, ServerA);

            Assert.Equal(
                new[] { ("2026-01-05", ServerA, 2), ("2026-01-06", ServerA, 1) },
                Rows("ref-1"));
        }

        [Fact]
        public void A_status_check_counts_against_the_activation_its_fingerprint_belongs_to()
        {
            var code = VendorCode("ref-1");
            var licence = _service.ActivateAndSign(Ask(code, ServerA), "10.0.0.1").Licence;
            var fingerprint = LicenceFormat.Fingerprint(licence);

            // Activate, sign, activate: two check-ins already.
            Assert.Equal(new[] { ("2026-01-05", ServerA, 2) }, Rows("ref-1"));

            Assert.True(Statuses().Check(Status(fingerprint), "10.0.0.1").IsAnswered);

            Assert.Equal(new[] { ("2026-01-05", ServerA, 3) }, Rows("ref-1"));

            _service.Clock.Advance(TimeSpan.FromDays(1));
            Statuses().Check(Status(fingerprint), "10.0.0.1");
            Statuses().Check(Status(fingerprint), "10.0.0.1");

            Assert.Equal(
                new[] { ("2026-01-05", ServerA, 3), ("2026-01-06", ServerA, 2) },
                Rows("ref-1"));
        }

        [Fact]
        public void A_status_check_brings_the_activations_plugin_version_up_to_date()
        {
            // A licensed server never activates again, so without this the
            // vendor API reports the version it was activated with for ever.
            var code = VendorCode("ref-1");
            var fingerprint = LicenceFormat.Fingerprint(_service.ActivateAndSign(Ask(code, ServerA), "10.0.0.1").Licence);

            Assert.Equal("1.4.0", PluginVersion("ref-1"));

            Statuses().Check(Status(fingerprint, "  1.4.3  "), "10.0.0.1");

            Assert.Equal("1.4.3", PluginVersion("ref-1"));

            // An older plugin sends no version: what was stored stays.
            Statuses().Check(Status(fingerprint, null), "10.0.0.1");
            Statuses().Check(Status(fingerprint, "   "), "10.0.0.1");

            Assert.Equal("1.4.3", PluginVersion("ref-1"));

            // Capped like activation's, so a hostile client cannot store a novel.
            Statuses().Check(Status(fingerprint, new string('9', 500)), "10.0.0.1");

            Assert.Equal(ActivationService.MaximumPluginVersionLength, PluginVersion("ref-1").Length);
        }

        [Fact]
        public void A_status_check_about_an_unknown_licence_stores_no_version()
        {
            var code = VendorCode("ref-1");

            _service.ActivateAndSign(Ask(code, ServerA), "10.0.0.1");
            Statuses().Check(Status("sha256:" + new string('a', 64), "9.9.9"), "10.0.0.1");

            Assert.Equal("1.4.0", PluginVersion("ref-1"));
        }

        [Fact]
        public void A_revoked_answer_is_still_a_check_in()
        {
            // The server asked and was answered; that it was told "revoked" is
            // exactly the history the portal wants to show.
            var code = VendorCode("ref-1");
            var fingerprint = LicenceFormat.Fingerprint(_service.ActivateAndSign(Ask(code, ServerA), "10.0.0.1").Licence);

            _service.Store.ReleaseVendorActivation("ref-1", ServerA, _service.Clock.GetUtcNow());
            _service.Clock.Advance(TimeSpan.FromDays(1));

            Statuses().Check(Status(fingerprint), "10.0.0.1");

            Assert.Contains(("2026-01-06", ServerA, 1), Rows("ref-1"));
        }

        [Fact]
        public void Refused_and_unknown_requests_record_nothing()
        {
            var code = VendorCode("ref-1", seats: 1);

            // Not a code this store knows.
            Activate(RedemptionCode.Format(RedemptionCode.Generate()), ServerA);

            // A status check about a licence this store never issued, and one
            // that is malformed.
            Statuses().Check(Status("sha256:" + new string('a', 64)), "10.0.0.1");
            Statuses().Check(Status("not-a-fingerprint"), "10.0.0.1");

            Assert.Equal(0, CountCheckinRows());

            // One seat: the second server is refused and must leave no trace.
            Activate(code, ServerA);
            var refused = Activate(code, ServerB);

            Assert.False(refused.IsSuccess);
            Assert.Equal(new[] { ("2026-01-05", ServerA, 1) }, Rows("ref-1"));

            // A void code is refused at activation, and records nothing either.
            _service.Store.UpsertVendorCode(
                "ref-1", RedemptionCode.Hash(Normalise(code)), "test", 1, PaidUntil, true, "refunded", _service.Clock.GetUtcNow());
            Activate(code, ServerA);

            Assert.Equal(new[] { ("2026-01-05", ServerA, 1) }, Rows("ref-1"));
        }

        [Fact]
        public void Rows_older_than_the_retention_are_pruned_on_the_first_check_in_of_a_day()
        {
            var code = VendorCode("ref-1");
            var start = _service.Clock.GetUtcNow();

            Activate(code, ServerA);
            _service.Clock.Advance(TimeSpan.FromDays(1));
            Activate(code, ServerA);

            // 400 days after the first row: that one is now day 401 and goes;
            // the second is day 400, the last one kept.
            _service.Clock.Set(start.AddDays(LicenceStore.CheckinRetentionDays));
            Activate(code, ServerA);

            Assert.Equal(
                new[] { ("2026-01-06", ServerA, 1), (LicenceStore.CheckinDay(start.AddDays(400)), ServerA, 1) },
                Rows("ref-1"));
            Assert.Equal(2, CountCheckinRows());
        }

        [Fact]
        public void An_existing_volume_without_the_table_gets_it_on_start()
        {
            using (var connection = new SqliteConnection("Data Source=" + _service.Options.DatabasePath))
            {
                connection.Open();

                using var command = connection.CreateCommand();

                command.CommandText = "DROP TABLE activation_checkins;";
                command.ExecuteNonQuery();
            }

            SqliteConnection.ClearAllPools();

            var store = new LicenceStore(_service.Options.DatabasePath);

            store.Initialise();
            store.UpsertVendorCode(
                "ref-1", RedemptionCode.Hash(RedemptionCode.Generate()), "test", 3, PaidUntil, false, null, _service.Clock.GetUtcNow());

            Assert.Empty(store.ReadVendorCheckins("ref-1", "2000-01-01", "2100-01-01"));
        }

        [Fact]
        public void Reading_an_unknown_ref_is_null_not_empty()
        {
            Assert.Null(_service.Store.ReadVendorCheckins("nope", "2000-01-01", "2100-01-01"));
        }

        private string VendorCode(string vendorRef, int seats = 3)
        {
            var raw = RedemptionCode.Generate();

            _service.Store.UpsertVendorCode(
                vendorRef, RedemptionCode.Hash(raw), "test", seats, PaidUntil, false, null, _service.Clock.GetUtcNow());

            return RedemptionCode.Format(raw);
        }

        private ActivationReply Activate(string code, string serverId)
        {
            return _service.Activations.Activate(Ask(code, serverId), "10.0.0.1");
        }

        private static ActivationRequest Ask(string code, string serverId)
        {
            return new ActivationRequest { Code = code, ServerId = serverId, PluginVersion = "1.4.0" };
        }

        private static LicenceStatusRequest Status(string fingerprint, string pluginVersion = null)
        {
            return new LicenceStatusRequest { ServerId = ServerA, Fingerprint = fingerprint, PluginVersion = pluginVersion };
        }

        private string PluginVersion(string vendorRef)
        {
            return _service.Store.FindVendorCode(vendorRef).Activations.Single().PluginVersion;
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

        private (string Day, string ServerId, int Checks)[] Rows(string vendorRef)
        {
            return _service.Store.ReadVendorCheckins(vendorRef, "2000-01-01", "2100-01-01")
                .Select(r => (r.Day, r.ServerId, r.Checks))
                .ToArray();
        }

        private int CountCheckinRows()
        {
            using var connection = new SqliteConnection("Data Source=" + _service.Options.DatabasePath);

            connection.Open();

            using var command = connection.CreateCommand();

            command.CommandText = "SELECT COUNT(*) FROM activation_checkins;";

            return Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
        }

        private static string Normalise(string code)
        {
            Assert.True(RedemptionCode.TryNormalise(code, out var normalised));

            return normalised;
        }
    }
}

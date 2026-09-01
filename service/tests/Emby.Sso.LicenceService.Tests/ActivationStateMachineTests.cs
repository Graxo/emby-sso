using System;
using System.IO;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The code's life: fresh, activated, re-activated onto more servers up to
    /// the cap, exhausted - and the one that costs nothing, re-activating a
    /// server the code already holds.
    ///
    /// These are the rules in contract.md that both halves of the system promise
    /// each other, so each test is named after the sentence it enforces.
    /// </summary>
    public class ActivationStateMachineTests : IDisposable
    {
        private const string ServerA = "c5bc6e91458540caa295c4efdda1a58a";
        private const string ServerB = "aaaa1111bbbb2222cccc3333dddd4444";
        private const string ServerC = "9999aaaa8888bbbb7777cccc6666dddd";
        private const string ServerD = "11112222333344445555666677778888";

        private readonly TestService _service = new TestService();

        public void Dispose()
        {
            _service.Dispose();
        }

        [Fact]
        public void A_fresh_code_activates_and_returns_a_licence_for_that_server()
        {
            var code = _service.GiveOutACode();

            var reply = Activate(code, ServerA);

            Assert.True(reply.IsSuccess);
            Assert.False(string.IsNullOrEmpty(reply.Licence));
            Assert.Equal(1, reply.ActivationsUsed);
            Assert.Equal(3, reply.ActivationsAllowed);
        }

        [Fact]
        public void An_unknown_code_is_invalid_code_and_not_something_more_specific()
        {
            var reply = Activate(RedemptionCode.Format(RedemptionCode.Generate()), ServerA);

            Assert.False(reply.IsSuccess);
            Assert.Equal(ActivationError.InvalidCode, reply.Error);
        }

        [Fact]
        public void Re_activating_the_same_code_onto_the_same_server_is_free_and_returns_200()
        {
            var code = _service.GiveOutACode();

            var first = Activate(code, ServerA);
            var second = Activate(code, ServerA);
            var third = Activate(code, ServerA);

            Assert.True(second.IsSuccess);
            Assert.True(third.IsSuccess);

            // "does NOT consume another activation" - contract.md.
            Assert.Equal(1, first.ActivationsUsed);
            Assert.Equal(1, second.ActivationsUsed);
            Assert.Equal(1, third.ActivationsUsed);
        }

        [Fact]
        public void A_case_different_retype_of_the_same_server_id_is_still_the_same_server()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var again = Activate(code, ServerA.ToUpperInvariant());

            Assert.True(again.IsSuccess);
            Assert.Equal(1, again.ActivationsUsed);
        }

        [Fact]
        public void Each_new_server_consumes_one_activation_up_to_the_limit()
        {
            var code = _service.GiveOutACode();

            Assert.Equal(1, Activate(code, ServerA).ActivationsUsed);
            Assert.Equal(2, Activate(code, ServerB).ActivationsUsed);
            Assert.Equal(3, Activate(code, ServerC).ActivationsUsed);
        }

        [Fact]
        public void The_server_after_the_limit_is_code_exhausted()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);
            Activate(code, ServerB);
            Activate(code, ServerC);

            var refused = Activate(code, ServerD);

            Assert.False(refused.IsSuccess);
            Assert.Equal(ActivationError.CodeExhausted, refused.Error);
        }

        [Fact]
        public void An_exhausted_code_still_re_activates_the_servers_it_already_holds()
        {
            // The customer who has used all three and reinstalls one of them must
            // not be locked out; that is the whole reason re-activation is free.
            var code = _service.GiveOutACode();

            Activate(code, ServerA);
            Activate(code, ServerB);
            Activate(code, ServerC);

            Assert.False(Activate(code, ServerD).IsSuccess);
            Assert.True(Activate(code, ServerA).IsSuccess);
        }

        [Fact]
        public void A_one_activation_code_is_exhausted_by_its_second_server()
        {
            var code = _service.GiveOutACode(activationsAllowed: 1);

            Assert.True(Activate(code, ServerA).IsSuccess);
            Assert.Equal(ActivationError.CodeExhausted, Activate(code, ServerB).Error);
        }

        [Fact]
        public void The_expiry_is_fixed_at_the_first_activation_and_re_activation_does_not_extend_it()
        {
            var code = _service.GiveOutACode(licenceDays: 365);

            var first = Activate(code, ServerA);

            _service.Clock.Advance(TimeSpan.FromDays(100));

            var later = Activate(code, ServerA);
            var second = Activate(code, ServerB);

            Assert.Equal(first.ExpiresUtc, later.ExpiresUtc);

            // And the second server does not get a longer licence than the first.
            Assert.Equal(first.ExpiresUtc, second.ExpiresUtc);
        }

        [Fact]
        public void A_voided_code_stops_activating_new_servers()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var hash = RedemptionCode.Hash(Normalise(code));
            var row = _service.Store.FindCode(hash);

            // Voiding is what a refund does; there is no other way in.
            using (var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + _service.Options.DatabasePath))
            {
                connection.Open();

                using var command = connection.CreateCommand();

                command.CommandText = "UPDATE codes SET status = 'void' WHERE id = $id;";
                command.Parameters.AddWithValue("$id", row.Id);
                command.ExecuteNonQuery();
            }

            var refused = Activate(code, ServerB);

            Assert.False(refused.IsSuccess);
            Assert.Equal(ActivationError.InvalidCode, refused.Error);
        }

        [Fact]
        public void Every_issued_licence_is_written_to_the_ledger_in_the_tools_format()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);
            Activate(code, ServerB);

            // The free re-activation adds NOTHING to the ledger, and that is a
            // change from when this service minted licences itself. There is now
            // one licence per server, signed once: re-activating hands back the
            // same string rather than minting a second live credential for the
            // same server. Fewer credentials in circulation for the same
            // customer is the better answer, and the ledger says so.
            Activate(code, ServerA);

            var lines = File.ReadAllLines(_service.Options.LedgerPath);

            Assert.Equal(2, lines.Length);

            foreach (var line in lines)
            {
                Assert.Contains("\"server_id\"", line, StringComparison.Ordinal);
                Assert.Contains("\"fingerprint\":\"sha256:", line, StringComparison.Ordinal);
            }
        }

        [Fact]
        public void The_licence_names_the_code_rather_than_the_buyers_email_address()
        {
            var code = _service.GiveOutACode();

            var reply = Activate(code, ServerA);
            var token = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(reply.Licence);

            // `sub` travels in a token that gets pasted into forums and support
            // threads. It must identify the customer to the vendor without being
            // their email address.
            Assert.StartsWith("code:", token.Subject, StringComparison.Ordinal);
            Assert.DoesNotContain("@", token.Subject, StringComparison.Ordinal);
        }

        [Fact]
        public void The_stored_row_never_contains_the_code_itself()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var database = File.ReadAllText(_service.Options.DatabasePath, System.Text.Encoding.Latin1);
            var normalised = Normalise(code);

            Assert.DoesNotContain(normalised, database, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(code, database, StringComparison.OrdinalIgnoreCase);
        }

        private static string Normalise(string code)
        {
            Assert.True(RedemptionCode.TryNormalise(code, out var normalised));

            return normalised;
        }

        /// <summary>
        /// Activate, get the licence signed, activate again - which is what a
        /// customer and the vendor between them do now that the private key is
        /// not on the service's host. Every test in this class is about the
        /// state machine rather than about the wait, so they all go through
        /// here; <see cref="OfflineSigningTests"/> is where the wait itself is
        /// the subject.
        /// </summary>
        private ActivationReply Activate(string code, string serverId)
        {
            return _service.ActivateAndSign(
                new ActivationRequest { Code = code, ServerId = serverId, PluginVersion = "1.4.0" },
                "10.0.0.1");
        }
    }
}

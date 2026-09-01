using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The property the whole offline-signing change exists for: THIS SERVICE
    /// CANNOT MINT A LICENCE.
    ///
    /// Everything else here - rate limits, the admin password, webhook signature
    /// verification, the container hardening - is a wall around one asset, and
    /// any single failure of any one of them used to lose it completely: the
    /// private key mints a valid licence for any Emby server, forever, and the
    /// plugin verifies offline so nothing can be recalled. These tests are the
    /// evidence that the asset is no longer here to lose, and that what replaced
    /// it cannot be talked into signing the wrong thing.
    /// </summary>
    public class OfflineSigningTests : IDisposable
    {
        private const string ServerA = "c5bc6e91458540caa295c4efdda1a58a";
        private const string ServerB = "0b3d0f8fd4d9412e9c4e5ba0d09a3f77";

        private readonly TestService _service = new TestService();

        public void Dispose()
        {
            _service.Dispose();

            GC.SuppressFinalize(this);
        }

        [Fact]
        public void A_first_activation_is_recorded_and_answers_that_it_is_being_signed()
        {
            var reply = Activate(_service.GiveOutACode(), ServerA);

            Assert.False(reply.IsSuccess);
            Assert.Equal(ActivationError.PendingSignature, reply.Error);
            Assert.Null(reply.Licence);

            // The allowance IS spent and the request IS waiting: the customer's
            // activation happened, only the signature is missing.
            Assert.Equal(1, _service.Store.CountWaitingToBeSigned());
        }

        [Fact]
        public void Asking_again_before_it_is_signed_does_not_ask_for_a_second_licence()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);
            Activate(code, ServerA);
            Activate(code, ServerA);

            // One server, one licence. Three requests would mean three live
            // credentials for one server once they were signed.
            Assert.Equal(1, _service.Store.CountWaitingToBeSigned());
        }

        [Fact]
        public void Once_signed_the_next_activation_carries_the_licence()
        {
            var code = _service.GiveOutACode();

            Assert.Equal(ActivationError.PendingSignature, Activate(code, ServerA).Error);
            Assert.Equal(1, _service.Sign());

            var reply = Activate(code, ServerA);

            Assert.True(reply.IsSuccess);
            Assert.False(string.IsNullOrEmpty(reply.Licence));
            Assert.Equal(0, _service.Store.CountWaitingToBeSigned());
        }

        [Fact]
        public void The_licence_that_comes_back_is_the_same_one_every_time()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);
            _service.Sign();

            var first = Activate(code, ServerA).Licence;
            var again = Activate(code, ServerA).Licence;

            // Re-activating is not re-issuing. Handing out a second, different
            // credential for the same server would double what has to be
            // accounted for and buys nothing.
            Assert.Equal(first, again);
        }

        [Fact]
        public async Task A_licence_signed_by_a_key_this_service_does_not_trust_is_refused()
        {
            // The rotation property, from the service's side: a signing machine
            // whose key is not in LICENCE_PUBLIC_KEYS cannot get a licence stored,
            // so a key that has been retired cannot quietly keep working.
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var report = await _service.Desk.UploadAsync(SignedWith(Stranger(), ServerA));

            Assert.Equal(0, report.Stored);
            Assert.Single(report.Rejected);
            Assert.Contains("trust", report.Rejected[0].Why, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(1, _service.Store.CountWaitingToBeSigned());
        }

        [Fact]
        public async Task A_licence_for_a_different_server_than_was_asked_for_is_refused()
        {
            // The upload's only authority is to supply a signature for terms
            // this service already decided. Whoever is at the admin page cannot
            // use it to license a server nobody paid for.
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var request = _service.Desk.Download().Requests.Single();
            var issuer = new LicenceIssuer(_service.Key.Key);

            var file = new SignedLicenceFile
            {
                SignedUtc = LicenceFormat.Iso(_service.Clock.GetUtcNow()),
                KeyId = _service.Key.Thumbprint,
            };

            file.Licences.Add(new SignedLicence
            {
                RequestId = request.RequestId,
                Licence = issuer.Issue(request.Licensee, ServerB, request.IssuedAtUtc, request.ExpiresUtc).Token,
            });

            var report = await _service.Desk.UploadAsync(SigningExchange.Write(file));

            Assert.Equal(0, report.Stored);
            Assert.Single(report.Rejected);
            Assert.Equal(1, _service.Store.CountWaitingToBeSigned());
        }

        [Fact]
        public async Task A_licence_that_lasts_longer_than_was_paid_for_is_refused()
        {
            var code = _service.GiveOutACode(licenceDays: 30);

            Activate(code, ServerA);

            var request = _service.Desk.Download().Requests.Single();
            var issuer = new LicenceIssuer(_service.Key.Key);

            var file = new SignedLicenceFile
            {
                SignedUtc = LicenceFormat.Iso(_service.Clock.GetUtcNow()),
                KeyId = _service.Key.Thumbprint,
            };

            file.Licences.Add(new SignedLicence
            {
                RequestId = request.RequestId,

                // Ten years, from the same key, for the right server.
                Licence = issuer.Issue(
                    request.Licensee,
                    request.ServerId,
                    request.IssuedAtUtc,
                    request.IssuedAtUtc.AddYears(10)).Token,
            });

            var report = await _service.Desk.UploadAsync(SigningExchange.Write(file));

            Assert.Equal(0, report.Stored);
            Assert.Contains("expires", report.Rejected.Single().Why, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task An_upload_naming_a_request_this_service_never_made_is_refused()
        {
            var file = new SignedLicenceFile
            {
                SignedUtc = LicenceFormat.Iso(_service.Clock.GetUtcNow()),
                KeyId = _service.Key.Thumbprint,
            };

            file.Licences.Add(new SignedLicence
            {
                RequestId = SigningRequestId.New(),
                Licence = new LicenceIssuer(_service.Key.Key)
                    .Issue("code:abcdef123456", ServerA, _service.Clock.GetUtcNow(), _service.Clock.GetUtcNow().AddDays(1))
                    .Token,
            });

            var report = await _service.Desk.UploadAsync(SigningExchange.Write(file));

            Assert.Equal(0, report.Stored);
            Assert.Single(report.Rejected);
        }

        [Fact]
        public async Task Uploading_the_same_file_twice_changes_nothing_and_is_not_an_error()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var request = _service.Desk.Download().Requests.Single();
            var json = SignedWith(_service.Key.Key, request);

            var first = await _service.Desk.UploadAsync(json);
            var second = await _service.Desk.UploadAsync(json);

            Assert.Equal(1, first.Stored);
            Assert.Equal(0, second.Stored);
            Assert.Equal(1, second.Unchanged);
            Assert.False(second.AnythingWrong);
        }

        [Fact]
        public async Task A_second_different_licence_for_the_same_request_is_refused()
        {
            // The customer may already be using the one that is there; replacing
            // it would stop their server working, and re-uploading an old file by
            // mistake is far too easy for that to happen silently.
            //
            // Asserted against the store rather than through an upload, because
            // an upload cannot reach this: two licences that both pass
            // verification have identical claims, and RS256 over identical
            // claims is the identical string. That makes this a guard against a
            // future change rather than against today's caller, which is exactly
            // when a guard is worth having a test.
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var request = _service.Desk.Download().Requests.Single();

            Assert.Equal(1, (await _service.Desk.UploadAsync(SignedWith(_service.Key.Key, request))).Stored);

            var replaced = _service.Store.StoreSignedLicence(
                request.RequestId,
                "a.completely.different.string",
                "somekey",
                "sha256:0000",
                _service.Clock.GetUtcNow());

            Assert.Equal(StoreSignedResult.AlreadySigned, replaced);

            // And the customer's licence is untouched.
            Assert.True(Activate(code, ServerA).IsSuccess);
        }

        [Fact]
        public async Task A_file_that_is_not_a_signed_licence_file_is_refused_by_name()
        {
            var report = await _service.Desk.UploadAsync("{\"format\":\"something-else\",\"version\":1}")
                ;

            Assert.False(report.IsReadable);
            Assert.Equal(0, report.Stored);
            Assert.Contains(LicenceFormat.SignedFormat, report.Summary(), StringComparison.Ordinal);
        }

        [Fact]
        public void The_download_carries_no_customer_detail_beyond_what_a_licence_needs()
        {
            // The file leaves the machine. It should say what has to be signed
            // and nothing about who the customer is.
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var json = SigningExchange.Write(_service.Desk.Download());

            // Not the redemption code, which is a bearer credential, and not
            // anything that names the buyer: the licensee is the code's tag.
            Assert.DoesNotContain(code, json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("@", json, StringComparison.Ordinal);
            Assert.Contains("\"licensee\": \"code:", json, StringComparison.Ordinal);
        }

        [Fact]
        public void The_ledger_records_a_licence_this_service_did_not_mint()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);
            _service.Sign();

            var line = Assert.Single(File.ReadAllLines(_service.Options.LedgerPath));

            Assert.Contains("\"server_id\":\"" + ServerA + "\"", line, StringComparison.Ordinal);
            Assert.Contains("\"fingerprint\":\"sha256:", line, StringComparison.Ordinal);
        }

        private ActivationReply Activate(string code, string serverId)
        {
            return _service.Activations.Activate(
                new ActivationRequest { Code = code, ServerId = serverId, PluginVersion = "1.4.0" },
                "10.0.0.1");
        }

        private string SignedWith(Microsoft.IdentityModel.Tokens.JsonWebKey key, string serverId)
        {
            var request = _service.Desk.Download().Requests.Single();

            Assert.Equal(serverId, request.ServerId);

            return SignedWith(key, request);
        }

        private string SignedWith(Microsoft.IdentityModel.Tokens.JsonWebKey key, SigningRequest request)
        {
            var file = new SignedLicenceFile
            {
                SignedUtc = LicenceFormat.Iso(_service.Clock.GetUtcNow()),
                KeyId = key.Kid,
            };

            file.Licences.Add(new SignedLicence
            {
                RequestId = request.RequestId,
                Licence = new LicenceIssuer(key)
                    .Issue(request.Licensee, request.ServerId, request.IssuedAtUtc, request.ExpiresUtc)
                    .Token,
            });

            return SigningExchange.Write(file);
        }

        /// <summary>A key nobody trusts: a second, unrelated signing machine.</summary>
        private static Microsoft.IdentityModel.Tokens.JsonWebKey Stranger()
        {
            var directory = TestKeys.TempDirectory();

            return SigningKeyFile.Load(TestKeys.WritePrivateKey(directory)).Key;
        }
    }
}

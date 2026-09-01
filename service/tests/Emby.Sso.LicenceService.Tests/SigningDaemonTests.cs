using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.Signing;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// Self-service activation: one press of Activate, and a licence.
    ///
    /// The signer exists because "your licence is being issued, come back
    /// later" is not something to say to somebody who has just paid. What it
    /// costs is that the private key is loaded by the process answering the
    /// internet - see SigningDaemon, which says so - and what it must NOT cost
    /// is any of the checks that guard a manual upload. These hold it to that:
    /// it signs through the same door an operator does, so it can issue exactly
    /// what a person could and nothing else.
    /// </summary>
    public class SigningDaemonTests : IDisposable
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
        public async Task It_signs_what_is_waiting()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            Assert.Equal(1, _service.Store.CountWaitingToBeSigned());
            Assert.Equal(1, await Daemon().SignWaitingAsync());
            Assert.Equal(0, _service.Store.CountWaitingToBeSigned());

            var reply = Activate(code, ServerA);

            Assert.True(reply.IsSuccess);
            Assert.False(string.IsNullOrEmpty(reply.Licence));
        }

        [Fact]
        public async Task With_nothing_waiting_it_does_nothing()
        {
            Assert.Equal(0, await Daemon().SignWaitingAsync());
        }

        [Fact]
        public async Task It_signs_a_whole_batch_in_one_pass()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);
            Activate(code, ServerB);

            Assert.Equal(2, await Daemon().SignWaitingAsync());
            Assert.True(Activate(code, ServerA).IsSuccess);
            Assert.True(Activate(code, ServerB).IsSuccess);
        }

        [Fact]
        public async Task Signing_twice_does_not_reissue_anything()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            var daemon = Daemon();

            Assert.Equal(1, await daemon.SignWaitingAsync());

            // Nothing is waiting now, so a second pass has nothing to do. A
            // signer that re-signed would put a second live credential into
            // circulation for one server.
            Assert.Equal(0, await daemon.SignWaitingAsync());

            var first = Activate(code, ServerA).Licence;
            var again = Activate(code, ServerA).Licence;

            Assert.Equal(first, again);
        }

        [Fact]
        public async Task It_cannot_issue_anything_a_person_could_not()
        {
            // It signs through SigningDesk, so the terms it signs are the ones
            // the store recorded - not anything it chooses. The licence that
            // comes out names the server that activated, and expires when the
            // code says, and would be refused by the desk if it did not.
            var code = _service.GiveOutACode(licenceDays: 30);

            Activate(code, ServerA);

            var expected = _service.Desk.Download().Requests.Single();

            Assert.Equal(1, await Daemon().SignWaitingAsync());

            var row = _service.Store.FindSigningRequest(expected.RequestId);

            Assert.NotNull(row.Licence);
            Assert.Equal(expected.ServerId, row.ServerId);
            Assert.Equal(expected.Expires, row.Expires);
            Assert.Equal(_service.Key.Thumbprint, row.KeyId);
        }

        [Fact]
        public async Task A_signed_licence_is_written_to_the_ledger()
        {
            var code = _service.GiveOutACode();

            Activate(code, ServerA);

            await Daemon().SignWaitingAsync();

            var line = Assert.Single(System.IO.File.ReadAllLines(_service.Options.LedgerPath));

            Assert.Contains(ServerA, line, StringComparison.Ordinal);
        }

        [Fact]
        public async Task One_press_of_activate_is_enough_when_a_signer_is_running()
        {
            // The whole point of the feature. ActivateAsync holds the request
            // open for a few seconds, so an activation that arrives while the
            // signer is working answers with a licence rather than with "come
            // back later".
            var code = _service.GiveOutACode();
            var daemon = Daemon();

            using var signer = new CancellationTokenSource();

            // Stands in for the background loop, at the same cadence.
            var running = Task.Run(async () =>
            {
                while (!signer.IsCancellationRequested)
                {
                    await daemon.SignWaitingAsync();

                    try
                    {
                        await Task.Delay(TimeSpan.FromMilliseconds(50), signer.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                }
            });

            try
            {
                _service.Activations.SignatureWait = TimeSpan.FromSeconds(1);

                var reply = await _service.Activations.ActivateAsync(
                    new ActivationRequest { Code = code, ServerId = ServerA, PluginVersion = "1.4.0" },
                    "10.0.0.1");

                Assert.True(reply.IsSuccess, "one press should be enough: " + reply.Error);
                Assert.False(string.IsNullOrEmpty(reply.Licence));
            }
            finally
            {
                signer.Cancel();
                await running;
            }
        }

        [Fact]
        public async Task Without_a_signer_the_customer_is_told_to_come_back()
        {
            // The other half: with nothing signing, the wait times out on its
            // own and the answer is the pending reply. No cancellation token -
            // the timeout is measured with a stopwatch rather than the injected
            // clock, so this test running against a FROZEN clock is exactly the
            // case that would hang if that were ever changed back.
            var code = _service.GiveOutACode();

            _service.Activations.SignatureWait = TimeSpan.FromSeconds(1);

            var reply = await _service.Activations.ActivateAsync(
                new ActivationRequest { Code = code, ServerId = ServerA, PluginVersion = "1.4.0" },
                "10.0.0.1");

            Assert.False(reply.IsSuccess);
            Assert.Equal(ActivationError.PendingSignature, reply.Error);
            Assert.Null(reply.Licence);

            // And the request is still there for a signer to pick up later.
            Assert.Equal(1, _service.Store.CountWaitingToBeSigned());
        }

        private SigningDaemon Daemon()
        {
            return new SigningDaemon(
                _service.Desk,
                _service.Key,
                _service.Clock,
                NullLogger<SigningDaemon>.Instance);
        }

        private ActivationReply Activate(string code, string serverId)
        {
            return _service.Activations.Activate(
                new ActivationRequest { Code = code, ServerId = serverId, PluginVersion = "1.4.0" },
                "10.0.0.1");
        }
    }
}

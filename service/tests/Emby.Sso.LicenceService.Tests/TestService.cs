using System;
using System.IO;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.PayPal;
using Emby.Sso.LicenceService.RateLimiting;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging.Abstractions;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// A whole service in a temporary directory: real SQLite store, real ledger
    /// and outbox files, and a real keypair standing in for the vendor's offline
    /// signing machine. Nothing is mocked except the clock and, where the test is
    /// about the crypto rather than the network, PayPal's certificate.
    ///
    /// THE KEY IS NOT THE SERVICE'S. The service under test holds only the
    /// PUBLIC half, because that is all the real one holds - see
    /// Signing.SigningDesk. <see cref="Key"/> and <see cref="Sign"/> play the
    /// part of the person with the private key, so a test that wants an
    /// activated licence does what an operator does: activate, sign, activate.
    ///
    /// Using the real store rather than an in-memory fake is deliberate. Half of
    /// what the activation cap relies on IS the database - a UNIQUE index and an
    /// IMMEDIATE transaction - and a fake would test the half that is not.
    /// </summary>
    internal sealed class TestService : IDisposable
    {
        public TestService(Action<ServiceOptions> configure = null)
        {
            Directory = TestKeys.TempDirectory();
            KeyPath = TestKeys.WritePrivateKey(Directory);

            Key = SigningKeyFile.Load(KeyPath);

            Options = new ServiceOptions
            {
                PublicKeys = Key.PublicJwk,
                DataDirectory = Directory,
                ActivationsAllowed = 3,
                LicenceDays = 365,
            };

            Options.PayPal.WebhookId = "WH-TEST-0001";
            Options.PayPal.Currency = "GBP";
            Options.PayPal.Price = "19.00";
            Options.PayPal.MinimumAmount = "19.00";

            // Effectively off unless a test asks for it. A test about the
            // activation state machine that fails because it tripped the rate
            // limiter is a test that lies about what it is checking; the limiter
            // has its own tests, which set their own numbers.
            Options.RateLimit.PerClientBurst = 100000;
            Options.RateLimit.PerClientPerMinute = 100000;
            Options.RateLimit.GlobalPerMinute = 100000;

            configure?.Invoke(Options);

            Clock = new TestClock(new DateTimeOffset(2026, 1, 5, 12, 0, 0, TimeSpan.Zero));
            Store = new LicenceStore(Options.DatabasePath);
            Store.Initialise();

            Ledger = new LicenceLedger(Options.LedgerPath);
            Outbox = new CodeOutbox(Options.OutboxPath);
            Limiter = new ActivationRateLimiter(Options.RateLimit, Clock);

            Activations = new ActivationService(
                Store,
                Limiter,
                Options,
                Clock,
                NullLogger<ActivationService>.Instance);

            Desk = new Signing.SigningDesk(
                Store,
                Ledger,
                Configuration.TrustedKeys.Parse(Key.PublicJwk),
                Options,
                Clock,
                NullLogger<Signing.SigningDesk>.Instance);
        }

        public string Directory { get; }

        public string KeyPath { get; }

        public ServiceOptions Options { get; }

        public TestClock Clock { get; }

        public SigningKeyFile.SigningKey Key { get; }

        public LicenceStore Store { get; }

        public LicenceLedger Ledger { get; }

        public CodeOutbox Outbox { get; }

        public ActivationRateLimiter Limiter { get; }

        public ActivationService Activations { get; }

        public Signing.SigningDesk Desk { get; }

        /// <summary>
        /// Plays the vendor: takes everything waiting, signs it with the private
        /// key, and uploads the result exactly as the admin page would. Returns
        /// how many licences were stored.
        ///
        /// This is the whole offline-signing round trip, and tests go through it
        /// rather than reaching into the store, so that a change which breaks the
        /// exchange format breaks the tests that depend on licences existing.
        /// </summary>
        public int Sign()
        {
            var requests = Desk.Download();

            if (requests.Requests.Count == 0)
            {
                return 0;
            }

            var issuer = new LicenceIssuer(Key.Key);
            var signed = new SignedLicenceFile
            {
                SignedUtc = LicenceFormat.Iso(Clock.GetUtcNow()),
                KeyId = Key.Thumbprint,
            };

            foreach (var request in requests.Requests)
            {
                signed.Licences.Add(new SignedLicence
                {
                    RequestId = request.RequestId,
                    Licence = issuer.Issue(
                        request.Licensee,
                        request.ServerId,
                        request.IssuedAtUtc,
                        request.ExpiresUtc).Token,
                });
            }

            var report = Desk.UploadAsync(SigningExchange.Write(signed)).GetAwaiter().GetResult();

            return report.Stored;
        }

        /// <summary>
        /// Activate, sign what that asked for, activate again - which is what a
        /// customer and the vendor between them actually do. Returns the second
        /// reply, the one that carries the licence.
        /// </summary>
        public Activation.ActivationReply ActivateAndSign(Activation.ActivationRequest request, string clientKey)
        {
            Activations.Activate(request, clientKey);
            Sign();

            return Activations.Activate(request, clientKey);
        }

        /// <summary>
        /// The webhook handler. <paramref name="mail"/> is null by default, which
        /// is the unconfigured service: no SMTP_HOST, no mailer, outbox only.
        /// </summary>
        public PayPalWebhookHandler Webhooks(
            IPayPalCertificateSource certificates,
            Delivery.CodeDeliveryQueue mail = null,
            Microsoft.Extensions.Logging.ILogger<PayPalWebhookHandler> log = null)
        {
            return new PayPalWebhookHandler(
                new PayPalWebhookVerifier(certificates, Options.PayPal),
                Store,
                Outbox,
                Options,
                Clock,
                log ?? NullLogger<PayPalWebhookHandler>.Instance,
                mail);
        }

        /// <summary>Creates a paid code directly, for tests that are about activation rather than payment.</summary>
        public string GiveOutACode(int activationsAllowed = 3, int licenceDays = 365)
        {
            var code = RedemptionCode.Generate();

            Store.CreateManualCode(
                RedemptionCode.Hash(code),
                "test",
                activationsAllowed,
                licenceDays,
                null,
                Clock.GetUtcNow());

            return RedemptionCode.Format(code);
        }

        public void Dispose()
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

            try
            {
                System.IO.Directory.Delete(Directory, recursive: true);
            }
            catch (IOException)
            {
                // A test that leaves a file locked should not fail the run it is
                // otherwise passing.
            }
        }
    }
}

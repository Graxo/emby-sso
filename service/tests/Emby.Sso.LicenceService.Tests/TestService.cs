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
    /// A whole service in a temporary directory: real signing key, real SQLite
    /// store, real ledger and outbox files. Nothing is mocked except the clock
    /// and, where the test is about the crypto rather than the network, PayPal's
    /// certificate.
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

            Options = new ServiceOptions
            {
                SigningKeyPath = KeyPath,
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
            Key = SigningKeyFile.Load(KeyPath);
            Store = new LicenceStore(Options.DatabasePath);
            Store.Initialise();

            Ledger = new LicenceLedger(Options.LedgerPath);
            Outbox = new CodeOutbox(Options.OutboxPath);
            Limiter = new ActivationRateLimiter(Options.RateLimit, Clock);

            Activations = new ActivationService(
                Store,
                new LicenceIssuer(Key.Key),
                Ledger,
                Limiter,
                Options,
                Clock,
                NullLogger<ActivationService>.Instance);
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

        public PayPalWebhookHandler Webhooks(IPayPalCertificateSource certificates)
        {
            return new PayPalWebhookHandler(
                new PayPalWebhookVerifier(certificates, Options.PayPal),
                Store,
                Outbox,
                Options,
                Clock,
                NullLogger<PayPalWebhookHandler>.Instance);
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

using System;
using System.Collections.Generic;
using System.Linq;
using Emby.Sso.LicenceService.Configuration;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// Configuration is the only way anything gets into this service, so a
    /// mistake in it is the most likely way the service is wrong in production.
    /// Everything here is about failing at startup rather than at the first sale.
    /// </summary>
    public class ServiceOptionsTests
    {
        [Fact]
        public void A_complete_configuration_has_no_problems()
        {
            Assert.Empty(Read(Complete()).Problems());
        }

        [Fact]
        public void The_defaults_are_the_contracts_defaults()
        {
            var options = Read(Complete());

            Assert.Equal(3, options.ActivationsAllowed);
            Assert.Equal(365, options.LicenceDays);
            Assert.Equal(0, options.TrustedProxyHops);
            Assert.Equal(PayPalOptions.Sandbox, options.PayPal.Environment);
            Assert.False(options.PayPal.IsLive);
        }

        [Fact]
        public void A_signing_key_path_turns_on_self_service_signing()
        {
            // LICENCE_SIGNING_KEY_PATH is the switch between the two ways this
            // service can work, and it is not a misconfiguration either way.
            //
            //   set    it signs licences itself, so a customer who activates
            //          gets one immediately - and the private key is loaded by
            //          the process that answers the internet.
            //   unset  it cannot sign; an operator signs elsewhere and uploads
            //          at /admin/signing. Safer, and not instant.
            //
            // Signing.SigningDaemon carries the reasoning. What matters here is
            // that neither is refused, because a refusal would make one of them
            // unreachable.
            var environment = Complete();

            Assert.False(Read(environment).SignsItsOwnLicences);
            Assert.Empty(Read(environment).Problems());

            environment["LICENCE_SIGNING_KEY_PATH"] = "/run/secrets/licence-signing-key.private.json";

            var options = Read(environment);

            Assert.True(options.SignsItsOwnLicences);
            Assert.Equal("/run/secrets/licence-signing-key.private.json", options.SigningKeyPath);
            Assert.Empty(options.Problems());
        }

        [Fact]
        public void Without_trusted_public_keys_it_refuses_to_start()
        {
            // With none, nothing signed could ever be checked before it is
            // stored, and the first anyone would know is a customer's server
            // refusing a licence.
            var environment = Complete();

            environment.Remove("LICENCE_PUBLIC_KEYS");

            Assert.Contains(Read(environment).Problems(), p => p.Contains("LICENCE_PUBLIC_KEYS", StringComparison.Ordinal));
        }

        [Fact]
        public void A_private_key_pasted_into_the_public_key_list_refuses_to_start()
        {
            // The one mistake that would put a signing key back on this host,
            // in a variable rather than a mount. Caught by name.
            var environment = Complete();

            environment["LICENCE_PUBLIC_KEYS"] =
                "{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"d\":\"AQAB\"}";

            Assert.Contains(
                Read(environment).Problems(),
                p => p.Contains("PRIVATE", StringComparison.Ordinal));
        }

        [Fact]
        public void Without_a_webhook_id_it_refuses_to_start()
        {
            // Without it there is nothing to verify a signature against, so every
            // webhook would be refused - silently, at the moment somebody pays.
            var environment = Complete();

            environment.Remove("PAYPAL_WEBHOOK_ID");

            Assert.Contains(Read(environment).Problems(), p => p.Contains("PAYPAL_WEBHOOK_ID", StringComparison.Ordinal));
        }

        [Fact]
        public void Without_a_minimum_amount_it_refuses_to_start()
        {
            var environment = Complete();

            environment.Remove("PAYPAL_PRICE");
            environment.Remove("PAYPAL_MINIMUM_AMOUNT");

            Assert.Contains(Read(environment).Problems(), p => p.Contains("PAYPAL_MINIMUM_AMOUNT", StringComparison.Ordinal));
        }

        [Fact]
        public void The_minimum_amount_defaults_to_the_price()
        {
            var options = Read(Complete());

            Assert.Equal("19.00", options.PayPal.MinimumAmount);
        }

        [Fact]
        public void There_is_no_environment_variable_that_turns_signature_checking_off()
        {
            // The brief: "do not ship a 'verification skipped' mode that could be
            // left on". This asserts the absence of one - every property of
            // PayPalOptions is inspected, and none of them is a switch that could
            // weaken verification.
            var suspicious = new[] { "skip", "disable", "insecure", "unsafe", "bypass", "nocheck", "trustall" };

            foreach (var property in typeof(PayPalOptions).GetProperties())
            {
                foreach (var word in suspicious)
                {
                    Assert.False(
                        property.Name.Contains(word, StringComparison.OrdinalIgnoreCase),
                        "PayPalOptions." + property.Name + " looks like a way to turn verification off");
                }
            }
        }

        [Theory]
        [InlineData("PAYPAL_ENV", "production")]
        [InlineData("PAYPAL_ENV", "live-ish")]
        [InlineData("LICENCE_ACTIVATIONS_ALLOWED", "0")]
        [InlineData("LICENCE_ACTIVATIONS_ALLOWED", "banana")]
        [InlineData("LICENCE_DAYS", "0")]
        [InlineData("LICENCE_DAYS", "-5")]
        [InlineData("LICENCE_RATE_PER_CLIENT_PER_MINUTE", "0")]
        [InlineData("LICENCE_RATE_GLOBAL_PER_MINUTE", "nonsense")]
        [InlineData("PAYPAL_PRICE", "nineteen pounds")]
        [InlineData("PAYPAL_CURRENCY", "POUNDS")]
        [InlineData("LICENCE_PUBLIC_BASE_URL", "http://licence.example.com")]
        [InlineData("LICENCE_PUBLIC_BASE_URL", "licence.example.com")]
        public void A_value_that_cannot_be_honoured_is_a_refusal_to_start(string name, string value)
        {
            var environment = Complete();

            environment[name] = value;

            Assert.NotEmpty(Read(environment).Problems());
        }

        [Fact]
        public void A_mistyped_number_is_never_silently_the_default()
        {
            // A limit that quietly becomes 10 because somebody typed "1O" is a
            // limit nobody knows the value of.
            var environment = Complete();

            environment["LICENCE_RATE_PER_CLIENT_PER_MINUTE"] = "1O";

            Assert.NotEmpty(Read(environment).Problems());
        }

        [Fact]
        public void The_return_and_cancel_urls_are_derived_from_the_public_base_url()
        {
            var environment = Complete();

            environment["LICENCE_PUBLIC_BASE_URL"] = "https://licence.koper.cloud/";

            var options = Read(environment);

            Assert.Equal("https://licence.koper.cloud/buy/complete", options.PayPal.ReturnUrl);
            Assert.Equal("https://licence.koper.cloud/buy/cancelled", options.PayPal.CancelUrl);
        }

        [Fact]
        public void An_explicit_return_url_wins_over_the_derived_one()
        {
            var environment = Complete();

            environment["LICENCE_PUBLIC_BASE_URL"] = "https://licence.koper.cloud";
            environment["PAYPAL_RETURN_URL"] = "https://shop.example.com/thanks";

            Assert.Equal("https://shop.example.com/thanks", Read(environment).PayPal.ReturnUrl);
        }

        [Fact]
        public void Everything_wrong_is_reported_at_once_rather_than_one_restart_at_a_time()
        {
            var options = Read(new Dictionary<string, string>(StringComparer.Ordinal));

            Assert.True(options.Problems().Count >= 2, "expected several problems, got " + options.Problems().Count);
        }

        [Fact]
        public void The_data_files_all_live_under_the_mounted_volume()
        {
            var options = Read(Complete());

            Assert.StartsWith(options.DataDirectory, options.DatabasePath, StringComparison.Ordinal);
            Assert.StartsWith(options.DataDirectory, options.LedgerPath, StringComparison.Ordinal);
            Assert.StartsWith(options.DataDirectory, options.OutboxPath, StringComparison.Ordinal);

            // The ledger is the offline tool's file name, so `licencetool list`
            // reads it without being told anything.
            Assert.EndsWith("licences-issued.jsonl", options.LedgerPath, StringComparison.Ordinal);
        }

        private static ServiceOptions Read(IDictionary<string, string> environment)
        {
            return ServiceOptions.FromEnvironment(name => environment.TryGetValue(name, out var value) ? value : null);
        }

        private static Dictionary<string, string> Complete()
        {
            return new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["LICENCE_PUBLIC_KEYS"] = TestKeys.SamplePublicJwk,
                ["LICENCE_DATA_DIR"] = "/data",
                ["PAYPAL_ENV"] = "sandbox",
                ["PAYPAL_WEBHOOK_ID"] = "WH-1",
                ["PAYPAL_CURRENCY"] = "GBP",
                ["PAYPAL_PRICE"] = "19.00",
            };
        }
    }
}

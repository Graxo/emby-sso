using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace Emby.Sso.LicenceService.Configuration
{
    /// <summary>
    /// Everything the service is told, and it is told all of it through the
    /// environment.
    ///
    /// Nothing here has a default that is a secret, and nothing here is read
    /// from a file inside the image: the image is a public artifact and an
    /// operator who pulls it must get something that cannot sell anything until
    /// they configure it. Two things are deliberately NOT configurable - see
    /// PayPalOptions.WebhookId and the absence of any "skip verification"
    /// switch.
    /// </summary>
    public sealed class ServiceOptions
    {
        public const string DefaultDataDirectory = "/data";

        /// <summary>Where the read-only mounted private key is.</summary>
        public string SigningKeyPath { get; set; }

        /// <summary>The mounted volume: SQLite store, ledger, outbox.</summary>
        public string DataDirectory { get; set; } = DefaultDataDirectory;

        /// <summary>
        /// How many distinct Emby servers one code may be activated onto. The
        /// contract's default, and the number the plugin reports back to the
        /// operator as activationsAllowed.
        /// </summary>
        public int ActivationsAllowed { get; set; } = 3;

        /// <summary>
        /// How long a licence lasts, fixed at the code's FIRST activation and
        /// carried by every licence minted from that code afterwards. Changing
        /// this affects codes sold from then on; codes already activated keep the
        /// expiry they were given, because a customer's licence must not move
        /// under them.
        /// </summary>
        public int LicenceDays { get; set; } = 365;

        /// <summary>
        /// How many reverse proxies sit in front of this service. 0 means the
        /// service is exposed directly and the socket's peer address is the
        /// client; 1 means one proxy you control appends the real client to
        /// X-Forwarded-For.
        ///
        /// GETTING THIS WRONG WEAKENS THE RATE LIMITER, in one direction only:
        /// too low and every caller is bucketed under the proxy's address, which
        /// is safe but throttles everyone together; too high and a caller can
        /// forge the header and give themselves a fresh bucket per request. It
        /// defaults to 0 for that reason.
        /// </summary>
        public int TrustedProxyHops { get; set; }

        /// <summary>
        /// The https URL this service is reached on from outside - the same one
        /// the plugin has compiled in as its service base. It is not used to
        /// route anything; it is what the PayPal return and cancel URLs are built
        /// from when those are not set explicitly, and PayPal will not accept a
        /// return URL that is not a real address.
        /// </summary>
        public string PublicBaseUrl { get; set; }

        public RateLimitOptions RateLimit { get; } = new RateLimitOptions();

        public PayPalOptions PayPal { get; } = new PayPalOptions();

        public string DatabasePath => Path.Combine(DataDirectory, "licences.db");

        public string LedgerPath => Path.Combine(DataDirectory, Licensing.LicenceFormat.LedgerFileName);

        public string OutboxPath => Path.Combine(DataDirectory, "codes-outbox.jsonl");

        public static ServiceOptions FromEnvironment(Func<string, string> read)
        {
            if (read == null)
            {
                throw new ArgumentNullException(nameof(read));
            }

            var options = new ServiceOptions
            {
                SigningKeyPath = Text(read, "LICENCE_SIGNING_KEY_PATH"),
                DataDirectory = Text(read, "LICENCE_DATA_DIR") ?? DefaultDataDirectory,
                ActivationsAllowed = Number(read, "LICENCE_ACTIVATIONS_ALLOWED", 3),
                LicenceDays = Number(read, "LICENCE_DAYS", 365),
                TrustedProxyHops = Number(read, "LICENCE_TRUSTED_PROXY_HOPS", 0),
                PublicBaseUrl = Text(read, "LICENCE_PUBLIC_BASE_URL"),
            };

            options.RateLimit.PerClientPerMinute = Number(read, "LICENCE_RATE_PER_CLIENT_PER_MINUTE", 10);
            options.RateLimit.PerClientBurst = Number(read, "LICENCE_RATE_PER_CLIENT_BURST", 5);
            options.RateLimit.GlobalPerMinute = Number(read, "LICENCE_RATE_GLOBAL_PER_MINUTE", 300);
            options.RateLimit.MaxTrackedClients = Number(read, "LICENCE_RATE_MAX_TRACKED_CLIENTS", 20000);

            options.PayPal.Environment = Text(read, "PAYPAL_ENV") ?? PayPalOptions.Sandbox;
            options.PayPal.WebhookId = Text(read, "PAYPAL_WEBHOOK_ID");
            options.PayPal.ClientId = Text(read, "PAYPAL_CLIENT_ID");
            options.PayPal.ClientSecret = Text(read, "PAYPAL_CLIENT_SECRET");
            options.PayPal.Currency = Text(read, "PAYPAL_CURRENCY") ?? "GBP";
            options.PayPal.Price = Text(read, "PAYPAL_PRICE");
            options.PayPal.MinimumAmount = Text(read, "PAYPAL_MINIMUM_AMOUNT") ?? options.PayPal.Price;
            options.PayPal.ProductName = Text(read, "PAYPAL_PRODUCT_NAME") ?? "Emby SSO plugin licence";
            options.PayPal.ReturnUrl = Text(read, "PAYPAL_RETURN_URL");
            options.PayPal.CancelUrl = Text(read, "PAYPAL_CANCEL_URL");

            // Derived rather than required twice. An operator who has told the
            // service its own address should not also have to spell out two URLs
            // underneath it, and getting them subtly wrong is how a buyer ends up
            // on somebody else's page after paying.
            if (!string.IsNullOrWhiteSpace(options.PublicBaseUrl))
            {
                var root = options.PublicBaseUrl.TrimEnd('/');

                options.PayPal.ReturnUrl ??= root + "/buy/complete";
                options.PayPal.CancelUrl ??= root + "/buy/cancelled";
            }

            return options;
        }

        /// <summary>
        /// Everything wrong with this configuration, all at once. A list rather
        /// than the first failure, so an operator bringing the service up for the
        /// first time gets one round of corrections rather than six restarts.
        ///
        /// An empty list is the only thing that starts the service.
        /// </summary>
        public IReadOnlyList<string> Problems()
        {
            var problems = new List<string>();

            if (string.IsNullOrWhiteSpace(SigningKeyPath))
            {
                problems.Add(
                    "LICENCE_SIGNING_KEY_PATH is not set. It must point at the "
                    + Licensing.LicenceFormat.PrivateKeyFileName + " mounted read-only into this container.");
            }

            if (string.IsNullOrWhiteSpace(DataDirectory))
            {
                problems.Add("LICENCE_DATA_DIR is empty. It must be a writable mounted volume that survives a restart.");
            }

            if (ActivationsAllowed < 1)
            {
                problems.Add("LICENCE_ACTIVATIONS_ALLOWED must be at least 1; a code nobody can activate is not a product.");
            }

            if (LicenceDays < 1)
            {
                problems.Add("LICENCE_DAYS must be at least 1; a licence must expire, and it must be usable first.");
            }

            if (TrustedProxyHops < 0)
            {
                problems.Add("LICENCE_TRUSTED_PROXY_HOPS cannot be negative.");
            }

            if (!string.IsNullOrWhiteSpace(PublicBaseUrl))
            {
                if (!Uri.TryCreate(PublicBaseUrl, UriKind.Absolute, out var url)
                    || !string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
                {
                    problems.Add(
                        "LICENCE_PUBLIC_BASE_URL must be an absolute https URL, e.g. https://licence.example.com. "
                        + "It is the address the plugin has compiled in and the address PayPal sends buyers back to.");
                }
            }

            problems.AddRange(RateLimit.Problems());
            problems.AddRange(PayPal.Problems());

            return problems;
        }

        private static string Text(Func<string, string> read, string name)
        {
            var value = read(name);

            return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        }

        private static int Number(Func<string, string> read, string name, int fallback)
        {
            var value = Text(read, name);

            if (value == null)
            {
                return fallback;
            }

            if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
            {
                // Not a silent fallback: a mistyped limit that quietly becomes
                // the default is a limit nobody knows the value of. -1 fails
                // Problems() below with the variable named.
                return -1;
            }

            return number;
        }
    }

    /// <summary>
    /// See <see cref="RateLimiting.ActivationRateLimiter"/> for what these
    /// guarantee. The defaults assume a real customer activates a handful of
    /// times in a lifetime and never twice in a second.
    /// </summary>
    public sealed class RateLimitOptions
    {
        public int PerClientPerMinute { get; set; } = 10;

        public int PerClientBurst { get; set; } = 5;

        public int GlobalPerMinute { get; set; } = 300;

        /// <summary>
        /// The limiter is a dictionary keyed by client address, so an attacker
        /// with a large address space could otherwise make it grow without
        /// bound. Past this many tracked clients the oldest idle entries are
        /// dropped; dropping one only ever costs an attacker's own budget, since
        /// an entry is only idle if it has not been used for a full window.
        /// </summary>
        public int MaxTrackedClients { get; set; } = 20000;

        public IReadOnlyList<string> Problems()
        {
            var problems = new List<string>();

            if (PerClientPerMinute < 1)
            {
                problems.Add("LICENCE_RATE_PER_CLIENT_PER_MINUTE must be a positive number.");
            }

            if (PerClientBurst < 1)
            {
                problems.Add("LICENCE_RATE_PER_CLIENT_BURST must be a positive number.");
            }

            if (GlobalPerMinute < 1)
            {
                problems.Add("LICENCE_RATE_GLOBAL_PER_MINUTE must be a positive number.");
            }

            if (MaxTrackedClients < 1)
            {
                problems.Add("LICENCE_RATE_MAX_TRACKED_CLIENTS must be a positive number.");
            }

            return problems;
        }
    }

    /// <summary>
    /// PayPal, sandbox or live. The only difference between the two is the host
    /// and the credentials; there is no third mode, and in particular there is
    /// no mode in which a webhook is accepted without its signature being
    /// checked.
    /// </summary>
    public sealed class PayPalOptions
    {
        public const string Sandbox = "sandbox";
        public const string Live = "live";

        public string Environment { get; set; } = Sandbox;

        /// <summary>
        /// The id of the webhook as PayPal registered it. IT IS PART OF THE
        /// SIGNATURE: the signed message is
        /// transmissionId|transmissionTime|webhookId|crc32(body), so a signature
        /// PayPal produced for somebody else's webhook does not verify against
        /// this one. Configuring the wrong id fails every webhook closed, which
        /// is the correct direction to fail.
        /// </summary>
        public string WebhookId { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string Currency { get; set; } = "GBP";

        /// <summary>What checkout charges.</summary>
        public string Price { get; set; }

        /// <summary>
        /// The least a capture may be worth and still buy a code. Defaults to
        /// <see cref="Price"/>. Without it, a captured payment for one penny -
        /// from an order built by hand against the same account - buys a
        /// licence, because the webhook only says money arrived.
        /// </summary>
        public string MinimumAmount { get; set; }

        public string ProductName { get; set; } = "Emby SSO plugin licence";

        public string ReturnUrl { get; set; }

        public string CancelUrl { get; set; }

        public bool IsLive => string.Equals(Environment, Live, StringComparison.OrdinalIgnoreCase);

        public string ApiBase => IsLive ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";

        /// <summary>Whether /v1/checkout can work at all. The webhook does not need these.</summary>
        public bool CheckoutConfigured =>
            !string.IsNullOrWhiteSpace(ClientId)
            && !string.IsNullOrWhiteSpace(ClientSecret)
            && !string.IsNullOrWhiteSpace(Price);

        public IReadOnlyList<string> Problems()
        {
            var problems = new List<string>();

            if (!string.Equals(Environment, Sandbox, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(Environment, Live, StringComparison.OrdinalIgnoreCase))
            {
                problems.Add("PAYPAL_ENV must be exactly 'sandbox' or 'live'.");
            }

            if (string.IsNullOrWhiteSpace(WebhookId))
            {
                problems.Add(
                    "PAYPAL_WEBHOOK_ID is not set. Every webhook would be rejected, because the webhook id is "
                    + "part of the message PayPal signs and there is nothing to check the signature against.");
            }

            if (!string.IsNullOrWhiteSpace(Price) && !Money.TryParse(Price, out _))
            {
                problems.Add("PAYPAL_PRICE must be a decimal amount like 19.00.");
            }

            if (!string.IsNullOrWhiteSpace(MinimumAmount) && !Money.TryParse(MinimumAmount, out _))
            {
                problems.Add("PAYPAL_MINIMUM_AMOUNT must be a decimal amount like 19.00.");
            }

            if (string.IsNullOrWhiteSpace(MinimumAmount))
            {
                problems.Add(
                    "PAYPAL_MINIMUM_AMOUNT is not set and PAYPAL_PRICE gives it no default. Without a floor, a "
                    + "captured payment of any size buys a licence.");
            }

            if (Currency != null && Currency.Length != 3)
            {
                problems.Add("PAYPAL_CURRENCY must be a three-letter ISO code, e.g. GBP.");
            }

            return problems;
        }
    }

    /// <summary>
    /// Amounts arrive from PayPal as strings and are compared against a
    /// configured string. Parsing both with the invariant culture, once, is the
    /// difference between "19.00" and "19,00" meaning the same thing to the
    /// service as they do to PayPal.
    /// </summary>
    public static class Money
    {
        public static bool TryParse(string value, out decimal amount)
        {
            return decimal.TryParse(
                value,
                NumberStyles.AllowDecimalPoint | NumberStyles.AllowLeadingSign,
                CultureInfo.InvariantCulture,
                out amount);
        }
    }
}

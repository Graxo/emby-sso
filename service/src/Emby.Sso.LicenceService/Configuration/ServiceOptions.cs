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

        /// <summary>
        /// How a redemption code reaches the person who paid for it. Entirely
        /// optional: with no SMTP_HOST the service behaves exactly as it did
        /// before mail existed, and the outbox is the delivery mechanism.
        /// </summary>
        public MailOptions Mail { get; } = new MailOptions();

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

            // SMTP_HOST alone decides whether mail is attempted at all. Every
            // other SMTP_* variable is inert without it, and setting one of them
            // without it is a configuration problem rather than a silent no-op -
            // an operator who has filled in a password believes mail is on.
            options.Mail.Host = Text(read, "SMTP_HOST");
            options.Mail.Security = Text(read, "SMTP_SECURITY") ?? MailOptions.StartTls;
            options.Mail.Port = Number(read, "SMTP_PORT", MailOptions.DefaultPortFor(options.Mail.Security));
            options.Mail.Username = Text(read, "SMTP_USERNAME");

            // Deliberately not trimmed and not Text(): a password may legitimately
            // begin or end with a space, and silently eating one turns a working
            // relay into an authentication failure nobody can see the cause of.
            options.Mail.Password = read("SMTP_PASSWORD");

            options.Mail.FromAddress = Text(read, "SMTP_FROM_ADDRESS");
            options.Mail.FromName = Text(read, "SMTP_FROM_NAME") ?? MailOptions.DefaultFromName;
            options.Mail.ReplyTo = Text(read, "SMTP_REPLY_TO");
            options.Mail.Subject = Text(read, "SMTP_SUBJECT") ?? MailOptions.DefaultSubject;
            options.Mail.ProductName = options.PayPal.ProductName;
            options.Mail.SupportContact = Text(read, "SMTP_SUPPORT_CONTACT");
            options.Mail.TemplatePath = Text(read, "SMTP_TEMPLATE_PATH");
            options.Mail.TimeoutSeconds = Number(read, "SMTP_TIMEOUT_SECONDS", 30);
            options.Mail.MaxAttempts = Number(read, "SMTP_MAX_ATTEMPTS", 4);
            options.Mail.RetrySeconds = Number(read, "SMTP_RETRY_SECONDS", 30);

            // Whoever the buyer should reply to if the code does not work. The
            // reply-to if there is one, otherwise the from address: a message
            // that tells a paying customer to contact nobody is worse than one
            // that tells them to reply to it.
            options.Mail.SupportContact ??= options.Mail.ReplyTo ?? options.Mail.FromAddress;

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
            problems.AddRange(Mail.Problems());

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
    /// SMTP, and the shape of the message a buyer gets.
    ///
    /// THE WHOLE THING IS OPTIONAL AND OFF BY DEFAULT. Without SMTP_HOST the
    /// service does exactly what it did before this existed: the code goes to
    /// codes-outbox.jsonl and a human sends it. That was the operator's working
    /// arrangement and turning mail on must be a decision they make, not a
    /// default they discover.
    ///
    /// There is deliberately no way to turn certificate validation off, no way
    /// to accept a self-signed relay certificate, and no "try STARTTLS and carry
    /// on in the clear if it is not offered" mode - see MailSecurity. A switch
    /// that downgrades a connection carrying a bearer credential is the same
    /// class of thing as a switch that skips webhook verification, and this
    /// service does not have one of those either.
    /// </summary>
    public sealed class MailOptions
    {
        /// <summary>Implicit TLS. The whole session is inside TLS from the first byte. Port 465.</summary>
        public const string ImplicitTls = "tls";

        /// <summary>
        /// Plain connection upgraded by STARTTLS, and REQUIRED to upgrade: a
        /// server that does not offer STARTTLS fails the send rather than
        /// carrying on in the clear. Port 587. The default.
        /// </summary>
        public const string StartTls = "starttls";

        /// <summary>
        /// No encryption at all. Legitimate for a relay on localhost or a
        /// trusted LAN, and a disclosure of every code sent through it anywhere
        /// else. Port 25.
        /// </summary>
        public const string NoEncryption = "none";

        public const string DefaultFromName = "Emby SSO licences";

        public const string DefaultSubject = "Your Emby SSO plugin licence code";

        public string Host { get; set; }

        public int Port { get; set; } = 587;

        public string Security { get; set; } = StartTls;

        public string Username { get; set; }

        /// <summary>
        /// NEVER LOG THIS. It is treated the way PAYPAL_CLIENT_SECRET is: read
        /// from the environment, handed to one library call, and named nowhere
        /// else. <see cref="Describe"/> is what goes in a log line.
        /// </summary>
        public string Password { get; set; }

        public string FromAddress { get; set; }

        public string FromName { get; set; } = DefaultFromName;

        public string ReplyTo { get; set; }

        public string Subject { get; set; } = DefaultSubject;

        /// <summary>
        /// What the message calls the thing they bought. Not its own variable:
        /// it is PAYPAL_PRODUCT_NAME, so the name on the PayPal receipt and the
        /// name in the email cannot drift apart.
        /// </summary>
        public string ProductName { get; set; }

        /// <summary>Where the message tells the buyer to go when the code does not work.</summary>
        public string SupportContact { get; set; }

        /// <summary>
        /// An optional plain-text template file, so the wording can be changed
        /// without rebuilding the image. Read once at startup; a missing file is
        /// a refusal to start rather than a surprise at the first sale.
        /// </summary>
        public string TemplatePath { get; set; }

        public int TimeoutSeconds { get; set; } = 30;

        /// <summary>
        /// How many times one code's message is attempted before the outbox is
        /// left to be the delivery mechanism. Bounded, because an unbounded
        /// retry against a permanently wrong host is a queue that never drains.
        /// </summary>
        public int MaxAttempts { get; set; } = 4;

        /// <summary>The first backoff, quadrupled each attempt: 30s, 2m, 8m.</summary>
        public int RetrySeconds { get; set; } = 30;

        /// <summary>The one switch. Mail is attempted if and only if this is true.</summary>
        public bool Configured => !string.IsNullOrWhiteSpace(Host);

        public bool UsesAuthentication => !string.IsNullOrWhiteSpace(Username);

        public bool IsEncrypted => !string.Equals(Security, NoEncryption, StringComparison.OrdinalIgnoreCase);

        public static int DefaultPortFor(string security)
        {
            if (string.Equals(security, ImplicitTls, StringComparison.OrdinalIgnoreCase))
            {
                return 465;
            }

            if (string.Equals(security, NoEncryption, StringComparison.OrdinalIgnoreCase))
            {
                return 25;
            }

            return 587;
        }

        /// <summary>
        /// What a log line is allowed to say about this configuration. The
        /// password is not in it and there is no overload that puts it in.
        /// </summary>
        public string Describe()
        {
            if (!Configured)
            {
                return "off (no SMTP_HOST); codes go to the outbox only";
            }

            return Host + ":" + Port.ToString(CultureInfo.InvariantCulture)
                + " " + (Security ?? "(unset)").ToLowerInvariant()
                + (UsesAuthentication ? ", authenticating as " + Username : ", no authentication")
                + ", from " + (FromAddress ?? "(unset)");
        }

        public IReadOnlyList<string> Problems()
        {
            var problems = new List<string>();

            if (!Configured)
            {
                // Mail is off. Anything else set is almost certainly an operator
                // who believes it is on, so say so rather than silently not
                // sending: that failure mode looks exactly like working.
                if (!string.IsNullOrWhiteSpace(FromAddress)
                    || !string.IsNullOrWhiteSpace(Username)
                    || !string.IsNullOrEmpty(Password)
                    || !string.IsNullOrWhiteSpace(TemplatePath))
                {
                    problems.Add(
                        "SMTP_HOST is not set but other SMTP_* variables are. Nothing would be emailed and codes "
                        + "would go to the outbox only. Set SMTP_HOST, or unset the rest so it is clear that "
                        + "delivery is by hand.");
                }

                return problems;
            }

            if (!string.Equals(Security, ImplicitTls, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(Security, StartTls, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(Security, NoEncryption, StringComparison.OrdinalIgnoreCase))
            {
                problems.Add(
                    "SMTP_SECURITY must be exactly 'tls' (implicit TLS, usually port 465), 'starttls' (usually "
                    + "587) or 'none' (usually 25). It is '" + Security + "'.");
            }

            if (Port < 1 || Port > 65535)
            {
                problems.Add("SMTP_PORT must be a port number between 1 and 65535.");
            }

            if (string.IsNullOrWhiteSpace(FromAddress))
            {
                problems.Add("SMTP_FROM_ADDRESS is not set. A relay will refuse a message with no sender, and a "
                    + "buyer needs somewhere to reply.");
            }
            else if (!LooksLikeAnAddress(FromAddress))
            {
                problems.Add("SMTP_FROM_ADDRESS does not look like an email address: '" + FromAddress + "'.");
            }

            if (!string.IsNullOrWhiteSpace(ReplyTo) && !LooksLikeAnAddress(ReplyTo))
            {
                problems.Add("SMTP_REPLY_TO does not look like an email address: '" + ReplyTo + "'.");
            }

            if (UsesAuthentication && string.IsNullOrEmpty(Password))
            {
                problems.Add("SMTP_USERNAME is set but SMTP_PASSWORD is empty.");
            }

            if (!UsesAuthentication && !string.IsNullOrEmpty(Password))
            {
                problems.Add("SMTP_PASSWORD is set but SMTP_USERNAME is empty.");
            }

            if (UsesAuthentication && !IsEncrypted)
            {
                // Refused rather than warned. SMTP AUTH over a cleartext socket
                // puts the relay password on the wire in base64 on every send,
                // and an operator who wanted an unauthenticated local relay only
                // has to unset the username.
                problems.Add(
                    "SMTP_SECURITY is 'none' and SMTP_USERNAME is set. That sends the relay password over the "
                    + "network in the clear on every message. Use 'tls' or 'starttls', or unset SMTP_USERNAME "
                    + "and SMTP_PASSWORD if the relay genuinely needs no login.");
            }

            if (TimeoutSeconds < 1 || TimeoutSeconds > 300)
            {
                problems.Add("SMTP_TIMEOUT_SECONDS must be between 1 and 300.");
            }

            if (MaxAttempts < 1 || MaxAttempts > 10)
            {
                problems.Add("SMTP_MAX_ATTEMPTS must be between 1 and 10. The outbox is the fallback after them.");
            }

            if (RetrySeconds < 1 || RetrySeconds > 3600)
            {
                problems.Add("SMTP_RETRY_SECONDS must be between 1 and 3600.");
            }

            if (!string.IsNullOrWhiteSpace(TemplatePath) && !File.Exists(TemplatePath))
            {
                problems.Add(
                    "SMTP_TEMPLATE_PATH points at '" + TemplatePath + "', which does not exist. Mount it into the "
                    + "container, or unset it to use the built-in wording.");
            }

            return problems;
        }

        /// <summary>
        /// Not RFC 5322. This exists to catch a pasted display name or a missing
        /// domain at startup rather than at the first sale; the relay is the
        /// authority on what it will accept.
        /// </summary>
        private static bool LooksLikeAnAddress(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            var at = value.IndexOf('@');

            return at > 0
                && at == value.LastIndexOf('@')
                && at < value.Length - 1
                && value.IndexOf(' ') < 0
                && value.IndexOf('.', at) > at + 1;
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

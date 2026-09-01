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

        /// <summary>
        /// LICENCE_SIGNING_KEY_PATH - the switch that makes activation
        /// self-service.
        ///
        /// SET: this service signs licences itself, the moment a customer
        /// activates, and they get one immediately. The private key is loaded by
        /// the process that answers the internet, which is what that costs - see
        /// Signing.SigningDaemon, which says it plainly and says what the
        /// alternative is.
        ///
        /// UNSET: nothing here can sign. Activations queue, and an operator
        /// signs them from /admin/signing with `licencetool sign` on a machine
        /// that answers no requests. Safer, and not instant.
        ///
        /// Both are supported and neither is deprecated. The default is unset.
        /// </summary>
        public string SigningKeyPath { get; set; }

        /// <summary>Whether this deployment signs licences itself.</summary>
        public bool SignsItsOwnLicences => !string.IsNullOrWhiteSpace(SigningKeyPath);

        /// <summary>
        /// LICENCE_PUBLIC_KEYS - one JWK or a JSON array of them. The PUBLIC
        /// halves the plugin build trusts, used to check licences uploaded from
        /// the signing machine before they are stored. Never a private key; the
        /// service refuses to start if one is given.
        /// </summary>
        public string PublicKeys { get; set; }

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

        /// <summary>
        /// LICENCE_BACKUP_PASSPHRASE. With it set, the admin page can hand the
        /// operator an ENCRYPTED copy of everything on the volume that cannot be
        /// rebuilt: who bought what, which servers are activated, which licences
        /// were issued, the outbox and the audit trail.
        ///
        /// Encrypted, not plain, because a backup of this store is the customer
        /// list plus every signed licence, and the whole point of taking it off
        /// the box is that it then lives somewhere less careful than the box -
        /// a laptop, a cloud drive, an email to yourself. Unset means the backup
        /// download does not exist; there is no unencrypted option.
        /// </summary>
        public string BackupPassphrase { get; set; }

        public RateLimitOptions RateLimit { get; } = new RateLimitOptions();

        public PayPalOptions PayPal { get; } = new PayPalOptions();

        /// <summary>
        /// How a redemption code reaches the person who paid for it. Entirely
        /// optional: with no SMTP_HOST the service behaves exactly as it did
        /// before mail existed, and the outbox is the delivery mechanism.
        /// </summary>
        public MailOptions Mail { get; } = new MailOptions();

        /// <summary>
        /// The admin page. Entirely optional and ABSENT unless a password is
        /// configured - see <see cref="AdminOptions"/>. With nothing set there
        /// is no /admin, no login form and no route: the door is not there,
        /// rather than there and unlocked.
        /// </summary>
        public AdminOptions Admin { get; } = new AdminOptions();

        public string DatabasePath => Path.Combine(DataDirectory, "licences.db");

        public string LedgerPath => Path.Combine(DataDirectory, Licensing.LicenceFormat.LedgerFileName);

        public string OutboxPath => Path.Combine(DataDirectory, "codes-outbox.jsonl");

        /// <summary>
        /// Where the admin page's audit trail is appended. Derived rather than
        /// configured: it belongs beside the store it is an account of, and on
        /// the volume that gets backed up. Nothing else writes to it.
        /// </summary>
        public string AdminAuditPath => Path.Combine(DataDirectory, "admin-audit.jsonl");

        public static ServiceOptions FromEnvironment(Func<string, string> read)
        {
            if (read == null)
            {
                throw new ArgumentNullException(nameof(read));
            }

            var options = new ServiceOptions
            {
                SigningKeyPath = Text(read, "LICENCE_SIGNING_KEY_PATH"),
                PublicKeys = Text(read, "LICENCE_PUBLIC_KEYS"),
                DataDirectory = Text(read, "LICENCE_DATA_DIR") ?? DefaultDataDirectory,
                ActivationsAllowed = Number(read, "LICENCE_ACTIVATIONS_ALLOWED", 3),
                LicenceDays = Number(read, "LICENCE_DAYS", 365),
                TrustedProxyHops = Number(read, "LICENCE_TRUSTED_PROXY_HOPS", 0),
                PublicBaseUrl = Text(read, "LICENCE_PUBLIC_BASE_URL"),

                // Not trimmed, for the same reason the passwords are not: a
                // passphrase may legitimately begin or end with a space, and
                // eating one makes a backup nobody can open.
                BackupPassphrase = read("LICENCE_BACKUP_PASSPHRASE"),
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

            // The admin page. Not trimmed, for the same reason SMTP_PASSWORD is
            // not: a password may legitimately begin or end with a space, and
            // eating one turns a correct password into a wrong one with no
            // visible cause.
            options.Admin.PasswordHash = Text(read, "ADMIN_PASSWORD_HASH");
            options.Admin.Password = read("ADMIN_PASSWORD");
            options.Admin.IdleMinutes = Number(read, "ADMIN_SESSION_IDLE_MINUTES", AdminOptions.DefaultIdleMinutes);
            options.Admin.AbsoluteMinutes =
                Number(read, "ADMIN_SESSION_ABSOLUTE_MINUTES", AdminOptions.DefaultAbsoluteMinutes);
            options.Admin.LoginDelaySeconds =
                Number(read, "ADMIN_LOGIN_DELAY_SECONDS", AdminOptions.DefaultLoginDelaySeconds);
            options.Admin.LoginMaxDelaySeconds =
                Number(read, "ADMIN_LOGIN_MAX_DELAY_SECONDS", AdminOptions.DefaultLoginMaxDelaySeconds);

            // Defence in depth in front of the password. Both optional, both
            // fail closed when set: see AdminOptions.
            options.Admin.AllowedNetworks = Text(read, "ADMIN_ALLOWED_CIDRS");
            options.Admin.RequiredHeaderName = Text(read, "ADMIN_REQUIRED_HEADER");
            options.Admin.RequiredHeaderValue = read("ADMIN_REQUIRED_HEADER_VALUE");

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

            if (string.IsNullOrWhiteSpace(PublicKeys))
            {
                problems.Add(
                    "LICENCE_PUBLIC_KEYS is not set. It is the PUBLIC key or keys the plugin build trusts, as one "
                    + "JWK or a JSON array of them, and it is what lets this service check a signed licence before "
                    + "storing it. `licencetool keygen` printed it; it is the same value that is in the plugin's "
                    + "LicencePublicKey.cs. It is not a secret.");
            }
            else
            {
                try
                {
                    TrustedKeys.Parse(PublicKeys);
                }
                catch (FormatException ex)
                {
                    problems.Add("LICENCE_PUBLIC_KEYS is not usable: " + ex.Message);
                }
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

            if (!string.IsNullOrEmpty(BackupPassphrase) && BackupPassphrase.Length < 16)
            {
                problems.Add(
                    "LICENCE_BACKUP_PASSPHRASE is shorter than 16 characters. It is the only thing between a copy of "
                    + "the whole customer store and whoever finds the backup file; a short one is worse than no "
                    + "backup, because it looks like protection. Use a generated passphrase and store it somewhere "
                    + "other than beside the backups.");
            }

            problems.AddRange(RateLimit.Problems());
            problems.AddRange(PayPal.Problems());
            problems.AddRange(Mail.Problems());
            problems.AddRange(Admin.Problems());

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
    /// The admin page at /admin: whether there is one at all, and the numbers
    /// that bound a session and a guesser.
    ///
    /// THE PAGE IS ABSENT UNLESS A PASSWORD IS SET. Not open, not defaulted, not
    /// behind a warning banner - the routes are never mapped, so /admin answers
    /// exactly what /nonsense answers. An operator who has not set a password
    /// must find the door missing rather than ajar, because this page reaches
    /// the signing key by way of issuing licences and the password is the whole
    /// barrier.
    ///
    /// A password that is set and WRONG - a hash this service cannot read, a
    /// plaintext that is too short, both forms set at once - is a refusal to
    /// start rather than a missing page. Those are not "no admin configured";
    /// they are an operator who believes there is one.
    /// </summary>
    public sealed class AdminOptions
    {
        /// <summary>
        /// Long enough that the operator is not retyping a long password all
        /// afternoon, short enough that a session left open on a laptop in a
        /// cafe is not a standing invitation.
        /// </summary>
        public const int DefaultIdleMinutes = 30;

        /// <summary>
        /// The ceiling no amount of activity extends. Eight hours: one working
        /// day, after which the session is gone whatever it was doing.
        /// </summary>
        public const int DefaultAbsoluteMinutes = 480;

        /// <summary>The first wait a wrong password buys. It doubles from here.</summary>
        public const int DefaultLoginDelaySeconds = 2;

        /// <summary>
        /// Where the doubling stops. Deliberately not "locked out": see
        /// Admin.AdminLoginThrottle for why a lockout on a one-operator service
        /// is a denial of service against the only person who can lift it.
        /// </summary>
        public const int DefaultLoginMaxDelaySeconds = 60;

        /// <summary>
        /// ADMIN_PASSWORD_HASH - the supported form. See
        /// Admin.AdminPassword for what it looks like and why the environment
        /// should hold a verifier rather than a credential.
        /// </summary>
        public string PasswordHash { get; set; }

        /// <summary>
        /// ADMIN_PASSWORD - the plaintext form. Accepted, refused if weak, and
        /// second best. It is turned into a verifier at startup and the
        /// plaintext is not kept anywhere but the environment it came from.
        /// </summary>
        public string Password { get; set; }

        public int IdleMinutes { get; set; } = DefaultIdleMinutes;

        public int AbsoluteMinutes { get; set; } = DefaultAbsoluteMinutes;

        public int LoginDelaySeconds { get; set; } = DefaultLoginDelaySeconds;

        public int LoginMaxDelaySeconds { get; set; } = DefaultLoginMaxDelaySeconds;

        /// <summary>
        /// ADMIN_ALLOWED_CIDRS - a comma-separated list of networks the admin
        /// page may be reached from, e.g. "203.0.113.4/32, 10.0.0.0/8". Empty
        /// means no network restriction, which is the default and is what the
        /// password alone protects.
        ///
        /// WHY IT IS WORTH SETTING. The admin page is on the public internet
        /// behind one password. That password is a good one and the login is
        /// throttled, but it is a single factor and a single mistake - a
        /// reused password, a keylogger, a screenshot - away from being the
        /// whole story. A network restriction is a second, independent thing an
        /// attacker has to have, it costs nothing on a machine you already own,
        /// and unlike the password it cannot be phished.
        ///
        /// IT DEPENDS ON LICENCE_TRUSTED_PROXY_HOPS BEING RIGHT. Behind a proxy
        /// with the hop count set to 0, every request appears to come from the
        /// proxy, and either everyone is allowed or nobody is. See
        /// Admin.AdminAccessGate, which refuses rather than guesses.
        /// </summary>
        public string AllowedNetworks { get; set; }

        /// <summary>
        /// ADMIN_REQUIRED_HEADER and ADMIN_REQUIRED_HEADER_VALUE - a header the
        /// request must carry, with exactly this value, before the admin page
        /// exists at all.
        ///
        /// This is the hook for whatever the operator already has in front of
        /// the service: a Cloudflare Access or oauth2-proxy assertion, a client
        /// certificate the proxy verified and forwarded, or simply a long shared
        /// secret the proxy adds and the internet cannot. It is checked in
        /// constant time and before the password, so an attacker who cannot
        /// produce it never reaches a PBKDF2 verification at all.
        ///
        /// THE PROXY MUST STRIP IT FROM INCOMING REQUESTS. A header a client can
        /// set is not a check. That cannot be enforced from here, and it is said
        /// plainly in the documentation instead.
        /// </summary>
        public string RequiredHeaderName { get; set; }

        public string RequiredHeaderValue { get; set; }

        /// <summary>Whether anything beyond the password guards the admin page.</summary>
        public bool HasNetworkRestriction => !string.IsNullOrWhiteSpace(AllowedNetworks);

        public bool HasRequiredHeader => !string.IsNullOrWhiteSpace(RequiredHeaderName);

        /// <summary>
        /// The one switch. There is an admin page if and only if this is true,
        /// and there is no second way to turn one on.
        /// </summary>
        public bool Configured =>
            !string.IsNullOrWhiteSpace(PasswordHash) || !string.IsNullOrEmpty(Password);

        public bool UsesPlaintext => string.IsNullOrWhiteSpace(PasswordHash) && !string.IsNullOrEmpty(Password);

        /// <summary>
        /// What a log line may say about this. Neither the password nor the
        /// verifier is in it, and there is no overload that puts them there.
        /// </summary>
        public string Describe()
        {
            if (!Configured)
            {
                return "off (no ADMIN_PASSWORD_HASH); /admin does not exist on this service";
            }

            var guards = HasNetworkRestriction || HasRequiredHeader
                ? (HasNetworkRestriction ? "network allow-list" : null)
                : "PASSWORD ONLY - consider ADMIN_ALLOWED_CIDRS or ADMIN_REQUIRED_HEADER";

            if (HasRequiredHeader)
            {
                guards = guards == null ? "required header" : guards + " and required header";
            }

            return "on at /admin, "
                + (UsesPlaintext ? "ADMIN_PASSWORD (plaintext in the environment)" : "ADMIN_PASSWORD_HASH")
                + ", idle timeout " + IdleMinutes.ToString(CultureInfo.InvariantCulture)
                + "m, absolute " + AbsoluteMinutes.ToString(CultureInfo.InvariantCulture) + "m"
                + "; in front of it: " + guards;
        }

        public IReadOnlyList<string> Problems()
        {
            var problems = new List<string>();

            if (!Configured)
            {
                // Not a problem. It is the default, and it is the safe one.
                return problems;
            }

            if (!string.IsNullOrWhiteSpace(PasswordHash) && !string.IsNullOrEmpty(Password))
            {
                problems.Add(
                    "ADMIN_PASSWORD_HASH and ADMIN_PASSWORD are both set. Only one can be the password and "
                    + "guessing which would mean an operator whose password does not work, or worse, one whose "
                    + "old password still does. Unset ADMIN_PASSWORD.");
            }
            else if (!string.IsNullOrWhiteSpace(PasswordHash))
            {
                if (!Admin.AdminPassword.TryParse(PasswordHash, out _, out var problem))
                {
                    problems.Add(problem);
                }
            }
            else
            {
                var weakness = Admin.AdminPassword.Weakness(Password);

                if (weakness != null)
                {
                    problems.Add(
                        "ADMIN_PASSWORD is not acceptable: " + weakness + ". Set a longer one, or better, run "
                        + "`hash-password` and put the result in ADMIN_PASSWORD_HASH so the environment holds a "
                        + "verifier rather than the credential itself.");
                }
            }

            if (HasNetworkRestriction && !Admin.AdminAccessGate.TryParseNetworks(AllowedNetworks, out _, out var networkProblem))
            {
                problems.Add("ADMIN_ALLOWED_CIDRS is not usable: " + networkProblem);
            }

            if (HasRequiredHeader && string.IsNullOrEmpty(RequiredHeaderValue))
            {
                problems.Add(
                    "ADMIN_REQUIRED_HEADER is set but ADMIN_REQUIRED_HEADER_VALUE is empty. A header check against "
                    + "an empty value would pass for any request that sets the header to nothing, which is worse "
                    + "than not having one.");
            }

            if (HasRequiredHeader && RequiredHeaderValue != null && RequiredHeaderValue.Length < 16)
            {
                problems.Add(
                    "ADMIN_REQUIRED_HEADER_VALUE is shorter than 16 characters. It is a shared secret sitting in "
                    + "front of the admin page; make it long enough that guessing it is not a strategy.");
            }

            if (IdleMinutes < 1 || IdleMinutes > 1440)
            {
                problems.Add("ADMIN_SESSION_IDLE_MINUTES must be between 1 and 1440.");
            }

            if (AbsoluteMinutes < 1 || AbsoluteMinutes > 10080)
            {
                problems.Add("ADMIN_SESSION_ABSOLUTE_MINUTES must be between 1 and 10080 (a week).");
            }

            if (AbsoluteMinutes < IdleMinutes)
            {
                problems.Add(
                    "ADMIN_SESSION_ABSOLUTE_MINUTES is smaller than ADMIN_SESSION_IDLE_MINUTES, which makes the "
                    + "idle timeout unreachable. The absolute one is the ceiling; it has to be the larger.");
            }

            if (LoginDelaySeconds < 1 || LoginDelaySeconds > 60)
            {
                problems.Add("ADMIN_LOGIN_DELAY_SECONDS must be between 1 and 60. It is the FIRST wait a wrong "
                    + "password buys and it doubles from there; 0 would disable the brake entirely.");
            }

            if (LoginMaxDelaySeconds < LoginDelaySeconds || LoginMaxDelaySeconds > 3600)
            {
                problems.Add(
                    "ADMIN_LOGIN_MAX_DELAY_SECONDS must be at least ADMIN_LOGIN_DELAY_SECONDS and at most 3600. "
                    + "It is where the doubling stops - not a lockout, which this service deliberately does not "
                    + "have.");
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

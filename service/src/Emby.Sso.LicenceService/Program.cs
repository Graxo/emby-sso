using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.LicenceService.Admin;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.Http;
using Emby.Sso.LicenceService.Management;
using Emby.Sso.LicenceService.PayPal;
using Emby.Sso.LicenceService.RateLimiting;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Emby.Sso.LicenceService
{
    /// <summary>
    /// The host, the routes, and the commands that are not routes.
    ///
    /// Everything a route does is one call into a class that can be tested
    /// without a socket. What is left here is HTTP: reading a capped body,
    /// working out who the caller is, and turning a reply into a status code.
    ///
    /// The commands are the other half of running this: `issue-code` mints a
    /// code no payment bought, `healthcheck` is what the container asks itself,
    /// and `list-codes`, `show-code`, `void-code` and `list-outbox` are how a
    /// vendor manages what they have sold. All of them are dispatched here and
    /// implemented in ManagementCommands, which explains why none of them is an
    /// HTTP endpoint.
    /// </summary>
    public static class Program
    {
        /// <summary>sysexits.h EX_CONFIG. Docker restart policies and the operator both read it.</summary>
        private const int ConfigurationError = 78;

        /// <summary>
        /// Bodies are small and fixed in shape. 64 KiB is far more than either
        /// endpoint needs and small enough that an unauthenticated caller cannot
        /// make the service hold anything.
        /// </summary>
        private const int MaximumBodyBytes = 64 * 1024;

        public static int Main(string[] args)
        {
            if (args.Length > 0)
            {
                // The management commands. All of them need a shell on this
                // box, which is the strongest authentication this service has -
                // see ManagementCommands. The admin page reaches the same logic
                // over HTTP behind a password, and exists only when one is
                // configured; these keep working whether it is or not, and are
                // what is left when it is turned off.
                switch (args[0])
                {
                    case "issue-code":
                        return IssueCode(args);

                    case "healthcheck":
                        return HealthCheck(args);

                    case "hash-password":
                        return HashPassword();

                    case "restore":
                        return Restore(args);

                    case "list-codes":
                        return Manage(args, ManagementCommands.ListCodes);

                    case "show-code":
                        return Manage(args, ManagementCommands.ShowCode);

                    case "void-code":
                        return Manage(args, ManagementCommands.VoidCode);

                    case "list-outbox":
                        return Manage(args, ManagementCommands.ListOutbox);

                    case "--help":
                    case "help":
                        Console.WriteLine(Usage);

                        return 0;

                    default:
                        if (args[0].StartsWith("-", StringComparison.Ordinal))
                        {
                            break;
                        }

                        Console.Error.WriteLine("There is no `" + args[0] + "` command.");
                        Console.Error.WriteLine();
                        Console.Error.WriteLine(Usage);

                        return 1;
                }
            }

            var options = ServiceOptions.FromEnvironment(Environment.GetEnvironmentVariable);
            var problems = options.Problems();

            if (problems.Count > 0)
            {
                Console.Error.WriteLine("REFUSING TO START. This service is misconfigured:");

                foreach (var problem in problems)
                {
                    Console.Error.WriteLine("  - " + problem);
                }

                Console.Error.WriteLine();
                Console.Error.WriteLine("See service/README.md for what each variable is for.");

                return ConfigurationError;
            }

            WebApplication app;

            try
            {
                app = BuildApp(options, null);
            }
            catch (MailTemplateException ex)
            {
                Console.Error.WriteLine("REFUSING TO START. " + ex.Message);

                return ConfigurationError;
            }
            catch (SigningKeyFile.SigningKeyException ex)
            {
                // The loudest failure this service has. An operator who has
                // asked it to sign, and whose key cannot be loaded, must not get
                // a service that starts and quietly queues every activation.
                Console.Error.WriteLine("REFUSING TO START. " + ex.Message);

                return ConfigurationError;
            }

            app.Run();

            return 0;
        }

        /// <summary>
        /// Builds the host. Separated from <see cref="Main"/> so the tests can
        /// start the same routes, with the same wiring, over a TestServer -
        /// there is no second code path for tests to be right about.
        /// </summary>
        internal static WebApplication BuildApp(
            ServiceOptions options,
            Action<WebApplicationBuilder> configure)
        {
            // The PUBLIC keys, always: they are what checks a signed licence
            // before it is stored, whoever signed it.
            var trusted = TrustedKeys.Parse(options.PublicKeys);

            // The PRIVATE key, only when the operator has asked this service to
            // sign for itself. That makes activation self-service and puts the
            // key in the process that answers the internet; both halves of that
            // are spelled out in Signing.SigningDaemon. With it unset, nothing
            // here can sign and /admin/signing is how licences are made.
            SigningKeyFile.SigningKey signingKey = null;

            if (options.SignsItsOwnLicences)
            {
                signingKey = SigningKeyFile.Load(options.SigningKeyPath);
            }

            var builder = WebApplication.CreateBuilder(Array.Empty<string>());

            builder.Logging.ClearProviders();
            builder.Logging.AddSimpleConsole(console =>
            {
                console.SingleLine = true;
                console.UseUtcTimestamp = true;
                console.TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss'Z' ";
            });

            builder.WebHost.ConfigureKestrel(kestrel =>
            {
                kestrel.Limits.MaxRequestBodySize = MaximumBodyBytes;
                kestrel.AddServerHeader = false;
            });

            var store = new LicenceStore(options.DatabasePath);

            store.Initialise();

            builder.Services.AddSingleton(options);
            builder.Services.AddSingleton(options.PayPal);
            builder.Services.AddSingleton(options.RateLimit);
            builder.Services.AddSingleton(store);
            builder.Services.AddSingleton(trusted);

            // The release key's PUBLIC half, when configured. Used only to check
            // a manifest before publishing it; the plugin checks again, and that
            // check is the one that matters.
            TrustedKeys releaseKeys = null;

            if (!string.IsNullOrWhiteSpace(options.ReleasePublicKeys))
            {
                releaseKeys = TrustedKeys.Parse(options.ReleasePublicKeys);
            }

            builder.Services.AddSingleton(provider => new Release.ReleaseStore(
                options,
                releaseKeys,
                provider.GetRequiredService<ILogger<Release.ReleaseStore>>()));

            // Null when this deployment does not sign for itself. The status
            // service then reports that it cannot answer, and the plugin - which
            // refuses an unsigned answer anyway - carries on unaffected.
            builder.Services.AddSingleton(provider => new LicenceStatusService(
                provider.GetRequiredService<LicenceStore>(),
                provider.GetRequiredService<ActivationRateLimiter>(),
                signingKey?.Key,
                provider.GetRequiredService<TimeProvider>(),
                provider.GetRequiredService<ILogger<LicenceStatusService>>()));

            if (signingKey != null)
            {
                builder.Services.AddSingleton(signingKey);
                builder.Services.AddSingleton<Signing.SigningDaemon>();
                builder.Services.AddHostedService(provider => provider.GetRequiredService<Signing.SigningDaemon>());
            }

            builder.Services.AddSingleton(new LicenceLedger(options.LedgerPath));
            builder.Services.AddSingleton<Signing.SigningDesk>();
            builder.Services.AddSingleton<Backup.BackupService>();
            var outbox = new CodeOutbox(options.OutboxPath);

            builder.Services.AddSingleton(outbox);
            builder.Services.AddSingleton(options.Mail);

            // Mail is registered ONLY when SMTP_HOST is set. With it unset there
            // is no mailer, no background service and no queue in the container
            // at all, and PayPalWebhookHandler's optional dependency stays null -
            // so the unconfigured service is not "mail turned off", it is the
            // same service it was before mail existed.
            if (options.Mail.Configured)
            {
                // Loaded here rather than at first sale: a template with no
                // {code} in it must stop the service starting, not produce one
                // cheerful codeless email per customer. Main turns the exception
                // into exit 78 alongside every other configuration refusal.
                var template = CodeMessage.LoadTemplate(options.Mail.TemplatePath);

                builder.Services.AddSingleton<ISmtpTransport>(new MailKitSmtpTransport(options.Mail));
                builder.Services.AddSingleton(provider => new CodeMailer(
                    options.Mail,
                    provider.GetRequiredService<ISmtpTransport>(),
                    outbox,
                    template,
                    provider.GetRequiredService<ILogger<CodeMailer>>()));
                builder.Services.AddSingleton<CodeDeliveryQueue>();
                builder.Services.AddHostedService(provider => provider.GetRequiredService<CodeDeliveryQueue>());
            }
            builder.Services.AddSingleton(TimeProvider.System);
            builder.Services.AddSingleton(options.Admin);
            builder.Services.AddSingleton<ActivationRateLimiter>();
            builder.Services.AddSingleton<CheckoutRateLimiter>();
            builder.Services.AddSingleton<ActivationService>();
            builder.Services.AddSingleton<PayPalWebhookVerifier>();
            builder.Services.AddSingleton<PayPalWebhookHandler>();

            builder.Services.AddHttpClient<IPayPalCertificateSource, HttpPayPalCertificateSource>(http =>
            {
                http.Timeout = TimeSpan.FromSeconds(10);
            });

            builder.Services.AddHttpClient<PayPalOrdersClient>(http =>
            {
                http.Timeout = TimeSpan.FromSeconds(20);
            });

            // The admin page's own machinery, registered ONLY when a password
            // is configured. With none set there is no session store, no login
            // throttle, no audit file and no route: /admin is not a page that
            // refuses, it is a page that does not exist. See AdminEndpoints.
            AdminPassword adminPassword = null;

            if (options.Admin.Configured)
            {
                if (!string.IsNullOrWhiteSpace(options.Admin.PasswordHash))
                {
                    if (!AdminPassword.TryParse(options.Admin.PasswordHash, out adminPassword, out var problem))
                    {
                        // Unreachable through Main, which runs Problems() first
                        // and refuses to start. Here so that a caller that skips
                        // that check cannot get a service with an admin page and
                        // no working password on it.
                        throw new InvalidOperationException(problem);
                    }
                }
                else
                {
                    var weakness = AdminPassword.Weakness(options.Admin.Password);

                    if (weakness != null)
                    {
                        throw new InvalidOperationException("ADMIN_PASSWORD is not acceptable: " + weakness + ".");
                    }

                    adminPassword = AdminPassword.FromPlaintext(options.Admin.Password);
                }

                builder.Services.AddSingleton(adminPassword);
                builder.Services.AddSingleton<AdminSessions>();
                builder.Services.AddSingleton<AdminLoginThrottle>();
                builder.Services.AddSingleton<PasswordVerificationGate>();
                builder.Services.AddSingleton(provider => new AdminAudit(
                    options.AdminAuditPath,
                    provider.GetRequiredService<ILoggerFactory>().CreateLogger("admin")));
            }

            configure?.Invoke(builder);

            var app = builder.Build();

            var log = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Emby.Sso.LicenceService");

            log.LogInformation(
                "signing: {Signing}. Trusted licence keys: {Keys}. "
                + "store {Store}; ledger {Ledger}; paypal {Env}; "
                + "{Allowed} activations per code; {Days} day licences",
                signingKey != null
                    ? "AUTOMATIC with key " + signingKey.Thumbprint + " - the private key is loaded by this process"
                    : "off - this service cannot sign; licences are signed elsewhere and uploaded at /admin/signing",
                trusted.Describe(),
                store.Path,
                options.LedgerPath,
                options.PayPal.IsLive ? "LIVE" : "sandbox",
                options.ActivationsAllowed,
                options.LicenceDays);

            // The password is not in Describe() and there is no overload that
            // puts it there.
            log.LogInformation("code delivery by email: {Mail}", options.Mail.Describe());

            if (options.Mail.Configured && !options.Mail.IsEncrypted)
            {
                log.LogWarning(
                    "SMTP_SECURITY is 'none'. Every redemption code sent through {Host}:{Port} crosses the network "
                    + "in the clear, and a redemption code is a bearer credential. This is only reasonable for a "
                    + "relay on this machine or a network you own end to end.",
                    options.Mail.Host,
                    options.Mail.Port);
            }

            log.LogInformation("admin page: {Admin}", options.Admin.Describe());

            var waiting = store.CountWaitingToBeSigned();

            if (waiting > 0)
            {
                // At startup, because it is the one number a restart should not
                // let an operator forget: every one of these is a customer who
                // has paid and is being told to try again later.
                log.LogWarning(
                    "{Waiting} licence(s) are waiting to be signed. Download them from /admin/signing, sign them "
                    + "with `licencetool sign`, and upload the result.",
                    waiting);
            }

            if (!string.IsNullOrEmpty(options.BackupPassphrase))
            {
                log.LogInformation("encrypted backups: on, downloadable from /admin/backup");
            }
            else
            {
                log.LogWarning(
                    "encrypted backups: OFF. Nothing here can rebuild who bought what if this volume is lost. "
                    + "Set LICENCE_BACKUP_PASSPHRASE and take one from /admin/backup.");
            }

            // Before any route, so that every response carries them - including
            // the ones a route never reaches, such as a 404 or a 413.
            app.UseSecurityHeaders();

            MapRoutes(app, options);

            if (adminPassword != null)
            {
                AdminEndpoints.Map(app, options, adminPassword, new AdminAccessGate(options.Admin, options.TrustedProxyHops));
            }

            return app;
        }

        private static void MapRoutes(WebApplication app, ServiceOptions options)
        {
            app.MapPost("/v1/activate", async (HttpContext context, ActivationService activations) =>
            {
                var body = await ReadBodyAsync(context).ConfigureAwait(false);
                var client = ClientKey(context, options.TrustedProxyHops);

                if (body == null)
                {
                    return Error(context, ActivationError.MalformedRequest, "The request body is too large.", 400, TimeSpan.Zero);
                }

                ActivationRequest request;

                try
                {
                    request = JsonSerializer.Deserialize<ActivationRequest>(
                        body,
                        new JsonSerializerOptions(JsonSerializerDefaults.Web));
                }
                catch (JsonException)
                {
                    // Parsed here rather than by model binding so that a bad body
                    // produces the contract's malformed_request shape instead of
                    // the framework's problem+json, which the plugin does not
                    // know how to read.
                    return Error(context, ActivationError.MalformedRequest, "The request body is not JSON.", 400, TimeSpan.Zero);
                }

                var reply = await activations
                    .ActivateAsync(request, client, context.RequestAborted)
                    .ConfigureAwait(false);

                if (reply.IsSuccess)
                {
                    return Results.Json(
                        new
                        {
                            licence = reply.Licence,
                            expiresUtc = LicenceFormat.Iso(reply.ExpiresUtc),
                            activationsUsed = reply.ActivationsUsed,
                            activationsAllowed = reply.ActivationsAllowed,
                        },
                        statusCode: 200);
                }

                return Error(context, reply.Error, reply.Message, StatusFor(reply.Error), reply.RetryAfter);
            });

            // The current release manifest, for the plugin's update check.
            //
            // UNAUTHENTICATED AND UNRATE-LIMITED, deliberately. It is a single
            // signed, public statement - the same bytes for everybody - and it
            // is exactly what a plugin needs before it can be told an update
            // exists. Putting a credential in front of it would mean a plugin
            // whose licence had lapsed could never learn about the fix for the
            // bug that lapsed it.
            app.MapGet("/v1/release", (Release.ReleaseStore releases) =>
            {
                var manifest = releases.Current();

                return manifest == null
                    ? Results.StatusCode(404)
                    : Results.Json(new { manifest }, statusCode: 200);
            });

            // The plugin file itself, when this service is hosting it.
            //
            // WHY THIS SERVES A BINARY AT ALL. A manifest names an address, and
            // that address has to answer an Emby server that has no account
            // anywhere and sends no credential. A package registry behind a
            // sign-in cannot do that, and the failure is silent: the manifest
            // verifies, the admin page says published, and every customer's
            // server reports the download unreachable. This service is already
            // the one address every plugin is configured to reach, so it is the
            // one place the file is certain to be fetchable from.
            //
            // SERVING IT GRANTS NOTHING. The bytes are checked against the
            // SHA-256 in the signed manifest by the plugin that downloads them,
            // and that check is the real one. Somebody who takes this host can
            // stop serving the file or serve garbage; they cannot make an Emby
            // server install either, because they cannot sign a manifest for
            // what they served.
            app.MapGet(Release.ReleaseStore.DownloadPath, (Release.ReleaseStore releases) =>
            {
                var file = releases.OpenFile();

                return file == null
                    ? Results.StatusCode(404)
                    : Results.File(file, "application/octet-stream", "Emby.Sso.dll");
            });

            // The checksum, as `sha256sum -c` input, for an operator installing
            // by hand. It is a convenience and never a security control: it
            // comes from the same host as the file, so anybody able to change
            // one can change the other. The guarantee is the signed manifest.
            app.MapGet(Release.ReleaseStore.DownloadPath + ".sha256", (Release.ReleaseStore releases) =>
            {
                var hash = releases.PublishedHash();

                return hash == null
                    ? Results.StatusCode(404)
                    : Results.Text(hash + "  Emby.Sso.dll" + Environment.NewLine, "text/plain");
            });

            // The daily "is my licence still good?" call. See
            // LicenceStatusService: the answer is signed, the plugin fails open
            // when there is no answer, and nothing here can be used to fish for
            // a licence - only to ask about one the caller already holds.
            app.MapPost("/v1/licence/status", async (HttpContext context, LicenceStatusService statuses) =>
            {
                var body = await ReadBodyAsync(context).ConfigureAwait(false);
                var client = ClientKey(context, options.TrustedProxyHops);

                if (body == null)
                {
                    return Results.StatusCode(400);
                }

                LicenceStatusRequest request;

                try
                {
                    request = JsonSerializer.Deserialize<LicenceStatusRequest>(
                        body,
                        new JsonSerializerOptions(JsonSerializerDefaults.Web));
                }
                catch (JsonException)
                {
                    return Results.StatusCode(400);
                }

                var reply = statuses.Check(request, client);

                if (!reply.IsAnswered)
                {
                    if (reply.RetryAfter > TimeSpan.Zero)
                    {
                        context.Response.Headers.RetryAfter =
                            ((int)Math.Ceiling(reply.RetryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
                    }

                    return Results.StatusCode(reply.StatusCode);
                }

                return Results.Json(new { status = reply.Token }, statusCode: 200);
            });

            app.MapPost("/paypal/webhook", async (HttpContext context, PayPalWebhookHandler handler) =>
            {
                var body = await ReadBodyAsync(context).ConfigureAwait(false);

                if (body == null)
                {
                    return Results.StatusCode((int)HttpStatusCode.RequestEntityTooLarge);
                }

                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                foreach (var header in context.Request.Headers)
                {
                    headers[header.Key] = header.Value.ToString();
                }

                var outcome = await handler.HandleAsync(headers, body, context.RequestAborted).ConfigureAwait(false);

                switch (outcome.Status)
                {
                    case WebhookStatus.Refused:
                        // 401 and nothing else. The reason is in the log; a caller
                        // probing the endpoint learns only that it refused.
                        return Results.StatusCode((int)HttpStatusCode.Unauthorized);

                    case WebhookStatus.Unusable:
                        // 400 so PayPal stops retrying something we will never
                        // understand, and the vendor sees it in their webhook
                        // dashboard rather than only in our log.
                        return Results.StatusCode((int)HttpStatusCode.BadRequest);

                    default:
                        // Everything else - created, replay, ignored, and even a
                        // code we could not write down - is 200. PayPal retries
                        // anything else, and a retry of a payment already recorded
                        // achieves nothing.
                        return Results.Ok(new { received = true });
                }
            });

            // The bare domain. Nothing is served here, but this host exists to
            // sell licences and its name is the thing that ends up in an email
            // or on a page, so somebody will type it. A 404 is a poor answer to
            // "what is this?" when the answer is one redirect away.
            //
            // 302, not 301: a permanent redirect is cached by browsers more or
            // less forever, and this is a young service whose root may yet grow
            // a real page.
            app.MapGet("/", (HttpContext context) =>
            {
                context.Response.Redirect("/buy", permanent: false);
                return Task.CompletedTask;
            });

            // GET /buy is the link the plugin's configuration page renders. It is
            // opened by a person, in a browser, so it answers HTML. See BuyPage
            // for why it shows a button instead of redirecting straight into a
            // PayPal order.
            app.MapGet("/buy", (HttpContext context) =>
            {
                var model = ModelFor(options, context.Request.Query["serverId"].ToString());

                return Results.Content(BuyPage.Render(model), "text/html; charset=utf-8");
            });

            app.MapGet("/buy/complete", (HttpContext context) =>
                Results.Content(
                    BuyPage.RenderComplete(ModelFor(options, context.Request.Query["serverId"].ToString())),
                    "text/html; charset=utf-8"));

            app.MapGet("/buy/cancelled", (HttpContext context) =>
                Results.Content(
                    BuyPage.RenderCancelled(ModelFor(options, context.Request.Query["serverId"].ToString())),
                    "text/html; charset=utf-8"));

            // The button's target. A form POST rather than a link, so that no
            // prefetcher, crawler or reload creates a PayPal order; 303 to
            // PayPal, so the browser's back button returns to the buy page rather
            // than re-submitting.
            // Someone will open /buy/start in a browser - it is the URL in the
            // address bar mid-purchase, so it gets bookmarked, shared and
            // retried. A GET must not create an order (that is why the purchase
            // is a form POST: prefetchers, link previewers and crawlers all
            // follow GETs), but 405 is a dead end. Send them to the page with
            // the button on it instead.
            app.MapGet("/buy/start", (HttpContext context) =>
            {
                var serverId = context.Request.Query["serverId"].ToString();

                context.Response.Redirect(
                    string.IsNullOrEmpty(serverId)
                        ? "/buy"
                        : "/buy?serverId=" + Uri.EscapeDataString(serverId),
                    permanent: false);

                return Task.CompletedTask;
            });

            app.MapPost("/buy/start", async (
                HttpContext context,
                PayPalOrdersClient paypal,
                CheckoutRateLimiter throttle,
                ILoggerFactory logs) =>
            {
                var log = logs.CreateLogger("buy");
                var client = ClientKey(context, options.TrustedProxyHops);
                var limit = throttle.Check(client);

                if (!limit.IsAllowed)
                {
                    log.LogWarning("buy/start RATE LIMITED client={Client} scope={Scope}", client, limit.Scope);
                    context.Response.Headers.RetryAfter =
                        ((int)Math.Ceiling(limit.RetryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);

                    return Results.StatusCode((int)HttpStatusCode.TooManyRequests);
                }

                string serverId = null;

                if (context.Request.HasFormContentType)
                {
                    var form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);

                    serverId = CleanServerId(form["serverId"].ToString());
                }

                var model = ModelFor(options, serverId);

                if (!model.CanSell)
                {
                    log.LogWarning("buy/start was called but PAYPAL_CLIENT_ID/SECRET/PRICE are not all set");

                    return Results.Content(BuyPage.Render(model), "text/html; charset=utf-8", null, 503);
                }

                try
                {
                    var order = await paypal.CreateOrderAsync(serverId, context.RequestAborted).ConfigureAwait(false);

                    log.LogInformation(
                        "buy/start created paypal order {Order} client={Client} origin={Origin}",
                        order.OrderId,
                        client,
                        serverId ?? "(none)");

                    return Results.Redirect(order.ApproveUrl, permanent: false, preserveMethod: false);
                }
                catch (Exception ex) when (ex is PayPalApiException || ex is HttpRequestException || ex is JsonException)
                {
                    log.LogError(ex, "buy/start could not create a PayPal order");

                    return Results.Content(
                        BuyPage.RenderFailed(model),
                        "text/html; charset=utf-8",
                        null,
                        502);
                }
            });

            // The same thing as /buy/start for anything that would rather have
            // JSON than a redirect. Kept because the contract's plugin side may
            // want to start a purchase without opening a browser.
            app.MapPost("/v1/checkout", async (
                HttpContext context,
                PayPalOrdersClient paypal,
                CheckoutRateLimiter throttle,
                ILoggerFactory logs) =>
            {
                var log = logs.CreateLogger("checkout");
                var client = ClientKey(context, options.TrustedProxyHops);
                var limit = throttle.Check(client);

                if (!limit.IsAllowed)
                {
                    context.Response.Headers.RetryAfter =
                        ((int)Math.Ceiling(limit.RetryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);

                    return Results.Json(
                        new { error = "rate_limited", message = "Too many checkout attempts. Wait and try again." },
                        statusCode: 429);
                }

                if (!options.PayPal.CheckoutConfigured)
                {
                    log.LogWarning("checkout was called but PAYPAL_CLIENT_ID/SECRET/PRICE are not all set");

                    return Results.Json(
                        new { error = "not_configured", message = "Checkout is not configured on this service." },
                        statusCode: 503);
                }

                try
                {
                    var serverId = CleanServerId(context.Request.Query["serverId"].ToString());
                    var order = await paypal.CreateOrderAsync(serverId, context.RequestAborted).ConfigureAwait(false);

                    log.LogInformation("checkout created paypal order {Order} client={Client}", order.OrderId, client);

                    return Results.Json(new { orderId = order.OrderId, approveUrl = order.ApproveUrl }, statusCode: 200);
                }
                catch (Exception ex) when (ex is PayPalApiException || ex is HttpRequestException || ex is JsonException)
                {
                    log.LogError(ex, "checkout could not create a PayPal order");

                    return Results.Json(
                        new { error = "checkout_failed", message = "Could not start a PayPal checkout. Try again shortly." },
                        statusCode: 502);
                }
            });

            app.MapGet("/healthz", (LicenceStore store, TrustedKeys trusted, ActivationRateLimiter limiter) =>
            {
                try
                {
                    store.CheckWritable();
                }
                catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException || ex is IOException)
                {
                    return Results.Json(
                        new { status = "unhealthy", store = "unwritable", detail = ex.Message },
                        statusCode: 503);
                }

                return Results.Json(
                    new
                    {
                        status = "ok",

                        // Which PUBLIC keys this box will accept a signed
                        // licence from, so "does the service agree with the
                        // plugin build?" is answerable from outside without a
                        // shell. Nothing here is secret, and there is no private
                        // key on this host to name.
                        trustedKeys = trusted.Describe(),
                        paypal = options.PayPal.IsLive ? "live" : "sandbox",
                        rateLimiterClients = limiter.TrackedClients,
                    },
                    statusCode: 200);
            });
        }

        private static BuyPageModel ModelFor(ServiceOptions options, string serverId)
        {
            return new BuyPageModel
            {
                ProductName = options.PayPal.ProductName,
                Price = options.PayPal.Price,
                Currency = options.PayPal.Currency,
                LicenceDays = options.LicenceDays,
                ActivationsAllowed = options.ActivationsAllowed,
                ServerId = CleanServerId(serverId),
                CanSell = options.PayPal.CheckoutConfigured,
            };
        }

        /// <summary>
        /// The server id on a /buy link is optional, untrusted and only ever
        /// metadata. Anything that is not plausibly an Emby server id is dropped
        /// rather than rejected: somebody who typed the URL by hand, or a plugin
        /// from a future Emby with a different id format, should still be able to
        /// buy a licence. Nothing downstream depends on it being present or
        /// correct - and it is HTML-encoded wherever it is rendered, whatever it
        /// turns out to be.
        /// </summary>
        internal static string CleanServerId(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            var trimmed = value.Trim();

            return Activation.ActivationService.IsPlausibleServerId(trimmed) ? trimmed : null;
        }

        /// <summary>
        /// Maps the contract's machine codes onto status codes.
        ///
        /// The plugin keys on the `error` string, not on this, which is the point
        /// of the contract having machine codes at all - so these are chosen to
        /// be what a proxy, a log aggregator or a person reading an access log
        /// would expect, and can be changed without breaking the plugin.
        /// </summary>
        private static int StatusFor(string error)
        {
            switch (error)
            {
                case ActivationError.MalformedRequest:
                case ActivationError.InvalidCode:
                    return 400;

                case ActivationError.CodeExhausted:
                    return 409;

                case ActivationError.RateLimited:
                    return 429;

                // 202 Accepted, and the one code in this contract that is not a
                // failure: the activation IS recorded and the licence is being
                // signed on a machine this service cannot reach. The plugin
                // shows the message and the customer presses Activate again.
                case ActivationError.PendingSignature:
                    return 202;

                default:
                    return 500;
            }
        }

        private static IResult Error(HttpContext context, string error, string message, int status, TimeSpan retryAfter)
        {
            if (retryAfter > TimeSpan.Zero)
            {
                context.Response.Headers.RetryAfter =
                    ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
            }

            return Results.Json(new { error, message }, statusCode: status);
        }

        /// <summary>
        /// Reads at most <see cref="MaximumBodyBytes"/>, returning null if there
        /// is more. Kestrel's own limit would also stop it; this is here so the
        /// limit is visible where the body is read, and so a body that is over it
        /// produces this service's error shape rather than the framework's.
        /// </summary>
        private static async Task<byte[]> ReadBodyAsync(HttpContext context)
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];

            while (true)
            {
                var read = await context.Request.Body.ReadAsync(chunk, context.RequestAborted).ConfigureAwait(false);

                if (read == 0)
                {
                    break;
                }

                if (buffer.Length + read > MaximumBodyBytes)
                {
                    return null;
                }

                buffer.Write(chunk, 0, read);
            }

            return buffer.ToArray();
        }

        /// <summary>
        /// Who the rate limiter is counting.
        ///
        /// With LICENCE_TRUSTED_PROXY_HOPS at 0 this is the socket's peer, which
        /// cannot be forged. Each hop configured takes one entry further left in
        /// X-Forwarded-For, which is the entry the LAST trusted proxy wrote. A
        /// caller can put anything they like in that header; what they cannot do
        /// is stop the proxy appending their real address after it, which is why
        /// the count matters and why it defaults to trusting nothing.
        /// </summary>
        internal static string ClientKey(HttpContext context, int trustedProxyHops)
        {
            var peer = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            if (trustedProxyHops <= 0)
            {
                return peer;
            }

            if (!context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwarded))
            {
                return peer;
            }

            var chain = forwarded
                .ToString()
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (chain.Length == 0)
            {
                return peer;
            }

            // The rightmost entry was written by the proxy nearest us. Walking
            // left by the number of proxies we actually have lands on the address
            // the outermost trusted proxy saw.
            var index = chain.Length - trustedProxyHops;

            if (index < 0 || index >= chain.Length)
            {
                // Fewer entries than there are proxies: the header was not
                // written by the chain we were told about. Fall back to the peer,
                // which is at worst the proxy itself - safe, and it throttles
                // everybody together rather than trusting a forged header.
                return peer;
            }

            return chain[index];
        }

        /// <summary>
        /// `issue-code` - a code that no payment bought.
        ///
        /// For a tester, a comp, a refund gone wrong, or the one case the webhook
        /// cannot recover from by itself: a code created and then not writable to
        /// the outbox. It needs a shell on the box, which is the only
        /// authentication story this service can honestly offer for an operation
        /// that mints a saleable credential.
        /// </summary>
        private static int IssueCode(string[] args)
        {
            var parsed = ParseArguments(args);

            var options = ServiceOptions.FromEnvironment(Environment.GetEnvironmentVariable);

            if (string.IsNullOrWhiteSpace(options.DataDirectory))
            {
                Console.Error.WriteLine("LICENCE_DATA_DIR is not set, so there is no store to write to.");

                return ConfigurationError;
            }

            parsed.TryGetValue("licensee", out var licensee);
            parsed.TryGetValue("note", out var note);

            // One implementation, shared with the admin page's Issue form. The
            // validation, the ceilings and what reaches the store are all in
            // CodeIssuing, so the two front ends cannot mint different things.
            var request = new CodeIssuing.Request
            {
                Licensee = licensee,
                ActivationsAllowed = Number(parsed, "activations", options.ActivationsAllowed),
                LicenceDays = Number(parsed, "days", options.LicenceDays),
                Note = note,
            };

            var wrong = CodeIssuing.Problems(request);

            if (wrong.Count > 0)
            {
                foreach (var problem in wrong)
                {
                    Console.Error.WriteLine(problem);
                }

                Console.Error.WriteLine();
                Console.Error.WriteLine(Usage);

                return 1;
            }

            var store = new LicenceStore(options.DatabasePath);

            store.Initialise();

            var issued = CodeIssuing.Issue(store, request, DateTimeOffset.UtcNow);

            Console.Error.WriteLine("Code id     : " + issued.Id.ToString(CultureInfo.InvariantCulture));
            Console.Error.WriteLine("Licensee    : " + request.Licensee);
            Console.Error.WriteLine("Activations : " + request.ActivationsAllowed.ToString(CultureInfo.InvariantCulture));
            Console.Error.WriteLine("Licence     : " + request.LicenceDays.ToString(CultureInfo.InvariantCulture) + " days from first activation");
            Console.Error.WriteLine("Tag         : " + issued.Tag + "  (this is what the logs show)");
            Console.Error.WriteLine();
            Console.Error.WriteLine("The code itself is on stdout, and is stored here ONLY as a hash. If you lose it,");
            Console.Error.WriteLine("nothing can recover it and you issue another one.");
            Console.Error.WriteLine();

            // stdout alone, so `> code.txt` gives just the code.
            Console.WriteLine(issued.Code);

            return 0;
        }

        /// <summary>
        /// `hash-password` - turns a password into the verifier that goes in
        /// ADMIN_PASSWORD_HASH.
        ///
        /// It reads the password on STDIN and not from an argument, deliberately.
        /// An argument is in the shell history of whoever typed it, in the
        /// process list of everybody on the box while it runs, and in the
        /// container logs of anything that wraps it. Stdin is in none of those.
        ///
        ///     read -rs ADMIN; printf %s "$ADMIN" | ... hash-password
        ///
        /// The verifier is printed on stdout and nothing else is, so it can be
        /// redirected straight into an env file.
        /// </summary>
        private static int HashPassword()
        {
            // ReadToEnd, so at a terminal this returns on EOF and not on the
            // newline. Saying "press enter" - which this did - leaves the
            // operator watching a cursor blink, concluding the command has
            // hung, and killing it.
            Console.Error.WriteLine("Type the admin password, press enter, then press Ctrl-D.");
            Console.Error.WriteLine();
            Console.Error.WriteLine("It is read from stdin rather than from an argument, so it does not reach your");
            Console.Error.WriteLine("shell history, the process list, or the logs of anything wrapping this.");

            var password = Console.In.ReadToEnd();

            // A trailing newline is what a pipe or a terminal adds; anything
            // else the operator typed is theirs, including spaces at the ends.
            password = password.TrimEnd('\r', '\n');

            var weakness = Admin.AdminPassword.Weakness(password);

            if (weakness != null)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine("REFUSED: " + weakness + ".");
                Console.Error.WriteLine();
                Console.Error.WriteLine("This password is the only thing between the internet and a page that can");
                Console.Error.WriteLine("issue a licence for any server, forever, with no way to recall one. Use a");
                Console.Error.WriteLine("long random string from a password manager.");

                return 1;
            }

            var encoded = Admin.AdminPassword.Encode(password);

            Console.Error.WriteLine();
            Console.Error.WriteLine("Put this in the service's environment, and keep the password itself only in");
            Console.Error.WriteLine("your password manager. There is no way to recover it from the line below.");
            Console.Error.WriteLine();

            Console.WriteLine("ADMIN_PASSWORD_HASH=" + encoded);

            return 0;
        }

        /// <summary>
        /// The one place the management commands meet the process: the
        /// environment, the parsed flags, the two streams and the clock. They
        /// take those rather than reaching for Console or DateTimeOffset.UtcNow
        /// themselves, so every one of them can be run in a test against a
        /// temporary directory and have its output read back.
        /// </summary>
        /// <summary>
        /// `restore` - reads an encrypted backup back out.
        ///
        /// A COMMAND, NOT A PAGE, and deliberately. Taking a backup is routine
        /// and belongs on the admin page; putting one back is the one operation
        /// that could destroy a live store, and it should require a shell on the
        /// box rather than a session cookie. It also has to work when the
        /// service will not start, which is exactly when a restore is needed.
        ///
        /// It never writes over anything: the destination has to be empty, and
        /// moving the files into place afterwards is the operator's own,
        /// deliberate step.
        /// </summary>
        private static int Restore(string[] args)
        {
            var parsed = ParseArguments(args);

            if (!parsed.TryGetValue("in", out var input) || string.IsNullOrWhiteSpace(input))
            {
                Console.Error.WriteLine("restore --in <backup file> --out <an empty directory>");

                return 1;
            }

            if (!parsed.TryGetValue("out", out var output) || string.IsNullOrWhiteSpace(output))
            {
                Console.Error.WriteLine("restore --in <backup file> --out <an empty directory>");

                return 1;
            }

            var passphrase = Environment.GetEnvironmentVariable("LICENCE_BACKUP_PASSPHRASE");

            if (string.IsNullOrEmpty(passphrase))
            {
                Console.Error.WriteLine(
                    "LICENCE_BACKUP_PASSPHRASE is not set. It has to be the passphrase that was in force WHEN THE "
                    + "BACKUP WAS TAKEN, which is not necessarily the one this deployment uses now.");

                return ConfigurationError;
            }

            byte[] blob;

            try
            {
                blob = File.ReadAllBytes(input);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                Console.Error.WriteLine("Could not read " + input + ": " + ex.Message);

                return 1;
            }

            try
            {
                var restored = Backup.BackupArchive.Restore(blob, passphrase, output);

                Console.Error.WriteLine(
                    "Restored " + restored.ToString(CultureInfo.InvariantCulture) + " file(s) into "
                    + Path.GetFullPath(output) + ".");
                Console.Error.WriteLine(
                    "Nothing live has been touched. Stop the service, move licences.db and the .jsonl files into "
                    + "LICENCE_DATA_DIR yourself, make sure they are owned by uid 5678, and start it again.");

                return 0;
            }
            catch (Exception ex) when (ex is InvalidOperationException || ex is ArgumentException)
            {
                Console.Error.WriteLine(ex.Message);

                return 1;
            }
        }

        private static int Manage(
            string[] args,
            Func<IDictionary<string, string>, ServiceOptions, TextWriter, TextWriter, DateTimeOffset, int> command)
        {
            return command(
                ParseArguments(args),
                ServiceOptions.FromEnvironment(Environment.GetEnvironmentVariable),
                Console.Out,
                Console.Error,
                DateTimeOffset.UtcNow);
        }

        /// <summary>
        /// `healthcheck` - what the container's HEALTHCHECK runs.
        ///
        /// It is a command in this binary rather than a curl in the image
        /// because the aspnet runtime image ships neither curl nor wget, and
        /// installing one to ask a question the service can answer itself would
        /// add a package - and a CVE feed - to the box that holds the signing
        /// key.
        /// </summary>
        private static int HealthCheck(string[] args)
        {
            var parsed = ParseArguments(args);

            if (!parsed.TryGetValue("url", out var url) || string.IsNullOrWhiteSpace(url))
            {
                url = "http://127.0.0.1:8080/healthz";
            }

            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                using var response = http.GetAsync(url).GetAwaiter().GetResult();

                if (response.IsSuccessStatusCode)
                {
                    return 0;
                }

                Console.Error.WriteLine("unhealthy: " + url + " answered " + (int)response.StatusCode);

                return 1;
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is TaskCanceledException)
            {
                Console.Error.WriteLine("unhealthy: " + url + " did not answer: " + ex.Message);

                return 1;
            }
        }

        private static int Number(IDictionary<string, string> parsed, string name, int fallback)
        {
            if (!parsed.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
            {
                return fallback;
            }

            return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) ? number : -1;
        }

        /// <summary>
        /// `--flag value` and `--flag`, from the second argument on - the first
        /// is the command name. Internal so the command tests parse exactly what
        /// an operator types rather than a dictionary a test made up.
        /// </summary>
        internal static IDictionary<string, string> ParseArguments(string[] args)
        {
            var parsed = new Dictionary<string, string>(StringComparer.Ordinal);

            for (var i = 1; i < args.Length; i++)
            {
                if (!args[i].StartsWith("--", StringComparison.Ordinal))
                {
                    continue;
                }

                var name = args[i].Substring(2);
                var hasValue = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal);

                parsed[name] = hasValue ? args[++i] : string.Empty;
            }

            return parsed;
        }

        /// <summary>
        /// What `--help` prints. Internal so a test can assert every command
        /// the binary answers to is listed: a command nobody can discover is a
        /// command that does not exist.
        /// </summary>
        internal const string Usage = @"Emby SSO licence service

  (no arguments)
      Runs the service. Everything is configured through the environment;
      see service/README.md.

  issue-code --licensee <name> [--activations <n>] [--days <n>] [--note <text>]
      Creates a redemption code that no payment bought, prints it on stdout
      and stores only its hash. For testers, comps, and recovering a sale
      whose code could not be delivered.

  list-codes [--needs-attention] [--for <text>] [--soon <days>]
      Every code: state, when it was created, paid or comped, activations used
      of allowed, the licence length and expiry, and whether delivery is still
      outstanding. Sorted so what needs attention is at the top. --for matches
      a licensee, a buyer address or a tag. NO CODE IS PRINTED: the store holds
      only hashes.

  show-code (--code <as the customer typed it> | --tag <hash prefix>)
      Everything about one code, plus every server it has been activated onto.
      The support command. --code takes any case, with or without separators.
      It confirms a code it is given; it cannot reveal one.

  void-code (--code <...> | --tag <...>) [--reason <text>]
      Stops a code activating again - a refund, a mistake, a leak. Says in its
      own output what it CANNOT do, which is recall a licence already issued.
      Voiding twice is not an error.

  list-outbox [--all] [--reveal]
      Sales whose code has not reached the buyer. --reveal prints the codes
      themselves, which are in the outbox file in the clear.

  restore --in <backup file> --out <an empty directory>
      Decrypts a backup taken from /admin/backup, using the passphrase in
      LICENCE_BACKUP_PASSPHRASE - which must be the one that was in force when
      the backup was TAKEN. Restores into an empty directory and never over a
      live store; moving the files into place is your own step.

  healthcheck [--url <url>]
      Exits 0 if /healthz answers 200. What the container HEALTHCHECK runs.

  hash-password
      Reads a password on stdin and prints the ADMIN_PASSWORD_HASH line that
      turns on the admin page at /admin. With no such variable set there is no
      admin page at all: the routes are never mapped. Read the section in
      service/README.md before turning it on - it is a public door to the box
      that holds the customer store. ADMIN_ALLOWED_CIDRS and
      ADMIN_REQUIRED_HEADER put something in front of the password; both are
      off by default and both fail closed when set.

Exit codes: 0 done, 1 no such code or bad usage, 66 there is no store at
LICENCE_DATA_DIR, 78 the configuration is wrong.";
    }
}

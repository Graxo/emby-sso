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
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.Http;
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
    /// The host, the routes, and the two commands that are not routes.
    ///
    /// Everything a route does is one call into a class that can be tested
    /// without a socket. What is left here is HTTP: reading a capped body,
    /// working out who the caller is, and turning a reply into a status code.
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
            if (args.Length > 0 && string.Equals(args[0], "issue-code", StringComparison.Ordinal))
            {
                return IssueCode(args);
            }

            if (args.Length > 0 && string.Equals(args[0], "healthcheck", StringComparison.Ordinal))
            {
                return HealthCheck(args);
            }

            if (args.Length > 0 && (args[0] == "--help" || args[0] == "help"))
            {
                Console.WriteLine(Usage);

                return 0;
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

            SigningKeyFile.SigningKey key;

            try
            {
                key = SigningKeyFile.Load(options.SigningKeyPath);
            }
            catch (SigningKeyFile.SigningKeyException ex)
            {
                // The loudest failure in the service, and the earliest. A licence
                // service that starts without a usable signing key would take
                // money and fail at the last step.
                Console.Error.WriteLine(ex.Message);

                return ConfigurationError;
            }

            WebApplication app;

            try
            {
                app = BuildApp(options, key, null);
            }
            catch (MailTemplateException ex)
            {
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
            SigningKeyFile.SigningKey key,
            Action<WebApplicationBuilder> configure)
        {
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
            builder.Services.AddSingleton(key);
            builder.Services.AddSingleton(new LicenceIssuer(key.Key));
            builder.Services.AddSingleton(new LicenceLedger(options.LedgerPath));
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

            configure?.Invoke(builder);

            var app = builder.Build();

            var log = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Emby.Sso.LicenceService");

            log.LogInformation(
                "signing key {Thumbprint} loaded from {Path}; store {Store}; ledger {Ledger}; paypal {Env}; "
                + "{Allowed} activations per code; {Days} day licences",
                key.Thumbprint,
                key.Path,
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

            MapRoutes(app, options);

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

                var reply = activations.Activate(request, client);

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

            app.MapGet("/healthz", (LicenceStore store, SigningKeyFile.SigningKey key, ActivationRateLimiter limiter) =>
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

                        // The PUBLIC key's thumbprint, so "which key is this box
                        // signing with" is answerable from outside without a
                        // shell, and answerable by comparing it to the plugin
                        // build's embedded key. Nothing here is secret.
                        signingKey = key.Thumbprint,
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

            if (!parsed.TryGetValue("licensee", out var licensee) || string.IsNullOrWhiteSpace(licensee))
            {
                Console.Error.WriteLine("--licensee is required: who is this code for?");
                Console.Error.WriteLine();
                Console.Error.WriteLine(Usage);

                return 1;
            }

            var allowed = Number(parsed, "activations", options.ActivationsAllowed);
            var days = Number(parsed, "days", options.LicenceDays);

            if (allowed < 1 || days < 1)
            {
                Console.Error.WriteLine("--activations and --days must both be positive.");

                return 1;
            }

            var store = new LicenceStore(options.DatabasePath);

            store.Initialise();

            var code = RedemptionCode.Generate();
            var hash = RedemptionCode.Hash(code);

            parsed.TryGetValue("note", out var note);

            var id = store.CreateManualCode(hash, licensee, allowed, days, note, DateTimeOffset.UtcNow);

            Console.Error.WriteLine("Code id     : " + id.ToString(CultureInfo.InvariantCulture));
            Console.Error.WriteLine("Licensee    : " + licensee);
            Console.Error.WriteLine("Activations : " + allowed.ToString(CultureInfo.InvariantCulture));
            Console.Error.WriteLine("Licence     : " + days.ToString(CultureInfo.InvariantCulture) + " days from first activation");
            Console.Error.WriteLine("Tag         : " + RedemptionCode.LogTag(hash) + "  (this is what the logs show)");
            Console.Error.WriteLine();
            Console.Error.WriteLine("The code itself is on stdout, and is stored here ONLY as a hash. If you lose it,");
            Console.Error.WriteLine("nothing can recover it and you issue another one.");
            Console.Error.WriteLine();

            // stdout alone, so `> code.txt` gives just the code.
            Console.WriteLine(RedemptionCode.Format(code));

            return 0;
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

        private static IDictionary<string, string> ParseArguments(string[] args)
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

        private const string Usage = @"Emby SSO licence service

  (no arguments)
      Runs the service. Everything is configured through the environment;
      see service/README.md.

  issue-code --licensee <name> [--activations <n>] [--days <n>] [--note <text>]
      Creates a redemption code that no payment bought, prints it on stdout
      and stores only its hash. For testers, comps, and recovering a sale
      whose code could not be delivered.

  healthcheck [--url <url>]
      Exits 0 if /healthz answers 200. What the container HEALTHCHECK runs.";
    }
}

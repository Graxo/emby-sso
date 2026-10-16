using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Emby.Sso.LicenceService.Vendor
{
    /// <summary>
    /// The API the reseller's system (the portal) uses to create and change the
    /// codes it sells, and to free a seat. Mapped ONLY when LICENCE_VENDOR_TOKEN
    /// is set; with none there is no route at all.
    ///
    /// One shared bearer token, compared in constant time, and a 401 that says
    /// nothing about which half was wrong. The code itself never arrives here:
    /// the portal sends the SHA-256 of it, so this API cannot be used to read
    /// codes back, only to register and manage them.
    /// </summary>
    internal static class VendorEndpoints
    {
        private static readonly Regex RefPattern = new Regex("^[a-z0-9-]{1,64}$", RegexOptions.CultureInvariant);

        private static readonly Regex HashPattern = new Regex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);

        // Server ids are 32 hex characters on the wire; this only has to keep
        // junk out of the lookup, so it is deliberately looser.
        private static readonly Regex ServerIdPattern = new Regex("^[A-Za-z0-9-]{1,64}$", RegexOptions.CultureInvariant);

        private const int MaximumSeats = 100;

        private const int MaximumLicenseeLength = 200;

        private const int MaximumVoidReasonLength = 500;

        private static readonly JsonSerializerOptions Web = new JsonSerializerOptions(JsonSerializerDefaults.Web);

        public static void Map(WebApplication app, ServiceOptions options)
        {
            var store = app.Services.GetRequiredService<LicenceStore>();
            var clock = app.Services.GetRequiredService<TimeProvider>();
            var log = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Emby.Sso.LicenceService.Vendor");
            var token = Encoding.UTF8.GetBytes(options.VendorToken);

            app.MapPut("/v1/vendor/licences/{vendorRef}", async (HttpContext context, string vendorRef) =>
            {
                if (!Authorised(context, token))
                {
                    return Refused(log);
                }

                if (!RefPattern.IsMatch(vendorRef))
                {
                    return Bad("ref");
                }

                var body = await Program.ReadBodyAsync(context).ConfigureAwait(false);

                if (body == null)
                {
                    return Bad("body");
                }

                PutBody put;

                try
                {
                    put = JsonSerializer.Deserialize<PutBody>(body, Web);
                }
                catch (JsonException)
                {
                    return Bad("body");
                }

                var problem = Validate(put);

                if (problem != null)
                {
                    return Bad(problem);
                }

                var voided = put.Status == "void";

                var result = store.UpsertVendorCode(
                    vendorRef,
                    put.CodeHash,
                    put.Licensee,
                    put.Seats.Value,
                    put.ExpiresUtc.Value,
                    voided,
                    voided ? put.VoidReason : null,
                    clock.GetUtcNow());

                log.LogInformation("vendor PUT {Ref}: {Outcome}", vendorRef, result);

                if (result == VendorUpsertResult.HashConflict)
                {
                    return Results.Json(new { error = "hash_conflict" }, Web, statusCode: 409);
                }

                return Results.Json(
                    Shape(store.FindVendorCode(vendorRef)),
                    Web,
                    statusCode: result == VendorUpsertResult.Created ? 201 : 200);
            });

            app.MapGet("/v1/vendor/licences/{vendorRef}", (HttpContext context, string vendorRef) =>
            {
                if (!Authorised(context, token))
                {
                    return Refused(log);
                }

                var row = RefPattern.IsMatch(vendorRef) ? store.FindVendorCode(vendorRef) : null;

                return row == null
                    ? Results.Json(new { error = "not_found" }, Web, statusCode: 404)
                    : Results.Json(Shape(row), Web, statusCode: 200);
            });

            // Codes sold before the portal existed - PayPal sales, `issue-code`
            // comps - so the portal can offer to import them. Only hashes go
            // out, like everything else on this API; a code itself cannot be
            // read back from here.
            app.MapGet("/v1/vendor/unmanaged", (HttpContext context) =>
            {
                if (!Authorised(context, token))
                {
                    return Refused(log);
                }

                var codes = store.ListUnmanagedCodes();

                log.LogInformation("vendor unmanaged: {Count} codes", codes.Count);

                return Results.Json(new { codes = codes.Select(c => Shape(c)).ToList() }, Web, statusCode: 200);
            });

            // Takes one of those codes over: gives it the portal's ref, and
            // nothing else. The portal's next PUT on the ref sets licensee,
            // seats, expiry and status through the ordinary update path, so
            // there is still exactly one way a code's terms are changed.
            app.MapPost("/v1/vendor/licences/{vendorRef}/adopt", async (HttpContext context, string vendorRef) =>
            {
                if (!Authorised(context, token))
                {
                    return Refused(log);
                }

                if (!RefPattern.IsMatch(vendorRef))
                {
                    return Bad("ref");
                }

                var body = await Program.ReadBodyAsync(context).ConfigureAwait(false);

                if (body == null)
                {
                    return Bad("body");
                }

                AdoptBody adopt;

                try
                {
                    adopt = JsonSerializer.Deserialize<AdoptBody>(body, Web);
                }
                catch (JsonException)
                {
                    return Bad("body");
                }

                if (adopt == null)
                {
                    return Bad("body");
                }

                if (adopt.CodeHash == null || !HashPattern.IsMatch(adopt.CodeHash))
                {
                    return Bad("codeHash");
                }

                var result = store.AdoptVendorCode(vendorRef, adopt.CodeHash);

                // The log tag (a short prefix of the hash) and not the hash: it
                // is enough to find the row with `show-code`, and the full hash
                // is the one thing that identifies the customer's code.
                log.LogInformation(
                    "vendor adopt {Ref} code={Tag}: {Outcome}",
                    vendorRef,
                    RedemptionCode.LogTag(adopt.CodeHash),
                    result);

                switch (result)
                {
                    case VendorAdoptResult.NotFound:
                        return Results.Json(new { error = "not_found" }, Web, statusCode: 404);
                    case VendorAdoptResult.AlreadyManaged:
                        return Results.Json(new { error = "already_managed" }, Web, statusCode: 409);
                    case VendorAdoptResult.RefInUse:
                        return Results.Json(new { error = "ref_in_use" }, Web, statusCode: 409);
                    default:
                        return Results.Json(Shape(store.FindVendorCode(vendorRef)), Web, statusCode: 200);
                }
            });

            app.MapDelete("/v1/vendor/licences/{vendorRef}/activations/{serverId}", (HttpContext context, string vendorRef, string serverId) =>
            {
                if (!Authorised(context, token))
                {
                    return Refused(log);
                }

                if (!RefPattern.IsMatch(vendorRef) || !ServerIdPattern.IsMatch(serverId))
                {
                    return Results.Json(new { error = "not_found" }, Web, statusCode: 404);
                }

                var result = store.ReleaseVendorActivation(vendorRef, serverId, clock.GetUtcNow());

                log.LogInformation("vendor release {Ref}: {Outcome}", vendorRef, result);

                return result == ReleaseResult.NotFound
                    ? Results.Json(new { error = "not_found" }, Web, statusCode: 404)
                    : Results.StatusCode(204);
            });
        }

        /// <summary>
        /// The 401, and one Warning to go with it. Neither the presented token nor
        /// the ref is logged: the first is somebody's guess at a credential and
        /// the second is only known to a caller who has not proved they may ask.
        /// </summary>
        private static IResult Refused(ILogger log)
        {
            log.LogWarning("vendor API: request refused, the bearer token was missing or wrong");

            return Results.StatusCode(401);
        }

        private static bool Authorised(HttpContext context, byte[] token)
        {
            var header = context.Request.Headers.Authorization.ToString();
            const string scheme = "Bearer ";

            if (!header.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var presented = Encoding.UTF8.GetBytes(header.Substring(scheme.Length));

            // FixedTimeEquals is only constant-time for equal lengths and
            // returns false at once otherwise; the length of the token is not
            // the secret.
            return CryptographicOperations.FixedTimeEquals(presented, token);
        }

        private static string Validate(PutBody put)
        {
            if (put == null)
            {
                return "body";
            }

            if (put.CodeHash == null || !HashPattern.IsMatch(put.CodeHash))
            {
                return "codeHash";
            }

            if (put.Licensee == null || put.Licensee.Length > MaximumLicenseeLength)
            {
                return "licensee";
            }

            if (put.VoidReason != null && put.VoidReason.Length > MaximumVoidReasonLength)
            {
                return "voidReason";
            }

            if (put.Seats == null || put.Seats < 1 || put.Seats > MaximumSeats)
            {
                return "seats";
            }

            if (put.ExpiresUtc == null)
            {
                return "expiresUtc";
            }

            if (put.Status != "active" && put.Status != "void")
            {
                return "status";
            }

            return null;
        }

        private static IResult Bad(string field)
        {
            return Results.Json(new { error = "invalid", field }, Web, statusCode: 400);
        }

        private static object Shape(VendorLicenceRow row)
        {
            return new
            {
                @ref = row.Ref,
                status = row.Status,
                seats = row.Seats,
                expiresUtc = row.ExpiresUtc.HasValue ? LicenceFormat.Iso(row.ExpiresUtc.Value) : null,
                activations = Shape(row.Activations),
            };
        }

        private static object Shape(UnmanagedCodeRow row)
        {
            return new
            {
                codeHash = row.CodeHash,
                licensee = row.Licensee,

                // For a manual code the column holds the `issue-code --note`,
                // not an address, so it goes out as `note` and buyerEmail is
                // null: the portal must never mail, or match a customer on,
                // free text somebody typed about a comp.
                buyerEmail = row.IsManual ? null : row.BuyerEmailOrNote,
                note = row.IsManual ? row.BuyerEmailOrNote : null,
                seats = row.Seats,
                status = row.Status,
                source = row.Source,
                createdUtc = LicenceFormat.Iso(row.CreatedUtc),

                // Null when the code was never activated: a PayPal or manual
                // code's expiry is fixed at its first activation.
                expiresUtc = row.ExpiresUtc.HasValue ? LicenceFormat.Iso(row.ExpiresUtc.Value) : null,
                licenceDays = row.LicenceDays,
                activations = Shape(row.Activations),
            };
        }

        private static List<object> Shape(IReadOnlyList<VendorActivationRow> activations)
        {
            return activations.Select(a => (object)new
            {
                serverId = a.ServerId,
                pluginVersion = a.PluginVersion,
                firstSeenUtc = LicenceFormat.Iso(a.FirstSeenUtc),
                lastSeenUtc = LicenceFormat.Iso(a.LastSeenUtc),
                releasedUtc = a.ReleasedUtc.HasValue ? LicenceFormat.Iso(a.ReleasedUtc.Value) : null,
            }).ToList();
        }

        private sealed class AdoptBody
        {
            public string CodeHash { get; set; }
        }

        private sealed class PutBody
        {
            public string CodeHash { get; set; }

            public string Licensee { get; set; }

            public int? Seats { get; set; }

            public DateTimeOffset? ExpiresUtc { get; set; }

            public string Status { get; set; }

            public string VoidReason { get; set; }
        }
    }
}

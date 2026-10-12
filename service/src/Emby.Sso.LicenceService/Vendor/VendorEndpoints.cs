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
                    return Results.StatusCode(401);
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
                    return Results.StatusCode(401);
                }

                var row = RefPattern.IsMatch(vendorRef) ? store.FindVendorCode(vendorRef) : null;

                return row == null
                    ? Results.Json(new { error = "not_found" }, Web, statusCode: 404)
                    : Results.Json(Shape(row), Web, statusCode: 200);
            });

            app.MapDelete("/v1/vendor/licences/{vendorRef}/activations/{serverId}", (HttpContext context, string vendorRef, string serverId) =>
            {
                if (!Authorised(context, token))
                {
                    return Results.StatusCode(401);
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
                expiresUtc = LicenceFormat.Iso(row.ExpiresUtc),
                activations = row.Activations.Select(a => new
                {
                    serverId = a.ServerId,
                    pluginVersion = a.PluginVersion,
                    firstSeenUtc = LicenceFormat.Iso(a.FirstSeenUtc),
                    lastSeenUtc = LicenceFormat.Iso(a.LastSeenUtc),
                    releasedUtc = a.ReleasedUtc.HasValue ? LicenceFormat.Iso(a.ReleasedUtc.Value) : null,
                }).ToList(),
            };
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

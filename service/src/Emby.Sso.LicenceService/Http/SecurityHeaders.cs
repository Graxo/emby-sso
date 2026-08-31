using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Emby.Sso.LicenceService.Http
{
    /// <summary>
    /// The headers every response carries, and the extra ones the admin pages
    /// carry.
    ///
    /// The content security policy is the interesting one. These pages have NO
    /// JavaScript at all - not a framework, not a CDN, not an inline handler -
    /// so the policy can be `default-src 'none'`, which is the strongest thing
    /// a page can say: an injected &lt;script&gt;, an injected image beacon, an
    /// injected iframe and an injected fetch are all refused by the browser
    /// before they run. That is a second line behind the HTML encoding, not a
    /// replacement for it, and the encoding has its own tests.
    ///
    /// `form-action 'self'` matters on the admin pages specifically: it stops an
    /// injected form posting the operator's session somewhere else, and it is
    /// one of the few CSP directives an XSS cannot work around.
    ///
    /// NO-STORE ON /admin. A browser cache of a customer list on a laptop is a
    /// leak with no upside, and the back button after a logout must not paint
    /// the page again from cache. It is set on every admin response including
    /// the redirects, because a cached 303 is just as good a way to bring a page
    /// back.
    /// </summary>
    public static class SecurityHeaders
    {
        /// <summary>
        /// What a page may load. Nothing, except styles this service wrote
        /// inline. There is no script-src because there is no script: with
        /// default-src 'none' an injected one has nowhere to come from,
        /// including from an inline attribute.
        /// </summary>
        public const string PagePolicy =
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

        /// <summary>What the JSON endpoints say. They are never rendered, so nothing is allowed at all.</summary>
        public const string ApiPolicy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

        public static void UseSecurityHeaders(this WebApplication app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            app.Use(async (context, next) =>
            {
                // OnStarting rather than set-and-hope: a result that writes its
                // own headers later would otherwise be able to run after this
                // middleware has set them and before they are sent.
                context.Response.OnStarting(() =>
                {
                    var headers = context.Response.Headers;
                    var isAdmin = IsAdmin(context.Request.Path);

                    headers["X-Content-Type-Options"] = "nosniff";
                    headers["X-Frame-Options"] = "DENY";
                    headers["Referrer-Policy"] = "no-referrer";
                    headers["Content-Security-Policy"] = isAdmin || IsPage(context.Request.Path)
                        ? PagePolicy
                        : ApiPolicy;

                    // Nothing here uses a camera, a microphone, a location or a
                    // payment API in the browser - PayPal is reached by a
                    // redirect, not by a script - so all of it is turned off.
                    headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=(), usb=()";

                    // Ignored by browsers over plain http, so it costs nothing
                    // here and is correct the moment this is behind the TLS
                    // proxy it is meant to be behind. Without includeSubDomains:
                    // this service does not know what else lives on the parent
                    // domain and must not make promises for it.
                    headers["Strict-Transport-Security"] = "max-age=31536000";

                    if (isAdmin)
                    {
                        headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private";
                        headers["Pragma"] = "no-cache";
                        headers["Expires"] = "0";
                    }

                    return System.Threading.Tasks.Task.CompletedTask;
                });

                await next(context).ConfigureAwait(false);
            });
        }

        /// <summary>
        /// Anything under /admin, matched the way a router would rather than by
        /// StartsWith: "/administrator" is not an admin path, and neither is
        /// "/adminx".
        /// </summary>
        public static bool IsAdmin(PathString path)
        {
            return path.StartsWithSegments("/admin", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsPage(PathString path)
        {
            return path.StartsWithSegments("/buy", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/", StringComparison.Ordinal);
        }
    }
}

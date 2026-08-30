using Emby.Sso;

namespace Emby.Sso.Api
{
    /// <summary>
    /// The only thing a failed sign-in shows the browser: one short reason drawn
    /// from a fixed set of our own strings. Every diagnostic detail, and every
    /// byte the identity provider supplied, goes to the log instead.
    /// </summary>
    internal static class ErrorPage
    {
        /// <param name="userSafeReason">
        /// One of the <c>SsoErrors</c> constants, or null for a failure that fits
        /// none of them.
        /// </param>
        /// <param name="baseUrl">
        /// A validated http/https base URL with no trailing slash, or an empty
        /// string to emit root-relative links.
        /// </param>
        public static string Render(string userSafeReason, string baseUrl)
        {
            var reason = PageText.Html(
                string.IsNullOrWhiteSpace(userSafeReason)
                    ? "Something went wrong completing this sign-in."
                    : userSafeReason);
            var prefix = baseUrl ?? string.Empty;
            var home = PageText.Html(prefix + "/web/index.html");
            var retry = PageText.Html(prefix + "/emby" + SsoRoutes.StartPath);

            return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + "<meta name=\"referrer\" content=\"no-referrer\">"
                + "<title>Sign-in failed</title><style>" + PageText.BaseStyle
                + "</style></head><body><main>"
                + "<h1>Sign-in failed</h1><p>" + reason + "</p>"
                + "<p><a href=\"" + retry + "\">Try again</a> &middot; "
                + "<a href=\"" + home + "\">Back to Emby</a></p>"
                + "</main></body></html>";
        }
    }
}

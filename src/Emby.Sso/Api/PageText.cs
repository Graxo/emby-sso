using System.Net;
using Newtonsoft.Json;

namespace Emby.Sso.Api
{
    /// <summary>
    /// The two escapes every value embedded in a served page must go through.
    /// Nothing in this namespace writes a dynamic value into HTML or into a
    /// script without one of these.
    /// </summary>
    internal static class PageText
    {
        /// <summary>Escapes a value for an HTML text node or a quoted attribute.</summary>
        public static string Html(string value)
        {
            return WebUtility.HtmlEncode(value ?? string.Empty);
        }

        /// <summary>
        /// Produces a complete, quoted JavaScript string literal.
        /// </summary>
        /// <remarks>
        /// <see cref="JsonConvert.ToString(string)"/> handles quotes, backslashes,
        /// control characters and the line separators U+2028/U+2029, but leaves
        /// '&lt;' alone - and a value containing "&lt;/script&gt;" would otherwise
        /// end the element from inside a string literal. The three extra
        /// replacements close that hole; '\uXXXX' is a valid escape inside a
        /// JavaScript string and decodes back to the original character.
        /// </remarks>
        public static string JsString(string value)
        {
            return JsonConvert.ToString(value ?? string.Empty)
                .Replace("<", "\\u003c")
                .Replace(">", "\\u003e")
                .Replace("&", "\\u0026");
        }

        /// <summary>
        /// The CSS shared by every page this plugin serves directly to a
        /// browser - the error page and the sign-in completion page - so the two
        /// stay visually identical without copy-pasting the block. Each page's
        /// own <c>&lt;style&gt;</c> block may append rules after this one.
        /// </summary>
        public const string BaseStyle =
            "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;"
            + "background:#101010;color:#eee;display:flex;min-height:100vh;margin:0;"
            + "align-items:center;justify-content:center;text-align:center}"
            + "main{max-width:32rem;padding:2rem}h1{font-size:1.25rem;font-weight:600}"
            + "p{color:#bbb;line-height:1.5}a{color:#9cf}";
    }
}

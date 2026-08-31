using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Character-set checks that keep administrator-supplied or derived values
    /// out of a header where they could end an attribute, start a new header, or
    /// otherwise be used for injection. Pure string handling, so it lives in
    /// <c>Protocol/</c> where the test project can reach it, even though every
    /// caller today is in <c>Api/</c>.
    /// </summary>
    internal static class HeaderSafety
    {
        /// <summary>
        /// True when every character in <paramref name="path"/> is safe to place
        /// unescaped into a <c>Set-Cookie</c> header's <c>Path</c> attribute.
        /// </summary>
        public static bool IsPathSafe(string path)
        {
            if (path == null)
            {
                return false;
            }

            foreach (var character in path)
            {
                var allowed = (character >= 'a' && character <= 'z')
                    || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9')
                    || character == '/' || character == '-' || character == '_'
                    || character == '.' || character == '~' || character == '%';

                if (!allowed)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// True when <paramref name="value"/> is safe to place unescaped as a
        /// cookie value - alphanumeric plus '-' and '_' only, which is what
        /// <c>SecureRandom</c>'s base64url tokens always produce. Exists so a
        /// future change to the token alphabet cannot silently become header
        /// injection.
        /// </summary>
        public static bool IsCookieValueSafe(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            foreach (var character in value)
            {
                var allowed = (character >= 'a' && character <= 'z')
                    || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9')
                    || character == '-' || character == '_';

                if (!allowed)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// A trimmed, trailing-slash-stripped http(s) URL, or an empty string
        /// when <paramref name="url"/> is missing, blank, or not an http(s) URL -
        /// so a bad or absent setting can never become the href of a link on a
        /// page, or the target of a redirect built from it.
        /// </summary>
        public static string SanitizeBaseUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                return string.Empty;
            }

            var trimmed = url.Trim().TrimEnd('/');

            var acceptable = trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                || trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase);

            return acceptable ? trimmed : string.Empty;
        }
    }
}

using System;
using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The string handling behind the browser-binding cookie check: parsing a
    /// raw <c>Cookie</c> header into candidate values for one cookie name, and
    /// deciding whether any of them match. Kept free of any HTTP type so it can
    /// live in <c>Protocol/</c> and be exercised by the test project, which does
    /// not compile <c>Api/</c> - this is pure string handling that defends
    /// against login CSRF, and it should not be the only untested logic of
    /// consequence in the codebase.
    /// </summary>
    internal static class CookieBinding
    {
        /// <summary>
        /// Every value presented for a cookie named <paramref name="name"/>,
        /// across all supplied <c>Cookie</c> header values. A browser may send
        /// several cookies of the same name when their paths differ, or a proxy
        /// may fold multiple <c>Cookie</c> headers into several strings, so both
        /// repetition within one header and across several are collected.
        /// </summary>
        public static IReadOnlyList<string> ExtractCookieValues(IEnumerable<string> cookieHeaders, string name)
        {
            var found = new List<string>();

            if (cookieHeaders == null || string.IsNullOrEmpty(name))
            {
                return found;
            }

            var prefix = name + "=";

            foreach (var header in cookieHeaders)
            {
                if (string.IsNullOrEmpty(header))
                {
                    continue;
                }

                foreach (var part in header.Split(';'))
                {
                    var item = part.Trim();

                    if (item.StartsWith(prefix, StringComparison.Ordinal) && item.Length > prefix.Length)
                    {
                        found.Add(item.Substring(prefix.Length));
                    }
                }
            }

            return found;
        }

        /// <summary>
        /// Whether any presented value matches <paramref name="expected"/>, in
        /// constant time. An empty <paramref name="expected"/> never matches -
        /// including against an empty presented value - so a caller can never
        /// turn "nothing was bound" into "the binding matched" by presenting an
        /// empty cookie.
        /// </summary>
        public static bool BindingMatches(string expected, IEnumerable<string> presented)
        {
            if (string.IsNullOrEmpty(expected) || presented == null)
            {
                return false;
            }

            foreach (var candidate in presented)
            {
                if (FixedTime.Equals(expected, candidate))
                {
                    return true;
                }
            }

            return false;
        }
    }
}

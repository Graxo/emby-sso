using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Asks the vendor whether this server's licence is still good, once a day.
    ///
    /// EVERYTHING HERE IS ALLOWED TO FAIL, and failing means "no answer", which
    /// means nothing changes. There is no retry, no backoff, no escalation and
    /// no error worth surfacing to a user: the plugin asked, it did not get a
    /// usable answer, it will ask again tomorrow. The only thing that must never
    /// happen is a failure that stops sign-ins, and the only way to stop them is
    /// a correctly signed revocation.
    ///
    /// THE LICENCE ITSELF IS NEVER SENT. What goes out is this server's id and
    /// the licence's SHA-256, both of which the vendor already has. A
    /// fingerprint is one-way, so a service that received it - or anything that
    /// intercepted it - learns nothing it could use as a licence.
    ///
    /// It goes through the same outbound guard as everything else, so a
    /// configured service address pointing at a private or loopback address is
    /// refused unless the operator has explicitly allowed that.
    /// </summary>
    internal static class LicenceStatusClient
    {
        /// <summary>
        /// Short. This runs unattended on a timer and its answer is optional, so
        /// there is no reason to hold a connection open waiting for a service
        /// that is not answering.
        /// </summary>
        public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

        /// <summary>
        /// The most this will read. An answer is one small JWT; anything larger
        /// is not one, and reading it would be doing work for whoever sent it.
        /// </summary>
        public const int MaximumResponseBytes = 16 * 1024;

        /// <summary>
        /// Returns what the vendor said, or <see cref="LicenceStatusOutcome
        /// .NoAnswer"/> for every way that can fail.
        /// </summary>
        public static async Task<LicenceStatusOutcome> CheckAsync(
            HttpClient client,
            string serviceBase,
            string serverId,
            string licence,
            IReadOnlyList<string> publicKeyJwks,
            DateTimeOffset now,
            CancellationToken cancellationToken)
        {
            if (client == null || string.IsNullOrWhiteSpace(serverId) || string.IsNullOrWhiteSpace(licence))
            {
                return LicenceStatusOutcome.NoAnswer;
            }

            if (!ActivationEndpoint.TryBuildStatusUrl(serviceBase, out var url, out _))
            {
                return LicenceStatusOutcome.NoAnswer;
            }

            var fingerprint = Fingerprint(licence);

            string body;

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent(
                        "{\"serverId\":\"" + JsonEscape(serverId.Trim()) + "\",\"fingerprint\":\"" + fingerprint + "\"}",
                        Encoding.UTF8,
                        "application/json"),
                };

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

                timeout.CancelAfter(Timeout);

                using var response = await client.SendAsync(request, timeout.Token).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    // Including 501, which is what a vendor deployment that does
                    // not sign for itself answers. Not an error - there is
                    // simply no revocation service, and nothing changes.
                    return LicenceStatusOutcome.NoAnswer;
                }

                body = await ReadCappedAsync(response, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Every network failure, every timeout, every refusal by the
                // outbound guard, and cancellation at shutdown. All the same
                // thing: no answer.
                return LicenceStatusOutcome.NoAnswer;
            }

            var token = ReadStatusToken(body);

            return await LicenceStatusCheck
                .ReadAsync(token, publicKeyJwks, serverId, fingerprint, now)
                .ConfigureAwait(false);
        }

        /// <summary>
        /// The SHA-256 of the licence, in the shape the service records - the
        /// literal "sha256:" and 64 lowercase hex characters. It must match
        /// <c>Emby.Sso.Licensing.LicenceFormat.Fingerprint</c> character for
        /// character, or the vendor will never find the licence being asked
        /// about and every answer will be "unknown".
        /// </summary>
        public static string Fingerprint(string licence)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(licence));
                var text = new StringBuilder("sha256:", 71);

                foreach (var b in hash)
                {
                    text.Append(b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
                }

                return text.ToString();
            }
        }

        /// <summary>
        /// Pulls the token out of {"status":"..."} without a JSON parser, the
        /// way ActivationMessage does: the body is from a service this build
        /// does not trust yet, and the token that comes out of it is about to be
        /// verified cryptographically anyway. Nothing here believes anything.
        /// </summary>
        private static string ReadStatusToken(string body)
        {
            if (string.IsNullOrEmpty(body))
            {
                return null;
            }

            const string Key = "\"status\"";

            var at = body.IndexOf(Key, StringComparison.Ordinal);

            if (at < 0)
            {
                return null;
            }

            var colon = body.IndexOf(':', at + Key.Length);

            if (colon < 0)
            {
                return null;
            }

            var open = body.IndexOf('"', colon + 1);

            if (open < 0)
            {
                return null;
            }

            var close = body.IndexOf('"', open + 1);

            return close < 0 ? null : body.Substring(open + 1, close - open - 1);
        }

        private static async Task<string> ReadCappedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);

            var buffer = new byte[MaximumResponseBytes];
            var filled = 0;

            while (filled < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer, filled, buffer.Length - filled, cancellationToken)
                    .ConfigureAwait(false);

                if (read == 0)
                {
                    break;
                }

                filled += read;
            }

            return Encoding.UTF8.GetString(buffer, 0, filled);
        }

        private static string JsonEscape(string value)
        {
            // The two callers pass a server id that has already been checked
            // against a strict character set, so this is belt and braces rather
            // than the only guard - but a request body built by concatenation
            // deserves it anyway.
            return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}

using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Fetches the vendor's signed release manifest and verifies it.
    ///
    /// Every failure is "no update", and no failure is worth telling a user
    /// about: the plugin looked, it did not learn of anything newer, it will
    /// look again tomorrow. Nothing here can make a server install anything -
    /// it can only ever hand back a release that
    /// <see cref="ReleaseCheck"/> has already verified was signed by the
    /// release key and is strictly newer than what is running.
    /// </summary>
    internal static class ReleaseClient
    {
        public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

        public const int MaximumResponseBytes = 16 * 1024;

        /// <summary>
        /// The newest signed release, or null when there is nothing newer, or
        /// nothing verifiable, or nothing reachable.
        /// </summary>
        public static async Task<SignedRelease> FetchAsync(
            HttpClient client,
            string serviceBase,
            Version running,
            System.Collections.Generic.IReadOnlyList<string> releaseKeyJwks,
            DateTimeOffset now,
            CancellationToken cancellationToken)
        {
            if (client == null)
            {
                return null;
            }

            if (!ActivationEndpoint.TryBuildReleaseUrl(serviceBase, out var url, out _))
            {
                return null;
            }

            string body;

            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

                timeout.CancelAfter(Timeout);

                using var response = await client.GetAsync(url, timeout.Token).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    // Including 404, which is what a service with nothing
                    // published answers. Not an error.
                    return null;
                }

                var content = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);

                if (content.Length > MaximumResponseBytes)
                {
                    return null;
                }

                body = System.Text.Encoding.UTF8.GetString(content);
            }
            catch (Exception)
            {
                return null;
            }

            return await ReleaseCheck
                .ReadAsync(ReadManifest(body), releaseKeyJwks, running, now)
                .ConfigureAwait(false);
        }

        /// <summary>
        /// Pulls the manifest out of {"manifest":"..."} without a JSON parser,
        /// as the other clients here do. What comes out is about to be verified
        /// cryptographically, so nothing at this stage is believed.
        /// </summary>
        private static string ReadManifest(string body)
        {
            if (string.IsNullOrEmpty(body))
            {
                return null;
            }

            const string Key = "\"manifest\"";

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
    }
}

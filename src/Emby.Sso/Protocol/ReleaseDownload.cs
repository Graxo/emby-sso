using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Emby.Sso.Protocol
{
    /// <summary>What a download attempt produced. Zero is a refusal, as everywhere else here.</summary>
    internal enum ReleaseDownloadOutcome
    {
        /// <summary>Fail-closed default. Nothing was written.</summary>
        Failed = 0,

        /// <summary>The bytes arrived and their SHA-256 is the one the vendor signed for.</summary>
        Verified = 1,

        /// <summary>Nothing came back: DNS, TLS, a timeout, a refusal by the outbound guard.</summary>
        Unreachable = 2,

        /// <summary>Something came back and it is not what the manifest named. NOTHING IS WRITTEN.</summary>
        WrongBytes = 3,

        /// <summary>More bytes than a plugin could plausibly be. Stopped rather than buffered.</summary>
        TooLarge = 4,
    }

    /// <summary>The bytes, and only when they matched.</summary>
    internal sealed class ReleaseDownloadResult
    {
        private ReleaseDownloadResult(ReleaseDownloadOutcome outcome, byte[] content, string detail)
        {
            Outcome = outcome;
            Content = content;
            Detail = detail;
        }

        public ReleaseDownloadOutcome Outcome { get; }

        /// <summary>
        /// The verified DLL, and ONLY on <see cref="ReleaseDownloadOutcome
        /// .Verified"/>. Null on every other outcome, so a caller that writes
        /// whatever is here cannot write unverified bytes by mistake.
        /// </summary>
        public byte[] Content { get; }

        /// <summary>For the server log. Never rendered into a page.</summary>
        public string Detail { get; }

        public static ReleaseDownloadResult Verified(byte[] content)
        {
            return new ReleaseDownloadResult(ReleaseDownloadOutcome.Verified, content, "the download matched the signed hash");
        }

        public static ReleaseDownloadResult Refused(ReleaseDownloadOutcome outcome, string detail)
        {
            if (outcome == ReleaseDownloadOutcome.Verified)
            {
                throw new ArgumentException("Verified is not a refusal", nameof(outcome));
            }

            return new ReleaseDownloadResult(outcome, null, detail);
        }
    }

    /// <summary>
    /// Fetches a release and checks it is the one the vendor signed for.
    ///
    /// THE HASH IS THE ONLY THING TRUSTED HERE. The address came out of a signed
    /// manifest, but an address is not a guarantee: the download host can be
    /// compromised, the DNS entry hijacked, a proxy interposed, a CDN cache
    /// poisoned. Every one of those ends the same way - the bytes do not hash to
    /// what the vendor signed, and nothing is written.
    ///
    /// So the order matters and is not an accident: download entirely, hash,
    /// compare, and only then hand the bytes back. Nothing is streamed to disk
    /// as it arrives, because a partially written plugin DLL is a broken server
    /// and a fully written unverified one is a compromised server.
    ///
    /// The comparison is constant-time. That is close to superstition here - the
    /// attacker already knows the hash, it is in a manifest they can read - but
    /// a hash comparison that short-circuits is a habit worth not having.
    /// </summary>
    internal static class ReleaseDownload
    {
        /// <summary>
        /// The merged plugin is a couple of megabytes. Sixty-four is far more
        /// than it will ever be and small enough that a hostile or broken host
        /// cannot make this process hold an arbitrary amount.
        /// </summary>
        public const int MaximumBytes = 64 * 1024 * 1024;

        public static readonly TimeSpan Timeout = TimeSpan.FromMinutes(5);

        public static async Task<ReleaseDownloadResult> FetchAsync(
            HttpClient client,
            SignedRelease release,
            CancellationToken cancellationToken)
        {
            if (client == null || release == null)
            {
                return ReleaseDownloadResult.Refused(ReleaseDownloadOutcome.Failed, "nothing to fetch");
            }

            byte[] content;

            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

                timeout.CancelAfter(Timeout);

                using var response = await client.GetAsync(
                    release.Url,
                    HttpCompletionOption.ResponseHeadersRead,
                    timeout.Token).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    return ReleaseDownloadResult.Refused(
                        ReleaseDownloadOutcome.Unreachable,
                        "the release address answered " + (int)response.StatusCode);
                }

                // Refuse on the declared length before reading a byte, when the
                // host declares one. Cheaper than finding out at the cap.
                if (response.Content.Headers.ContentLength > MaximumBytes)
                {
                    return ReleaseDownloadResult.Refused(
                        ReleaseDownloadOutcome.TooLarge,
                        "the release address declared more than " + MaximumBytes + " bytes");
                }

                content = await ReadCappedAsync(response, timeout.Token).ConfigureAwait(false);

                if (content == null)
                {
                    return ReleaseDownloadResult.Refused(
                        ReleaseDownloadOutcome.TooLarge,
                        "the release address sent more than " + MaximumBytes + " bytes");
                }
            }
            catch (Exception ex)
            {
                // The exception TYPE only, as everywhere else in this plugin: a
                // message from a remote host has no business in a log line.
                return ReleaseDownloadResult.Refused(
                    ReleaseDownloadOutcome.Unreachable,
                    "the release could not be downloaded: " + ex.GetType().Name);
            }

            var actual = Sha256(content);

            if (!FixedTimeEquals(actual, release.Sha256))
            {
                // THE ONE THAT MATTERS. A signed manifest said these bytes would
                // hash to something, and they do not. Whatever answered is not
                // the release, whether by accident or otherwise.
                return ReleaseDownloadResult.Refused(
                    ReleaseDownloadOutcome.WrongBytes,
                    "the download does not match the signed hash (expected " + release.Sha256 + ", got " + actual + ")");
            }

            return ReleaseDownloadResult.Verified(content);
        }

        public static string Sha256(byte[] content)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                var hash = sha.ComputeHash(content);
                var text = new StringBuilder(64);

                foreach (var b in hash)
                {
                    text.Append(b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
                }

                return text.ToString();
            }
        }

        private static bool FixedTimeEquals(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            var difference = 0;

            for (var i = 0; i < a.Length; i++)
            {
                difference |= a[i] ^ b[i];
            }

            return difference == 0;
        }

        private static async Task<byte[]> ReadCappedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using var buffer = new System.IO.MemoryStream();

            var chunk = new byte[81920];

            while (true)
            {
                var read = await stream.ReadAsync(chunk, 0, chunk.Length, cancellationToken).ConfigureAwait(false);

                if (read == 0)
                {
                    break;
                }

                if (buffer.Length + read > MaximumBytes)
                {
                    // Null rather than a truncated buffer: a caller that got
                    // bytes back would have to remember they might be partial.
                    return null;
                }

                buffer.Write(chunk, 0, read);
            }

            return buffer.ToArray();
        }
    }
}

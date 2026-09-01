using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Redeems a code at the vendor's activation service and comes back with a
    /// licence THIS BUILD has already verified, or with a refusal.
    ///
    /// THE SERVICE IS NOT TRUSTED. This is the whole security argument, so it is
    /// written out. The licence is an RS256 JWT signed by a private key that
    /// never leaves the vendor and bound to one Emby server id. That makes it
    /// self-verifying, and self-verifying is the entire licensing model - it is
    /// why the ordinary licence check needs no network, works forever offline,
    /// and cannot be fooled by anything on the wire. A plugin that stored
    /// whatever an activation service handed it would have thrown that away:
    /// spoof the service (or compromise it, or point an override at your own)
    /// and you mint yourself a licence. So the token that comes back is put
    /// through the SAME <see cref="LicenceCheck"/> that guards every sign-in,
    /// against the SAME embedded <see cref="LicencePublicKey"/> set, against THIS
    /// server's id, and it is stored only if that passes. A service that
    /// answers 200 with a forged licence gets
    /// <see cref="ActivationOutcome.LicenceRejected"/> and nothing is written.
    ///
    /// THIS IS NEVER ON A SIGN-IN PATH. It is called once, from the
    /// configuration page, by an administrator who pressed Activate. Nothing in
    /// <c>LicenceGate</c>, <c>SsoService</c> or <c>SsoCredentialValidator</c>
    /// reaches this file. If the vendor's service is unreachable, or gone
    /// forever, sign-ins are completely unaffected: the licence check that runs
    /// on them reads a string out of the configuration and validates it
    /// offline.
    ///
    /// Nothing here knows about Emby: the server id, the clock, the public key
    /// and the HTTP client are all arguments, so the whole decision is under
    /// test.
    /// </summary>
    internal static class ActivationClient
    {
        /// <summary>
        /// The most of a response body this will read. A licence is a couple of
        /// kilobytes of JWT; anything approaching this is a service having a
        /// very bad day or trying something, and either way the answer is a
        /// refusal rather than an unbounded read into memory.
        /// </summary>
        public const int MaxResponseBytes = 64 * 1024;

        private const string UnreachableMessage =
            "The licensing service could not be reached. This does not affect sign-ins at all - the "
            + "licence check is offline and never contacts anything - so you can safely try again later.";

        public static async Task<ActivationResult> ActivateAsync(
            HttpClient http,
            string serviceBase,
            string code,
            string serverId,
            string pluginVersion,
            System.Collections.Generic.IReadOnlyList<string> publicKeyJwks,
            DateTimeOffset now,
            CancellationToken cancellationToken)
        {
            if (http == null)
            {
                throw new ArgumentNullException(nameof(http));
            }

            if (string.IsNullOrWhiteSpace(code))
            {
                return ActivationResult.Refused(
                    ActivationOutcome.NotAttempted,
                    "Enter the redemption code you were given, then press Activate.",
                    "no redemption code was entered; nothing was sent");
            }

            if (string.IsNullOrWhiteSpace(serverId))
            {
                // The same fail-closed direction LicenceCheck takes: a licence
                // whose binding cannot be checked is a licence that was not
                // checked, so there is no point asking for one.
                return ActivationResult.Refused(
                    ActivationOutcome.NotAttempted,
                    "This server did not report a server id, so a licence could not be issued for it or "
                    + "checked against it. Restart Emby and look for a startup error from this plugin.",
                    "this server reported no system id; nothing was sent");
            }

            if (!ActivationEndpoint.TryBuildActivateUrl(serviceBase, out var url, out var refusal))
            {
                return ActivationResult.Refused(
                    ActivationOutcome.NotAttempted,
                    "The licensing service address is not usable: " + refusal + ".",
                    "activation not attempted: " + refusal);
            }

            string body;
            int statusCode;
            string retryAfter;

            try
            {
                using (var request = new HttpRequestMessage(HttpMethod.Post, url))
                {
                    // The redemption code travels in the BODY, never in the URL.
                    // A query string is written to access logs, proxy logs and
                    // Referer headers; this is a bearer secret and is treated
                    // the way the client secret is.
                    request.Content = new StringContent(
                        ActivationMessage.BuildRequest(code, serverId, pluginVersion),
                        Encoding.UTF8,
                        "application/json");

                    request.Headers.Accept.Add(
                        new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                    using (var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false))
                    {
                        statusCode = (int)response.StatusCode;
                        retryAfter = FirstHeader(response, "Retry-After");
                        body = await ReadCappedAsync(response).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception ex)
            {
                // A destination this plugin refused to send to is not an
                // unreachable service: nothing left this process, and what an
                // operator needs to read is the rule that fired. Same
                // distinction OidcClient draws, for the same reason.
                var refused = OutboundRefusedException.Find(ex);

                if (refused != null)
                {
                    return ActivationResult.Refused(
                        ActivationOutcome.NotAttempted,
                        "This plugin refused to send the activation request: " + refused.Message,
                        "activation refused before sending: " + LogSafeText.Flatten(refused.Message));
                }

                return ActivationResult.Refused(
                    ActivationOutcome.Unreachable,
                    UnreachableMessage,
                    "the licensing service could not be reached: " + ex.GetType().Name);
            }

            var failure = ActivationMessage.ReadResponse(
                statusCode,
                body,
                retryAfter,
                out var licence,
                out var expiresUtc,
                out var activationsUsed,
                out var activationsAllowed);

            if (failure != null)
            {
                return failure;
            }

            // ---------------------------------------------------------------
            // P2. Everything above this line is what a possibly-hostile service
            // said. Nothing above it has been believed. The check below is what
            // makes any of it safe to store.
            // ---------------------------------------------------------------
            var licenceStatus = await LicenceCheck.EvaluateAsync(licence, publicKeyJwks, serverId, now).ConfigureAwait(false);

            if (!LicenceCheck.Permits(licenceStatus.Outcome))
            {
                return ActivationResult.Refused(
                    ActivationOutcome.LicenceRejected,
                    "The licensing service returned a licence this plugin refused (" + licenceStatus.Outcome
                    + "). NOTHING WAS SAVED. A genuine licence is signed by the vendor and names this "
                    + "server; this one is not, or does not. If you set a licensing service address of "
                    + "your own, that is the first thing to check.",
                    "REFUSED a licence returned by the activation service: " + licenceStatus.Outcome
                    + " - " + LogSafeText.Flatten(licenceStatus.Detail));
            }

            return ActivationResult.Success(
                licence,
                expiresUtc,
                activationsUsed,
                activationsAllowed,
                "activation accepted and verified locally: " + LogSafeText.Flatten(licenceStatus.Detail));
        }

        private static string FirstHeader(HttpResponseMessage response, string name)
        {
            if (response.Headers.TryGetValues(name, out var values))
            {
                foreach (var value in values)
                {
                    return value;
                }
            }

            return null;
        }

        /// <summary>
        /// Reads at most <see cref="MaxResponseBytes"/>. Reading the stream
        /// rather than <c>ReadAsStringAsync</c> so that a service which
        /// advertises no length - or lies about it - still cannot make this
        /// process allocate without bound.
        /// </summary>
        private static async Task<string> ReadCappedAsync(HttpResponseMessage response)
        {
            try
            {
                using (var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                using (var buffer = new MemoryStream())
                {
                    var chunk = new byte[8 * 1024];
                    int read;

                    while (buffer.Length < MaxResponseBytes
                        && (read = await stream.ReadAsync(chunk, 0, chunk.Length).ConfigureAwait(false)) > 0)
                    {
                        buffer.Write(chunk, 0, (int)Math.Min(read, MaxResponseBytes - buffer.Length));
                    }

                    return Encoding.UTF8.GetString(buffer.ToArray());
                }
            }
            catch (Exception)
            {
                // An answer arrived and then the body failed. Treated as an
                // unreadable answer rather than as an unreachable service,
                // because the service did answer.
                return null;
            }
        }
    }
}

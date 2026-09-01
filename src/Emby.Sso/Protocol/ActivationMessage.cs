using System;
using Newtonsoft.Json.Linq;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The two halves of the wire format in <c>contract.md</c>: the request body
    /// this plugin sends, and the reading of whatever comes back.
    ///
    /// Both are pure functions of their arguments, which is the point - the
    /// shaping and the error mapping are the parts of activation that can be
    /// tested without a network, so they live here rather than in the Emby-facing
    /// service.
    /// </summary>
    internal static class ActivationMessage
    {
        /// <summary>
        /// The request body.
        ///
        /// The code goes in AS TYPED, only trimmed of surrounding whitespace:
        /// the contract makes the SERVICE responsible for case and separators,
        /// so normalising here would be a second, divergent implementation of a
        /// rule that already has one owner.
        /// </summary>
        public static string BuildRequest(string code, string serverId, string pluginVersion)
        {
            var body = new JObject
            {
                ["code"] = (code ?? string.Empty).Trim(),
                ["serverId"] = (serverId ?? string.Empty).Trim(),
                ["pluginVersion"] = string.IsNullOrWhiteSpace(pluginVersion) ? "unknown" : pluginVersion.Trim(),
            };

            return body.ToString(Newtonsoft.Json.Formatting.None);
        }

        /// <summary>
        /// Turns an HTTP status and a body into a decision.
        ///
        /// A 200 here means only "the service says yes and handed over a
        /// string". It is NOT an activation: <see cref="ActivationClient"/>
        /// verifies that string against the embedded public key before anything
        /// is stored, and this method deliberately cannot express success -
        /// it hands the licence back through <paramref name="licence"/> and
        /// returns null so that the caller has to go on and check it.
        /// </summary>
        /// <returns>The refusal, or null when the service returned a licence to be verified.</returns>
        public static ActivationResult ReadResponse(int statusCode, string body, string retryAfter, out string licence, out string expiresUtc, out int? activationsUsed, out int? activationsAllowed)
        {
            licence = null;
            expiresUtc = null;
            activationsUsed = null;
            activationsAllowed = null;

            if (statusCode == 200)
            {
                var payload = Parse(body);

                if (payload == null)
                {
                    return ActivationResult.Refused(
                        ActivationOutcome.UnreadableResponse,
                        UnreadableMessage,
                        "the licensing service answered 200 with a body that is not JSON");
                }

                licence = (string)payload["licence"];

                if (string.IsNullOrWhiteSpace(licence))
                {
                    licence = null;

                    return ActivationResult.Refused(
                        ActivationOutcome.UnreadableResponse,
                        UnreadableMessage,
                        "the licensing service answered 200 with no licence in it");
                }

                expiresUtc = (string)payload["expiresUtc"];
                activationsUsed = ReadInt(payload, "activationsUsed");
                activationsAllowed = ReadInt(payload, "activationsAllowed");

                return null;
            }

            return ReadFailure(statusCode, body, retryAfter);
        }

        private const string UnreadableMessage =
            "The licensing service gave an answer this plugin could not read. Try again; if it keeps "
            + "happening, the service and this plugin version disagree and the vendor needs to know.";

        /// <summary>
        /// Maps the contract's machine codes onto sentences an administrator can
        /// act on, with a REFUSING default: a code this build has never heard of
        /// is a refusal, and adding a case must be the only way a new one is
        /// treated specially.
        ///
        /// The status code is used only to tell "unreachable-ish server fault"
        /// from "your code is wrong" when the body carries no code at all. The
        /// body's <c>error</c> is authoritative when it is present, because that
        /// is what the contract says both sides build to.
        /// </summary>
        private static ActivationResult ReadFailure(int statusCode, string body, string retryAfter)
        {
            var payload = Parse(body);
            var code = payload == null ? null : (string)payload["error"];

            // ONLY A CODE FROM THE CONTRACT IS EVER WRITTEN OUT, and it is
            // written from this build's own literal rather than from the
            // response. Two reasons, and the second is the important one:
            //
            //   * an arbitrary service-supplied string in a log line is a
            //     log-forging primitive (LogSafeText would flatten it, but
            //     flattening is not redaction);
            //   * a service - buggy, or hostile, or simply echoing - could put
            //     the REDEMPTION CODE in that field, and the code is a bearer
            //     secret that must never reach the log. Nothing the service
            //     chose the content of is copied out of here at all.
            var known = IsContractCode(code);
            var detail = "the licensing service answered " + statusCode
                + (known
                    ? " with error '" + code + "'"
                    : string.IsNullOrEmpty(code)
                        ? " with no error code"
                        : " with an error code this build does not recognise");

            switch (known ? code : null)
            {
                case "invalid_code":
                    return ActivationResult.Refused(
                        ActivationOutcome.InvalidCode,
                        "That redemption code was not recognised. Check it for typing mistakes - if it is "
                        + "exactly as it was given to you, the purchase it belongs to has not completed yet, "
                        + "and the vendor is the one to ask.",
                        detail);

                case "code_exhausted":
                    return ActivationResult.Refused(
                        ActivationOutcome.CodeExhausted,
                        "That redemption code has already been activated on as many servers as it allows. "
                        + "Re-activating the SAME server does not use one up, so this is a different server "
                        + "to the ones it was used on. Ask the vendor to release an activation, or buy "
                        + "another licence.",
                        detail);

                case "malformed_request":
                    return ActivationResult.Refused(
                        ActivationOutcome.MalformedRequest,
                        "The licensing service could not read the request this plugin sent. Check that a "
                        + "code is entered and that this server reports a server id; if both look right, "
                        + "the vendor needs to know.",
                        detail);

                case "rate_limited":
                    return ActivationResult.Refused(
                        ActivationOutcome.RateLimited,
                        "Too many activation attempts. " + WaitSentence(retryAfter),
                        // Only the numeric form, and re-rendered from the number
                        // this build parsed rather than from the header text -
                        // same rule as the error code above: nothing whose
                        // content the service chose is copied into the log.
                        detail + (TryReadSeconds(retryAfter, out var seconds)
                            ? ", Retry-After " + seconds.ToString(System.Globalization.CultureInfo.InvariantCulture) + "s"
                            : string.Empty));

                case "server_error":
                    return ActivationResult.Refused(
                        ActivationOutcome.ServiceError,
                        "The licensing service reported a problem of its own. Nothing is wrong with your "
                        + "code or your server. Try again in a few minutes.",
                        detail);

                case "pending_signature":
                    // Not an error, and the wording says so plainly, because an
                    // administrator who reads this as a failure will retype their
                    // code, then email the vendor, then give up - when all that
                    // is needed is to press the button again later.
                    return ActivationResult.Refused(
                        ActivationOutcome.PendingSignature,
                        "Your licence has been requested and is being issued. Nothing is wrong and your code "
                        + "has not been used up - the vendor signs licences on a machine that is deliberately "
                        + "kept offline, so it is not instant. Press Activate again in a few minutes.",
                        detail);

                default:
                    // No code, or one this build does not know. Still a refusal.
                    return ActivationResult.Refused(
                        ActivationOutcome.ServiceError,
                        "The licensing service refused this activation and did not say why in terms this "
                        + "plugin understands. The server log records exactly what it answered.",
                        detail);
            }
        }

        /// <summary>
        /// The closed set of codes from <c>contract.md</c>. Written as an
        /// explicit list, not derived from the switch below, because it also
        /// gates what may be copied into a log line - see the comment there.
        /// </summary>
        private static bool IsContractCode(string code)
        {
            switch (code)
            {
                case "invalid_code":
                case "code_exhausted":
                case "malformed_request":
                case "rate_limited":
                case "server_error":
                case "pending_signature":
                    return true;

                default:
                    return false;
            }
        }

        /// <summary>
        /// <c>Retry-After</c> is either a number of seconds or an HTTP date
        /// (RFC 9110 10.2.3). Only the numeric form is turned into advice; a
        /// date is left out rather than mis-stated, because a wrong number of
        /// minutes is worse than none.
        /// </summary>
        private static string WaitSentence(string retryAfter)
        {
            if (TryReadSeconds(retryAfter, out var seconds))
            {
                var minutes = (seconds + 59) / 60;

                return minutes <= 1
                    ? "Wait about a minute and try again."
                    : "Wait about " + minutes.ToString(System.Globalization.CultureInfo.InvariantCulture) + " minutes and try again.";
            }

            return "Wait a few minutes and try again.";
        }

        private static bool TryReadSeconds(string retryAfter, out int seconds)
        {
            seconds = 0;

            return !string.IsNullOrWhiteSpace(retryAfter)
                && int.TryParse(
                    retryAfter.Trim(),
                    System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out seconds)
                && seconds > 0;
        }

        private static int? ReadInt(JObject payload, string name)
        {
            var value = payload[name];

            if (value == null || value.Type == JTokenType.Null)
            {
                return null;
            }

            try
            {
                return (int)value;
            }
            catch (Exception)
            {
                // A count this build cannot read is not worth failing an
                // otherwise good activation for. It is display only.
                return null;
            }
        }

        private static JObject Parse(string body)
        {
            if (string.IsNullOrWhiteSpace(body))
            {
                return null;
            }

            try
            {
                // DateParseHandling.None: Json.NET otherwise turns anything that
                // looks like a date into a DateTime token, and reading it back
                // as a string hands out whatever the current culture renders -
                // so the service's "2027-08-31T00:00:00Z" would reach the page
                // as "08/31/2027 00:00:00". Every field here is text as far as
                // this plugin is concerned.
                using (var reader = new Newtonsoft.Json.JsonTextReader(new System.IO.StringReader(body))
                {
                    DateParseHandling = Newtonsoft.Json.DateParseHandling.None,
                })
                {
                    return JObject.Load(reader);
                }
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}

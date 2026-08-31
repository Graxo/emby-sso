using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// What one attempt to redeem a code at the vendor's activation service
    /// decided. Zero is a refusal, like every other decision enum in this
    /// layer: a value nobody assigned, or one produced by a future member the
    /// callers were never updated for, must not activate anything.
    /// </summary>
    internal enum ActivationOutcome
    {
        /// <summary>Fail-closed default. Nothing was stored.</summary>
        Failed = 0,

        /// <summary>
        /// The service returned a licence, and THIS BUILD verified it against
        /// its own embedded public key and this server's own id before saying
        /// so. It is the only member that ever carries a licence, and the only
        /// one a caller may store on.
        /// </summary>
        Activated = 1,

        /// <summary>
        /// Nothing left this process: no code was typed, this server reported
        /// no id, or the configured service base is not a usable HTTPS URL.
        /// </summary>
        NotAttempted = 2,

        /// <summary>The service does not know that code, or it is not paid for.</summary>
        InvalidCode = 3,

        /// <summary>The code has been activated on as many servers as it allows.</summary>
        CodeExhausted = 4,

        /// <summary>The service could not read the request this build sent.</summary>
        MalformedRequest = 5,

        /// <summary>Too many attempts. The service asked for a wait.</summary>
        RateLimited = 6,

        /// <summary>The service answered, with a failure of its own.</summary>
        ServiceError = 7,

        /// <summary>
        /// Nothing came back at all - DNS, TLS, a timeout, or a destination
        /// this plugin refused to send to. NOT a verdict on the code.
        /// </summary>
        Unreachable = 8,

        /// <summary>
        /// The service answered 200 with something this build cannot read as an
        /// activation response, or with no licence in it.
        /// </summary>
        UnreadableResponse = 9,

        /// <summary>
        /// THE ONE THAT MATTERS. The service returned a licence and this build
        /// refused it: the signature did not verify against the embedded public
        /// key, or it names a different Emby server, or it has expired. See
        /// <see cref="ActivationClient"/> - a plugin that stored this anyway
        /// would have thrown the whole licensing model away.
        /// </summary>
        LicenceRejected = 10,
    }

    /// <summary>
    /// The outcome of an activation attempt, plus everything the configuration
    /// page and the server log are allowed to see.
    ///
    /// NEITHER <see cref="Message"/> NOR <see cref="LogDetail"/> EVER CONTAINS
    /// THE REDEMPTION CODE. The code is a bearer secret - anyone holding it can
    /// spend an activation - and is treated the way the client secret is: it
    /// goes into the request body and nowhere else. <c>ActivationMessageTests</c>
    /// asserts this for every outcome.
    /// </summary>
    internal sealed class ActivationResult
    {
        private ActivationResult(
            ActivationOutcome outcome,
            string message,
            string logDetail,
            string licence = null,
            string expiresUtc = null,
            int? activationsUsed = null,
            int? activationsAllowed = null)
        {
            Outcome = outcome;
            Message = message;
            LogDetail = logDetail;
            Licence = licence;
            ExpiresUtc = expiresUtc;
            ActivationsUsed = activationsUsed;
            ActivationsAllowed = activationsAllowed;
        }

        public ActivationOutcome Outcome { get; }

        /// <summary>
        /// One sentence for the administrator standing at the configuration
        /// page, written so they can tell what to do next: an unknown code and
        /// an exhausted one need different actions from them.
        /// </summary>
        public string Message { get; }

        /// <summary>For the server log only. Never rendered into the page.</summary>
        public string LogDetail { get; }

        /// <summary>
        /// The verified licence, and ONLY on <see cref="ActivationOutcome
        /// .Activated"/>. Null on every refusal, so a caller that stores
        /// whatever is here cannot store an unverified token by mistake.
        /// </summary>
        public string Licence { get; }

        /// <summary>The service's own expiry statement, for display only - the licence's <c>exp</c> is what is enforced.</summary>
        public string ExpiresUtc { get; }

        public int? ActivationsUsed { get; }

        public int? ActivationsAllowed { get; }

        /// <summary>
        /// The single whitelist every caller must go through before storing
        /// anything, written as an explicit test against the one admitting
        /// member so that adding a member to <see cref="ActivationOutcome"/>
        /// cannot accidentally activate anybody.
        /// </summary>
        public static bool Succeeded(ActivationResult result)
        {
            return result != null
                && result.Outcome == ActivationOutcome.Activated
                && !string.IsNullOrWhiteSpace(result.Licence);
        }

        public static ActivationResult Success(
            string licence,
            string expiresUtc,
            int? activationsUsed,
            int? activationsAllowed,
            string logDetail)
        {
            if (string.IsNullOrWhiteSpace(licence))
            {
                // Cannot be constructed as a success without one: the licence
                // is the entire point of the call.
                throw new ArgumentException("an activation cannot succeed without a licence", nameof(licence));
            }

            return new ActivationResult(
                ActivationOutcome.Activated,
                "Activated. The licence for this server has been saved.",
                logDetail,
                licence,
                expiresUtc,
                activationsUsed,
                activationsAllowed);
        }

        public static ActivationResult Refused(ActivationOutcome outcome, string message, string logDetail)
        {
            if (outcome == ActivationOutcome.Activated)
            {
                throw new ArgumentException("Activated is not a refusal", nameof(outcome));
            }

            return new ActivationResult(outcome, message, logDetail);
        }
    }
}

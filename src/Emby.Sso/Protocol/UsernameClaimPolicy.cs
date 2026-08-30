using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The outcome of asking whether the configured username claim may be
    /// trusted to name a person on this token. Zero is a refusal, like every
    /// other decision enum here.
    /// </summary>
    public enum UsernameClaimOutcome
    {
        /// <summary>Fail-closed default, and the answer for a claim nobody configured.</summary>
        Refused = 0,

        /// <summary>The claim may be used to name an account on this token.</summary>
        Accepted = 1,

        /// <summary>
        /// The claim is <c>email</c> and the token says the address is NOT
        /// verified. An unverified address is a value the user typed, not a fact
        /// the identity provider established.
        /// </summary>
        EmailNotVerified = 2,

        /// <summary>
        /// The claim is <c>email</c> and the token carries no
        /// <c>email_verified</c> at all, so nothing says the address was ever
        /// checked. Refused for the same reason as an explicit false: silence is
        /// not verification.
        /// </summary>
        EmailVerificationUnknown = 3,
    }

    /// <summary>
    /// Constrains which claim may be used as an Emby username (assessment
    /// finding F1 / S1c).
    ///
    /// The configured claim is what this plugin treats as a person's name, and
    /// on many identity providers a user can set their own <c>email</c> - often
    /// without the provider enforcing uniqueness. OpenID Connect says as much
    /// itself: the <c>email</c> claim is explicitly NOT stable and NOT suitable
    /// as a unique identifier, and <c>email_verified</c> exists precisely
    /// because an address in a token may be nothing more than something the user
    /// typed in.
    ///
    /// So when an operator has configured <c>email</c>, this refuses any token
    /// that does not positively assert <c>email_verified</c>. Absent counts as
    /// not verified: a provider that never says an address was checked has not
    /// checked it, and reading silence as consent on an authentication decision
    /// is how this class of bug happens.
    ///
    /// This is a second line, not the main one. The main one is
    /// <see cref="SubjectBindingStore"/>, which binds each account to the
    /// identity provider's <c>sub</c> and would refuse a reassigned address at
    /// the second sign-in regardless. This guard narrows the trust-on-first-use
    /// window in front of it. A future reader must not drop it because the
    /// binding "already covers that" - the binding covers it AFTER the first
    /// sign-in.
    /// </summary>
    public static class UsernameClaimPolicy
    {
        /// <summary>
        /// The OpenID Connect standard claim name. Compared case-insensitively
        /// and after trimming, because this is an operator-typed setting and
        /// "Email " must not slip past a guard that "email" would have caught.
        /// </summary>
        public const string EmailClaim = "email";

        public static bool IsEmailClaim(string usernameClaim)
        {
            return usernameClaim != null
                && string.Equals(usernameClaim.Trim(), EmailClaim, StringComparison.OrdinalIgnoreCase);
        }

        /// <param name="usernameClaim">The operator's configured claim name.</param>
        /// <param name="emailVerified">
        /// The token's <c>email_verified</c>: true, false, or null when the
        /// token did not carry it at all. Null and false are both refusals, and
        /// they are distinguished only so the log can tell an operator which
        /// they are looking at.
        /// </param>
        public static UsernameClaimOutcome Evaluate(string usernameClaim, bool? emailVerified)
        {
            if (string.IsNullOrWhiteSpace(usernameClaim))
            {
                // Nothing configured to read a name out of. Unreachable in
                // practice - a token with no value for the claim is refused
                // before this - but an authentication helper must not have an
                // "anything goes" answer.
                return UsernameClaimOutcome.Refused;
            }

            if (!IsEmailClaim(usernameClaim))
            {
                return UsernameClaimOutcome.Accepted;
            }

            if (emailVerified == true)
            {
                return UsernameClaimOutcome.Accepted;
            }

            return emailVerified.HasValue
                ? UsernameClaimOutcome.EmailNotVerified
                : UsernameClaimOutcome.EmailVerificationUnknown;
        }

        /// <summary>
        /// The single whitelist, written as equality against the one admitting
        /// member so a future <see cref="UsernameClaimOutcome"/> cannot admit
        /// anyone by being forgotten.
        /// </summary>
        public static bool Permits(UsernameClaimOutcome outcome)
        {
            return outcome == UsernameClaimOutcome.Accepted;
        }
    }
}

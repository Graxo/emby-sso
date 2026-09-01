using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The outcome of checking this server's licence key. Zero is a refusal,
    /// like every other decision enum here: a value that was never assigned, or
    /// one produced by a future member nobody updated the callers for, must not
    /// license anybody.
    /// </summary>
    internal enum LicenceOutcome
    {
        /// <summary>
        /// Fail-closed default. Also the honest answer for an empty
        /// configuration field, which is the state a fresh install is in.
        /// </summary>
        Missing = 0,

        /// <summary>
        /// Not a JWT this build can read at all, or one whose payload is not
        /// shaped like a licence - no issued-at, a wrong issuer, unparseable
        /// segments. Distinct from <see cref="BadSignature"/> only in the log.
        /// </summary>
        Malformed = 1,

        /// <summary>
        /// The signature did not verify against ANY of the embedded public
        /// keys, or the token asked for an algorithm this build does not accept,
        /// or the build carries no public key to check against. Every one of
        /// those means the same thing: nothing here was signed by a key this
        /// build trusts. A licence signed by a key that has since been retired
        /// lands here too, which is what retiring a key means.
        /// </summary>
        BadSignature = 2,

        /// <summary>
        /// A genuine licence, for a different Emby server. Also the answer when
        /// this server did not report a system id at all, because a licence
        /// whose binding cannot be checked is a licence that was not checked.
        /// </summary>
        WrongServer = 3,

        /// <summary>The licence expired, or carries no expiry at all.</summary>
        Expired = 4,

        /// <summary>
        /// The licence starts in the future - a <c>nbf</c> or <c>iat</c> beyond
        /// the clock-skew allowance. Refused rather than held pending: a token
        /// dated forwards is either a clock that is badly wrong or a licence
        /// that was not issued for now, and neither should sign anyone in.
        /// </summary>
        NotYetValid = 5,

        /// <summary>Valid, and not close to expiry.</summary>
        Valid = 6,

        /// <summary>
        /// Valid, and inside <see cref="LicenceCheck.ExpiryWarningWindow"/> of
        /// its expiry. Admits exactly as <see cref="Valid"/> does; it exists so
        /// the caller can say so loudly while there is still time to act.
        /// </summary>
        ExpiringSoon = 7,
    }

    /// <summary>
    /// What <see cref="LicenceCheck.EvaluateAsync"/> decided, plus the detail a
    /// server log needs to act on it. <see cref="Detail"/> is for the log only.
    /// </summary>
    internal sealed class LicenceStatus
    {
        public LicenceStatus(LicenceOutcome outcome, string detail, string licensee = null, DateTimeOffset? expiresAt = null)
        {
            Outcome = outcome;
            Detail = detail;
            Licensee = licensee;
            ExpiresAt = expiresAt;
        }

        public LicenceOutcome Outcome { get; }

        /// <summary>Log-only. Never rendered into a page or an API response.</summary>
        public string Detail { get; }

        /// <summary>
        /// The <c>sub</c> claim, and only on an outcome that admits. A licensee
        /// name read off a token that failed validation is a name an attacker
        /// chose, so it is not carried out of a refusal.
        /// </summary>
        public string Licensee { get; }

        /// <summary>The <c>exp</c> claim, on an outcome that admits.</summary>
        public DateTimeOffset? ExpiresAt { get; }
    }

    /// <summary>
    /// Decides whether this server holds a valid licence for the plugin.
    ///
    /// WHAT THIS IS AND IS NOT. It is an offline check of a token the vendor
    /// signed with a private key that never touches this repository, bound to
    /// one Emby server. It raises the cost of casual copying between servers.
    /// It is NOT DRM and must never be described as such: this plugin ships as
    /// a .NET assembly, and a .NET assembly can be decompiled and a call to
    /// <see cref="Permits"/> deleted by anyone who cares to. The honest claim is
    /// "an operator cannot use this on a second server by accident or by
    /// copying a file", not "an operator cannot use this without paying".
    ///
    /// THE PART THAT MUST NOT BE WEAKENED. This is a JWT validated against an
    /// embedded public key, so the two classic bypasses apply directly:
    ///
    ///   * <c>alg: none</c> - a token with an empty signature. Refused by
    ///     <c>RequireSignedTokens</c>.
    ///   * algorithm confusion - an HMAC-signed token presented where an
    ///     asymmetric key is expected, so that the validator is tricked into
    ///     using the PUBLIC key (which anybody who has the DLL also has) as an
    ///     HMAC secret. Refused by <see cref="AllowedAlgorithms"/>, which is a
    ///     fixed one-element array and must stay one: an EMPTY
    ///     <c>ValidAlgorithms</c> is read by the token handler as "no
    ///     restriction", which is the opposite of a pin.
    ///
    /// Both are covered by tests that were confirmed to fail when the guard they
    /// name is removed, following the precedent of
    /// <c>OidcClientSignatureTests</c>. A licence check that a crafted token can
    /// walk through is worse than no licence check, because it looks like one.
    ///
    /// RS256, not ES256. The netstandard2.0 build of
    /// Microsoft.IdentityModel.Tokens - which is the build ILRepack merges into
    /// the shipped DLL - routes every ECDsa creation through an internal
    /// <c>ECDsaAdapter</c> that picks between an <c>ECParameters</c> path and a
    /// Windows-only <c>CngKey</c> path from a reflection probe at runtime
    /// (decompiled from the 8.22.0 package, not assumed). RSA has no such
    /// adapter and no such probe. The licence string is longer for it; that is
    /// a thing an operator pastes once.
    ///
    /// Nothing here knows about Emby: no <c>MediaBrowser.*</c> type appears, the
    /// server id and the current time are arguments, so the whole decision is
    /// under test.
    /// </summary>
    internal static class LicenceCheck
    {
        /// <summary>
        /// The <c>iss</c> every licence this build accepts must carry. It is not
        /// a security boundary - the signature is - but it stops a token signed
        /// by the same key for some unrelated purpose from being read as a
        /// licence.
        /// </summary>
        public const string Issuer = "urn:emby-sso:licence";

        /// <summary>
        /// The ONLY signing algorithm accepted, written as a fixed array rather
        /// than derived from anything. See the class comment: this array is what
        /// stands between the embedded public key and its use as an HMAC secret.
        /// It must never be empty, and must never come to include an HMAC
        /// algorithm.
        /// </summary>
        private static readonly string[] AllowedAlgorithms = { SecurityAlgorithms.RsaSha256 };

        /// <summary>
        /// Matches the tolerance the id_token path already uses. Small on
        /// purpose: a licence is issued for months, so a large skew buys nothing
        /// and only widens the window either side of expiry.
        /// </summary>
        public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);

        /// <summary>
        /// How far ahead of expiry a valid licence starts reporting
        /// <see cref="LicenceOutcome.ExpiringSoon"/>. The whole point of keeping
        /// existing sessions alive through a licensing failure is to give the
        /// operator time to act, which only helps if they are told before the
        /// failure rather than after it.
        /// </summary>
        public static readonly TimeSpan ExpiryWarningWindow = TimeSpan.FromDays(21);

        /// <summary>
        /// The single whitelist every caller must go through. Written as an
        /// explicit test against the two admitting members rather than as a set
        /// of refusals, so that adding a member to <see cref="LicenceOutcome"/>
        /// cannot accidentally license anybody.
        /// </summary>
        public static bool Permits(LicenceOutcome outcome)
        {
            return outcome == LicenceOutcome.Valid || outcome == LicenceOutcome.ExpiringSoon;
        }

        /// <summary>
        /// Asynchronous only because IdentityModel 8's <c>JsonWebTokenHandler</c>
        /// deprecated the synchronous <c>ValidateToken</c> overload, and a
        /// deprecation warning is an error in this build. Nothing here awaits
        /// I/O - the key is a compile-time constant - so this is a pure function
        /// of its four arguments.
        /// </summary>
        /// <param name="licence">The licence string an operator pasted into the configuration.</param>
        /// <param name="publicKeyJwk">One trusted public key, as a JWK. The overload taking a set is what the shipped build uses.</param>
        /// <param name="serverId">This Emby server's <c>IApplicationHost.SystemId</c>.</param>
        /// <param name="now">The current time. The only clock this decision reads.</param>
        public static Task<LicenceStatus> EvaluateAsync(
            string licence,
            string publicKeyJwk,
            string serverId,
            DateTimeOffset now)
        {
            return EvaluateAsync(licence, new[] { publicKeyJwk }, serverId, now);
        }

        /// <summary>
        /// The same decision against the SET of keys this build trusts - see
        /// <see cref="LicencePublicKey.TrustedJwks"/>. A licence is valid if one
        /// of them signed it; a licence signed by a key that is not in the set
        /// is refused exactly like a forgery, which is how a compromised key is
        /// retired without a revocation list or a callback.
        /// </summary>
        public static async Task<LicenceStatus> EvaluateAsync(
            string licence,
            IReadOnlyList<string> publicKeyJwks,
            string serverId,
            DateTimeOffset now)
        {
            if (string.IsNullOrWhiteSpace(licence))
            {
                return new LicenceStatus(LicenceOutcome.Missing, "no licence key is configured");
            }

            if (string.IsNullOrWhiteSpace(serverId))
            {
                // Not Malformed: the licence may be perfect. What failed is the
                // binding, and a binding that cannot be checked has not been
                // checked - so it refuses, in the direction that keeps a licence
                // for one server from working on another.
                return new LicenceStatus(
                    LicenceOutcome.WrongServer,
                    "this server did not report a system id, so the licence could not be checked against it");
            }

            IReadOnlyList<SecurityKey> keys;

            try
            {
                keys = ReadPublicKeys(publicKeyJwks);
            }
            catch (Exception ex)
            {
                return new LicenceStatus(
                    LicenceOutcome.BadSignature,
                    "the licence public keys embedded in this build are unusable: " + ex.Message);
            }

            // Set by the lifetime delegate below, which is the only thing that
            // reads `now` for expiry. Defaults to a refusal so that a delegate
            // the handler never calls cannot be mistaken for a pass.
            var lifetime = LicenceOutcome.Expired;

            var parameters = new TokenValidationParameters
            {
                IssuerSigningKeys = keys,

                // Explicit rather than left to the library's default. A licence
                // whose `kid` names no key here - one issued before key ids
                // existed, or by a build whose canonical JWK spelling differs by
                // a byte - must still be tried against every trusted key, or a
                // cosmetic difference would read as a forgery. It costs one
                // extra RSA verification in a case that should not arise.
                TryAllIssuerSigningKeys = true,

                ValidIssuer = Issuer,
                ValidAudience = serverId.Trim(),

                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,

                // The server binding. `aud` is the standard claim for "who this
                // token is for", so the library enforces it rather than this
                // file re-implementing a string comparison.
                ValidateAudience = true,

                // See the class comment. One element, never empty, never HMAC.
                ValidAlgorithms = AllowedAlgorithms,

                // Refuses `alg: none`.
                RequireSignedTokens = true,

                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = ClockSkew,

                // Supplied so that the decision reads the caller's clock and
                // nothing else, which is what makes expiry testable. It replaces
                // the library's own lifetime check entirely (Validators
                // .ValidateLifetime short-circuits on a non-null delegate,
                // decompiled from 8.22.0), so RequireExpirationTime above is
                // documentation, not enforcement - the missing-`exp` refusal has
                // to be, and is, made here.
                LifetimeValidator = (notBefore, expires, token, _) =>
                {
                    if (!expires.HasValue)
                    {
                        lifetime = LicenceOutcome.Expired;
                        return false;
                    }

                    if (notBefore.HasValue && ToOffset(notBefore.Value) > now + ClockSkew)
                    {
                        lifetime = LicenceOutcome.NotYetValid;
                        return false;
                    }

                    if (ToOffset(expires.Value) < now - ClockSkew)
                    {
                        lifetime = LicenceOutcome.Expired;
                        return false;
                    }

                    lifetime = LicenceOutcome.Valid;
                    return true;
                },
            };

            TokenValidationResult result;

            try
            {
                result = await new JsonWebTokenHandler().ValidateTokenAsync(licence, parameters).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // ValidateTokenAsync reports failures through the result rather
                // than by throwing, but a malformed string can still throw out
                // of argument checking before validation starts. Refuse.
                return new LicenceStatus(LicenceOutcome.Malformed, "the licence could not be read: " + ex.GetType().Name);
            }

            if (!result.IsValid)
            {
                return Refuse(result.Exception, lifetime);
            }

            var token = result.SecurityToken as JsonWebToken;

            if (token == null)
            {
                // Cannot happen for a JWT string, and is a refusal rather than a
                // cast exception if the library ever changes what it hands back.
                return new LicenceStatus(LicenceOutcome.Malformed, "the licence validated to something that is not a JWT");
            }

            // `iat` is not part of the library's lifetime check at all, and a
            // licence dated in the future is not a licence for now - it is a
            // clock that is wrong or a token that was not issued for this
            // moment. Required, because every licence this project mints carries
            // one and a token without one did not come from the issuing tool.
            if (!token.TryGetClaim(JwtRegisteredClaimNames.Iat, out _))
            {
                return new LicenceStatus(LicenceOutcome.Malformed, "the licence carries no issued-at claim");
            }

            var issuedAt = ToOffset(token.IssuedAt);

            if (issuedAt > now + ClockSkew)
            {
                return new LicenceStatus(
                    LicenceOutcome.NotYetValid,
                    "the licence is dated in the future (issued at " + Format(issuedAt) + ")");
            }

            var expiresAt = ToOffset(token.ValidTo);
            var licensee = token.Subject;

            var outcome = expiresAt - now <= ExpiryWarningWindow
                ? LicenceOutcome.ExpiringSoon
                : LicenceOutcome.Valid;

            return new LicenceStatus(
                outcome,
                "licensed to '" + LogSafeText.Flatten(licensee) + "' until " + Format(expiresAt),
                licensee,
                expiresAt);
        }

        /// <summary>
        /// Turns a validation failure into an outcome. Written as an explicit
        /// list with a REFUSING default: an exception type this build does not
        /// recognise must still be a refusal, and adding a case must be the only
        /// way anything new is admitted.
        /// </summary>
        private static LicenceStatus Refuse(Exception exception, LicenceOutcome lifetime)
        {
            var detail = exception?.Message ?? "no detail";

            switch (exception)
            {
                // Raised by the LifetimeValidator delegate above, which recorded
                // which of the two lifetime refusals it made.
                case SecurityTokenInvalidLifetimeException _:
                    return new LicenceStatus(
                        lifetime == LicenceOutcome.NotYetValid ? LicenceOutcome.NotYetValid : LicenceOutcome.Expired,
                        detail);

                // Only reachable if the delegate is ever removed. Kept so that
                // removing it degrades to the right outcome rather than to
                // "Malformed", which would read as a broken licence rather than
                // an expired one.
                case SecurityTokenExpiredException _:
                    return new LicenceStatus(LicenceOutcome.Expired, detail);

                case SecurityTokenNotYetValidException _:
                    return new LicenceStatus(LicenceOutcome.NotYetValid, detail);

                case SecurityTokenInvalidAudienceException _:
                    return new LicenceStatus(
                        LicenceOutcome.WrongServer,
                        "the licence was issued for a different Emby server: " + detail);

                // Every way the signature can fail to prove the vendor signed
                // this, INCLUDING an algorithm the pin refuses. They are one
                // outcome on purpose: in all of them the embedded public key
                // never authenticated this token. Listed most-derived first -
                // SecurityTokenSignatureKeyNotFoundException derives from
                // SecurityTokenInvalidSignatureException, and the compiler
                // refuses the other order.
                case SecurityTokenSignatureKeyNotFoundException _:
                case SecurityTokenInvalidSigningKeyException _:
                case SecurityTokenInvalidAlgorithmException _:
                case SecurityTokenInvalidSignatureException _:
                    return new LicenceStatus(LicenceOutcome.BadSignature, detail);

                default:
                    // Malformed covers the rest - an unsigned token, an
                    // unparseable one, a wrong issuer - and is a refusal, which
                    // is the only property that matters here.
                    return new LicenceStatus(LicenceOutcome.Malformed, detail);
            }
        }

        /// <summary>
        /// Reads every embedded key, and refuses anything that is not an RSA
        /// PUBLIC key.
        ///
        /// The private-material check is not paranoia about a hostile input -
        /// these strings are compile-time constants. It is a guard against the
        /// one mistake that would give the whole scheme away: pasting the output
        /// of the issuing tool's private key file into the public constant, and
        /// shipping the licence signing key inside every copy of the plugin.
        ///
        /// One bad entry fails the whole set rather than being skipped. A build
        /// that quietly trusts three of the four keys it was given is a build
        /// whose behaviour nobody can predict from reading it, and the fix - a
        /// corrected constant and a rebuild - is the same either way.
        /// </summary>
        private static IReadOnlyList<SecurityKey> ReadPublicKeys(IReadOnlyList<string> publicKeyJwks)
        {
            if (publicKeyJwks == null || publicKeyJwks.Count == 0)
            {
                throw new ArgumentException("this build has no licence public keys embedded; see LicencePublicKey");
            }

            var keys = new List<SecurityKey>(publicKeyJwks.Count);

            foreach (var jwk in publicKeyJwks)
            {
                keys.Add(ReadPublicKey(jwk));
            }

            return keys;
        }

        private static SecurityKey ReadPublicKey(string publicKeyJwk)
        {
            if (string.IsNullOrWhiteSpace(publicKeyJwk))
            {
                throw new ArgumentException("this build has no licence public key embedded; see LicencePublicKey");
            }

            var key = new JsonWebKey(publicKeyJwk);

            if (!string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal))
            {
                throw new ArgumentException("the embedded licence key is '" + LogSafeText.Flatten(key.Kty) + "', not RSA");
            }

            if (!string.IsNullOrEmpty(key.D)
                || !string.IsNullOrEmpty(key.P)
                || !string.IsNullOrEmpty(key.Q)
                || !string.IsNullOrEmpty(key.QI)
                || !string.IsNullOrEmpty(key.DP)
                || !string.IsNullOrEmpty(key.DQ))
            {
                throw new ArgumentException(
                    "the embedded licence key carries PRIVATE key material - it must be the public half only");
            }

            if (string.IsNullOrEmpty(key.N) || string.IsNullOrEmpty(key.E))
            {
                throw new ArgumentException("the embedded licence key is missing its RSA modulus or exponent");
            }

            // The name the issuer put in the licence's `kid` header, derived the
            // same way on both sides so neither has to be told it. Setting it
            // lets the handler go straight to the right key out of several; it
            // is not what admits the licence - the signature is - and
            // TryAllIssuerSigningKeys above means a `kid` that matches nothing
            // still gets checked against every key.
            key.KeyId = KeyIdOf(key.N, key.E);

            return key;
        }

        /// <summary>
        /// The first 16 hex characters of the SHA-256 of the canonical public
        /// JWK. This has to agree character for character with
        /// <c>Emby.Sso.Licensing.LicenceFormat.KeyId</c>, which is what the
        /// issuing tool writes into the `kid` header - hence the fixed member
        /// order and the absence of any whitespace below.
        /// </summary>
        private static string KeyIdOf(string modulus, string exponent)
        {
            var canonical = "{\"kty\":\"RSA\",\"n\":\"" + modulus + "\",\"e\":\"" + exponent + "\"}";

            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(canonical));
                var text = new StringBuilder(16);

                for (var i = 0; i < 8; i++)
                {
                    text.Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
                }

                return text.ToString();
            }
        }

        /// <summary>
        /// IdentityModel hands back <see cref="DateTime"/> values it has already
        /// normalised to UTC but whose Kind can be Unspecified, which
        /// <see cref="DateTimeOffset"/> would otherwise read as local time - a
        /// silent hours-wide error in an expiry comparison on any server not set
        /// to UTC.
        /// </summary>
        private static DateTimeOffset ToOffset(DateTime value)
        {
            return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
        }

        private static string Format(DateTimeOffset value)
        {
            return value.UtcDateTime.ToString("u", CultureInfo.InvariantCulture);
        }
    }
}

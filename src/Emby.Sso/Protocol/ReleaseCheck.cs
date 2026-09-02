using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// A release the vendor has signed for: which version, which bytes, and
    /// where to get them. Only ever produced by <see cref="ReleaseCheck"/>, and
    /// only from a manifest that verified.
    /// </summary>
    internal sealed class SignedRelease
    {
        public SignedRelease(Version version, string versionText, string sha256, string url)
        {
            Version = version;
            VersionText = versionText;
            Sha256 = sha256;
            Url = url;
        }

        public Version Version { get; }

        public string VersionText { get; }

        /// <summary>Lowercase hex. THE authority on what may be installed.</summary>
        public string Sha256 { get; }

        /// <summary>Where to fetch it. A convenience; the hash is what is trusted.</summary>
        public string Url { get; }
    }

    /// <summary>
    /// Reads the vendor's signed release manifest.
    ///
    /// WHAT IS AT STAKE. Whatever comes out of here ends up executing on the
    /// server. So this is written the same way the licence check is - one pinned
    /// algorithm, signed tokens only, a fixed issuer, a refusing default - and
    /// with one extra rule that has no equivalent anywhere else in the plugin:
    ///
    ///   IT NEVER OFFERS A VERSION THAT IS NOT NEWER THAN THE RUNNING ONE.
    ///
    /// That is what stops a downgrade attack. An old manifest is perfectly valid
    /// forever - it was really signed, and it really describes a real build - so
    /// replaying last year's manifest is the cheapest way to put a version with
    /// a known hole back onto somebody's server. Comparing versions is the only
    /// thing that prevents it, and expiry would not: a manifest has to outlive
    /// the release it describes.
    ///
    /// The URL is carried but not trusted. Only the SHA-256 decides what may be
    /// installed - see <see cref="SignedRelease.Sha256"/>.
    /// </summary>
    internal static class ReleaseCheck
    {
        public const string Issuer = "urn:emby-sso:release";

        public const string HashClaim = "sha256";

        public const string UrlClaim = "url";

        private static readonly string[] AllowedAlgorithms = { SecurityAlgorithms.RsaSha256 };

        private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);

        /// <summary>
        /// The verified release, or null for every way this can fail - which
        /// includes a manifest that is genuine but does not offer anything newer
        /// than <paramref name="running"/>.
        /// </summary>
        public static async Task<SignedRelease> ReadAsync(
            string manifest,
            IReadOnlyList<string> releaseKeyJwks,
            Version running,
            DateTimeOffset now)
        {
            if (string.IsNullOrWhiteSpace(manifest) || releaseKeyJwks == null || releaseKeyJwks.Count == 0)
            {
                // No key means this build cannot verify a manifest, so it must
                // never install anything.
                return null;
            }

            IReadOnlyList<SecurityKey> keys;

            try
            {
                keys = LicenceCheck.ReadTrustedKeys(releaseKeyJwks);
            }
            catch (Exception)
            {
                return null;
            }

            var parameters = new TokenValidationParameters
            {
                IssuerSigningKeys = keys,
                TryAllIssuerSigningKeys = true,

                ValidIssuer = Issuer,
                ValidateIssuer = true,

                // A release is about a build, not about a server, so there is no
                // audience to check. Every other pin is in place.
                ValidateAudience = false,

                ValidateIssuerSigningKey = true,
                ValidAlgorithms = AllowedAlgorithms,
                RequireSignedTokens = true,

                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = ClockSkew,

                // Reads the CALLER's clock, like LicenceCheck does. Without
                // this the library reads the machine's, which makes the decision
                // untestable and - worse - means the one time source this
                // function is handed is silently ignored.
                LifetimeValidator = (notBefore, expires, _, __) =>
                {
                    if (!expires.HasValue)
                    {
                        return false;
                    }

                    if (notBefore.HasValue && ToOffset(notBefore.Value) > now + ClockSkew)
                    {
                        return false;
                    }

                    return ToOffset(expires.Value) >= now - ClockSkew;
                },
            };

            TokenValidationResult result;

            try
            {
                result = await new JsonWebTokenHandler().ValidateTokenAsync(manifest, parameters).ConfigureAwait(false);
            }
            catch (Exception)
            {
                return null;
            }

            if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt)
            {
                return null;
            }

            if (!jwt.TryGetClaim(HashClaim, out var hash) || !IsPlausibleHash(hash.Value))
            {
                return null;
            }

            if (!jwt.TryGetClaim(UrlClaim, out var url) || !IsUsableUrl(url.Value))
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(jwt.Subject) || !Version.TryParse(jwt.Subject.Trim(), out var offered))
            {
                return null;
            }

            // THE DOWNGRADE GUARD. Strictly newer, so re-offering the running
            // version is also refused - there is nothing to install.
            if (running != null && offered <= running)
            {
                return null;
            }

            return new SignedRelease(offered, jwt.Subject.Trim(), hash.Value.Trim().ToLowerInvariant(), url.Value.Trim());
        }

        private static DateTimeOffset ToOffset(DateTime value)
        {
            return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
        }

        public static bool IsPlausibleHash(string sha256)
        {
            if (sha256 == null)
            {
                return false;
            }

            var value = sha256.Trim().ToLowerInvariant();

            if (value.Length != 64)
            {
                return false;
            }

            foreach (var c in value)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// https, absolute, and nothing else. The hash is what makes a download
        /// safe, but there is no reason to fetch over plaintext as well - and a
        /// non-http scheme in a URL that reaches a download routine is the kind
        /// of thing that turns into a file-read primitive.
        /// </summary>
        private static bool IsUsableUrl(string url)
        {
            return !string.IsNullOrWhiteSpace(url)
                && Uri.TryCreate(url.Trim(), UriKind.Absolute, out var address)
                && string.Equals(address.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal);
        }
    }
}

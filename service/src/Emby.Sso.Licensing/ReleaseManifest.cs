using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Licensing
{
    /// <summary>
    /// The vendor's signed statement that a particular build of the plugin is a
    /// real release: this version, this SHA-256, at this address.
    ///
    /// THIS IS THE MOST DANGEROUS OBJECT IN THE PROJECT. A plugin that installs
    /// what a manifest names is executing whatever the manifest's signer chose,
    /// on every customer's media server. Nothing else here comes close: a forged
    /// licence costs the vendor a sale, a forged manifest costs every customer
    /// their server.
    ///
    /// So two rules, and neither is negotiable:
    ///
    ///   1. IT IS SIGNED BY THE RELEASE KEY, NOT THE LICENCE KEY. The licence
    ///      key lives on the licence service, which answers requests from the
    ///      internet; if it also signed manifests, a break-in there would
    ///      escalate from "mint free licences" to "ship a backdoor to
    ///      everybody". The release key lives on the vendor's own machine and
    ///      goes nowhere near a server or a CI variable.
    ///
    ///   2. THE HASH IS THE AUTHORITY, NOT THE ADDRESS. The manifest names where
    ///      to fetch the DLL, but the plugin trusts only the SHA-256 it carries.
    ///      A compromised download host, a hijacked DNS entry or an intercepting
    ///      proxy can serve whatever it likes; it will not match, and nothing is
    ///      installed. The URL is a convenience, the hash is the security
    ///      boundary.
    ///
    /// It is deliberately NOT a licence and cannot be read as one: a distinct
    /// issuer, a distinct key, and no audience - a release is about a build, not
    /// about a server.
    /// </summary>
    public static class ReleaseManifest
    {
        /// <summary>Distinct from every other token this project signs.</summary>
        public const string Issuer = "urn:emby-sso:release";

        /// <summary>The SHA-256 of the DLL, lowercase hex, no prefix.</summary>
        public const string HashClaim = "sha256";

        /// <summary>Where to fetch it. A convenience; see rule 2.</summary>
        public const string UrlClaim = "url";

        /// <summary>
        /// Long, because a manifest is a statement about a build and builds do
        /// not stop being what they are. Downgrades are prevented by comparing
        /// versions, not by expiry - an attacker replaying an old manifest is
        /// offering an OLDER version, and the plugin refuses those outright.
        /// </summary>
        public static readonly TimeSpan Lifetime = TimeSpan.FromDays(3650);

        public static string Issue(
            JsonWebKey releaseKey,
            string version,
            string sha256,
            string url,
            DateTimeOffset now)
        {
            if (releaseKey == null)
            {
                throw new ArgumentNullException(nameof(releaseKey));
            }

            if (string.IsNullOrWhiteSpace(version))
            {
                throw new ArgumentException("a release must name its version", nameof(version));
            }

            if (!IsPlausibleHash(sha256))
            {
                throw new ArgumentException("a release must carry a SHA-256 of the file it names", nameof(sha256));
            }

            if (string.IsNullOrWhiteSpace(url)
                || !Uri.TryCreate(url, UriKind.Absolute, out var address)
                || !string.Equals(address.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
            {
                // https only, and refused here rather than only in the plugin.
                // The hash is what makes the download safe, but there is no
                // reason to publish a plaintext address as well.
                throw new ArgumentException("a release must be published over https", nameof(url));
            }

            var payload = JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["iss"] = Issuer,
                ["sub"] = version.Trim(),
                [HashClaim] = sha256.Trim().ToLowerInvariant(),
                [UrlClaim] = url.Trim(),
                ["iat"] = EpochTime.GetIntDate(now.UtcDateTime),
                ["nbf"] = EpochTime.GetIntDate(now.UtcDateTime),
                ["exp"] = EpochTime.GetIntDate((now + Lifetime).UtcDateTime),
            });

            return new JsonWebTokenHandler().CreateToken(
                payload,
                new SigningCredentials(releaseKey, LicenceFormat.Algorithm));
        }

        /// <summary>64 lowercase hex characters, and nothing else.</summary>
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
    }
}

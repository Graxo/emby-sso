using System;
using System.IO;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.LicenceService.Release
{
    /// <summary>
    /// The current release manifest: one signed statement, served to every
    /// plugin that asks.
    ///
    /// THIS SERVICE HOLDS IT BUT CANNOT MAKE IT. The manifest is signed by the
    /// release key, which lives on the vendor's own machine and never comes
    /// here - so a total compromise of this host lets an attacker serve an OLD
    /// manifest, or none, but not one they wrote. Serving an old one cannot
    /// downgrade anybody either: the plugin refuses a version that is not newer
    /// than what it is running.
    ///
    /// It is still verified before it is stored, against the release PUBLIC key.
    /// Not because this service is trusted to decide - the plugin checks again,
    /// and that check is the real one - but because a manifest signed with the
    /// wrong key, or truncated by a copy-paste, should be caught on the
    /// operator's screen rather than by every customer at once.
    ///
    /// One file, replaced atomically. There is no history: a manifest names a
    /// version, the newest one is the only one anybody wants, and keeping the
    /// old ones would just be a way to serve one by accident.
    /// </summary>
    public sealed class ReleaseStore
    {
        private static readonly string[] AllowedAlgorithms = { LicenceFormat.Algorithm };

        private readonly string _path;
        private readonly TrustedKeys _releaseKeys;
        private readonly ILogger<ReleaseStore> _log;

        /// <summary>
        /// <paramref name="releaseKeys"/> is null when LICENCE_RELEASE_PUBLIC_KEYS
        /// is not configured. The store then serves whatever was already there
        /// and refuses to accept anything new, because it cannot check it.
        /// </summary>
        public ReleaseStore(ServiceOptions options, TrustedKeys releaseKeys, ILogger<ReleaseStore> log)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _path = Path.Combine(options.DataDirectory, "release-manifest.jwt");
            _releaseKeys = releaseKeys;
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public bool CanAccept => _releaseKeys != null;

        /// <summary>The stored manifest, or null when none has been published.</summary>
        public string Current()
        {
            try
            {
                return File.Exists(_path) ? File.ReadAllText(_path).Trim() : null;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                _log.LogError(ex, "release: the manifest at {Path} could not be read", _path);

                return null;
            }
        }

        /// <summary>
        /// Checks a manifest and stores it. Returns null on success, or one
        /// sentence for the operator.
        /// </summary>
        public async Task<string> PublishAsync(string manifest)
        {
            if (!CanAccept)
            {
                return "This service has no release public key configured, so it cannot check a manifest before "
                    + "publishing it. Set LICENCE_RELEASE_PUBLIC_KEYS to the PUBLIC half of your release key - the "
                    + "same value that is compiled into the plugin's ReleasePublicKey.cs.";
            }

            if (string.IsNullOrWhiteSpace(manifest))
            {
                return "There is nothing there. Paste the manifest `licencetool sign-release` printed.";
            }

            var trimmed = manifest.Trim();

            var parameters = new TokenValidationParameters
            {
                IssuerSigningKeys = _releaseKeys.Keys,
                TryAllIssuerSigningKeys = true,

                ValidIssuer = ReleaseManifest.Issuer,
                ValidateIssuer = true,

                // A release is about a build, not about a server.
                ValidateAudience = false,

                ValidateIssuerSigningKey = true,
                ValidAlgorithms = AllowedAlgorithms,
                RequireSignedTokens = true,

                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.FromMinutes(2),
            };

            TokenValidationResult result;

            try
            {
                result = await new JsonWebTokenHandler().ValidateTokenAsync(trimmed, parameters).ConfigureAwait(false);
            }
            catch (Exception)
            {
                return "That is not a release manifest this service can read.";
            }

            if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt)
            {
                return "That manifest did not verify. It has to be signed by the RELEASE key whose public half is "
                    + "in LICENCE_RELEASE_PUBLIC_KEYS - not the licence key, and not a key from a different "
                    + "machine.";
            }

            if (string.IsNullOrWhiteSpace(jwt.Subject) || !Version.TryParse(jwt.Subject.Trim(), out var version))
            {
                return "That manifest does not name a version the plugin could compare.";
            }

            if (!jwt.TryGetClaim(ReleaseManifest.HashClaim, out var hash) || !ReleaseManifest.IsPlausibleHash(hash.Value))
            {
                return "That manifest carries no usable SHA-256, so nothing could verify a download against it.";
            }

            // A version going backwards is almost always a mistake - the wrong
            // file, or an old manifest pasted twice. It is refused here rather
            // than published, because every plugin would ignore it anyway and
            // the operator would be left wondering why nobody updated.
            var current = Current();

            if (current != null && TryReadVersion(current, out var published) && version <= published)
            {
                return "That manifest is for " + version + ", and " + published + " is already published. "
                    + "Plugins refuse a version that is not newer, so publishing this would do nothing.";
            }

            try
            {
                var temporary = _path + ".new";

                File.WriteAllText(temporary, trimmed);

                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }

                // Replaced in one step, so a plugin asking mid-publish gets the
                // old manifest or the new one and never half a file.
                File.Move(temporary, _path, overwrite: true);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                _log.LogError(ex, "release: the manifest could not be written to {Path}", _path);

                return "The manifest could not be saved. Check that the data volume is writable.";
            }

            _log.LogInformation("release: published {Version}, sha256 {Hash}", version, hash.Value);

            return null;
        }

        /// <summary>The published version, for the admin page. Null when there is none.</summary>
        public string PublishedVersion()
        {
            var current = Current();

            return current != null && TryReadVersion(current, out var version) ? version.ToString() : null;
        }

        /// <summary>
        /// Reads the version out WITHOUT verifying - only ever used on a
        /// manifest this store already verified before writing, and only to
        /// compare against a new one.
        /// </summary>
        private static bool TryReadVersion(string manifest, out Version version)
        {
            version = null;

            try
            {
                return Version.TryParse(new JsonWebToken(manifest).Subject?.Trim(), out version);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}

using System;
using System.IO;
using System.Security.Cryptography;
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

        /// <summary>
        /// The path a plugin fetches the file from, when this service is the one
        /// hosting it. Kept beside the manifest so that the two are one thing to
        /// back up, and named in one place so the store, the endpoint and the
        /// admin page cannot disagree about it.
        /// </summary>
        public const string DownloadPath = "/v1/release/download";

        private readonly string _path;
        private readonly string _filePath;
        private readonly string _hostedUrl;
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
            _filePath = Path.Combine(options.DataDirectory, "release-file.dll");
            _hostedUrl = string.IsNullOrWhiteSpace(options.PublicBaseUrl)
                ? null
                : options.PublicBaseUrl.TrimEnd('/') + DownloadPath;
            _releaseKeys = releaseKeys;
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public bool CanAccept => _releaseKeys != null;

        /// <summary>
        /// The address this service would serve the plugin from, or null when
        /// LICENCE_PUBLIC_BASE_URL is unset and it therefore does not know its
        /// own name. Shown on the admin page so the vendor signs for the right
        /// address rather than guessing at it.
        /// </summary>
        public string HostedUrl => _hostedUrl;

        /// <summary>
        /// The stored plugin file, or null when the published manifest points
        /// somewhere else. Opened rather than read: it is megabytes, and every
        /// customer's server fetches it.
        /// </summary>
        public Stream OpenFile()
        {
            try
            {
                return File.Exists(_filePath)
                    ? new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true)
                    : null;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                _log.LogError(ex, "release: the stored plugin file at {Path} could not be opened", _filePath);

                return null;
            }
        }

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
        public async Task<string> PublishAsync(string manifest, byte[] file = null)
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

            // WHERE THE MANIFEST SAYS THE FILE IS decides whether a file has to
            // come with it.
            //
            // Pointing at this service and storing nothing here is the one
            // mistake that looks like success: the manifest verifies, the page
            // says published, and every customer's server then reports the
            // download unreachable. So it is refused, here, on the vendor's own
            // screen.
            jwt.TryGetClaim(ReleaseManifest.UrlClaim, out var url);

            var hostedHere = _hostedUrl != null
                && string.Equals(url?.Value?.Trim(), _hostedUrl, StringComparison.OrdinalIgnoreCase);

            if (file != null && file.Length > 0)
            {
                if (!hostedHere)
                {
                    return "That manifest points at " + (url?.Value ?? "nowhere")
                        + ", not at this service, so a file uploaded here would never be fetched. Sign for "
                        + (_hostedUrl ?? "this service's own download address") + " instead, or publish the "
                        + "manifest on its own.";
                }

                string uploaded;

                using (var sha = SHA256.Create())
                {
                    uploaded = Convert.ToHexString(sha.ComputeHash(file)).ToLowerInvariant();
                }

                if (!string.Equals(uploaded, hash.Value.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    return "That file is not the one the manifest was signed for. The manifest names "
                        + hash.Value.Trim() + " and the upload hashes to " + uploaded + ". Publishing it would "
                        + "give every server a download it refuses.";
                }
            }
            else if (hostedHere && !File.Exists(_filePath))
            {
                return "That manifest points at this service, but no plugin file has been uploaded with it, so "
                    + "there would be nothing at that address to download. Choose the same Emby.Sso.dll you "
                    + "signed for.";
            }

            try
            {
                // THE FILE GOES FIRST, always. Between these two writes the
                // service is serving the OLD manifest against the NEW file - a
                // hash mismatch, which every plugin refuses and nothing
                // installs. The other order would briefly offer a new manifest
                // against an old file, which is the same refusal but reached by
                // every customer at once rather than by nobody.
                if (file != null && file.Length > 0)
                {
                    var temporaryFile = _filePath + ".new";

                    await File.WriteAllBytesAsync(temporaryFile, file).ConfigureAwait(false);

                    if (!OperatingSystem.IsWindows())
                    {
                        File.SetUnixFileMode(temporaryFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    }

                    File.Move(temporaryFile, _filePath, overwrite: true);
                }
                else if (!hostedHere)
                {
                    // The new release lives somewhere else, so whatever is here
                    // belongs to a version nobody is being offered any more.
                    // Left in place it would be served, by hand or by habit, as
                    // if it were current.
                    File.Delete(_filePath);
                }

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

            _log.LogInformation(
                "release: published {Version}, sha256 {Hash}, hosted here: {Hosted}",
                version,
                hash.Value,
                hostedHere);

            return null;
        }

        /// <summary>The published version, for the admin page. Null when there is none.</summary>
        public string PublishedVersion()
        {
            var current = Current();

            return current != null && TryReadVersion(current, out var version) ? version.ToString() : null;
        }

        /// <summary>
        /// The SHA-256 the published manifest names, for the checksum an
        /// operator installing by hand wants. Null when nothing is published.
        /// </summary>
        public string PublishedHash()
        {
            var current = Current();

            if (current == null)
            {
                return null;
            }

            try
            {
                return new JsonWebToken(current).TryGetClaim(ReleaseManifest.HashClaim, out var hash)
                    ? hash.Value
                    : null;
            }
            catch (Exception)
            {
                return null;
            }
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

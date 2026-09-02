using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using MediaBrowser.Model.Logging;
using MediaBrowser.Model.Services;

namespace Emby.Sso.Api
{
    /// <summary>
    /// The update button: what is available, and installing it.
    ///
    /// THE CALLER SUPPLIES NOTHING. There is no version parameter and no URL
    /// parameter, deliberately - the only thing this will ever install is the
    /// release named by a manifest that
    /// <see cref="ReleaseCheck"/> verified was signed by the RELEASE key and is
    /// strictly newer than the running build, downloaded to bytes whose SHA-256
    /// matches what was signed for. An administrator can press the button or
    /// not; they cannot aim it.
    ///
    /// WHAT IT WRITES, AND WHERE. One file, into
    /// <see cref="Plugin.PluginsPath"/> - the directory Emby itself reports,
    /// not a configured one, because a settable install path is a way to make a
    /// server write an assembly wherever somebody likes. The name is the running
    /// assembly's own file name, so an update replaces the plugin rather than
    /// adding a second copy Emby would try to load alongside it.
    ///
    /// IT NEVER RESTARTS EMBY. It writes the file and calls
    /// NotifyPendingRestart, so Emby shows its own "restart to finish"
    /// banner. A media server that reboots itself mid-playback because an update
    /// landed is worse behaved than one that waits to be told.
    /// </summary>
    public class UpdateService : IService
    {
        private readonly ILogger _logger;

        public UpdateService(ILogManager logManager)
        {
            _logger = logManager.GetLogger("AuthentikSso");
        }

        public async Task<object> Get(SsoUpdateInfo request)
        {
            var running = SsoRuntime.RunningVersion;

            SignedRelease release;

            try
            {
                release = await SsoRuntime.FindUpdateAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.Warn("SSO update check failed ({0}). Nothing has changed.", ex.GetType().Name);

                release = null;
            }

            return new UpdateInfoResult
            {
                CurrentVersion = running?.ToString() ?? string.Empty,
                AvailableVersion = release?.VersionText ?? string.Empty,
                UpdateAvailable = release != null,
                RestartPending = Plugin.Instance?.Host?.HasPendingRestart == true,
            };
        }

        public async Task<object> Post(SsoUpdateInstall request)
        {
            SignedRelease release;

            try
            {
                release = await SsoRuntime.FindUpdateAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.Warn("SSO update: could not read the release manifest ({0}).", ex.GetType().Name);

                return Refused("The vendor's release information could not be read. Nothing has been changed.");
            }

            if (release == null)
            {
                // Also the answer when somebody presses the button twice: the
                // second press finds nothing newer, because the first one has
                // not taken effect until Emby restarts.
                return Refused("There is no newer signed release to install.");
            }

            var target = TargetPath();

            if (target == null)
            {
                return Refused(
                    "This server did not report where its plugins live, so there is nowhere safe to write. "
                    + "Nothing has been changed.");
            }

            var download = await ReleaseDownload
                .FetchAsync(SsoRuntime.ActivationHttpClient, release, CancellationToken.None)
                .ConfigureAwait(false);

            if (download.Outcome != ReleaseDownloadOutcome.Verified)
            {
                // The important refusal. Logged at Error for WrongBytes, because
                // that means something served a file that is not the release -
                // which is either a broken host or an attack, and both are worth
                // a look.
                if (download.Outcome == ReleaseDownloadOutcome.WrongBytes)
                {
                    _logger.Error(
                        "SSO update REFUSED: {0}. NOTHING WAS WRITTEN. The address in the vendor's signed manifest "
                        + "served something that is not the release it names.",
                        LogSafeText.Flatten(download.Detail));

                    return Refused(
                        "The download did not match the vendor's signature, so NOTHING was installed. This means "
                        + "the file served was not the release. Try again later; if it persists, the vendor needs "
                        + "to know.");
                }

                _logger.Warn("SSO update: {0}. Nothing has been changed.", LogSafeText.Flatten(download.Detail));

                return Refused("The update could not be downloaded. Nothing has been changed.");
            }

            try
            {
                Write(target, download.Content);
            }
            catch (Exception ex)
            {
                _logger.Error("SSO update: the verified release could not be written ({0}).", ex.GetType().Name);

                return Refused(
                    "The update was downloaded and verified, but this server could not write it. Check that Emby "
                    + "can write to its plugins directory. Nothing has been changed.");
            }

            _logger.Info(
                "SSO update: version {0} verified and written to {1}. Emby must be restarted to load it.",
                LogSafeText.Flatten(release.VersionText),
                LogSafeText.Flatten(target));

            try
            {
                Plugin.Instance?.Host?.NotifyPendingRestart();
            }
            catch (Exception ex)
            {
                // The file is written; the banner is a nicety.
                _logger.Warn("SSO update: could not flag the pending restart ({0}).", ex.GetType().Name);
            }

            return new UpdateInstallResult
            {
                Installed = true,
                Version = release.VersionText,
                Message = "Version " + release.VersionText + " has been downloaded, verified and installed. "
                    + "RESTART EMBY WHEN CONVENIENT to start using it - the running version is unchanged until "
                    + "you do.",
            };
        }

        /// <summary>
        /// The file to replace: this assembly's own name, inside the directory
        /// Emby reports. Null when either is unavailable, and then nothing is
        /// written at all.
        /// </summary>
        private static string TargetPath()
        {
            var directory = Plugin.Instance?.PluginsPath;

            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            {
                return null;
            }

            var name = Path.GetFileName(typeof(UpdateService).Assembly.Location);

            if (string.IsNullOrWhiteSpace(name))
            {
                // A single-file or in-memory load has no location. Fall back to
                // the name this plugin is always shipped as rather than guessing
                // something else.
                name = "Emby.Sso.dll";
            }

            var target = Path.GetFullPath(Path.Combine(directory, name));

            // Belt and braces. The name comes from this assembly rather than
            // from anything remote, but a path that leaves the plugins directory
            // must never be written to whatever the reason.
            return target.StartsWith(Path.GetFullPath(directory) + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                ? target
                : null;
        }

        /// <summary>
        /// Writes beside the target and then moves it into place, so that a
        /// failure part-way leaves the OLD plugin intact. A half-written
        /// assembly is a server that will not start.
        /// </summary>
        private static void Write(string target, byte[] content)
        {
            var temporary = target + ".update";

            File.WriteAllBytes(temporary, content);

            try
            {
                if (File.Exists(target))
                {
                    File.Delete(target);
                }

                File.Move(temporary, target);
            }
            catch
            {
                try
                {
                    File.Delete(temporary);
                }
                catch (Exception)
                {
                    // Nothing useful to do; the throw below is the real story.
                }

                throw;
            }
        }

        private static UpdateInstallResult Refused(string message)
        {
            return new UpdateInstallResult { Installed = false, Message = message, Version = string.Empty };
        }
    }
}

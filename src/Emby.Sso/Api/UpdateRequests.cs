using MediaBrowser.Controller.Net;
using MediaBrowser.Model.Services;

namespace Emby.Sso.Api
{
    /// <summary>What the configuration page shows in the update area.</summary>
    /// <remarks>
    /// Admin only, for the reason on <see cref="SsoActivationInfo"/>. Nothing
    /// here is secret - a version number and a release address - but it makes
    /// this server reach out to the vendor, and that is not something an
    /// ordinary signed-in user gets to trigger.
    /// </remarks>
    [Route(SsoRoutes.UpdateInfoPath, "GET")]
    [Authenticated(Roles = "Admin")]
    public class SsoUpdateInfo : IReturn<UpdateInfoResult>
    {
    }

    /// <summary>
    /// Installs the offered update.
    /// </summary>
    /// <remarks>
    /// ADMIN ONLY, AND THE MOST DANGEROUS ENDPOINT IN THIS PLUGIN. It writes an
    /// assembly that Emby will load and run. Everything that makes that safe is
    /// on the other side of this call - a manifest signed by the release key,
    /// a version strictly newer than the running one, and a download whose
    /// SHA-256 matches what was signed for - and none of it can be influenced by
    /// the caller, who supplies no parameters at all. There is deliberately no
    /// way to say "install this URL" or "install this version".
    /// </remarks>
    [Route(SsoRoutes.UpdateInstallPath, "POST")]
    [Authenticated(Roles = "Admin")]
    public class SsoUpdateInstall : IReturn<UpdateInstallResult>
    {
    }

    public class UpdateInfoResult
    {
        /// <summary>The version running now, as Emby reports it.</summary>
        public string CurrentVersion { get; set; }

        /// <summary>The newer version the vendor has signed for, or empty.</summary>
        public string AvailableVersion { get; set; }

        /// <summary>True when <see cref="AvailableVersion"/> is worth showing a button for.</summary>
        public bool UpdateAvailable { get; set; }

        /// <summary>True once an update has been written and Emby is waiting to be restarted.</summary>
        public bool RestartPending { get; set; }
    }

    public class UpdateInstallResult
    {
        /// <summary>True only when a verified assembly was written to disk.</summary>
        public bool Installed { get; set; }

        /// <summary>One sentence for the administrator. Never a remote host's text.</summary>
        public string Message { get; set; }

        public string Version { get; set; }
    }
}

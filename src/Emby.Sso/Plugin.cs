using System;
using System.Collections.Generic;
using Emby.Sso.Configuration;
using MediaBrowser.Common;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Emby.Sso
{
    public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
    {
        public static Plugin Instance { get; private set; }

        public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer, IApplicationHost applicationHost)
            : base(applicationPaths, xmlSerializer)
        {
            Instance = this;
            SubjectBindingFilePath = BuildSubjectBindingFilePath(applicationPaths);
            ServerId = applicationHost?.SystemId;
            PluginsPath = applicationPaths?.PluginsPath;
            Host = applicationHost;
        }

        /// <summary>
        /// Where Emby loads plugin assemblies from. The one directory the
        /// updater is allowed to write into, and it is taken from Emby rather
        /// than guessed or configured - a settable install path is a way to make
        /// a server write an assembly wherever somebody likes.
        /// </summary>
        public string PluginsPath { get; }

        /// <summary>
        /// Emby itself, for <c>NotifyPendingRestart</c> after an update is
        /// written. The plugin never restarts the server: a media server that
        /// reboots itself mid-playback because an update landed is worse than
        /// one that waits to be told.
        /// </summary>
        public MediaBrowser.Common.IApplicationHost Host { get; }

        /// <summary>
        /// This server's identity, which the licence is bound to
        /// (<see cref="Protocol.LicenceCheck"/>). It is
        /// <c>IApplicationHost.SystemId</c> - the same value Emby logs at
        /// startup as "ServerId" and returns as <c>ServerId</c> in an
        /// authentication response, confirmed present on the 4.9.1.90 reference
        /// assembly and read off <c>ApplicationHost.SystemId</c> in a decompiled
        /// 4.9.5.0 server.
        ///
        /// Taken as a CONSTRUCTOR argument rather than resolved later because
        /// Emby builds plugins through its container
        /// (<c>ApplicationHost.FindParts</c> -&gt;
        /// <c>GetExportsWithInfo&lt;IPlugin&gt;</c> -&gt;
        /// <c>Container.GetInstance</c>, decompiled from 4.9.5.0), which
        /// auto-wires constructor dependencies, and
        /// <c>RegisterSingleInstance&lt;IApplicationHost&gt;(this)</c> runs in
        /// <c>RegisterResources</c>, before <c>FindParts</c>. There is no other
        /// route: <c>BasePlugin</c> exposes paths and serialisation and nothing
        /// about the host.
        ///
        /// UNVERIFIED on a live server. If the container ever failed to supply
        /// it, <c>CreateInstanceSafe</c> catches the exception and logs "Error
        /// creating Emby.Sso.Plugin", and the plugin simply does not load -
        /// visible in the log and in the dashboard, not a silent weakening.
        /// Null here (a host that reports no system id) makes the licence check
        /// refuse rather than skip the server binding.
        /// </summary>
        public string ServerId { get; }

        /// <summary>
        /// Where the subject-to-account bindings live
        /// (<see cref="Protocol.SubjectBindingStore"/>). Null when Emby did not
        /// supply a data path, which makes the store refuse every sign-in rather
        /// than guess at a location.
        ///
        /// DELIBERATELY NOT IN THE PLUGIN CONFIGURATION. The settings page
        /// rewrites this plugin's whole configuration object, and Emby then
        /// serialises it over
        /// <c>plugins/configurations/Emby.Sso.xml</c> - so anything kept there
        /// is destroyed the next time an administrator presses Save. These
        /// bindings are the only thing standing between a reassigned username
        /// claim and somebody else's account; losing them silently re-opens
        /// that door for every account at once.
        ///
        /// It is also not under <c>PluginConfigurationsPath</c> at all, even
        /// under a different file name: that directory belongs to
        /// administrator-edited configuration and to the plugin installer.
        /// <see cref="IApplicationPaths.DataPath"/> is the server's own durable
        /// data directory - it survives restarts, plugin upgrades and config
        /// saves, and it is inside the volume an operator already backs up.
        ///
        /// UNVERIFIED on a live server: that Emby 4.9.5.0 resolves DataPath to a
        /// writable directory inside the container's config volume is read from
        /// MediaBrowser.Common's own documentation of the property
        /// ("the folder path to the data directory"), not measured here. If it
        /// were not writable the store would refuse every sign-in and say so in
        /// the log - loudly wrong rather than quietly permissive.
        /// </summary>
        public string SubjectBindingFilePath { get; }

        private static string BuildSubjectBindingFilePath(IApplicationPaths applicationPaths)
        {
            var dataPath = applicationPaths?.DataPath;

            return string.IsNullOrWhiteSpace(dataPath)
                ? null
                : System.IO.Path.Combine(dataPath, "emby-sso", "subject-bindings.json");
        }

        public override Guid Id => new Guid("ad89f430-b0d0-4e9a-996d-c088f6961158");

        public override string Name => "Authentik SSO";

        public override string Description =>
            "Sign in to Emby with an OpenID Connect provider such as Authentik.";

        public IEnumerable<PluginPageInfo> GetPages()
        {
            return new[]
            {
                new PluginPageInfo
                {
                    Name = "AuthentikSso",
                    EmbeddedResourcePath = GetType().Namespace + ".Configuration.configPage.html",
                },
                new PluginPageInfo
                {
                    Name = "AuthentikSsoScript",
                    EmbeddedResourcePath = GetType().Namespace + ".Configuration.configPage.js",
                    IsMainConfigPage = false,
                },
            };
        }
    }
}

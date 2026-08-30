using System;
using System.Collections.Generic;
using Emby.Sso.Configuration;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Emby.Sso
{
    public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
    {
        public static Plugin Instance { get; private set; }

        public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
            : base(applicationPaths, xmlSerializer)
        {
            Instance = this;
            SubjectBindingFilePath = BuildSubjectBindingFilePath(applicationPaths);
        }

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

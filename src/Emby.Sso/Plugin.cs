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
            };
        }
    }
}

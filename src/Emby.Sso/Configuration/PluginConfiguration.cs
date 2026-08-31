using MediaBrowser.Model.Plugins;

namespace Emby.Sso.Configuration
{
    public class PluginConfiguration : BasePluginConfiguration
    {
        public string IssuerUrl { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string Scopes { get; set; } = "openid profile email";
        public string EmbyPublicBaseUrl { get; set; } = string.Empty;
        public string UsernameClaim { get; set; } = "preferred_username";
        public bool EnableDirectGrant { get; set; } = false;
        public bool EnableButtonInjection { get; set; } = false;
        public bool AllowInsecureHttp { get; set; } = false;

        /// <summary>
        /// Permits the plugin to fetch the discovery document, the JWKS and the
        /// token endpoint from a loopback, RFC1918 or carrier-grade-NAT address.
        /// Off by default, because an issuer URL an administrator was talked
        /// into pasting - or a discovery document from a provider that has been
        /// compromised - would otherwise let this server be used to reach
        /// services on its own network. On, because a great many people quite
        /// legitimately run their identity provider on exactly such an address.
        /// See <see cref="Protocol.OutboundAddressPolicy"/>; link-local
        /// addresses (169.254.0.0/16, which carries the cloud metadata service)
        /// stay refused either way.
        /// </summary>
        public bool AllowPrivateNetworkProvider { get; set; } = false;

        public bool EnableAutoCreate { get; set; } = false;
        public string RequiredGroup { get; set; } = string.Empty;
        public string TemplateUserName { get; set; } = string.Empty;
        public string GroupsClaim { get; set; } = "groups";

        public bool IsConfigured =>
            !string.IsNullOrWhiteSpace(IssuerUrl) &&
            !string.IsNullOrWhiteSpace(ClientId) &&
            !string.IsNullOrWhiteSpace(EmbyPublicBaseUrl);
    }
}

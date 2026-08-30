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

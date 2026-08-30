namespace Emby.Sso.Protocol
{
    public sealed class OidcOptions
    {
        public string IssuerUrl { get; set; } = string.Empty;

        public string ClientId { get; set; } = string.Empty;

        public string ClientSecret { get; set; } = string.Empty;

        public string Scopes { get; set; } = "openid profile email";

        public string RedirectUri { get; set; } = string.Empty;

        public string UsernameClaim { get; set; } = "preferred_username";

        public string MetadataAddress => IssuerUrl.TrimEnd('/') + "/.well-known/openid-configuration";
    }
}

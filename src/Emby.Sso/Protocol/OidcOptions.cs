namespace Emby.Sso.Protocol
{
    internal sealed class OidcOptions
    {
        public string IssuerUrl { get; set; } = string.Empty;

        public string ClientId { get; set; } = string.Empty;

        public string ClientSecret { get; set; } = string.Empty;

        public string Scopes { get; set; } = "openid profile email";

        public string RedirectUri { get; set; } = string.Empty;

        public string UsernameClaim { get; set; } = "preferred_username";

        public string GroupsClaim { get; set; } = "groups";

        /// <summary>
        /// Whether the discovery document and JWKS fetches must use HTTPS.
        /// Defaults to true (secure by default); the Emby-facing caller sets
        /// this explicitly from its own "allow insecure HTTP" setting rather
        /// than leaving it to be inferred from the address itself - an address
        /// under attacker or administrator-typo control is not evidence that
        /// fetching it over plain HTTP is acceptable.
        /// </summary>
        public bool RequireHttps { get; set; } = true;

        public string MetadataAddress => IssuerUrl.TrimEnd('/') + "/.well-known/openid-configuration";
    }
}

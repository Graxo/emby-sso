using System;
using System.Net.Http;
using Emby.Sso.Configuration;
using Emby.Sso.Protocol;

namespace Emby.Sso
{
    /// <summary>
    /// The process-wide state the plugin needs. Emby constructs authentication
    /// providers and API services independently, so the stores they must share
    /// live here.
    /// </summary>
    public static class SsoRuntime
    {
        private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        private static readonly object ClientLock = new object();

        private static OidcClient _client;
        private static (string IssuerUrl, string ClientId, string ClientSecret, string Scopes, string UsernameClaim, string EmbyPublicBaseUrl, bool AllowInsecureHttp) _clientKey;

        public static PendingLoginStore PendingLogins { get; } =
            new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

        public static HandoffSecretStore HandoffSecrets { get; } =
            new HandoffSecretStore(() => DateTimeOffset.UtcNow, TimeSpan.FromSeconds(30));

        public static SsoCredentialValidator Validator { get; } =
            new SsoCredentialValidator(
                HandoffSecrets,
                GetClient,
                () => Configuration?.EnableDirectGrant == true);

        public static PluginConfiguration Configuration => Plugin.Instance?.Configuration;

        /// <summary>The callback URL registered with the identity provider.</summary>
        public static string RedirectUri()
        {
            var configuration = Configuration;

            return configuration == null ? null : BuildRedirectUri(configuration);
        }

        /// <summary>Returns null when the plugin has not been configured.</summary>
        public static OidcClient GetClient()
        {
            var configuration = Configuration;

            if (configuration == null || !configuration.IsConfigured)
            {
                return null;
            }

            // Single read of Configuration for this call: everything below is derived
            // from this one snapshot, so a settings save racing this call cannot mix
            // fields from two different configurations into one OidcOptions.
            var redirectUri = BuildRedirectUri(configuration);

            // Rebuild whenever a setting that shapes the client changes. Compared as
            // individual fields (not a delimited string) so a delimiter appearing
            // inside one field - a ClientSecret containing '|', say - can never make
            // two different configurations collide onto the same key.
            var key = (
                configuration.IssuerUrl,
                configuration.ClientId,
                configuration.ClientSecret,
                configuration.Scopes,
                configuration.UsernameClaim,
                configuration.EmbyPublicBaseUrl,
                configuration.AllowInsecureHttp);

            lock (ClientLock)
            {
                if (_client != null && _clientKey.Equals(key))
                {
                    return _client;
                }

                _client = new OidcClient(Http, new OidcOptions
                {
                    IssuerUrl = configuration.IssuerUrl,
                    ClientId = configuration.ClientId,
                    ClientSecret = configuration.ClientSecret,
                    Scopes = configuration.Scopes,
                    RedirectUri = redirectUri,
                    UsernameClaim = configuration.UsernameClaim,

                    // The flag, not the address: Protocol/ never reads
                    // configuration itself, and deriving this from whether the
                    // issuer URL happens to start with "https://" would make it
                    // impossible for this to ever refuse an http:// issuer - the
                    // exact tautology this replaces.
                    RequireHttps = !configuration.AllowInsecureHttp,
                });
                _clientKey = key;

                return _client;
            }
        }

        private static string BuildRedirectUri(PluginConfiguration configuration)
        {
            return configuration.EmbyPublicBaseUrl.TrimEnd('/') + "/emby" + SsoRoutes.CallbackPath;
        }
    }
}

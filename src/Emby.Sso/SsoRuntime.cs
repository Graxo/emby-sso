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
        private static string _clientKey;

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

            return configuration == null
                ? null
                : configuration.EmbyPublicBaseUrl.TrimEnd('/') + "/emby/Sso/Callback";
        }

        /// <summary>Returns null when the plugin has not been configured.</summary>
        public static OidcClient GetClient()
        {
            var configuration = Configuration;

            if (configuration == null || !configuration.IsConfigured)
            {
                return null;
            }

            // Rebuild whenever a setting that shapes the client changes.
            var key = string.Join("|",
                configuration.IssuerUrl,
                configuration.ClientId,
                configuration.ClientSecret,
                configuration.Scopes,
                configuration.UsernameClaim,
                configuration.EmbyPublicBaseUrl);

            lock (ClientLock)
            {
                if (_client != null && string.Equals(_clientKey, key, StringComparison.Ordinal))
                {
                    return _client;
                }

                _client = new OidcClient(Http, new OidcOptions
                {
                    IssuerUrl = configuration.IssuerUrl,
                    ClientId = configuration.ClientId,
                    ClientSecret = configuration.ClientSecret,
                    Scopes = configuration.Scopes,
                    RedirectUri = RedirectUri(),
                    UsernameClaim = configuration.UsernameClaim,
                });
                _clientKey = key;

                return _client;
            }
        }
    }
}

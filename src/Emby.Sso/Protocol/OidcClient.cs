using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Talks OpenID Connect to the identity provider. Knows nothing about Emby.
    /// Metadata and signing keys are cached and refreshed by ConfigurationManager,
    /// which also backs off when the provider is unreachable.
    /// </summary>
    public sealed partial class OidcClient
    {
        private readonly HttpClient _http;
        private readonly OidcOptions _options;
        private readonly ConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

        public OidcClient(HttpClient http, OidcOptions options)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _options = options ?? throw new ArgumentNullException(nameof(options));

            _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                _options.MetadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(http) { RequireHttps = _options.MetadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase) });
        }

        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancellationToken)
        {
            return _configurationManager.GetConfigurationAsync(cancellationToken);
        }

        public async Task<string> BuildAuthorizationUrlAsync(PendingLogin login, CancellationToken cancellationToken)
        {
            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            var configuration = await GetConfigurationAsync(cancellationToken).ConfigureAwait(false);

            var parameters = new Dictionary<string, string>
            {
                ["response_type"] = "code",
                ["client_id"] = _options.ClientId,
                ["redirect_uri"] = _options.RedirectUri,
                ["scope"] = _options.Scopes,
                ["state"] = login.State,
                ["nonce"] = login.Nonce,
                ["code_challenge"] = login.CodeChallenge,
                ["code_challenge_method"] = "S256",
            };

            var query = new List<string>();
            foreach (var pair in parameters)
            {
                query.Add(Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value));
            }

            var separator = configuration.AuthorizationEndpoint.IndexOf('?') >= 0 ? "&" : "?";
            return configuration.AuthorizationEndpoint + separator + string.Join("&", query);
        }
    }
}

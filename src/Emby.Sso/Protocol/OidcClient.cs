using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

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

        public async Task<OidcIdentity> ExchangeCodeAsync(string code, PendingLogin login, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(code))
            {
                throw new SsoException(SsoErrors.ProviderRejected, "authorization code missing from callback");
            }

            // A pending login is always minted with a nonce (PendingLoginStore.Create);
            // a missing one here means the invariant broke somewhere, not that the
            // caller opted out. Fail closed rather than silently skipping the check.
            if (string.IsNullOrEmpty(login.Nonce))
            {
                throw new SsoException(SsoErrors.InvalidToken, "pending login had no nonce");
            }

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = _options.RedirectUri,
                ["code_verifier"] = login.CodeVerifier,
            };

            var idToken = await PostTokenRequestAsync(form, cancellationToken).ConfigureAwait(false);
            var configuration = await GetConfigurationOrThrowAsync(cancellationToken).ConfigureAwait(false);
            return ValidateIdToken(idToken, login.Nonce, requireNonce: true, configuration);
        }

        /// <summary>
        /// Resource owner password credentials. Used only by native clients that
        /// cannot perform a browser redirect. Cannot satisfy multi-factor
        /// authentication, and is disabled unless an administrator enables it.
        /// </summary>
        public async Task<OidcIdentity> DirectGrantAsync(string username, string password, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                throw new SsoException(SsoErrors.ProviderRejected, "direct grant attempted with an empty credential");
            }

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = username,
                ["password"] = password,
                ["scope"] = _options.Scopes,
            };

            var idToken = await PostTokenRequestAsync(form, cancellationToken).ConfigureAwait(false);
            var configuration = await GetConfigurationOrThrowAsync(cancellationToken).ConfigureAwait(false);

            // No nonce: there was no authorization request to bind one to. Unlike
            // ExchangeCodeAsync, this is an explicit, named opt-out rather than an
            // inferred one.
            return ValidateIdToken(idToken, null, requireNonce: false, configuration);
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationOrThrowAsync(CancellationToken cancellationToken)
        {
            try
            {
                return await GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new SsoException(SsoErrors.ProviderUnreachable, "provider metadata could not be retrieved", ex);
            }
        }

        private async Task<string> PostTokenRequestAsync(Dictionary<string, string> form, CancellationToken cancellationToken)
        {
            var configuration = await GetConfigurationOrThrowAsync(cancellationToken).ConfigureAwait(false);

            using (var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint))
            {
                if (string.IsNullOrEmpty(_options.ClientSecret))
                {
                    // Public client: identify without authenticating.
                    form["client_id"] = _options.ClientId;
                    request.Content = new FormUrlEncodedContent(form);
                }
                else
                {
                    request.Content = new FormUrlEncodedContent(form);

                    // RFC 6749 §2.3.1: the client id and secret are each encoded per
                    // application/x-www-form-urlencoded before being joined and
                    // base64-encoded, so a secret containing ':', '+', '%' or a space
                    // round-trips correctly at strict providers.
                    var credentials = Convert.ToBase64String(
                        System.Text.Encoding.UTF8.GetBytes(FormUrlEncode(_options.ClientId) + ":" + FormUrlEncode(_options.ClientSecret)));
                    request.Headers.Authorization =
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);
                }

                HttpResponseMessage response;
                try
                {
                    response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    throw new SsoException(SsoErrors.ProviderUnreachable, "token endpoint request failed", ex);
                }

                using (response)
                {
                    string body;
                    try
                    {
                        body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        throw new SsoException(SsoErrors.ProviderUnreachable, "token endpoint response could not be read", ex);
                    }

                    if (!response.IsSuccessStatusCode)
                    {
                        // Only the OAuth error code is logged; the body may contain more.
                        throw new SsoException(
                            SsoErrors.ProviderRejected,
                            "token endpoint returned " + (int)response.StatusCode + " " + ReadErrorCode(body));
                    }

                    var idToken = ReadStringField(body, "id_token");

                    if (string.IsNullOrEmpty(idToken))
                    {
                        throw new SsoException(SsoErrors.InvalidToken, "token response contained no id_token");
                    }

                    return idToken;
                }
            }
        }

        private static string FormUrlEncode(string value)
        {
            return Uri.EscapeDataString(value ?? string.Empty).Replace("%20", "+");
        }

        private OidcIdentity ValidateIdToken(string idToken, string expectedNonce, bool requireNonce, OpenIdConnectConfiguration configuration)
        {
            var parameters = new TokenValidationParameters
            {
                ValidIssuer = configuration.Issuer,
                ValidAudience = _options.ClientId,
                IssuerSigningKeys = configuration.SigningKeys,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ClockSkew = TimeSpan.FromMinutes(2),
            };

            var result = new JsonWebTokenHandler().ValidateToken(idToken, parameters);

            if (!result.IsValid)
            {
                throw new SsoException(
                    SsoErrors.InvalidToken,
                    "id_token validation failed: " + (result.Exception?.GetType().Name ?? "unknown"),
                    result.Exception);
            }

            var token = (JsonWebToken)result.SecurityToken;

            if (requireNonce)
            {
                token.TryGetClaim("nonce", out var nonceClaim);

                if (nonceClaim == null || !FixedTime.Equals(expectedNonce, nonceClaim.Value))
                {
                    throw new SsoException(SsoErrors.InvalidToken, "id_token nonce did not match the pending login");
                }
            }

            var username = ReadClaim(token, _options.UsernameClaim);

            if (string.IsNullOrWhiteSpace(username))
            {
                throw new SsoException(
                    SsoErrors.InvalidToken,
                    "id_token did not contain the configured username claim '" + _options.UsernameClaim + "'");
            }

            return new OidcIdentity(ReadClaim(token, "sub"), username.Trim(), ReadClaim(token, "name") ?? username.Trim());
        }

        private static string ReadClaim(JsonWebToken token, string name)
        {
            return token.TryGetClaim(name, out var claim) ? claim.Value : null;
        }

        private static string ReadStringField(string json, string field)
        {
            try
            {
                return (string)Newtonsoft.Json.Linq.JObject.Parse(json)[field];
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static string ReadErrorCode(string json)
        {
            return ReadStringField(json, "error") ?? "unknown_error";
        }
    }
}

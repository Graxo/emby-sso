using System;
using System.Collections.Generic;
using System.Linq;
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

            // RequireHttps comes from the caller's own configuration, not from
            // inspecting the address it is about to police - an http:// issuer
            // must be refused here even though nothing about the address itself
            // says so. The same retriever instance also fetches the JWKS
            // (OpenIdConnectConfigurationRetriever reuses it for jwks_uri), so
            // this one flag covers both the discovery document and the signing
            // keys.
            _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                _options.MetadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(http) { RequireHttps = _options.RequireHttps });
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

            // Via the throwing helper, so a discovery failure at login initiation
            // surfaces as SsoException with a user-safe reason like every other
            // provider fetch, instead of an HttpRequestException the caller would
            // have to guess at.
            var configuration = await GetConfigurationOrThrowAsync(cancellationToken).ConfigureAwait(false);

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

            // PendingLoginStore.Consume returns null for an expired, unknown, or
            // already-consumed (replayed) state - exactly what the callback handler
            // passes in here. That is a routine, expected outcome, not a broken
            // invariant, so it gets its own reason rather than falling through to
            // the nonce check below and throwing a bare NullReferenceException.
            if (login == null)
            {
                throw new SsoException(SsoErrors.SessionExpired, "no pending login for the callback state");
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
                // The typed exception, not the string: nothing was asked of the
                // provider that it answered, so a failure here tested no
                // credential. See SsoException.Unreachable.
                throw SsoException.Unreachable("provider metadata could not be retrieved", ex);
            }
        }

        private async Task<string> PostTokenRequestAsync(Dictionary<string, string> form, CancellationToken cancellationToken)
        {
            var configuration = await GetConfigurationOrThrowAsync(cancellationToken).ConfigureAwait(false);

            // The one place a credential leaves this process, and until this
            // check the only thing that ever asserted a scheme was
            // HttpDocumentRetriever.RequireHttps - which governs fetching the
            // discovery document and the JWKS, NOT the address that document
            // then points at. An https issuer may advertise an http token
            // endpoint, and this POST carries either an authorization code or,
            // on the native path, a user's real password. Refuse rather than
            // send it in cleartext.
            //
            // Governed by the same RequireHttps flag as the metadata fetch, so
            // an operator who has deliberately allowed plain HTTP still gets a
            // lab that works - but see SsoRuntime.DirectGrantPermitted: allowing
            // plain HTTP switches password sign-in off entirely, so the form
            // this branch can still carry over http is an authorization code,
            // never a password.
            if (_options.RequireHttps && !IsHttps(configuration.TokenEndpoint))
            {
                throw new SsoException(
                    SsoErrors.NotConfigured,
                    "the provider's advertised token endpoint is not HTTPS");
            }

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
                    // No response at all, so no verdict on the credential was ever
                    // learned - by this process or by anyone watching it.
                    throw SsoException.Unreachable("token endpoint request failed", ex);
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
                        // NOT marked unreachable, deliberately, even though the
                        // sentence the caller gets is the same one. An answer
                        // did arrive - a mid-flight transport failure surfaces
                        // from SendAsync above, measured, not assumed - so what
                        // reaches here is a response this process could not
                        // decode, e.g. one declaring a character set it cannot
                        // use. The provider was reached; only we could not read
                        // what it said. That is not "no credential was tested",
                        // and the rule for the provisioning throttle is that
                        // anything short of certainly-transport counts. Marking
                        // this would trade a real brake for an outage case it
                        // does not cover.
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

        /// <summary>
        /// True only for an absolute https URL. A missing or unparseable address
        /// is not HTTPS, so it is refused rather than attempted.
        /// </summary>
        private static bool IsHttps(string url)
        {
            return Uri.TryCreate(url, UriKind.Absolute, out var uri)
                && string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase);
        }

        private static string FormUrlEncode(string value)
        {
            return Uri.EscapeDataString(value ?? string.Empty).Replace("%20", "+");
        }

        /// <summary>
        /// The RSA signing algorithms this client will accept, in the order the
        /// OIDC signing-algorithm registry lists them. Restricting to this set -
        /// rather than trusting whatever alg header the token carries - is what
        /// prevents an algorithm-confusion attack: without a pin, a validator
        /// that resolves a signing key by <c>kid</c> alone can be tricked into
        /// verifying an HMAC-signed token against key material that was only
        /// ever meant to be used as an RSA public key.
        /// </summary>
        private static readonly string[] RsaAlgorithms =
        {
            SecurityAlgorithms.RsaSha256,
            SecurityAlgorithms.RsaSha384,
            SecurityAlgorithms.RsaSha512,
            SecurityAlgorithms.RsaSsaPssSha256,
            SecurityAlgorithms.RsaSsaPssSha384,
            SecurityAlgorithms.RsaSsaPssSha512,
        };

        private OidcIdentity ValidateIdToken(string idToken, string expectedNonce, bool requireNonce, OpenIdConnectConfiguration configuration)
        {
            var parameters = new TokenValidationParameters
            {
                ValidIssuer = configuration.Issuer,
                ValidAudience = _options.ClientId,
                IssuerSigningKeys = configuration.SigningKeys,
                ValidAlgorithms = AllowedRsaAlgorithms(configuration),
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

            var groups = ReadClaims(token, _options.GroupsClaim);
            var hasGroupsClaim = ClaimExistsInPayload(token, _options.GroupsClaim);

            return new OidcIdentity(
                ReadClaim(token, "sub"),
                username.Trim(),
                ReadClaim(token, "name") ?? username.Trim(),
                groups,
                hasGroupsClaim);
        }

        /// <summary>
        /// The RSA algorithms both this client supports and the discovery
        /// document advertises. Falls back to RS256 alone when the document
        /// advertises no RSA algorithm this client recognises, rather than
        /// producing an empty list - an empty <c>ValidAlgorithms</c> is treated
        /// by the token handler as "no restriction", which is exactly what
        /// pinning exists to avoid.
        /// </summary>
        private static IList<string> AllowedRsaAlgorithms(OpenIdConnectConfiguration configuration)
        {
            var advertised = configuration?.IdTokenSigningAlgValuesSupported;
            var allowed = new List<string>();

            if (advertised != null)
            {
                foreach (var algorithm in RsaAlgorithms)
                {
                    if (advertised.Contains(algorithm))
                    {
                        allowed.Add(algorithm);
                    }
                }
            }

            if (allowed.Count == 0)
            {
                allowed.Add(SecurityAlgorithms.RsaSha256);
            }

            return allowed;
        }

        private static string ReadClaim(JsonWebToken token, string name)
        {
            return token.TryGetClaim(name, out var claim) ? claim.Value : null;
        }

        private static IReadOnlyList<string> ReadClaims(JsonWebToken token, string name)
        {
            var values = new List<string>();

            foreach (var claim in token.Claims)
            {
                if (string.Equals(claim.Type, name, StringComparison.Ordinal))
                {
                    values.Add(claim.Value);
                }
            }

            return values;
        }

        /// <summary>
        /// Checks whether a claim exists in the token's raw JSON payload.
        /// This distinguishes between a claim being absent and a claim containing an empty array.
        /// IdentityModel flattens arrays into one claim per element, so an empty array
        /// produces zero claims in the flattened Claims collection; checking the raw payload
        /// is the only way to distinguish this case from the claim being missing entirely.
        /// </summary>
        private static bool ClaimExistsInPayload(JsonWebToken token, string name)
        {
            try
            {
                var payloadBytes = Base64UrlEncoder.DecodeBytes(token.EncodedPayload);
                var payloadJson = System.Text.Encoding.UTF8.GetString(payloadBytes);
                var payload = Newtonsoft.Json.Linq.JObject.Parse(payloadJson);
                return payload.ContainsKey(name);
            }
            catch (Newtonsoft.Json.JsonException)
            {
                // Payload exists but is not valid JSON. This should not happen for a valid token.
                return false;
            }
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

        /// <summary>
        /// The provider's own "error" field, going straight into an exception
        /// message that later reaches the server log. Flattened and capped the
        /// same way <c>SsoService.ForLog</c> treats every other provider-supplied
        /// string, so a hostile or compromised token endpoint cannot use it to
        /// forge additional log lines.
        /// </summary>
        private static string ReadErrorCode(string json)
        {
            return LogSafeText.Flatten(ReadStringField(json, "error") ?? "unknown_error");
        }
    }
}

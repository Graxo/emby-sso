using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// An in-process OpenID Connect provider: real RSA keys, real signatures,
    /// no network. Tests drive it to produce the tokens they want to reject.
    /// </summary>
    public sealed class FakeIdentityProvider : HttpMessageHandler
    {
        public const string Issuer = "https://idp.test/application/o/emby/";
        public const string ClientId = "emby-client";
        public const string ClientSecret = "emby-secret";
        public const string KeyId = "test-key-1";

        private readonly RSA _rsa = RSA.Create(2048);

        /// <summary>Body returned by the token endpoint. Set by each test.</summary>
        public string TokenResponseJson { get; set; }

        public HttpStatusCode TokenResponseStatus { get; set; } = HttpStatusCode.OK;

        /// <summary>The form fields of the most recent token request.</summary>
        public Dictionary<string, string> LastTokenRequestForm { get; private set; }

        public AuthenticationHeaderValueSnapshot LastTokenRequestAuthorization { get; private set; }

        public int DiscoveryRequestCount { get; private set; }

        public string CreateIdToken(
            string subject = "sub-1",
            string username = "alice",
            string displayName = "Alice Example",
            string nonce = null,
            string issuer = Issuer,
            string audience = ClientId,
            DateTime? expires = null,
            DateTime? notBefore = null,
            IDictionary<string, object> extraClaims = null)
        {
            var claims = new Dictionary<string, object> { ["sub"] = subject };

            // Omitted rather than set to null, so that tests can produce a token
            // that genuinely lacks the claim.
            if (username != null)
            {
                claims["preferred_username"] = username;
            }

            if (displayName != null)
            {
                claims["name"] = displayName;
            }

            if (nonce != null)
            {
                claims["nonce"] = nonce;
            }

            if (extraClaims != null)
            {
                foreach (var pair in extraClaims)
                {
                    claims[pair.Key] = pair.Value;
                }
            }

            var key = new RsaSecurityKey(_rsa) { KeyId = KeyId };
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                Claims = claims,
                NotBefore = notBefore ?? DateTime.UtcNow.AddMinutes(-1),
                Expires = expires ?? DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            };

            return new JsonWebTokenHandler().CreateToken(descriptor);
        }

        public string CreateTokenResponse(string idToken)
        {
            return new JObject
            {
                ["access_token"] = "access-token-value",
                ["token_type"] = "Bearer",
                ["expires_in"] = 300,
                ["id_token"] = idToken,
            }.ToString();
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri.AbsoluteUri;

            if (path.EndsWith(".well-known/openid-configuration", StringComparison.Ordinal))
            {
                DiscoveryRequestCount++;
                return Json(HttpStatusCode.OK, DiscoveryDocument());
            }

            if (path.EndsWith("/jwks/", StringComparison.Ordinal))
            {
                return Json(HttpStatusCode.OK, JwksDocument());
            }

            if (path.EndsWith("/token/", StringComparison.Ordinal))
            {
                var body = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
                LastTokenRequestForm = ParseForm(body);
                LastTokenRequestAuthorization = request.Headers.Authorization == null
                    ? null
                    : new AuthenticationHeaderValueSnapshot(
                        request.Headers.Authorization.Scheme,
                        request.Headers.Authorization.Parameter);

                return Json(TokenResponseStatus, TokenResponseJson ?? "{}");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static Dictionary<string, string> ParseForm(string body)
        {
            var form = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var pair in body.Split('&'))
            {
                if (pair.Length == 0)
                {
                    continue;
                }

                var parts = pair.Split(new[] { '=' }, 2);
                form[Uri.UnescapeDataString(parts[0])] =
                    parts.Length > 1 ? Uri.UnescapeDataString(parts[1].Replace("+", "%20")) : string.Empty;
            }

            return form;
        }

        private static string DiscoveryDocument()
        {
            return new JObject
            {
                ["issuer"] = Issuer,
                ["authorization_endpoint"] = Issuer + "authorize/",
                ["token_endpoint"] = Issuer + "token/",
                ["jwks_uri"] = Issuer + "jwks/",
                ["userinfo_endpoint"] = Issuer + "userinfo/",
                ["response_types_supported"] = new JArray("code"),
                ["subject_types_supported"] = new JArray("public"),
                ["id_token_signing_alg_values_supported"] = new JArray("RS256"),
            }.ToString();
        }

        private string JwksDocument()
        {
            var parameters = _rsa.ExportParameters(false);

            return new JObject
            {
                ["keys"] = new JArray(new JObject
                {
                    ["kty"] = "RSA",
                    ["use"] = "sig",
                    ["alg"] = "RS256",
                    ["kid"] = KeyId,
                    ["n"] = Base64UrlEncoder.Encode(parameters.Modulus),
                    ["e"] = Base64UrlEncoder.Encode(parameters.Exponent),
                }),
            }.ToString();
        }

        private static HttpResponseMessage Json(HttpStatusCode status, string body)
        {
            return new HttpResponseMessage(status)
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
            };
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _rsa.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    public sealed class AuthenticationHeaderValueSnapshot
    {
        public AuthenticationHeaderValueSnapshot(string scheme, string parameter)
        {
            Scheme = scheme;
            Parameter = parameter;
        }

        public string Scheme { get; }

        public string Parameter { get; }
    }
}

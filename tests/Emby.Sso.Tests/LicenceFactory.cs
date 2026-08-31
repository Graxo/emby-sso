using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// Mints licences the way the issuing tool does, plus the ones it never
    /// would: unsigned, HMAC-signed, signed by a stranger, and tampered with
    /// after signing. Every test in <c>LicenceCheckTests</c> that names an
    /// attack builds it here rather than pasting a fixed string, so the attack
    /// stays valid as the format moves.
    /// </summary>
    internal sealed class LicenceFactory : IDisposable
    {
        public const string ServerId = "c5bc6e91458540caa295c4efdda1a58a";

        private readonly RSA _rsa = RSA.Create();
        private readonly RSA _stranger = RSA.Create();

        public LicenceFactory()
        {
            _rsa.KeySize = 2048;
            _stranger.KeySize = 2048;
        }

        /// <summary>The public half, in the shape <c>LicencePublicKey.Jwk</c> holds.</summary>
        public string PublicKeyJwk => PublicJwk(_rsa);

        /// <summary>
        /// The same key with its private half included - what a careless release
        /// would embed, and what the check must refuse.
        /// </summary>
        public string PrivateKeyJwk
        {
            get
            {
                var p = _rsa.ExportParameters(true);

                return "{\"kty\":\"RSA\",\"n\":\"" + Base64UrlEncoder.Encode(p.Modulus)
                    + "\",\"e\":\"" + Base64UrlEncoder.Encode(p.Exponent)
                    + "\",\"d\":\"" + Base64UrlEncoder.Encode(p.D) + "\"}";
            }
        }

        public string Issue(
            string licensee = "Test Operator",
            string serverId = ServerId,
            string issuer = "urn:emby-sso:licence",
            DateTime? issuedAt = null,
            DateTime? notBefore = null,
            DateTime? expires = null,
            bool includeExpiry = true,
            bool includeIssuedAt = true,
            string algorithm = SecurityAlgorithms.RsaSha256,
            bool signedByAStranger = false)
        {
            var now = issuedAt ?? DateTime.UtcNow;

            var claims = new Dictionary<string, object>
            {
                ["sub"] = licensee,
                ["aud"] = serverId,
                ["iss"] = issuer,
            };

            if (includeIssuedAt)
            {
                claims["iat"] = EpochTime.GetIntDate(now);
            }

            claims["nbf"] = EpochTime.GetIntDate(notBefore ?? now);

            if (includeExpiry)
            {
                claims["exp"] = EpochTime.GetIntDate(expires ?? now.AddDays(365));
            }

            var key = new RsaSecurityKey(signedByAStranger ? _stranger : _rsa);

            return new JsonWebTokenHandler().CreateToken(
                Newtonsoft.Json.JsonConvert.SerializeObject(claims),
                new SigningCredentials(key, algorithm));
        }

        /// <summary>
        /// A token with <c>"alg":"none"</c> and an empty signature, otherwise
        /// perfectly formed. Built by hand because no signing library will
        /// produce one.
        /// </summary>
        public static string Unsigned(string serverId = ServerId, string licensee = "Test Operator")
        {
            var now = EpochTime.GetIntDate(DateTime.UtcNow);
            var header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
            var payload = "{\"sub\":\"" + licensee + "\",\"aud\":\"" + serverId
                + "\",\"iss\":\"urn:emby-sso:licence\",\"iat\":" + now
                + ",\"nbf\":" + now
                + ",\"exp\":" + EpochTime.GetIntDate(DateTime.UtcNow.AddDays(365)) + "}";

            return Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header))
                + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload))
                + ".";
        }

        /// <summary>
        /// The algorithm-confusion attack: an HS256 token whose HMAC secret is
        /// the public key material that ships inside the plugin. Anyone holding
        /// the DLL holds this "secret".
        /// </summary>
        public string HmacSignedWithThePublicKey(string serverId = ServerId)
        {
            var secret = _rsa.ExportParameters(false).Modulus;
            var now = DateTime.UtcNow;

            var claims = new Dictionary<string, object>
            {
                ["sub"] = "Forged",
                ["aud"] = serverId,
                ["iss"] = "urn:emby-sso:licence",
                ["iat"] = EpochTime.GetIntDate(now),
                ["nbf"] = EpochTime.GetIntDate(now),
                ["exp"] = EpochTime.GetIntDate(now.AddDays(365)),
            };

            return new JsonWebTokenHandler().CreateToken(
                Newtonsoft.Json.JsonConvert.SerializeObject(claims),
                new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256));
        }

        /// <summary>
        /// Rewrites one claim of an already-signed licence and leaves the
        /// original signature attached.
        /// </summary>
        public static string Tamper(string licence, string claim, string newValue)
        {
            var parts = licence.Split('.');
            var payload = Newtonsoft.Json.Linq.JObject.Parse(Base64UrlEncoder.Decode(parts[1]));

            payload[claim] = newValue;

            parts[1] = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToString(Newtonsoft.Json.Formatting.None)));

            return string.Join(".", parts);
        }

        private static string PublicJwk(RSA rsa)
        {
            var p = rsa.ExportParameters(false);

            return "{\"kty\":\"RSA\",\"n\":\"" + Base64UrlEncoder.Encode(p.Modulus)
                + "\",\"e\":\"" + Base64UrlEncoder.Encode(p.Exponent) + "\"}";
        }

        public void Dispose()
        {
            _rsa.Dispose();
            _stranger.Dispose();
        }
    }
}

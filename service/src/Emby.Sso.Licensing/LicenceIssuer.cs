using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.Licensing
{
    /// <summary>
    /// Mints a licence. This is <c>licencetool issue</c>'s signing block, moved
    /// somewhere both the tool and the service can call it.
    ///
    /// The claim set below is the interface with the plugin, which validates it
    /// through the library rather than by re-reading the payload: `iss` is
    /// checked against <see cref="LicenceFormat.Issuer"/>, `aud` against the
    /// server's own <c>IApplicationHost.SystemId</c>, and iat/nbf/exp are the
    /// standard lifetime claims. Adding a claim is safe; renaming or dropping
    /// one of these breaks every plugin build already in the field.
    /// </summary>
    public sealed class LicenceIssuer
    {
        private readonly JsonWebKey _key;
        private readonly JsonWebTokenHandler _handler = new JsonWebTokenHandler();

        public LicenceIssuer(JsonWebKey key)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(_key.D))
            {
                throw new ArgumentException("this JWK carries no private key material and cannot sign", nameof(key));
            }

            if (string.IsNullOrEmpty(_key.Kid))
            {
                // Every licence has to name the key that signed it, or it can
                // never be rotated away from: see LicenceFormat.KeyId. Loading
                // the key through SigningKeyFile sets this; constructing one by
                // hand has to as well, and finding out here beats finding out
                // when a customer's plugin refuses a licence for having no kid.
                throw new ArgumentException(
                    "this signing key has no key id. Set Kid to LicenceFormat.KeyId of its public half, or load it "
                    + "through SigningKeyFile, which does.",
                    nameof(key));
            }
        }

        /// <summary>
        /// One licence, valid on one Emby server, from <paramref name="issuedAt"/>
        /// until <paramref name="expiresAt"/>.
        ///
        /// <paramref name="serverId"/> goes into `aud` EXACTLY as the plugin sent
        /// it. It is not trimmed, lowercased or otherwise tidied here, because
        /// the plugin compares `aud` to its own id character for character and a
        /// helpful normalisation is how you mint a licence that the server it was
        /// bought for rejects. Normalisation for the purpose of counting
        /// activations happens elsewhere, on a copy.
        /// </summary>
        public IssuedLicence Issue(string licensee, string serverId, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
        {
            if (string.IsNullOrWhiteSpace(licensee))
            {
                throw new ArgumentException("a licence must name its licensee", nameof(licensee));
            }

            if (string.IsNullOrWhiteSpace(serverId))
            {
                throw new ArgumentException("a licence must name the server it is for", nameof(serverId));
            }

            if (expiresAt <= issuedAt)
            {
                throw new ArgumentException("a licence must expire after it is issued", nameof(expiresAt));
            }

            var payload = JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["iss"] = LicenceFormat.Issuer,
                ["sub"] = licensee,
                ["aud"] = serverId,
                ["iat"] = EpochTime.GetIntDate(issuedAt.UtcDateTime),
                ["nbf"] = EpochTime.GetIntDate(issuedAt.UtcDateTime),
                ["exp"] = EpochTime.GetIntDate(expiresAt.UtcDateTime),
            });

            var token = _handler.CreateToken(payload, new SigningCredentials(_key, LicenceFormat.Algorithm));

            return new IssuedLicence(
                token,
                LicenceFormat.Fingerprint(token),
                licensee,
                serverId,
                issuedAt,
                expiresAt,
                _key.Kid);
        }
    }

    /// <summary>A minted licence and the facts about it worth keeping.</summary>
    public sealed class IssuedLicence
    {
        internal IssuedLicence(
            string token,
            string fingerprint,
            string licensee,
            string serverId,
            DateTimeOffset issuedAt,
            DateTimeOffset expiresAt,
            string keyId)
        {
            Token = token;
            Fingerprint = fingerprint;
            Licensee = licensee;
            ServerId = serverId;
            IssuedAt = issuedAt;
            ExpiresAt = expiresAt;
            KeyId = keyId;
        }

        /// <summary>The licence itself. A live credential: it goes to the buyer and nowhere else.</summary>
        public string Token { get; }

        /// <summary>What the ledger records instead of <see cref="Token"/>.</summary>
        public string Fingerprint { get; }

        public string Licensee { get; }

        public string ServerId { get; }

        public DateTimeOffset IssuedAt { get; }

        public DateTimeOffset ExpiresAt { get; }

        /// <summary>Which key signed it - the licence's `kid` header.</summary>
        public string KeyId { get; }
    }
}

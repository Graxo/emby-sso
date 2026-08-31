using System;
using System.IO;
using System.Threading.Tasks;
using Emby.Sso.Licensing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// A licence this service mints has to satisfy the check the PLUGIN runs, on
    /// somebody else's server, offline, months later. So every test here
    /// validates with the same TokenValidationParameters the plugin uses -
    /// signature required, algorithm pinned to RS256, issuer and audience
    /// enforced - rather than by decoding the token and reading it.
    /// </summary>
    public class LicenceIssuerTests
    {
        private const string ServerId = "c5bc6e91458540caa295c4efdda1a58a";

        [Fact]
        public async Task A_minted_licence_verifies_against_the_public_half_of_the_key()
        {
            var (issuer, publicKey) = NewIssuer();
            var now = DateTimeOffset.UtcNow;

            var licence = issuer.Issue("code:abcdef123456", ServerId, now, now.AddDays(365));

            var result = await Validate(licence.Token, publicKey, ServerId);

            Assert.True(result.IsValid, result.Exception?.Message);
        }

        [Fact]
        public async Task A_licence_for_one_server_does_not_verify_for_another()
        {
            var (issuer, publicKey) = NewIssuer();
            var now = DateTimeOffset.UtcNow;

            var licence = issuer.Issue("code:abcdef123456", ServerId, now, now.AddDays(365));

            var result = await Validate(licence.Token, publicKey, "0000000000000000000000000000dead");

            Assert.False(result.IsValid);
        }

        [Fact]
        public async Task A_licence_signed_by_a_different_key_does_not_verify()
        {
            var (issuer, _) = NewIssuer();
            var (_, otherPublicKey) = NewIssuer();
            var now = DateTimeOffset.UtcNow;

            var licence = issuer.Issue("code:abcdef123456", ServerId, now, now.AddDays(365));

            var result = await Validate(licence.Token, otherPublicKey, ServerId);

            Assert.False(result.IsValid);
        }

        [Fact]
        public async Task An_expired_licence_does_not_verify()
        {
            var (issuer, publicKey) = NewIssuer();
            var past = DateTimeOffset.UtcNow.AddDays(-400);

            var licence = issuer.Issue("code:abcdef123456", ServerId, past, past.AddDays(365));

            var result = await Validate(licence.Token, publicKey, ServerId);

            Assert.False(result.IsValid);
        }

        [Fact]
        public void The_server_id_reaches_the_audience_claim_exactly_as_it_was_sent()
        {
            var (issuer, _) = NewIssuer();
            var now = DateTimeOffset.UtcNow;

            // A mixed-case id: the plugin compares `aud` to its own SystemId
            // character for character, so a helpful lowercasing here would mint a
            // licence the server it was bought for rejects.
            const string Mixed = "C5BC6E91458540caa295c4efdda1a58a";

            var licence = issuer.Issue("code:abcdef123456", Mixed, now, now.AddDays(1));
            var token = new JsonWebToken(licence.Token);

            Assert.Equal(Mixed, Audience(token));
        }

        [Fact]
        public void The_issuer_and_algorithm_are_the_ones_the_plugin_pins()
        {
            var (issuer, _) = NewIssuer();
            var now = DateTimeOffset.UtcNow;

            var token = new JsonWebToken(issuer.Issue("code:abcdef123456", ServerId, now, now.AddDays(1)).Token);

            Assert.Equal(LicenceFormat.Issuer, token.Issuer);
            Assert.Equal("RS256", token.Alg);
        }

        [Fact]
        public void The_fingerprint_is_a_sha256_of_the_licence_and_not_the_licence()
        {
            var (issuer, _) = NewIssuer();
            var now = DateTimeOffset.UtcNow;

            var licence = issuer.Issue("code:abcdef123456", ServerId, now, now.AddDays(1));

            Assert.StartsWith("sha256:", licence.Fingerprint, StringComparison.Ordinal);
            Assert.Equal(LicenceFormat.Fingerprint(licence.Token), licence.Fingerprint);
            Assert.DoesNotContain(licence.Token, licence.Fingerprint, StringComparison.Ordinal);
        }

        [Fact]
        public void A_licence_that_expires_before_it_is_issued_is_refused()
        {
            var (issuer, _) = NewIssuer();
            var now = DateTimeOffset.UtcNow;

            Assert.Throws<ArgumentException>(() => issuer.Issue("code:abcdef123456", ServerId, now, now.AddDays(-1)));
        }

        [Fact]
        public void A_public_only_key_cannot_be_used_to_sign()
        {
            var directory = TestKeys.TempDirectory();

            try
            {
                var jwk = new JsonWebKey(File.ReadAllText(TestKeys.WritePublicKeyOnly(directory)));

                Assert.Throws<ArgumentException>(() => new LicenceIssuer(jwk));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        private static string Audience(JsonWebToken token)
        {
            foreach (var audience in token.Audiences)
            {
                return audience;
            }

            return null;
        }

        private static (LicenceIssuer Issuer, JsonWebKey PublicKey) NewIssuer()
        {
            var directory = TestKeys.TempDirectory();

            try
            {
                var path = TestKeys.WritePrivateKey(directory);
                var key = SigningKeyFile.Load(path);

                return (new LicenceIssuer(key.Key), new JsonWebKey(key.PublicJwk));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        /// <summary>
        /// The plugin's validation, as documented in
        /// tools/Emby.Sso.LicenceTool/README.md: the signature against the
        /// embedded public key, `alg` pinned so the public key cannot be turned
        /// into an HMAC secret, unsigned tokens refused, `aud` the server's own
        /// id.
        /// </summary>
        private static Task<TokenValidationResult> Validate(string token, JsonWebKey publicKey, string audience)
        {
            return new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
            {
                IssuerSigningKey = publicKey,
                ValidIssuer = LicenceFormat.Issuer,
                ValidAudience = audience,
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidAlgorithms = new[] { LicenceFormat.Algorithm },
                RequireSignedTokens = true,
                ClockSkew = TimeSpan.FromMinutes(2),
            });
        }
    }
}

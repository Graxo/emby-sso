using System;
using System.Linq;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class SecureRandomTests
    {
        [Fact]
        public void CreateToken_produces_url_safe_unpadded_output()
        {
            var token = SecureRandom.CreateToken(32);

            Assert.DoesNotContain('+', token);
            Assert.DoesNotContain('/', token);
            Assert.DoesNotContain('=', token);
            Assert.True(token.Length >= 43, "32 bytes of base64url is at least 43 characters");
        }

        [Fact]
        public void CreateToken_does_not_repeat()
        {
            var tokens = Enumerable.Range(0, 100).Select(_ => SecureRandom.CreateToken(32)).ToList();

            Assert.Equal(tokens.Count, tokens.Distinct().Count());
        }

        [Fact]
        public void CreateCodeChallenge_matches_rfc7636_test_vector()
        {
            // RFC 7636 Appendix B.
            const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

            var challenge = SecureRandom.CreateCodeChallenge(verifier);

            Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
        }

        [Fact]
        public void CreateCodeVerifier_is_within_rfc7636_length_limits()
        {
            var verifier = SecureRandom.CreateCodeVerifier();

            Assert.InRange(verifier.Length, 43, 128);
        }
    }
}

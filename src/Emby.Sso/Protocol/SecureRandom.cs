using System;
using System.Security.Cryptography;
using System.Text;

namespace Emby.Sso.Protocol
{
    public static class SecureRandom
    {
        public static string CreateToken(int byteLength)
        {
            if (byteLength <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(byteLength));
            }

            var bytes = new byte[byteLength];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            return Base64Url(bytes);
        }

        public static string CreateCodeVerifier()
        {
            return CreateToken(32);
        }

        public static string CreateCodeChallenge(string verifier)
        {
            if (string.IsNullOrEmpty(verifier))
            {
                throw new ArgumentException("verifier is required", nameof(verifier));
            }

            using (var sha = SHA256.Create())
            {
                return Base64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));
            }
        }

        private static string Base64Url(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
}

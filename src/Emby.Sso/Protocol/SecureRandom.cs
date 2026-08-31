using System;
using System.Security.Cryptography;
using System.Text;

namespace Emby.Sso.Protocol
{
    internal static class SecureRandom
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

        /// <summary>
        /// A string of <paramref name="length"/> characters drawn UNIFORMLY
        /// from <paramref name="alphabet"/>, for a secret a person has to read
        /// and type - see <see cref="SignInPin"/>.
        ///
        /// Uniformly is the whole point, and it is why this is not the obvious
        /// one-liner. <c>alphabet[randomByte % alphabet.Length]</c> is biased
        /// whenever the alphabet's size does not divide 256: with 30 characters
        /// the sixteen byte values 240-255 wrap round, so the first sixteen
        /// characters of the alphabet come up 9/256 of the time and the rest
        /// 8/256. That is not a rounding error, it is a real loss of entropy in
        /// a secret that has little to spare, and it is the classic way a
        /// short code ends up weaker than its length suggests. So the values
        /// that would wrap are REJECTED and redrawn instead, which costs
        /// nothing but a few extra bytes and makes every character exactly as
        /// likely as every other.
        ///
        /// A fresh generator per call, like the other methods here.
        /// </summary>
        public static string CreateCode(string alphabet, int length)
        {
            if (string.IsNullOrEmpty(alphabet) || alphabet.Length < 2 || alphabet.Length > 128)
            {
                // The upper bound keeps the rejection arithmetic below honest
                // (a limit that always fits a byte) and is far above any
                // alphabet a person could be asked to read.
                throw new ArgumentOutOfRangeException(nameof(alphabet));
            }

            if (length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            // The largest multiple of the alphabet size that fits in a byte.
            // Any drawn byte at or above it is thrown away.
            var limit = 256 - (256 % alphabet.Length);

            var result = new char[length];
            var buffer = new byte[length * 2];
            var produced = 0;

            using (var rng = RandomNumberGenerator.Create())
            {
                while (produced < length)
                {
                    rng.GetBytes(buffer);

                    foreach (var drawn in buffer)
                    {
                        if (drawn >= limit)
                        {
                            continue;
                        }

                        result[produced++] = alphabet[drawn % alphabet.Length];

                        if (produced == length)
                        {
                            break;
                        }
                    }
                }
            }

            return new string(result);
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

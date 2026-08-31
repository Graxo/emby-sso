using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Emby.Sso.LicenceService.Admin
{
    /// <summary>
    /// The one credential standing between the internet and a page that can mint
    /// licences for anybody's server, forever.
    ///
    /// WHAT THIS IS AND WHY IT IS SHAPED THIS WAY.
    ///
    /// The password is stored as a PBKDF2-HMAC-SHA256 verifier, never in the
    /// clear. ADMIN_PASSWORD_HASH is the supported form and holds one:
    ///
    ///     pbkdf2-sha256$210000$&lt;base64 salt&gt;$&lt;base64 hash&gt;
    ///
    /// so the environment of this container, and anything that can read it -
    /// `docker inspect`, a crash dump, a compose file in a backup, another
    /// process on the box - yields a verifier and not a credential. Generate one
    /// with `hash-password`, which reads the password on stdin so it never
    /// reaches a shell history or a process list.
    ///
    /// ADMIN_PASSWORD, the plaintext form, is accepted because refusing it
    /// entirely would send an operator to a text file with the password in it
    /// anyway. It is turned into a verifier at startup with a fresh random salt
    /// and the plaintext is not kept, and it is REFUSED if it is short or
    /// obvious - see <see cref="Weakness"/>. It is second best and the
    /// documentation says so.
    ///
    /// 210,000 iterations of PBKDF2-HMAC-SHA256, which is OWASP's 2023 figure
    /// for this construction. It costs this service about a tenth of a second
    /// per login attempt on a small VPS, which is the point: the login rate
    /// limiter bounds attempts per minute, and this bounds what each one is
    /// worth to a guesser who has somehow obtained the verifier.
    ///
    /// The comparison is <see cref="CryptographicOperations.FixedTimeEquals"/>
    /// over the derived bytes, so a wrong password costs the same time whatever
    /// prefix it shares with the right one.
    /// </summary>
    public sealed class AdminPassword
    {
        /// <summary>The only algorithm this understands. Not read from the stored string as a choice.</summary>
        public const string Algorithm = "pbkdf2-sha256";

        /// <summary>OWASP's 2023 figure for PBKDF2-HMAC-SHA256.</summary>
        public const int DefaultIterations = 210000;

        /// <summary>
        /// A stored verifier with fewer than this is refused rather than
        /// silently accepted: a hash generated years ago by a weaker tool is a
        /// hash that should be regenerated, and this service says so at startup
        /// rather than pretending it is as good as it was.
        /// </summary>
        public const int MinimumIterations = 100000;

        public const int SaltBytes = 16;

        public const int HashBytes = 32;

        /// <summary>
        /// A plaintext ADMIN_PASSWORD shorter than this is refused. Sixteen
        /// characters is not a policy about character classes; it is the length
        /// at which an offline guesser working from a stolen verifier stops
        /// being the cheapest way in.
        /// </summary>
        public const int MinimumLength = 16;

        private readonly byte[] _salt;
        private readonly byte[] _expected;

        private AdminPassword(int iterations, byte[] salt, byte[] expected)
        {
            Iterations = iterations;
            _salt = salt;
            _expected = expected;
        }

        public int Iterations { get; }

        /// <summary>
        /// Turns a plaintext password into the stored form. Used by
        /// `hash-password` and by the ADMIN_PASSWORD path, which derives one at
        /// startup and drops the plaintext.
        /// </summary>
        public static string Encode(string password, int iterations = DefaultIterations)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("a password is required", nameof(password));
            }

            var salt = RandomNumberGenerator.GetBytes(SaltBytes);
            var hash = Derive(password, salt, iterations);

            return Algorithm
                + "$" + iterations.ToString(CultureInfo.InvariantCulture)
                + "$" + Convert.ToBase64String(salt)
                + "$" + Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Reads ADMIN_PASSWORD_HASH. Every way it can be wrong produces a
        /// sentence naming what to do about it, because the operator sees this
        /// once, at three in the morning, when the service will not start.
        /// </summary>
        public static bool TryParse(string encoded, out AdminPassword password, out string problem)
        {
            password = null;
            problem = null;

            if (string.IsNullOrWhiteSpace(encoded))
            {
                problem = "ADMIN_PASSWORD_HASH is empty.";

                return false;
            }

            var parts = encoded.Trim().Split('$');

            if (parts.Length != 4)
            {
                problem = "ADMIN_PASSWORD_HASH is not in the form "
                    + Algorithm + "$<iterations>$<salt>$<hash>. Generate one with `hash-password`.";

                return false;
            }

            if (!string.Equals(parts[0], Algorithm, StringComparison.Ordinal))
            {
                problem = "ADMIN_PASSWORD_HASH names the algorithm '" + parts[0] + "'. The only one this service "
                    + "verifies is " + Algorithm + "; there is no second one to fall back to.";

                return false;
            }

            if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var iterations))
            {
                problem = "ADMIN_PASSWORD_HASH does not name a number of iterations.";

                return false;
            }

            if (iterations < MinimumIterations)
            {
                problem = "ADMIN_PASSWORD_HASH was made with " + iterations.ToString(CultureInfo.InvariantCulture)
                    + " PBKDF2 iterations, and this service will not accept fewer than "
                    + MinimumIterations.ToString(CultureInfo.InvariantCulture)
                    + ". Generate a new one with `hash-password`.";

                return false;
            }

            byte[] salt;
            byte[] hash;

            try
            {
                salt = Convert.FromBase64String(parts[2]);
                hash = Convert.FromBase64String(parts[3]);
            }
            catch (FormatException)
            {
                problem = "ADMIN_PASSWORD_HASH has a salt or a hash that is not base64. If it was pasted through "
                    + "something that wrapped the line, generate a fresh one with `hash-password`.";

                return false;
            }

            if (salt.Length < SaltBytes || hash.Length != HashBytes)
            {
                problem = "ADMIN_PASSWORD_HASH has a salt or a hash that is too short to be one this service made.";

                return false;
            }

            password = new AdminPassword(iterations, salt, hash);

            return true;
        }

        /// <summary>
        /// Derives a verifier from a plaintext password, for the ADMIN_PASSWORD
        /// path. Check <see cref="Weakness"/> first; this does not, because a
        /// caller that skipped the check is a bug rather than a user error.
        /// </summary>
        public static AdminPassword FromPlaintext(string password)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltBytes);

            return new AdminPassword(DefaultIterations, salt, Derive(password, salt, DefaultIterations));
        }

        /// <summary>
        /// Why a plaintext password is not acceptable, or null if it is.
        ///
        /// This is a refusal to start, not a warning. A warning about a weak
        /// password on the door to a signing key is a warning nobody reads, and
        /// the whole point of the door is that it is the only barrier.
        /// </summary>
        public static string Weakness(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return "it is empty";
            }

            if (password.Trim().Length == 0)
            {
                return "it is only whitespace";
            }

            if (password.Length < MinimumLength)
            {
                return "it is " + password.Length.ToString(CultureInfo.InvariantCulture)
                    + " characters and the minimum is " + MinimumLength.ToString(CultureInfo.InvariantCulture)
                    + ". This page can mint licences for any server, forever, and the password is the only thing "
                    + "in front of it";
            }

            var lower = password.Trim().ToLowerInvariant();

            foreach (var obvious in Obvious)
            {
                if (lower.Equals(obvious, StringComparison.Ordinal) || lower.StartsWith(obvious, StringComparison.Ordinal))
                {
                    return "it begins with '" + obvious + "', which is one of the first things anybody tries";
                }
            }

            var first = password[0];
            var same = true;

            foreach (var character in password)
            {
                if (character != first)
                {
                    same = false;

                    break;
                }
            }

            if (same)
            {
                return "it is the same character repeated";
            }

            return null;
        }

        /// <summary>
        /// Not a dictionary - a dictionary check belongs in a password manager,
        /// not in a service. These are the strings that turn up in an example
        /// file, a tutorial, or a hurried first deployment, which is the failure
        /// this catches.
        /// </summary>
        private static readonly string[] Obvious =
        {
            "password",
            "changeme",
            "change-me",
            "letmein",
            "admin",
            "administrator",
            "secret",
            "welcome",
            "qwerty",
            "12345678",
            "emby",
            "licence",
            "license",
            "put-a-long-random-password-here",
        };

        /// <summary>
        /// Whether this is the password. Constant time in the derived bytes, and
        /// it does the same PBKDF2 work whatever the candidate is, so nothing
        /// about the answer is visible in how long it took.
        /// </summary>
        public bool Verify(string candidate)
        {
            if (candidate == null)
            {
                return false;
            }

            var derived = Derive(candidate, _salt, Iterations);

            try
            {
                return CryptographicOperations.FixedTimeEquals(derived, _expected);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derived);
            }
        }

        private static byte[] Derive(string password, byte[] salt, int iterations)
        {
            var bytes = Encoding.UTF8.GetBytes(password);

            try
            {
                return Rfc2898DeriveBytes.Pbkdf2(bytes, salt, iterations, HashAlgorithmName.SHA256, HashBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }
}

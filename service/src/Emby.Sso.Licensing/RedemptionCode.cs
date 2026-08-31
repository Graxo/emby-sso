using System;
using System.Security.Cryptography;
using System.Text;

namespace Emby.Sso.Licensing
{
    /// <summary>
    /// The thing the buyer is sent and types into the plugin.
    ///
    /// A redemption code is a bearer secret that will be guessed at over the
    /// internet by anyone who finds /v1/activate, and it is also a string a
    /// human retypes off an email, possibly having read it down a phone. Those
    /// two facts set everything below.
    /// </summary>
    public static class RedemptionCode
    {
        /// <summary>
        /// Crockford's base32 alphabet: the digits and the capitals, minus I, L,
        /// O and U. I/L/1 and O/0 are the pairs people actually mistype, and are
        /// mapped back on input rather than being present to be confused;
        /// Crockford drops U so that no random draw spells anything the buyer
        /// has to read out loud to your support address.
        /// </summary>
        public const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

        /// <summary>
        /// 30 symbols x 5 bits = 150 bits, comfortably past the 128 the brief
        /// asks for. Every symbol is drawn uniformly (see <see cref="Generate"/>),
        /// so that is 150 bits of real entropy, not 150 bits of alphabet.
        ///
        /// This is the number that actually stops codes being guessed. The rate
        /// limiter bounds what a guesser costs us; it is the entropy here that
        /// makes guessing pointless at any rate.
        /// </summary>
        public const int Symbols = 30;

        /// <summary>Groups of five, hyphen-separated, for the version a human reads.</summary>
        public const int GroupSize = 5;

        /// <summary>
        /// Draws a fresh code. Each symbol is one random byte masked to five
        /// bits: 32 divides 256 exactly, so the mask is uniform and there is no
        /// modulo bias to argue about.
        /// </summary>
        public static string Generate()
        {
            var bytes = RandomNumberGenerator.GetBytes(Symbols);
            var code = new StringBuilder(Symbols);

            for (var i = 0; i < Symbols; i++)
            {
                code.Append(Alphabet[bytes[i] & 0x1F]);
            }

            CryptographicOperations.ZeroMemory(bytes);

            return code.ToString();
        }

        /// <summary>
        /// Turns what the customer typed into the canonical 30 symbols, or fails.
        ///
        /// The contract promises the code is case-insensitive and may be typed
        /// with or without separators, so: whitespace and hyphens and underscores
        /// are dropped wherever they fall, letters are upper-cased, and the three
        /// characters Crockford excludes are mapped to what the reader meant -
        /// I and L to 1, O to zero. Anything else is a code that was not typed
        /// correctly, and the caller answers `malformed_request` rather than
        /// spending a database lookup on it.
        /// </summary>
        public static bool TryNormalise(string input, out string normalised)
        {
            normalised = null;

            if (input == null)
            {
                return false;
            }

            var canonical = new StringBuilder(Symbols);

            foreach (var raw in input)
            {
                if (raw == '-' || raw == '_' || raw == ' ' || raw == '\t' || raw == '\r' || raw == '\n')
                {
                    continue;
                }

                var c = char.ToUpperInvariant(raw);

                switch (c)
                {
                    case 'I':
                    case 'L':
                        c = '1';
                        break;

                    case 'O':
                        c = '0';
                        break;

                    default:
                        break;
                }

                if (Alphabet.IndexOf(c) < 0)
                {
                    return false;
                }

                if (canonical.Length == Symbols)
                {
                    // Too long. Keep counting no further: this is not a code.
                    return false;
                }

                canonical.Append(c);
            }

            if (canonical.Length != Symbols)
            {
                return false;
            }

            normalised = canonical.ToString();

            return true;
        }

        /// <summary>The version that goes in the email: five-symbol groups.</summary>
        public static string Format(string normalised)
        {
            if (normalised == null)
            {
                throw new ArgumentNullException(nameof(normalised));
            }

            var text = new StringBuilder(normalised.Length + (normalised.Length / GroupSize));

            for (var i = 0; i < normalised.Length; i++)
            {
                if (i > 0 && i % GroupSize == 0)
                {
                    text.Append('-');
                }

                text.Append(normalised[i]);
            }

            return text.ToString();
        }

        /// <summary>
        /// What the store holds instead of the code: SHA-256 of the normalised
        /// form, lower-case hex.
        ///
        /// A PLAIN HASH IS THE RIGHT ANSWER HERE, and it is worth writing down
        /// why, because "you should have used argon2" is the reflex. Slow hashes
        /// exist because passwords have perhaps 30 bits of entropy and an
        /// offline attacker can try all of them; the work factor buys the time a
        /// weak secret does not have. A code drawn here has 150 bits. There is
        /// no dictionary, no rainbow table and no amount of GPU that touches
        /// 2^150, so a KDF would buy nothing and cost every activation.
        ///
        /// What the hash IS for: a copy of the database - a backup on a laptop,
        /// a stolen volume, a support dump - must not contain a single usable
        /// code. It does not.
        ///
        /// The lookup is by exact hash against a UNIQUE index, so there is no
        /// comparison here for a timing attack to read.
        /// </summary>
        public static string Hash(string normalised)
        {
            if (string.IsNullOrEmpty(normalised))
            {
                throw new ArgumentException("nothing to hash", nameof(normalised));
            }

            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalised));

            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        /// <summary>
        /// The first few characters of the hash, which is what the logs record
        /// in place of the code. Enough to follow one activation attempt through
        /// a log file and to match it to a row in the store; not enough to be a
        /// credential, and derived from the code rather than being it.
        /// </summary>
        public static string LogTag(string hash)
        {
            if (string.IsNullOrEmpty(hash))
            {
                return "-";
            }

            return hash.Length <= 12 ? hash : hash.Substring(0, 12);
        }
    }
}

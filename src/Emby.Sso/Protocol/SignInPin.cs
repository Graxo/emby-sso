using System.Text;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The shape of a sign-in PIN: what characters it is made of, how long it
    /// is, how it is shown to a person, and how a thing somebody typed on a TV
    /// remote is turned back into the value that was issued.
    ///
    /// WHY A PIN EXISTS AT ALL. Emby's native apps have one sign-in screen - a
    /// username and a password - and a plugin cannot add a second. So the only
    /// way a full browser sign-in (identity provider flows, MFA included) can
    /// reach a TV is for the browser to hand the person something short enough
    /// to retype into that one field. The PIN is that something. It is NOT a
    /// password: it is issued by this server at the end of a completed browser
    /// sign-in, it is bound to one Emby account, it lives minutes, and it is
    /// single use.
    ///
    /// THE ENTROPY, AND WHAT IT IS TRADED AGAINST. <see cref="Length"/> = 8
    /// characters drawn from a <see cref="Alphabet"/> of 30 is
    /// 8 x log2(30) = 39.3 bits, or 6.56 x 10^11 possible PINs.
    ///
    /// The number that actually decides brute-force resistance is not this one
    /// - it is <see cref="SignInPinStore.MaxAttemptsPerPin"/>, which caps the
    /// guesses that can ever be made against one issued PIN at ONE, so a blind
    /// guesser's chance per issuance is 1 in 6.56 x 10^11 whatever rate they
    /// send at. The length is chosen for what survives if a future reader
    /// weakens that cap without understanding it: at 39.3 bits, an attacker
    /// grinding an entirely unlimited 100 guesses a second for the whole
    /// five-minute life of a PIN still gets 3 x 10^4 / 6.56 x 10^11, about one
    /// chance in 22 million, per PIN issued. Six characters would be 29.4 bits
    /// and that same broken-cap case becomes one chance in 24 thousand, which
    /// is a real number. The two extra characters buy a margin that does not
    /// depend on any other part of this design being right.
    ///
    /// What it costs is real too and should not be waved away: eight characters
    /// on a D-pad and an on-screen keyboard is perhaps fifty button presses.
    /// That is the trade, stated plainly - it is still far less typing than the
    /// identity provider app-password token this replaces, which is the honest
    /// comparison because that token is what a TV user has to type today.
    ///
    /// THE ALPHABET. Digits 2-9 and the capital letters except I, L, O and U.
    /// 0/O and 1/I/L are the pairs people misread and mistype, and there is no
    /// point in a mapping that "corrects" them on input: because neither member
    /// of a confusable pair is in the alphabet, a person can never have SEEN
    /// one, so a typed 0 or I is simply a wrong character and is refused like
    /// any other. U is left out on Crockford's grounds - it keeps accidental
    /// obscenities out of a code a user is asked to read aloud to somebody
    /// across the room.
    /// </summary>
    internal static class SignInPin
    {
        /// <summary>
        /// Thirty characters: 2-9, and A-Z without I, L, O or U. Ordered so a
        /// reader can check the exclusions at a glance. Never reorder it for
        /// tidiness - nothing depends on the order, but a diff that changes it
        /// looks like a change to what a PIN can contain.
        /// </summary>
        public const string Alphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ";

        /// <summary>Characters in a PIN. See the class comment for the arithmetic.</summary>
        public const int Length = 8;

        /// <summary>
        /// How the PIN is broken up for display - "ABCD-EFGH". Purely
        /// cosmetic: <see cref="Normalize"/> throws the separator away, so a
        /// person may type it or not.
        /// </summary>
        public const int GroupSize = 4;

        private const char GroupSeparator = '-';

        /// <summary>
        /// A fresh PIN, from the cryptographic generator every other secret in
        /// this plugin comes from. Never <c>System.Random</c>: it is seeded
        /// predictably and its output is reconstructible from a handful of
        /// samples, which for a credential is the whole game.
        /// </summary>
        public static string Create()
        {
            return SecureRandom.CreateCode(Alphabet, Length);
        }

        /// <summary>
        /// The PIN as a person should see it: grouped, so it can be read off a
        /// phone and typed on a remote without losing one's place.
        /// </summary>
        public static string Format(string pin)
        {
            if (string.IsNullOrEmpty(pin))
            {
                return string.Empty;
            }

            var grouped = new StringBuilder(pin.Length + (pin.Length / GroupSize));

            for (var i = 0; i < pin.Length; i++)
            {
                if (i > 0 && i % GroupSize == 0)
                {
                    grouped.Append(GroupSeparator);
                }

                grouped.Append(pin[i]);
            }

            return grouped.ToString();
        }

        /// <summary>
        /// Turns what somebody typed into the exact string that was issued, or
        /// returns null when it cannot possibly be a PIN.
        ///
        /// Null is load-bearing, and it is what tells
        /// <see cref="SignInPinStore"/> not to spend the user's one attempt.
        /// Three credential shapes arrive in Emby's single password field - a
        /// browser handoff secret, a PIN, and a real password for the identity
        /// provider - and a person whose account has a live PIN might well type
        /// their password on the TV instead. If that counted as a failed guess
        /// it would destroy the PIN they were about to use, so only something
        /// that IS a PIN in shape may be charged as an attempt at one.
        ///
        /// Nothing about the answer is ever told to the caller of a sign-in:
        /// whether a value was PIN-shaped changes only which store is asked,
        /// never the refusal, and a value that fails here falls through to the
        /// remaining shapes exactly as it did before PINs existed.
        ///
        /// Case folding is done by hand against ASCII rather than with
        /// <c>ToUpper</c>, because a culture-sensitive uppercase is not the
        /// identity function on every alphabet - the Turkish dotless i is the
        /// famous one - and a comparison that depends on the server's locale is
        /// a comparison that behaves differently on two machines.
        /// </summary>
        public static string Normalize(string candidate)
        {
            if (string.IsNullOrEmpty(candidate))
            {
                return null;
            }

            // Bounded before the loop so a caller cannot make this walk an
            // arbitrarily long password. Anything longer than the separators
            // could possibly justify is not a PIN.
            if (candidate.Length > (Length * 4))
            {
                return null;
            }

            var kept = new char[Length];
            var count = 0;

            foreach (var raw in candidate)
            {
                if (raw == GroupSeparator || raw == ' ' || raw == '\t')
                {
                    // The separators a display format invites people to type.
                    continue;
                }

                var character = (raw >= 'a' && raw <= 'z') ? (char)(raw - 32) : raw;

                if (Alphabet.IndexOf(character) < 0)
                {
                    return null;
                }

                if (count == Length)
                {
                    // Too many PIN characters: not a PIN.
                    return null;
                }

                kept[count++] = character;
            }

            return count == Length ? new string(kept) : null;
        }

        /// <summary>
        /// Whether a value could be a PIN at all. Only ever used to decide
        /// whether an attempt is chargeable - see <see cref="Normalize"/>.
        /// </summary>
        public static bool IsPinShaped(string candidate)
        {
            return Normalize(candidate) != null;
        }
    }
}

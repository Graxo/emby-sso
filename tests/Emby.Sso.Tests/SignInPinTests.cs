using System;
using System.Collections.Generic;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The PIN's shape: what it is made of, what a person may type instead, and
    /// - most load-bearing of all - what is NOT a PIN, because that is what
    /// decides whether an attempt is allowed to destroy somebody's PIN.
    /// </summary>
    public class SignInPinTests
    {
        [Fact]
        public void A_pin_is_eight_characters_from_the_unambiguous_alphabet()
        {
            for (var i = 0; i < 200; i++)
            {
                var pin = SignInPin.Create();

                Assert.Equal(SignInPin.Length, pin.Length);

                foreach (var character in pin)
                {
                    Assert.Contains(character, SignInPin.Alphabet);
                }
            }
        }

        /// <summary>
        /// The exclusions are the whole reason this alphabet is not just
        /// base36: 0/O and 1/I/L are what people misread off a phone and
        /// mistype on a remote.
        /// </summary>
        [Theory]
        [InlineData('0')]
        [InlineData('O')]
        [InlineData('1')]
        [InlineData('I')]
        [InlineData('L')]
        [InlineData('U')]
        public void The_confusable_characters_are_not_in_the_alphabet(char excluded)
        {
            Assert.DoesNotContain(excluded, SignInPin.Alphabet);
        }

        [Fact]
        public void The_alphabet_has_no_repeated_character()
        {
            Assert.Equal(SignInPin.Alphabet.Length, new HashSet<char>(SignInPin.Alphabet).Count);
        }

        /// <summary>
        /// Not a proof of randomness - no test is - but it would catch the two
        /// failures that matter: a generator that returns the same PIN twice,
        /// and one whose output is so narrow that a collision shows up in a
        /// handful of draws.
        /// </summary>
        [Fact]
        public void Two_pins_are_not_the_same()
        {
            var seen = new HashSet<string>();

            for (var i = 0; i < 500; i++)
            {
                Assert.True(seen.Add(SignInPin.Create()), "the generator repeated a PIN");
            }
        }

        [Fact]
        public void A_pin_is_shown_in_groups_of_four()
        {
            Assert.Equal("ABCD-EFGH", SignInPin.Format("ABCDEFGH"));
        }

        [Fact]
        public void The_form_a_person_is_shown_is_accepted_back()
        {
            var pin = SignInPin.Create();

            Assert.Equal(pin, SignInPin.Normalize(SignInPin.Format(pin)));
        }

        [Theory]
        [InlineData("ABCDEFGH")]
        [InlineData("ABCD-EFGH")]
        [InlineData("abcd-efgh")]
        [InlineData("abcdefgh")]
        [InlineData("ABCD EFGH")]
        [InlineData(" ABCDEFGH ")]
        public void Separators_and_case_are_forgiven(string typed)
        {
            Assert.Equal("ABCDEFGH", SignInPin.Normalize(typed));
        }

        /// <summary>
        /// The one that matters most. Anything that is not PIN-shaped must
        /// answer null, because <see cref="SignInPinStore"/> uses that answer to
        /// decide NOT to spend a user's PIN - and a user's own password arriving
        /// in the same field is the ordinary case, not the exotic one.
        /// </summary>
        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("ABCDEFG")]           // too short
        [InlineData("ABCDEFGHJ")]         // too long
        [InlineData("ABCD0FGH")]          // a character the alphabet excludes
        [InlineData("ABCDIFGH")]
        [InlineData("correct horse battery staple")]
        [InlineData("ABCD_EFGH")]         // not a separator this accepts
        [InlineData("ABCD-EFG")]
        public void Anything_that_is_not_a_pin_is_refused(string typed)
        {
            Assert.Null(SignInPin.Normalize(typed));
            Assert.False(SignInPin.IsPinShaped(typed));
        }

        /// <summary>
        /// A base64url handoff secret is 43 characters and must never be read
        /// as a PIN: the two shapes share one password field and confusing them
        /// would mean a handoff attempt could spend somebody's PIN.
        /// </summary>
        [Fact]
        public void A_handoff_secret_is_not_pin_shaped()
        {
            for (var i = 0; i < 50; i++)
            {
                Assert.False(SignInPin.IsPinShaped(SecureRandom.CreateToken(32)));
            }
        }

        /// <summary>
        /// The length guard in Normalize: a caller must not be able to make it
        /// walk an arbitrarily long password looking for PIN characters.
        /// </summary>
        [Fact]
        public void A_very_long_value_is_refused_without_being_walked()
        {
            Assert.Null(SignInPin.Normalize(new string('A', 100000)));
        }

        /// <summary>
        /// Uniformity, to the extent a test can see it. A biased generator -
        /// the <c>byte % 30</c> one this deliberately avoids - would still pass
        /// this, but a generator that could not produce part of its alphabet at
        /// all would not, and that is the failure that would silently cost real
        /// entropy.
        /// </summary>
        [Fact]
        public void Every_character_of_the_alphabet_is_reachable()
        {
            var seen = new HashSet<char>();

            for (var i = 0; i < 2000; i++)
            {
                foreach (var character in SignInPin.Create())
                {
                    seen.Add(character);
                }
            }

            Assert.Equal(SignInPin.Alphabet.Length, seen.Count);
        }

        [Fact]
        public void The_code_generator_refuses_an_alphabet_it_cannot_draw_from_without_bias()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.CreateCode("A", 8));
            Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.CreateCode(null, 8));
            Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.CreateCode(SignInPin.Alphabet, 0));
        }

        /// <summary>
        /// An alphabet whose size divides 256 exercises the other side of the
        /// rejection arithmetic, where nothing is ever rejected.
        /// </summary>
        [Fact]
        public void An_alphabet_that_divides_evenly_still_produces_the_right_length()
        {
            var code = SecureRandom.CreateCode("ABCDEFGHJKMNPQRS", 12);

            Assert.Equal(12, code.Length);
        }
    }
}

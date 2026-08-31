using System;
using System.Collections.Generic;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    public class RedemptionCodeTests
    {
        [Fact]
        public void A_code_carries_at_least_the_128_bits_the_brief_asks_for()
        {
            var code = RedemptionCode.Generate();

            Assert.Equal(RedemptionCode.Symbols, code.Length);

            // 30 symbols drawn uniformly from a 32-symbol alphabet is 150 bits.
            // This is the assertion that fails if somebody shortens the code to
            // make it friendlier to type.
            var bits = RedemptionCode.Symbols * Math.Log2(RedemptionCode.Alphabet.Length);

            Assert.True(bits >= 128, "a redemption code must carry at least 128 bits, this one carries " + bits);
        }

        [Fact]
        public void Codes_only_use_the_alphabet_and_are_not_repeated()
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);

            for (var i = 0; i < 500; i++)
            {
                var code = RedemptionCode.Generate();

                foreach (var c in code)
                {
                    Assert.Contains(c, RedemptionCode.Alphabet);
                }

                Assert.True(seen.Add(code), "the generator repeated itself, which it cannot do by chance");
            }
        }

        [Fact]
        public void The_alphabet_excludes_the_characters_people_mistype()
        {
            Assert.DoesNotContain('I', RedemptionCode.Alphabet);
            Assert.DoesNotContain('L', RedemptionCode.Alphabet);
            Assert.DoesNotContain('O', RedemptionCode.Alphabet);
            Assert.DoesNotContain('U', RedemptionCode.Alphabet);
        }

        [Fact]
        public void The_contract_promises_case_insensitive_and_separator_insensitive()
        {
            var code = RedemptionCode.Generate();
            var formatted = RedemptionCode.Format(code);

            Assert.True(RedemptionCode.TryNormalise(formatted, out var fromFormatted));
            Assert.Equal(code, fromFormatted);

            Assert.True(RedemptionCode.TryNormalise(formatted.ToLowerInvariant(), out var fromLower));
            Assert.Equal(code, fromLower);

            Assert.True(RedemptionCode.TryNormalise("  " + formatted.Replace("-", " ") + "\n", out var fromSpaced));
            Assert.Equal(code, fromSpaced);

            Assert.True(RedemptionCode.TryNormalise(code, out var fromBare));
            Assert.Equal(code, fromBare);
        }

        [Theory]
        [InlineData('I', '1')]
        [InlineData('i', '1')]
        [InlineData('L', '1')]
        [InlineData('l', '1')]
        [InlineData('O', '0')]
        [InlineData('o', '0')]
        public void The_three_characters_the_alphabet_drops_are_read_as_what_was_meant(char typed, char meant)
        {
            var code = new string('2', RedemptionCode.Symbols - 1) + meant;
            var mistyped = new string('2', RedemptionCode.Symbols - 1) + typed;

            Assert.True(RedemptionCode.TryNormalise(mistyped, out var normalised));
            Assert.Equal(code, normalised);
        }

        [Theory]
        [InlineData("")]
        [InlineData("ABC")]
        [InlineData("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")]
        public void Anything_that_is_not_a_code_is_refused_rather_than_looked_up(string input)
        {
            Assert.False(RedemptionCode.TryNormalise(input, out var normalised));
            Assert.Null(normalised);
        }

        [Fact]
        public void A_code_with_one_symbol_too_many_is_refused()
        {
            var tooLong = RedemptionCode.Generate() + "2";

            Assert.False(RedemptionCode.TryNormalise(tooLong, out _));
        }

        [Fact]
        public void A_code_containing_U_is_refused_rather_than_guessed_at()
        {
            var withU = new string('2', RedemptionCode.Symbols - 1) + "U";

            Assert.False(RedemptionCode.TryNormalise(withU, out _));
        }

        [Fact]
        public void The_hash_is_stable_over_every_way_the_same_code_can_be_typed()
        {
            var code = RedemptionCode.Generate();
            var expected = RedemptionCode.Hash(code);

            Assert.True(RedemptionCode.TryNormalise(RedemptionCode.Format(code).ToLowerInvariant(), out var retyped));
            Assert.Equal(expected, RedemptionCode.Hash(retyped));
        }

        [Fact]
        public void The_hash_does_not_contain_the_code()
        {
            var code = RedemptionCode.Generate();
            var hash = RedemptionCode.Hash(code);

            Assert.Equal(64, hash.Length);
            Assert.DoesNotContain(code, hash, StringComparison.OrdinalIgnoreCase);
            Assert.NotEqual(hash, RedemptionCode.Hash(RedemptionCode.Generate()));
        }

        [Fact]
        public void The_log_tag_is_short_and_is_not_the_code()
        {
            var code = RedemptionCode.Generate();
            var tag = RedemptionCode.LogTag(RedemptionCode.Hash(code));

            Assert.Equal(12, tag.Length);
            Assert.DoesNotContain(tag, code, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void The_formatted_code_groups_into_fives()
        {
            var code = RedemptionCode.Generate();
            var formatted = RedemptionCode.Format(code);

            Assert.Equal(RedemptionCode.Symbols / RedemptionCode.GroupSize, formatted.Split('-').Length);

            foreach (var group in formatted.Split('-'))
            {
                Assert.Equal(RedemptionCode.GroupSize, group.Length);
            }
        }
    }
}

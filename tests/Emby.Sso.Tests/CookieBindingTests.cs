using System.Collections.Generic;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class CookieBindingTests
    {
        private const string CookieName = "emby_sso_binding";

        public class ExtractCookieValuesTests
        {
            [Fact]
            public void No_cookie_header_at_all_yields_nothing()
            {
                var result = CookieBinding.ExtractCookieValues(null, CookieName);

                Assert.Empty(result);
            }

            [Fact]
            public void An_empty_header_list_yields_nothing()
            {
                var result = CookieBinding.ExtractCookieValues(new List<string>(), CookieName);

                Assert.Empty(result);
            }

            [Fact]
            public void A_header_present_but_the_name_absent_yields_nothing()
            {
                var result = CookieBinding.ExtractCookieValues(new[] { "other=1; another=2" }, CookieName);

                Assert.Empty(result);
            }

            [Fact]
            public void The_name_present_among_several_cookies_is_found()
            {
                var result = CookieBinding.ExtractCookieValues(
                    new[] { "a=1; " + CookieName + "=abc123; b=2" }, CookieName);

                Assert.Equal(new[] { "abc123" }, result);
            }

            [Fact]
            public void The_same_name_repeated_yields_every_value()
            {
                // A browser may send several cookies of the same name when their
                // paths differ.
                var result = CookieBinding.ExtractCookieValues(
                    new[] { CookieName + "=first; " + CookieName + "=second" }, CookieName);

                Assert.Equal(new[] { "first", "second" }, result);
            }

            [Fact]
            public void A_repeated_name_where_only_one_value_matches_still_extracts_both_candidates()
            {
                var presented = CookieBinding.ExtractCookieValues(
                    new[] { CookieName + "=wrong; " + CookieName + "=right" }, CookieName);

                Assert.Equal(new[] { "wrong", "right" }, presented);
                Assert.True(CookieBinding.BindingMatches("right", presented));
            }

            [Fact]
            public void A_value_containing_an_equals_sign_is_captured_whole()
            {
                var result = CookieBinding.ExtractCookieValues(
                    new[] { CookieName + "=abc=def" }, CookieName);

                Assert.Equal(new[] { "abc=def" }, result);
            }

            [Fact]
            public void Whitespace_around_a_cookie_pair_is_trimmed()
            {
                var result = CookieBinding.ExtractCookieValues(
                    new[] { "  " + CookieName + "=abc123  ; other=1" }, CookieName);

                Assert.Equal(new[] { "abc123" }, result);
            }

            [Fact]
            public void Multiple_cookie_headers_are_all_searched()
            {
                var result = CookieBinding.ExtractCookieValues(
                    new[] { "other=1", CookieName + "=abc123" }, CookieName);

                Assert.Equal(new[] { "abc123" }, result);
            }

            [Fact]
            public void A_null_or_empty_header_value_in_the_list_is_skipped_without_error()
            {
                var result = CookieBinding.ExtractCookieValues(
                    new[] { null, string.Empty, CookieName + "=abc123" }, CookieName);

                Assert.Equal(new[] { "abc123" }, result);
            }
        }

        public class BindingMatchesTests
        {
            [Fact]
            public void A_matching_value_among_several_presented_matches()
            {
                Assert.True(CookieBinding.BindingMatches("expected", new[] { "other", "expected" }));
            }

            [Fact]
            public void A_non_matching_value_does_not_match()
            {
                Assert.False(CookieBinding.BindingMatches("expected", new[] { "not-it" }));
            }

            [Fact]
            public void No_presented_values_does_not_match()
            {
                Assert.False(CookieBinding.BindingMatches("expected", new string[0]));
            }

            [Fact]
            public void A_null_presented_list_does_not_match()
            {
                Assert.False(CookieBinding.BindingMatches("expected", null));
            }

            [Fact]
            public void An_empty_expected_value_never_matches_even_an_empty_presented_value()
            {
                Assert.False(CookieBinding.BindingMatches(string.Empty, new[] { string.Empty }));
                Assert.False(CookieBinding.BindingMatches(null, new[] { "anything" }));
            }
        }
    }
}

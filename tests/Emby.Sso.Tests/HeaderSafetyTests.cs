using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class HeaderSafetyTests
    {
        public class IsPathSafeTests
        {
            [Theory]
            [InlineData("/emby/Sso")]
            [InlineData("/a-b_c.d~e%20")]
            [InlineData("/")]
            [InlineData("")]
            public void Safe_paths_are_accepted(string path)
            {
                Assert.True(HeaderSafety.IsPathSafe(path));
            }

            [Theory]
            [InlineData("/emby\r\nSet-Cookie: evil=1")]
            [InlineData("/emby\nSet-Cookie: evil=1")]
            [InlineData("/emby;Domain=evil.test")]
            [InlineData("/emby path")]
            [InlineData("/emby\"quote")]
            public void Unsafe_characters_are_rejected(string path)
            {
                Assert.False(HeaderSafety.IsPathSafe(path));
            }

            [Fact]
            public void A_null_path_is_rejected()
            {
                Assert.False(HeaderSafety.IsPathSafe(null));
            }
        }

        public class IsCookieValueSafeTests
        {
            [Theory]
            [InlineData("abcXYZ0123-_")]
            public void Alphanumeric_dash_and_underscore_are_accepted(string value)
            {
                Assert.True(HeaderSafety.IsCookieValueSafe(value));
            }

            [Theory]
            [InlineData("abc def")]
            [InlineData("abc;def")]
            [InlineData("abc\r\ndef")]
            [InlineData("abc=def")]
            public void Anything_else_is_rejected(string value)
            {
                Assert.False(HeaderSafety.IsCookieValueSafe(value));
            }

            [Fact]
            public void Null_and_empty_are_rejected()
            {
                Assert.False(HeaderSafety.IsCookieValueSafe(null));
                Assert.False(HeaderSafety.IsCookieValueSafe(string.Empty));
            }
        }

        public class SanitizeBaseUrlTests
        {
            [Theory]
            [InlineData("https://emby.example.com", "https://emby.example.com")]
            [InlineData("https://emby.example.com/", "https://emby.example.com")]
            [InlineData("  https://emby.example.com  ", "https://emby.example.com")]
            [InlineData("http://emby.example.com", "http://emby.example.com")]
            public void Acceptable_urls_are_trimmed_and_returned(string input, string expected)
            {
                Assert.Equal(expected, HeaderSafety.SanitizeBaseUrl(input));
            }

            [Theory]
            [InlineData(null)]
            [InlineData("")]
            [InlineData("   ")]
            [InlineData("javascript:alert(1)")]
            [InlineData("ftp://emby.example.com")]
            [InlineData("not a url")]
            public void Unacceptable_values_yield_an_empty_string(string input)
            {
                Assert.Equal(string.Empty, HeaderSafety.SanitizeBaseUrl(input));
            }
        }
    }
}

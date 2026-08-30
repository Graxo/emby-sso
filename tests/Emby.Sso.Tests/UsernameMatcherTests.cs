using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class UsernameMatcherTests
    {
        [Theory]
        [InlineData("alice", "alice")]
        [InlineData("Alice", "alice")]
        [InlineData("alice", "ALICE")]
        [InlineData("  alice  ", "alice")]
        public void Equivalent_names_match(string claim, string emby)
        {
            Assert.True(UsernameMatcher.Matches(claim, emby));
        }

        [Theory]
        [InlineData("alice", "bob")]
        [InlineData("alice", "alice2")]
        [InlineData("alicia", "alice")]
        [InlineData(null, "alice")]
        [InlineData("alice", null)]
        [InlineData("", "alice")]
        [InlineData("   ", "alice")]
        public void Different_or_missing_names_do_not_match(string claim, string emby)
        {
            Assert.False(UsernameMatcher.Matches(claim, emby));
        }
    }
}

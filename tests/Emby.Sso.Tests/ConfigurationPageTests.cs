using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The configuration page's markup and its script, checked against each
    /// other.
    ///
    /// WHY THIS EXISTS. These two files are embedded resources shipped to a
    /// browser; nothing compiles them, so every mistake in them is found by an
    /// operator rather than by the build. The failure mode is always the same
    /// and always silent: the script reaches for an element that is not there,
    /// gets null, and either throws in a place nobody is looking or quietly
    /// does nothing. A button that does nothing when pressed is exactly what
    /// that looks like from the outside.
    ///
    /// So: every id the script asks for must exist in the page, and the
    /// controls that lead somewhere must be the kind of control that can.
    /// </summary>
    public sealed class ConfigurationPageTests
    {
        private static readonly string Html = Resource("configPage.html");
        private static readonly string Script = Resource("configPage.js");

        [Fact]
        public void Every_id_the_script_reaches_for_exists_in_the_page()
        {
            var missing = new List<string>();

            foreach (Match match in Regex.Matches(Script, @"querySelector\('#([A-Za-z0-9_-]+)'\)"))
            {
                var id = match.Groups[1].Value;

                if (!Html.Contains("id=\"" + id + "\"", StringComparison.Ordinal))
                {
                    missing.Add(id);
                }
            }

            Assert.Empty(missing);
        }

        /// <summary>
        /// The regression this file was written for. The buy control was a
        /// button whose click handler called window.open, which a browser
        /// treats as a popup and blocks without saying so - the operator
        /// presses it and nothing at all happens.
        ///
        /// An anchor cannot be blocked that way, so the rule is: no script-
        /// opened windows on this page. Anything that leaves for another site
        /// is a link.
        /// </summary>
        [Fact]
        public void Nothing_on_the_page_opens_a_window_from_script()
        {
            Assert.DoesNotContain("window.open", Script, StringComparison.Ordinal);
        }

        [Fact]
        public void The_buy_control_is_a_link_that_cannot_reach_back_into_the_dashboard()
        {
            var anchor = Regex.Match(Html, @"<a\b[^>]*id=""buyButton""[^>]*>", RegexOptions.Singleline);

            Assert.True(anchor.Success, "the buy control must be an anchor, not a button");
            Assert.Contains("target=\"_blank\"", anchor.Value, StringComparison.Ordinal);
            Assert.Contains("noopener", anchor.Value, StringComparison.Ordinal);
            Assert.Contains("noreferrer", anchor.Value, StringComparison.Ordinal);
        }

        /// <summary>
        /// Save reads the licence out of a hidden input rather than the visible
        /// disabled one, because a disabled input is not submitted and reading
        /// it would blank the licence of anybody who pressed Save. Losing that
        /// field is a one-character edit and an expensive mistake.
        /// </summary>
        [Fact]
        public void The_licence_is_carried_by_a_field_that_is_actually_submitted()
        {
            Assert.Contains("<input type=\"hidden\" id=\"licenceKey\" />", Html, StringComparison.Ordinal);
        }

        private static string Resource(string name)
        {
            // The plugin assembly itself cannot be referenced here - it builds
            // against Emby's reference assemblies - so the two files are
            // embedded into this test assembly straight from src/ by the
            // project file. Same bytes, different container.
            using var stream = typeof(ConfigurationPageTests).Assembly.GetManifestResourceStream(name)
                ?? throw new InvalidOperationException(
                    "no embedded resource " + name + " - check the EmbeddedResource items in the test project");

            using var reader = new StreamReader(stream);

            return reader.ReadToEnd();
        }
    }
}

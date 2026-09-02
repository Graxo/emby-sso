using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The drift detector between this service and tools/Emby.Sso.LicenceTool.
    ///
    /// The brief said to share the tool's signing logic and ledger format rather
    /// than write a second subtly different one. The sharing is half done: the
    /// tool references Emby.Sso.Licensing for the file formats and the signing
    /// key loader, but it still declares its own copies of the issuer, the
    /// algorithm and the ledger field names rather than reading them from here.
    /// So two copies of those constants exist, and these tests are what stops
    /// them drifting until the duplicates are deleted.
    ///
    /// They read the tool's SOURCE. That is unusual and it is deliberate: the
    /// tool is an executable with an internal Program class and no seam to call,
    /// so the only thing available to assert against is the text. A test that
    /// fails when somebody edits a constant in the tool is worth more than no
    /// test at all, and the failure message says exactly what to do.
    ///
    /// THE TOOL IS NOT IN THE PUBLIC REPOSITORY, so in CI there is nothing to
    /// read and the source-reading tests SKIP rather than fail. Skipped is the
    /// honest state: the guard is not running, the run says so out loud with a
    /// reason, and nobody is told the tool has been checked when it has not.
    /// Everything that can be asserted without the tool - that this library's
    /// own constants are the values the tool copies, and that a ledger line
    /// round-trips - still runs everywhere.
    ///
    /// The consequence is that drift is only caught where the tool actually
    /// lives. Run this suite in that checkout before issuing licences with a
    /// changed tool.
    /// </summary>
    public class LicenceToolCompatibilityTests
    {
        [ToolPresentTheory]
        [InlineData("private const string Issuer = \"urn:emby-sso:licence\";")]
        [InlineData("private const string Algorithm = SecurityAlgorithms.RsaSha256;")]
        [InlineData("private const string PrivateKeyFileName = \"licence-signing-key.private.json\";")]
        public void The_tool_still_declares_the_constants_this_library_copies(string declaration)
        {
            Assert.Contains(declaration, ToolSource(), StringComparison.Ordinal);
        }

        /// <summary>
        /// The half of that check which needs no tool. These four values are
        /// what every licence this service issues carries, so a change to one
        /// of them is a change to the format whether or not the tool is here to
        /// be compared against.
        /// </summary>
        [Fact]
        public void This_librarys_constants_are_the_ones_the_format_is_defined_by()
        {
            Assert.Equal("urn:emby-sso:licence", LicenceFormat.Issuer);
            Assert.Equal("licence-signing-key.private.json", LicenceFormat.PrivateKeyFileName);
            Assert.Equal("licences-issued.jsonl", LicenceFormat.LedgerFileName);
            Assert.Equal("RS256", LicenceFormat.Algorithm);
        }

        [ToolPresentFact]
        public void The_constants_in_this_library_are_the_tools_constants()
        {
            var source = ToolSource();

            Assert.Contains("\"" + LicenceFormat.Issuer + "\"", source, StringComparison.Ordinal);
            Assert.Contains("\"" + LicenceFormat.PrivateKeyFileName + "\"", source, StringComparison.Ordinal);
            Assert.Contains("\"" + LicenceFormat.LedgerFileName + "\"", source, StringComparison.Ordinal);
        }

        [ToolPresentTheory]
        [InlineData("[\"iss\"] = Issuer,")]
        [InlineData("[\"sub\"] = licensee,")]
        [InlineData("[\"aud\"] = serverId,")]
        public void The_tool_still_mints_the_same_claims(string claim)
        {
            Assert.Contains(claim, ToolSource(), StringComparison.Ordinal);
        }

        [ToolPresentTheory]
        [InlineData("issued_at")]
        [InlineData("expires_at")]
        [InlineData("days")]
        [InlineData("licensee")]
        [InlineData("server_id")]
        [InlineData("fingerprint")]
        public void The_tool_still_writes_and_reads_the_ledger_fields_this_service_writes(string field)
        {
            Assert.Contains("\"" + field + "\"", ToolSource(), StringComparison.Ordinal);
        }

        /// <summary>
        /// A line this service appends must survive the tool's reader, which is
        /// stricter than JSON: it wants five named fields and it parses the two
        /// timestamps with ParseExact on one format. This test is that reader,
        /// copied from Program.ReadLedger.
        /// </summary>
        [Fact]
        public void A_ledger_line_this_service_writes_parses_under_the_tools_reader()
        {
            var directory = TestKeys.TempDirectory();

            try
            {
                var path = Path.Combine(directory, LicenceFormat.LedgerFileName);
                var ledger = new LicenceLedger(path);
                var issuer = new LicenceIssuer(SigningKeyFile.Load(TestKeys.WritePrivateKey(directory)).Key);
                var now = DateTimeOffset.UtcNow;

                var licence = issuer.Issue("code:abcdef123456", "c5bc6e91458540caa295c4efdda1a58a", now, now.AddDays(365));

                Assert.True(ledger.TryAppend(new LedgerRecord(licence), out var error), error);

                var line = Assert.Single(File.ReadAllLines(path));

                using var document = JsonDocument.Parse(line);

                var root = document.RootElement;

                Assert.Equal(licence.Licensee, Text(root, "licensee"));
                Assert.Equal(licence.ServerId, Text(root, "server_id"));
                Assert.Equal(licence.Fingerprint, Text(root, "fingerprint"));
                Assert.Equal(365, root.GetProperty("days").GetInt32());

                // ParseExact, exactly as the tool does it. A trailing offset, a
                // fractional second or a space instead of the T would all pass
                // JsonDocument and fail here - which is the point.
                Assert.Equal(licence.IssuedAt.UtcDateTime.AddTicks(-(licence.IssuedAt.UtcDateTime.Ticks % TimeSpan.TicksPerSecond)),
                    ParseAsTheToolDoes(Text(root, "issued_at")).UtcDateTime);

                Assert.Equal(licence.ExpiresAt.UtcDateTime.AddTicks(-(licence.ExpiresAt.UtcDateTime.Ticks % TimeSpan.TicksPerSecond)),
                    ParseAsTheToolDoes(Text(root, "expires_at")).UtcDateTime);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void The_ledger_is_written_owner_only()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            var directory = TestKeys.TempDirectory();

            try
            {
                var path = Path.Combine(directory, LicenceFormat.LedgerFileName);
                var ledger = new LicenceLedger(path);
                var issuer = new LicenceIssuer(SigningKeyFile.Load(TestKeys.WritePrivateKey(directory)).Key);
                var now = DateTimeOffset.UtcNow;

                Assert.True(ledger.TryAppend(
                    new LedgerRecord(issuer.Issue("code:abcdef123456", "server", now, now.AddDays(1))),
                    out _));

                var mode = File.GetUnixFileMode(path);

                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void A_ledger_that_cannot_be_written_reports_rather_than_throws()
        {
            // The activation has already been committed by the time the ledger is
            // appended to; throwing here would fail a licence the customer has
            // paid for because a log file is wrong.
            var ledger = new LicenceLedger(Path.Combine(TestKeys.TempDirectory(), "a-file", LicenceFormat.LedgerFileName));
            var directory = TestKeys.TempDirectory();

            try
            {
                var issuer = new LicenceIssuer(SigningKeyFile.Load(TestKeys.WritePrivateKey(directory)).Key);
                var now = DateTimeOffset.UtcNow;
                var record = new LedgerRecord(issuer.Issue("code:abcdef123456", "server", now, now.AddDays(1)));

                File.WriteAllText(Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(ledger.Path)), "a-file"), "not a directory");

                Assert.False(ledger.TryAppend(record, out var error));
                Assert.False(string.IsNullOrEmpty(error));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        private static DateTimeOffset ParseAsTheToolDoes(string value)
        {
            return DateTimeOffset.ParseExact(
                value,
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        }

        private static string Text(JsonElement root, string name)
        {
            Assert.True(root.TryGetProperty(name, out var value), "the ledger line has no '" + name + "'");
            Assert.Equal(JsonValueKind.String, value.ValueKind);

            return value.GetString();
        }

        private static string ToolSource()
        {
            return File.ReadAllText(ToolProgram());
        }

        /// <summary>
        /// The tool's Program.cs, or null when this checkout does not have the
        /// tool - which is every checkout of the public repository.
        /// </summary>
        internal static string ToolProgram()
        {
            for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
            {
                var candidate = Path.Combine(directory.FullName, "tools", "Emby.Sso.LicenceTool", "Program.cs");

                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return null;
        }
    }

    /// <summary>
    /// A theory that runs only where the licence tool is checked out.
    ///
    /// Setting Skip in the constructor is how xUnit expresses a condition it
    /// can evaluate before the run. The reason is spelled out because a skipped
    /// test with no explanation is indistinguishable from a test somebody
    /// disabled to get a green pipeline.
    /// </summary>
    public sealed class ToolPresentTheoryAttribute : TheoryAttribute
    {
        public ToolPresentTheoryAttribute()
        {
            Skip = ToolPresence.Reason;
        }
    }

    /// <summary>The same thing for a single fact.</summary>
    public sealed class ToolPresentFactAttribute : FactAttribute
    {
        public ToolPresentFactAttribute()
        {
            Skip = ToolPresence.Reason;
        }
    }

    internal static class ToolPresence
    {
        /// <summary>Null when the tool is here, which is what xUnit reads as "do not skip".</summary>
        public static string Reason =>
            LicenceToolCompatibilityTests.ToolProgram() == null
                ? "tools/Emby.Sso.LicenceTool is not in this checkout - it is not published. "
                  + "Run this suite where the tool lives to check it for drift."
                : null;
    }
}

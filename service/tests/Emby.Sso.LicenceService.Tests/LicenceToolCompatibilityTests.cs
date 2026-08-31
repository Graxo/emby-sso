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
    /// than write a second subtly different one. The sharing is only half done:
    /// Emby.Sso.Licensing IS that shared code, but the tool has not been changed
    /// to reference it, because the task that wrote this directory was forbidden
    /// from touching tools/. So today there really are two copies, and these
    /// tests are what stops them drifting until the tool is pointed at this
    /// library - a one-line ProjectReference and a deletion.
    ///
    /// They read the tool's SOURCE. That is unusual and it is deliberate: the
    /// tool is an executable with an internal Program class and no seam to call,
    /// so the only thing available to assert against is the text. A test that
    /// fails when somebody edits a constant in the tool is worth more than no
    /// test at all, and the failure message says exactly what to do.
    /// </summary>
    public class LicenceToolCompatibilityTests
    {
        [Theory]
        [InlineData("private const string Issuer = \"urn:emby-sso:licence\";")]
        [InlineData("private const string Algorithm = SecurityAlgorithms.RsaSha256;")]
        [InlineData("private const string PrivateKeyFileName = \"licence-signing-key.private.json\";")]
        public void The_tool_still_declares_the_constants_this_library_copies(string declaration)
        {
            Assert.Contains(declaration, ToolSource(), StringComparison.Ordinal);
        }

        [Fact]
        public void The_constants_in_this_library_are_the_tools_constants()
        {
            var source = ToolSource();

            Assert.Contains("\"" + LicenceFormat.Issuer + "\"", source, StringComparison.Ordinal);
            Assert.Contains("\"" + LicenceFormat.PrivateKeyFileName + "\"", source, StringComparison.Ordinal);
            Assert.Contains("\"" + LicenceFormat.LedgerFileName + "\"", source, StringComparison.Ordinal);
            Assert.Equal("RS256", LicenceFormat.Algorithm);
        }

        [Theory]
        [InlineData("[\"iss\"] = Issuer,")]
        [InlineData("[\"sub\"] = licensee,")]
        [InlineData("[\"aud\"] = serverId,")]
        public void The_tool_still_mints_the_same_claims(string claim)
        {
            Assert.Contains(claim, ToolSource(), StringComparison.Ordinal);
        }

        [Theory]
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
            var path = Path.Combine(RepositoryRoot(), "tools", "Emby.Sso.LicenceTool", "Program.cs");

            Assert.True(
                File.Exists(path),
                "tools/Emby.Sso.LicenceTool/Program.cs was not found at " + path
                + ". If the tool has moved, this test and service/src/Emby.Sso.Licensing move with it.");

            return File.ReadAllText(path);
        }

        private static string RepositoryRoot()
        {
            for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
            {
                if (Directory.Exists(Path.Combine(directory.FullName, "tools", "Emby.Sso.LicenceTool")))
                {
                    return directory.FullName;
                }
            }

            throw new DirectoryNotFoundException(
                "walked up from " + AppContext.BaseDirectory + " without finding tools/Emby.Sso.LicenceTool");
        }
    }
}

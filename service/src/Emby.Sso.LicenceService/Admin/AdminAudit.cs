using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Emby.Sso.Licensing;
using Microsoft.Extensions.Logging;

namespace Emby.Sso.LicenceService.Admin
{
    /// <summary>
    /// What happened at /admin, in a file that survives the log.
    ///
    /// WHY A FILE AND NOT ONLY THE LOG. When a customer disputes a refund the
    /// question is "when was this voided, and from where", and it gets asked
    /// months later. Container logs rotate, get truncated by a restart policy,
    /// and are the first thing lost when a box is rebuilt. This is a JSONL file
    /// on the same mounted volume as the store it is an account of, so the
    /// backup that saves the customer list saves the record of what was done to
    /// it. It is ALSO logged, so an operator watching `docker logs` sees a
    /// login the moment it happens.
    ///
    /// WHAT IS NEVER IN IT:
    ///
    ///   * a redemption code. Not on an issue, not on a reveal, not in a free
    ///     text field somebody passes in. <see cref="Scrub"/> is a second line
    ///     of defence over the callers' first: anything shaped like a code is
    ///     replaced before the line is written, so a future caller that gets it
    ///     wrong produces a redacted line rather than a credential on disk.
    ///   * the password, or any part of one. Nothing here is ever handed the
    ///     submitted password - the caller records the OUTCOME.
    ///   * the session id. A short fingerprint of it goes in instead, so two
    ///     lines can be tied to the same session without the file holding
    ///     something that would authorise a request if it leaked.
    ///
    /// A write that fails must not stop the operator working - a full disk is
    /// not a reason to refuse a refund - so a failure is logged loudly and the
    /// action continues. The log line is then the surviving record, which is why
    /// there are two sinks and not one.
    /// </summary>
    public sealed class AdminAudit
    {
        public const string LoggedIn = "login";
        public const string LoginFailed = "login_failed";
        public const string LoginThrottled = "login_throttled";
        public const string LoggedOut = "logout";
        public const string CsrfRefused = "csrf_refused";
        public const string Voided = "void";
        public const string Issued = "issue";
        public const string Revealed = "outbox_reveal";
        public const string SessionMoved = "session_client_changed";

        /// <summary>
        /// The list of everyone waiting for a licence left the machine. Server
        /// ids and all: worth a line, even though it holds no credential.
        /// </summary>
        public const string SigningDownloaded = "signing_download";

        /// <summary>Signed licences came back in, and what was stored or refused.</summary>
        public const string SigningUploaded = "signing_upload";

        /// <summary>
        /// An encrypted copy of the entire store was downloaded. The single most
        /// sensitive act available on this page.
        /// </summary>
        public const string BackupTaken = "backup";

        /// <summary>
        /// A plugin release was published. The only act on this page that makes
        /// code run on somebody else's machine, so it is recorded whether it
        /// succeeded or was refused.
        /// </summary>
        public const string ReleasePublished = "release_published";

        /// <summary>
        /// A redemption code, in either shape it is ever written: thirty
        /// symbols, or six hyphenated groups of five. The alphabet is Crockford
        /// base32 as <see cref="RedemptionCode.Alphabet"/> defines it - no I, L,
        /// O or U - and the word boundaries stop this matching inside a longer
        /// hexadecimal string such as a hash.
        /// </summary>
        private static readonly Regex CodeShaped = new Regex(
            @"\b[0-9A-HJKMNP-TV-Z]{5}(?:-[0-9A-HJKMNP-TV-Z]{5}){5}\b|\b[0-9A-HJKMNP-TV-Z]{30}\b",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);

        private readonly object _gate = new object();
        private readonly ILogger _log;

        public AdminAudit(string path, ILogger log)
        {
            Path = string.IsNullOrWhiteSpace(path) ? null : System.IO.Path.GetFullPath(path);
            _log = log;
        }

        /// <summary>Where the trail is written, or null if it is only being logged.</summary>
        public string Path { get; }

        /// <summary>
        /// Records one thing that happened. <paramref name="detail"/> is free
        /// text - a void reason, a licensee's name - so it is attacker-influenced
        /// and is scrubbed and JSON-encoded, never concatenated into a line.
        /// </summary>
        public void Record(string what, string clientKey, AdminSession session, string detail = null, string tag = null)
        {
            Record(what, clientKey, session == null ? null : Fingerprint(session.Id), detail, tag);
        }

        public void Record(string what, string clientKey, string sessionFingerprint, string detail, string tag)
        {
            // The wall clock, deliberately, and not an injected TimeProvider.
            // Everything else here takes a clock so that a test can move it; an
            // account of what somebody did is the one thing whose timestamps
            // must not be movable by the code being audited.
            var when = DateTimeOffset.UtcNow;

            var fields = new Dictionary<string, object>
            {
                ["utc"] = LicenceFormat.Iso(when),
                ["event"] = what,
                ["client"] = string.IsNullOrEmpty(clientKey) ? "unknown" : clientKey,
                ["session"] = sessionFingerprint,
                ["tag"] = Scrub(tag),
                ["detail"] = Scrub(detail),
            };

            // Logged first and unconditionally: if the file write is what fails,
            // this line is the record that survives.
            if (_log != null)
            {
                var level = what == LoginFailed || what == LoginThrottled || what == CsrfRefused
                    ? LogLevel.Warning
                    : LogLevel.Information;

                _log.Log(
                    level,
                    "admin {Event} client={Client} session={Session} tag={Tag} detail={Detail}",
                    what,
                    fields["client"],
                    sessionFingerprint ?? "-",
                    Scrub(tag) ?? "-",
                    Scrub(detail) ?? "-");
            }

            if (Path == null)
            {
                return;
            }

            try
            {
                Append(JsonSerializer.Serialize(fields) + "\n");
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                _log?.LogError(
                    ex,
                    "THE ADMIN AUDIT TRAIL AT {Path} COULD NOT BE WRITTEN. The action above went ahead and this "
                    + "log line is now the only record of it.",
                    Path);
            }
        }

        /// <summary>
        /// A short, one-way name for a session, so two lines can be tied
        /// together without the file holding the id itself. Twelve hex
        /// characters of SHA-256 - the same shape as a code's log tag, and for
        /// the same reason.
        /// </summary>
        public static string Fingerprint(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
            {
                return null;
            }

            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(sessionId));

            return Convert.ToHexString(hash).ToLowerInvariant().Substring(0, 12);
        }

        /// <summary>
        /// Removes anything shaped like a redemption code. This is not the
        /// primary control - no caller passes one - it is the guard that makes
        /// "the audit trail never holds a code" true of code nobody has written
        /// yet.
        /// </summary>
        public static string Scrub(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return text;
            }

            return CodeShaped.Replace(text, "[redacted: this looked like a redemption code]");
        }

        private void Append(string line)
        {
            var bytes = Encoding.UTF8.GetBytes(line);
            var directory = System.IO.Path.GetDirectoryName(Path);

            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var options = new FileStreamOptions
            {
                Mode = FileMode.Append,
                Access = FileAccess.Write,
                Share = FileShare.ReadWrite,
            };

            if (!OperatingSystem.IsWindows())
            {
                // At creation rather than chmod-ed afterwards. It holds no
                // credential, but it does hold a customer list and a record of
                // who was refunded, and there must be no moment when that exists
                // at the umask default.
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            lock (_gate)
            {
                using var file = new FileStream(Path, options);

                file.Write(bytes, 0, bytes.Length);
                file.Flush(flushToDisk: true);
            }
        }

        /// <summary>Reads the trail back, newest first, for the page that shows it.</summary>
        public IReadOnlyList<AdminAuditLine> Recent(int limit)
        {
            var lines = new List<AdminAuditLine>();

            if (Path == null || !File.Exists(Path))
            {
                return lines;
            }

            try
            {
                foreach (var line in File.ReadLines(Path))
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    try
                    {
                        using var document = JsonDocument.Parse(line);
                        var root = document.RootElement;

                        lines.Add(new AdminAuditLine
                        {
                            Utc = Text(root, "utc"),
                            Event = Text(root, "event"),
                            Client = Text(root, "client"),
                            Session = Text(root, "session"),
                            Tag = Text(root, "tag"),
                            Detail = Text(root, "detail"),
                        });
                    }
                    catch (JsonException)
                    {
                        // One damaged line must not hide the rest, which is the
                        // rule the outbox reader and the offline tool follow too.
                        continue;
                    }
                }
            }
            catch (IOException ex)
            {
                _log?.LogWarning(ex, "the admin audit trail at {Path} could not be read", Path);

                return lines;
            }

            lines.Reverse();

            return limit > 0 && lines.Count > limit ? lines.GetRange(0, limit) : lines;
        }

        private static string Text(JsonElement root, string name)
        {
            return root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty(name, out var value)
                && value.ValueKind == JsonValueKind.String
                    ? value.GetString()
                    : null;
        }
    }

    /// <summary>
    /// One line of the trail, as the page shows it. Every field is
    /// attacker-influenced - a licensee's name reaches the detail of an issue
    /// line - so every field is HTML-encoded where it is rendered.
    /// </summary>
    public sealed class AdminAuditLine
    {
        public string Utc { get; set; }

        public string Event { get; set; }

        public string Client { get; set; }

        public string Session { get; set; }

        public string Tag { get; set; }

        public string Detail { get; set; }
    }
}

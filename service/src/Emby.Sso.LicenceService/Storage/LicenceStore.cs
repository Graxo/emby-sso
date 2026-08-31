using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.IO;
using Emby.Sso.Licensing;
using Microsoft.Data.Sqlite;

namespace Emby.Sso.LicenceService.Storage
{
    /// <summary>
    /// Everything the service must not forget when the container restarts: which
    /// codes exist (as hashes), which servers each has been activated onto, and
    /// which PayPal events have already been acted on.
    ///
    /// WHY SQLITE, and not the JSONL files the vendor's offline tool uses:
    ///
    ///   * The activation cap is a security control, and enforcing it means
    ///     read-count-then-insert. That has to be one atomic step or two
    ///     simultaneous activations both read "2 used, 3 allowed" and both
    ///     insert. SQLite gives that with BEGIN IMMEDIATE and a UNIQUE index; a
    ///     flat file gives it only if this code hand-rolls locking, and
    ///     hand-rolled locking around a security cap is exactly the thing to not
    ///     hand-roll.
    ///   * A half-written append is a corrupt record. SQLite's journal makes a
    ///     crash mid-write a no-op instead.
    ///   * It is one file on the volume, backed up by copying it (with the
    ///     database quiesced, or `sqlite3 licences.db ".backup"`), and read by
    ///     the vendor with the sqlite3 CLI when a customer emails - which is the
    ///     other half of "did this person's activation reach me?".
    ///   * No second process, no port, nothing else to operate. The volume of a
    ///     one-person vendor selling a plugin does not need a database server and
    ///     would not be better served by one.
    ///
    /// The ledger stays a JSONL file beside it, in the offline tool's exact
    /// format, so `licencetool list` and `licencetool show` keep working on
    /// licences this service issued. The two are not redundant: the database is
    /// the authority and the thing transactions run against, the ledger is the
    /// compatibility view.
    /// </summary>
    public sealed class LicenceStore
    {
        private readonly string _connectionString;

        public LicenceStore(string databasePath)
        {
            if (string.IsNullOrWhiteSpace(databasePath))
            {
                throw new ArgumentException("the store needs a path", nameof(databasePath));
            }

            Path = System.IO.Path.GetFullPath(databasePath);

            _connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = Path,
                Mode = SqliteOpenMode.ReadWriteCreate,

                // Every write path below takes the same IMMEDIATE transaction, so
                // writers queue rather than fail; five seconds is far more than a
                // queue of RSA signatures ever needs and still fails eventually
                // rather than hanging a request forever.
                DefaultTimeout = 5,
                Pooling = true,
                ForeignKeys = true,
            }.ToString();
        }

        public string Path { get; }

        /// <summary>
        /// Creates the schema if it is not there. Safe to call on every start;
        /// it is how an upgrade of an existing volume happens.
        /// </summary>
        public void Initialise()
        {
            var directory = System.IO.Path.GetDirectoryName(Path);

            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            using var connection = Open();

            // WAL is a property of the file, set once and persistent. A reader
            // (the health check, a support query) then never blocks the writer.
            Execute(connection, "PRAGMA journal_mode=WAL;");
            Execute(connection, "PRAGMA synchronous=FULL;");

            Execute(connection, @"
CREATE TABLE IF NOT EXISTS codes (
    id                   INTEGER PRIMARY KEY,
    code_hash            TEXT    NOT NULL UNIQUE,
    created_utc          TEXT    NOT NULL,
    status               TEXT    NOT NULL,
    licensee             TEXT    NOT NULL,
    activations_allowed  INTEGER NOT NULL,
    licence_days         INTEGER NOT NULL,
    expires_utc          TEXT,
    first_activated_utc  TEXT,
    source               TEXT    NOT NULL,
    paypal_event_id      TEXT,
    paypal_capture_id    TEXT,
    buyer_email          TEXT,
    origin_server_id     TEXT
);");

            // Columns added after a volume already exists. CREATE TABLE IF NOT
            // EXISTS does nothing to a table that is already there, so a new
            // column has to be added explicitly or an upgraded container fails on
            // the first sale rather than at startup.
            AddColumnIfMissing(connection, "codes", "origin_server_id", "TEXT");

            // The second replay guard, and the one that survives PayPal sending
            // two different event ids for one payment: a capture can buy exactly
            // one code, enforced by the database rather than by a lookup that
            // could race.
            Execute(connection, @"
CREATE UNIQUE INDEX IF NOT EXISTS ux_codes_capture
    ON codes (paypal_capture_id) WHERE paypal_capture_id IS NOT NULL;");

            Execute(connection, @"
CREATE TABLE IF NOT EXISTS activations (
    id                INTEGER PRIMARY KEY,
    code_id           INTEGER NOT NULL REFERENCES codes(id),
    server_key        TEXT    NOT NULL,
    server_id         TEXT    NOT NULL,
    first_seen_utc    TEXT    NOT NULL,
    last_seen_utc     TEXT    NOT NULL,
    issue_count       INTEGER NOT NULL,
    plugin_version    TEXT,
    last_fingerprint  TEXT,
    UNIQUE (code_id, server_key)
);");

            Execute(connection, @"
CREATE TABLE IF NOT EXISTS webhook_events (
    event_id         TEXT PRIMARY KEY,
    transmission_id  TEXT,
    event_type       TEXT,
    received_utc     TEXT NOT NULL,
    outcome          TEXT NOT NULL,
    code_id          INTEGER
);");
        }

        /// <summary>Cheap proof that the volume is mounted and writable, for /healthz.</summary>
        public void CheckWritable()
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction(deferred: false);

            Execute(connection, transaction, "CREATE TABLE IF NOT EXISTS health_probe (checked_utc TEXT NOT NULL);");
            Execute(connection, transaction, "DELETE FROM health_probe;");

            using (var insert = connection.CreateCommand())
            {
                insert.Transaction = transaction;
                insert.CommandText = "INSERT INTO health_probe (checked_utc) VALUES ($t);";
                insert.Parameters.AddWithValue("$t", LicenceFormat.Iso(DateTimeOffset.UtcNow));
                insert.ExecuteNonQuery();
            }

            transaction.Commit();
        }

        /// <summary>
        /// The whole activation decision, in one transaction.
        ///
        /// THIS METHOD IS THE ACTIVATION CAP. Everything about it is arranged so
        /// that the count and the insert cannot be separated: BEGIN IMMEDIATE
        /// takes the write lock before the count is read, so a second request
        /// waits rather than reading a stale count, and UNIQUE (code_id,
        /// server_key) is the backstop if that reasoning is ever wrong.
        ///
        /// <paramref name="mint"/> is called INSIDE the transaction, and is given
        /// the expiry the code carries. Signing an RS3072 token takes a couple of
        /// milliseconds and holds the write lock for that long, which at any
        /// volume this vendor will see is nothing - and it buys atomicity: there
        /// is no window in which an activation is recorded but no licence was
        /// produced, or a licence was produced against a count that then rolled
        /// back.
        /// </summary>
        public ActivationOutcome Activate(
            string codeHash,
            string serverId,
            string serverKey,
            string pluginVersion,
            DateTimeOffset now,
            Func<DateTimeOffset, IssuedLicence> mint)
        {
            if (mint == null)
            {
                throw new ArgumentNullException(nameof(mint));
            }

            using var connection = Open();
            using var transaction = connection.BeginTransaction(deferred: false);

            var code = ReadCode(connection, transaction, codeHash);

            if (code == null)
            {
                return ActivationOutcome.Unknown(ActivationStatus.UnknownCode);
            }

            if (!string.Equals(code.Status, CodeStatus.Active, StringComparison.Ordinal))
            {
                // Unpaid, or voided by a refund. The contract folds both into
                // invalid_code, deliberately: the caller holding the code learns
                // only that it is not usable, not the state of the vendor's
                // PayPal account.
                return ActivationOutcome.Unknown(
                    string.Equals(code.Status, CodeStatus.Unpaid, StringComparison.Ordinal)
                        ? ActivationStatus.NotPaid
                        : ActivationStatus.Void);
            }

            var used = CountActivations(connection, transaction, code.Id);
            var existing = ReadActivation(connection, transaction, code.Id, serverKey);

            // The expiry is fixed at the code's first activation and every
            // licence minted from it afterwards carries the same one. Re-issuing
            // therefore cannot extend a licence, and the second server a customer
            // activates does not get a longer one than the first.
            var expires = code.ExpiresUtc ?? now.AddDays(code.LicenceDays);

            if (existing == null && used >= code.ActivationsAllowed)
            {
                return ActivationOutcome.Refused(ActivationStatus.Exhausted, used, code.ActivationsAllowed, expires);
            }

            var licence = mint(expires);

            if (code.ExpiresUtc == null)
            {
                Update(
                    connection,
                    transaction,
                    "UPDATE codes SET expires_utc = $e, first_activated_utc = $f WHERE id = $id;",
                    ("$e", LicenceFormat.Iso(expires)),
                    ("$f", LicenceFormat.Iso(now)),
                    ("$id", code.Id));
            }

            if (existing == null)
            {
                Update(
                    connection,
                    transaction,
                    @"INSERT INTO activations
                        (code_id, server_key, server_id, first_seen_utc, last_seen_utc, issue_count, plugin_version, last_fingerprint)
                      VALUES ($c, $k, $s, $t, $t, 1, $v, $f);",
                    ("$c", code.Id),
                    ("$k", serverKey),
                    ("$s", serverId),
                    ("$t", LicenceFormat.Iso(now)),
                    ("$v", (object)pluginVersion ?? DBNull.Value),
                    ("$f", licence.Fingerprint));

                used++;
                transaction.Commit();

                return ActivationOutcome.Issued(ActivationStatus.NewActivation, licence, used, code.ActivationsAllowed, expires);
            }

            Update(
                connection,
                transaction,
                @"UPDATE activations
                     SET last_seen_utc = $t, issue_count = issue_count + 1, plugin_version = $v, last_fingerprint = $f
                   WHERE id = $id;",
                ("$t", LicenceFormat.Iso(now)),
                ("$v", (object)pluginVersion ?? DBNull.Value),
                ("$f", licence.Fingerprint),
                ("$id", existing.Value));

            transaction.Commit();

            return ActivationOutcome.Issued(ActivationStatus.AlreadyActivated, licence, used, code.ActivationsAllowed, expires);
        }

        /// <summary>
        /// Records a paid PayPal event and the code it bought, or says why it
        /// bought nothing. Event id and capture id are both UNIQUE, so a replay
        /// of either kind loses the race in the database rather than in an
        /// if-statement.
        /// </summary>
        public PaymentRecord RecordPayment(
            string eventId,
            string transmissionId,
            string eventType,
            string captureId,
            string buyerEmail,
            string licensee,
            string originServerId,
            string codeHash,
            int activationsAllowed,
            int licenceDays,
            DateTimeOffset now)
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction(deferred: false);

            if (Exists(connection, transaction, "SELECT 1 FROM webhook_events WHERE event_id = $id;", ("$id", eventId)))
            {
                return new PaymentRecord(PaymentOutcome.DuplicateEvent, 0);
            }

            if (!string.IsNullOrEmpty(captureId)
                && Exists(connection, transaction, "SELECT 1 FROM codes WHERE paypal_capture_id = $c;", ("$c", captureId)))
            {
                RecordEvent(connection, transaction, eventId, transmissionId, eventType, now, "duplicate_capture", null);
                transaction.Commit();

                return new PaymentRecord(PaymentOutcome.DuplicateCapture, 0);
            }

            Update(
                connection,
                transaction,
                @"INSERT INTO codes
                    (code_hash, created_utc, status, licensee, activations_allowed, licence_days,
                     source, paypal_event_id, paypal_capture_id, buyer_email, origin_server_id)
                  VALUES ($h, $t, $s, $l, $a, $d, 'paypal', $e, $c, $b, $o);",
                ("$h", codeHash),
                ("$t", LicenceFormat.Iso(now)),
                ("$s", CodeStatus.Active),
                ("$l", licensee),
                ("$a", activationsAllowed),
                ("$d", licenceDays),
                ("$e", eventId),
                ("$c", (object)captureId ?? DBNull.Value),
                ("$b", (object)buyerEmail ?? DBNull.Value),
                ("$o", (object)originServerId ?? DBNull.Value));

            var codeId = LastInsertId(connection, transaction);

            RecordEvent(connection, transaction, eventId, transmissionId, eventType, now, "code_created", codeId);
            transaction.Commit();

            return new PaymentRecord(PaymentOutcome.CodeCreated, codeId);
        }

        /// <summary>
        /// An event that was genuine and correctly signed but bought nothing - a
        /// type we do not act on, an amount below the floor. Recorded anyway: the
        /// question "did PayPal tell me about this and what did I do?" has to be
        /// answerable, and recording it also makes a redelivery of it a
        /// duplicate rather than a fresh decision.
        /// </summary>
        public bool RecordIgnoredEvent(
            string eventId,
            string transmissionId,
            string eventType,
            string outcome,
            DateTimeOffset now)
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction(deferred: false);

            if (Exists(connection, transaction, "SELECT 1 FROM webhook_events WHERE event_id = $id;", ("$id", eventId)))
            {
                return false;
            }

            RecordEvent(connection, transaction, eventId, transmissionId, eventType, now, outcome, null);
            transaction.Commit();

            return true;
        }

        /// <summary>
        /// Marks the code a refunded or reversed capture bought as void, so it
        /// stops activating. Returns whether there was one.
        ///
        /// It does NOT revoke licences already minted from that code: the plugin
        /// verifies offline against an embedded public key and never calls home,
        /// so nothing can. A voided code stops the customer activating a fourth
        /// server after charging back; the servers they already activated keep
        /// working until the licence expires. Say so to anyone who asks rather
        /// than implying a revocation exists.
        /// </summary>
        public bool VoidCodeForCapture(string captureId, DateTimeOffset now)
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction(deferred: false);

            var changed = Update(
                connection,
                transaction,
                "UPDATE codes SET status = $v WHERE paypal_capture_id = $c AND status <> $v;",
                ("$v", CodeStatus.Void),
                ("$c", captureId));

            transaction.Commit();

            return changed > 0;
        }

        /// <summary>
        /// Creates a code that no payment bought: a comp for a tester, a
        /// replacement for one that could not be delivered, a licence sold some
        /// other way. Recorded with source 'manual' so the vendor can tell those
        /// apart from sales when reconciling against PayPal.
        ///
        /// Reached only from the `issue-code` command line, which means somebody
        /// with a shell on this box. There is no HTTP route to it, because an
        /// endpoint that creates codes needs an authentication story and the only
        /// honest one for a service this size is "you have the shell or you do
        /// not".
        /// </summary>
        public long CreateManualCode(
            string codeHash,
            string licensee,
            int activationsAllowed,
            int licenceDays,
            string note,
            DateTimeOffset now)
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction(deferred: false);

            Update(
                connection,
                transaction,
                @"INSERT INTO codes
                    (code_hash, created_utc, status, licensee, activations_allowed, licence_days, source, buyer_email)
                  VALUES ($h, $t, $s, $l, $a, $d, 'manual', $n);",
                ("$h", codeHash),
                ("$t", LicenceFormat.Iso(now)),
                ("$s", CodeStatus.Active),
                ("$l", licensee),
                ("$a", activationsAllowed),
                ("$d", licenceDays),
                ("$n", (object)note ?? DBNull.Value));

            var id = LastInsertId(connection, transaction);

            transaction.Commit();

            return id;
        }

        /// <summary>Read-only, for /healthz and for answering support questions.</summary>
        public CodeRow FindCode(string codeHash)
        {
            using var connection = Open();

            return ReadCode(connection, null, codeHash);
        }

        public IReadOnlyList<ActivationRow> ActivationsFor(long codeId)
        {
            using var connection = Open();
            using var command = connection.CreateCommand();

            command.CommandText =
                "SELECT server_id, first_seen_utc, last_seen_utc, issue_count, plugin_version, last_fingerprint "
                + "FROM activations WHERE code_id = $c ORDER BY first_seen_utc;";
            command.Parameters.AddWithValue("$c", codeId);

            var rows = new List<ActivationRow>();

            using var reader = command.ExecuteReader();

            while (reader.Read())
            {
                rows.Add(new ActivationRow(
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetInt32(3),
                    reader.IsDBNull(4) ? null : reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5)));
            }

            return rows;
        }

        private SqliteConnection Open()
        {
            var connection = new SqliteConnection(_connectionString);

            connection.Open();

            return connection;
        }

        private static CodeRow ReadCode(SqliteConnection connection, SqliteTransaction transaction, string codeHash)
        {
            using var command = connection.CreateCommand();

            command.Transaction = transaction;
            command.CommandText =
                "SELECT id, status, licensee, activations_allowed, licence_days, expires_utc, buyer_email "
                + "FROM codes WHERE code_hash = $h;";
            command.Parameters.AddWithValue("$h", codeHash);

            using var reader = command.ExecuteReader();

            if (!reader.Read())
            {
                return null;
            }

            return new CodeRow(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetInt32(3),
                reader.GetInt32(4),
                reader.IsDBNull(5) ? (DateTimeOffset?)null : ParseIso(reader.GetString(5)),
                reader.IsDBNull(6) ? null : reader.GetString(6));
        }

        private static long? ReadActivation(SqliteConnection connection, SqliteTransaction transaction, long codeId, string serverKey)
        {
            using var command = connection.CreateCommand();

            command.Transaction = transaction;
            command.CommandText = "SELECT id FROM activations WHERE code_id = $c AND server_key = $k;";
            command.Parameters.AddWithValue("$c", codeId);
            command.Parameters.AddWithValue("$k", serverKey);

            var value = command.ExecuteScalar();

            return value == null || value == DBNull.Value ? (long?)null : Convert.ToInt64(value, CultureInfo.InvariantCulture);
        }

        private static int CountActivations(SqliteConnection connection, SqliteTransaction transaction, long codeId)
        {
            using var command = connection.CreateCommand();

            command.Transaction = transaction;
            command.CommandText = "SELECT COUNT(*) FROM activations WHERE code_id = $c;";
            command.Parameters.AddWithValue("$c", codeId);

            return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
        }

        private static void RecordEvent(
            SqliteConnection connection,
            SqliteTransaction transaction,
            string eventId,
            string transmissionId,
            string eventType,
            DateTimeOffset now,
            string outcome,
            long? codeId)
        {
            Update(
                connection,
                transaction,
                @"INSERT INTO webhook_events (event_id, transmission_id, event_type, received_utc, outcome, code_id)
                  VALUES ($i, $t, $y, $r, $o, $c);",
                ("$i", eventId),
                ("$t", (object)transmissionId ?? DBNull.Value),
                ("$y", (object)eventType ?? DBNull.Value),
                ("$r", LicenceFormat.Iso(now)),
                ("$o", outcome),
                ("$c", codeId.HasValue ? (object)codeId.Value : DBNull.Value));
        }

        private static bool Exists(
            SqliteConnection connection,
            SqliteTransaction transaction,
            string sql,
            params (string Name, object Value)[] parameters)
        {
            using var command = connection.CreateCommand();

            command.Transaction = transaction;
            command.CommandText = sql;

            foreach (var (name, value) in parameters)
            {
                command.Parameters.AddWithValue(name, value);
            }

            return command.ExecuteScalar() != null;
        }

        private static long LastInsertId(SqliteConnection connection, SqliteTransaction transaction)
        {
            using var command = connection.CreateCommand();

            command.Transaction = transaction;
            command.CommandText = "SELECT last_insert_rowid();";

            return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
        }

        private static int Update(
            SqliteConnection connection,
            SqliteTransaction transaction,
            string sql,
            params (string Name, object Value)[] parameters)
        {
            using var command = connection.CreateCommand();

            command.Transaction = transaction;
            command.CommandText = sql;

            foreach (var (name, value) in parameters)
            {
                command.Parameters.AddWithValue(name, value);
            }

            return command.ExecuteNonQuery();
        }

        /// <summary>
        /// Adds a column to an existing table, once. Reads the table's own shape
        /// rather than tracking a version number: there is exactly one deployment
        /// of this service and a schema version table it could get out of step
        /// with would be one more thing to be wrong.
        /// </summary>
        private static void AddColumnIfMissing(SqliteConnection connection, string table, string column, string type)
        {
            using (var check = connection.CreateCommand())
            {
                check.CommandText = "SELECT COUNT(*) FROM pragma_table_info($t) WHERE name = $c;";
                check.Parameters.AddWithValue("$t", table);
                check.Parameters.AddWithValue("$c", column);

                if (Convert.ToInt32(check.ExecuteScalar(), CultureInfo.InvariantCulture) > 0)
                {
                    return;
                }
            }

            Execute(connection, "ALTER TABLE " + table + " ADD COLUMN " + column + " " + type + ";");
        }

        private static void Execute(SqliteConnection connection, string sql)
        {
            Execute(connection, null, sql);
        }

        private static void Execute(SqliteConnection connection, SqliteTransaction transaction, string sql)
        {
            using var command = connection.CreateCommand();

            command.Transaction = transaction;
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }

        private static DateTimeOffset ParseIso(string value)
        {
            return DateTimeOffset.ParseExact(
                value,
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        }
    }

    public static class CodeStatus
    {
        public const string Unpaid = "unpaid";
        public const string Active = "active";
        public const string Void = "void";
    }

    public sealed class CodeRow
    {
        public CodeRow(
            long id,
            string status,
            string licensee,
            int activationsAllowed,
            int licenceDays,
            DateTimeOffset? expiresUtc,
            string buyerEmail)
        {
            Id = id;
            Status = status;
            Licensee = licensee;
            ActivationsAllowed = activationsAllowed;
            LicenceDays = licenceDays;
            ExpiresUtc = expiresUtc;
            BuyerEmail = buyerEmail;
        }

        public long Id { get; }

        public string Status { get; }

        public string Licensee { get; }

        public int ActivationsAllowed { get; }

        public int LicenceDays { get; }

        public DateTimeOffset? ExpiresUtc { get; }

        public string BuyerEmail { get; }
    }

    public sealed class ActivationRow
    {
        public ActivationRow(
            string serverId,
            string firstSeenUtc,
            string lastSeenUtc,
            int issueCount,
            string pluginVersion,
            string lastFingerprint)
        {
            ServerId = serverId;
            FirstSeenUtc = firstSeenUtc;
            LastSeenUtc = lastSeenUtc;
            IssueCount = issueCount;
            PluginVersion = pluginVersion;
            LastFingerprint = lastFingerprint;
        }

        public string ServerId { get; }

        public string FirstSeenUtc { get; }

        public string LastSeenUtc { get; }

        public int IssueCount { get; }

        public string PluginVersion { get; }

        public string LastFingerprint { get; }
    }

    public enum ActivationStatus
    {
        UnknownCode,
        NotPaid,
        Void,
        Exhausted,
        AlreadyActivated,
        NewActivation,
    }

    public sealed class ActivationOutcome
    {
        private ActivationOutcome(
            ActivationStatus status,
            IssuedLicence licence,
            int used,
            int allowed,
            DateTimeOffset? expires)
        {
            Status = status;
            Licence = licence;
            ActivationsUsed = used;
            ActivationsAllowed = allowed;
            ExpiresUtc = expires;
        }

        public ActivationStatus Status { get; }

        public IssuedLicence Licence { get; }

        public int ActivationsUsed { get; }

        public int ActivationsAllowed { get; }

        public DateTimeOffset? ExpiresUtc { get; }

        public static ActivationOutcome Unknown(ActivationStatus status)
        {
            return new ActivationOutcome(status, null, 0, 0, null);
        }

        public static ActivationOutcome Refused(ActivationStatus status, int used, int allowed, DateTimeOffset expires)
        {
            return new ActivationOutcome(status, null, used, allowed, expires);
        }

        public static ActivationOutcome Issued(
            ActivationStatus status,
            IssuedLicence licence,
            int used,
            int allowed,
            DateTimeOffset expires)
        {
            return new ActivationOutcome(status, licence, used, allowed, expires);
        }
    }

    public enum PaymentOutcome
    {
        CodeCreated,
        DuplicateEvent,
        DuplicateCapture,
    }

    public sealed class PaymentRecord
    {
        public PaymentRecord(PaymentOutcome outcome, long codeId)
        {
            Outcome = outcome;
            CodeId = codeId;
        }

        public PaymentOutcome Outcome { get; }

        public long CodeId { get; }
    }
}

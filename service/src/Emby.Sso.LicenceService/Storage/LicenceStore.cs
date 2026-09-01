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
            : this(databasePath, StoreAccess.CreateIfMissing)
        {
        }

        /// <summary>
        /// <paramref name="access"/> is how the management commands keep their
        /// promise not to invent a database. SQLite's default is to create the
        /// file, which is exactly wrong for `list-codes` against a mistyped
        /// LICENCE_DATA_DIR: the operator would get an empty table that reads as
        /// "no customers" and a stray licences.db in whatever directory they
        /// meant to look in. <see cref="StoreAccess.ReadOnly"/> also makes it
        /// impossible for a read command to write, rather than merely unlikely.
        /// </summary>
        public LicenceStore(string databasePath, StoreAccess access)
        {
            if (string.IsNullOrWhiteSpace(databasePath))
            {
                throw new ArgumentException("the store needs a path", nameof(databasePath));
            }

            Path = System.IO.Path.GetFullPath(databasePath);
            Access = access;

            _connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = Path,
                Mode = access switch
                {
                    StoreAccess.ReadOnly => SqliteOpenMode.ReadOnly,
                    StoreAccess.ExistingOnly => SqliteOpenMode.ReadWrite,
                    _ => SqliteOpenMode.ReadWriteCreate,
                },

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

        public StoreAccess Access { get; }

        /// <summary>Whether there is a store at all. Asked before opening one, so that a
        /// missing file is reported as a missing file rather than as an empty database.</summary>
        public static bool Exists(string databasePath)
        {
            return !string.IsNullOrWhiteSpace(databasePath) && File.Exists(System.IO.Path.GetFullPath(databasePath));
        }

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

            SqliteConnection connection;

            try
            {
                connection = Open();
            }
            catch (SqliteException ex)
            {
                // SQLite says "unable to open database file" for every reason a
                // file cannot be opened, and the stack trace it comes with is
                // eight frames of ADO.NET that name none of them. In a container
                // the reason is almost always the same one: the mounted data
                // directory belongs to somebody else, and this process is not
                // root. SQLite needs to CREATE files here - the database, and
                // its -wal and -shm siblings - so being able to read the
                // directory is not enough.
                //
                // Say which directory, and which user has to own it, because
                // that is the whole of the fix and the operator cannot see this
                // process's uid from the host.
                throw new InvalidOperationException(
                    "The licence store at " + Path + " could not be opened: " + ex.Message + Environment.NewLine +
                    "The directory " + (directory ?? ".") + " must be writable by the user this service runs as, " +
                    "which in the shipped image is uid 5678. In Docker that means the HOST directory you mounted " +
                    "there, which is a different thing from the path inside the container: " +
                    "`sudo chown -R 5678:5678 <the host directory>`." +
                    Environment.NewLine +
                    "See service/docs/first-run.md.",
                    ex);
            }

            using (connection)
            {

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

            // When a code was voided and why. Written by both void paths - the
            // refund webhook and the `void-code` command - so that `show-code`
            // can answer "why does this customer's code not work?" with the
            // reason somebody actually gave, months later.
            AddColumnIfMissing(connection, "codes", "voided_utc", "TEXT");
            AddColumnIfMissing(connection, "codes", "void_reason", "TEXT");

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

            // WHAT A LICENCE IS WAITING FOR. This service cannot sign: the
            // private key that mints licences is not on this host and is not
            // reachable from it, because a key that signs for every customer
            // has no business sitting behind a port on the internet. So an
            // activation records what has to be signed, and a person with the
            // key signs it elsewhere and uploads the result.
            //
            // One row per activation, created when the activation is first
            // allowed and never afterwards: the licensee, server id, issue date
            // and expiry are decided HERE, once, and the signing machine is only
            // asked to sign exactly them. That is what stops an operator - or
            // anyone who reaches the admin page - from quietly signing a longer
            // licence or one for a different server than was paid for; the
            // upload is checked against this row and refused if it disagrees.
            Execute(connection, @"
CREATE TABLE IF NOT EXISTS signing_requests (
    id             INTEGER PRIMARY KEY,
    request_id     TEXT    NOT NULL UNIQUE,
    activation_id  INTEGER NOT NULL UNIQUE REFERENCES activations(id),
    code_id        INTEGER NOT NULL REFERENCES codes(id),
    licensee       TEXT    NOT NULL,
    server_id      TEXT    NOT NULL,
    issued_at_utc  TEXT    NOT NULL,
    expires_utc    TEXT    NOT NULL,
    requested_utc  TEXT    NOT NULL,
    licence        TEXT,
    key_id         TEXT,
    fingerprint    TEXT,
    signed_utc     TEXT
);");

            Execute(connection, @"
CREATE INDEX IF NOT EXISTS ix_signing_requests_waiting
    ON signing_requests (requested_utc) WHERE signed_utc IS NULL;");

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
        }

        /// <summary>
        /// Writes a consistent copy of the whole database to
        /// <paramref name="path"/>, which must not exist.
        ///
        /// VACUUM INTO rather than File.Copy. This database runs in WAL mode, so
        /// at any instant the .db file alone is an old snapshot and the committed
        /// truth is spread across it and the -wal beside it. Copying just the .db
        /// silently loses recent activations; copying all three while a write is
        /// in flight can produce a set that do not agree. VACUUM INTO takes a
        /// read transaction and writes one self-contained, already-checkpointed
        /// file - which is the only cheap way to get a backup that is certain to
        /// open.
        /// </summary>
        public void SnapshotTo(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("a snapshot needs a destination", nameof(path));
            }

            var full = System.IO.Path.GetFullPath(path);

            if (File.Exists(full))
            {
                // VACUUM INTO refuses an existing file, and so does this, with a
                // sentence instead of a SQLite error code.
                throw new InvalidOperationException("There is already a file at " + full + ". A snapshot never overwrites.");
            }

            using var connection = Open();
            using var command = connection.CreateCommand();

            // Parameterised: the path is ours, but VACUUM INTO takes an
            // expression and building SQL by concatenating a file path is a
            // habit worth not having.
            command.CommandText = "VACUUM INTO $path;";
            command.Parameters.AddWithValue("$path", full);
            command.ExecuteNonQuery();
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
        /// IT NO LONGER MINTS ANYTHING. It used to be handed a signing function
        /// and call it inside the transaction, which was atomic and neat and
        /// required the private key to be on this host. It is not any more. What
        /// happens instead is that the terms of the licence - who, which server,
        /// from when, until when - are decided here, once, written to
        /// signing_requests, and never changed. A person with the key signs
        /// exactly those terms elsewhere and uploads the result, which is checked
        /// back against this row.
        ///
        /// The consequence is visible to the customer and is not hidden: the
        /// first activation of a code returns AwaitingSignature, not a licence.
        /// A repeat activation of a server whose licence has since been signed
        /// returns it immediately. That is the price of the key not being here,
        /// and it is the right price.
        /// </summary>
        /// <param name="newRequestId">
        /// Makes the opaque id the exchange file is matched on. Passed in rather
        /// than generated here so the randomness has one source and the tests can
        /// be deterministic.
        /// </param>
        public ActivationOutcome Activate(
            string codeHash,
            string serverId,
            string serverKey,
            string pluginVersion,
            DateTimeOffset now,
            Func<string> newRequestId)
        {
            if (newRequestId == null)
            {
                throw new ArgumentNullException(nameof(newRequestId));
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
            // licence signed from it afterwards carries the same one. Re-issuing
            // therefore cannot extend a licence, and the second server a customer
            // activates does not get a longer one than the first.
            var expires = code.ExpiresUtc ?? now.AddDays(code.LicenceDays);

            if (existing == null && used >= code.ActivationsAllowed)
            {
                return ActivationOutcome.Refused(ActivationStatus.Exhausted, used, code.ActivationsAllowed, expires);
            }

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

            long activationId;
            var first = existing == null;

            if (first)
            {
                Update(
                    connection,
                    transaction,
                    @"INSERT INTO activations
                        (code_id, server_key, server_id, first_seen_utc, last_seen_utc, issue_count, plugin_version, last_fingerprint)
                      VALUES ($c, $k, $s, $t, $t, 1, $v, NULL);",
                    ("$c", code.Id),
                    ("$k", serverKey),
                    ("$s", serverId),
                    ("$t", LicenceFormat.Iso(now)),
                    ("$v", (object)pluginVersion ?? DBNull.Value));

                activationId = ReadActivation(connection, transaction, code.Id, serverKey).Value;
                used++;
            }
            else
            {
                activationId = existing.Value;

                Update(
                    connection,
                    transaction,
                    @"UPDATE activations
                         SET last_seen_utc = $t, issue_count = issue_count + 1, plugin_version = $v
                       WHERE id = $id;",
                    ("$t", LicenceFormat.Iso(now)),
                    ("$v", (object)pluginVersion ?? DBNull.Value),
                    ("$id", activationId));
            }

            // One request per activation, created once. A second activation of
            // the same server does NOT create a second request: it is the same
            // licence, and asking for it to be signed twice would put two live
            // credentials for one server into circulation.
            var request = ReadSigningRequest(connection, transaction, activationId);

            if (request == null)
            {
                var requestId = newRequestId();

                Update(
                    connection,
                    transaction,
                    @"INSERT INTO signing_requests
                        (request_id, activation_id, code_id, licensee, server_id, issued_at_utc, expires_utc, requested_utc)
                      VALUES ($r, $a, $c, $l, $s, $i, $e, $i);",
                    ("$r", requestId),
                    ("$a", activationId),
                    ("$c", code.Id),
                    ("$l", LicenseeFor(codeHash)),
                    ("$s", serverId),
                    ("$i", LicenceFormat.Iso(now)),
                    ("$e", LicenceFormat.Iso(expires)));

                request = ReadSigningRequest(connection, transaction, activationId);
            }

            transaction.Commit();

            if (request.Licence == null)
            {
                return ActivationOutcome.Waiting(request, used, code.ActivationsAllowed, expires, first);
            }

            return ActivationOutcome.Issued(
                first ? ActivationStatus.NewActivation : ActivationStatus.AlreadyActivated,
                request,
                used,
                code.ActivationsAllowed,
                expires);
        }

        /// <summary>
        /// What goes in a licence's `sub` claim.
        ///
        /// The buyer's email is in this store and is NOT used. `sub` ends up in a
        /// token that sits in a config file on somebody else's server, gets
        /// pasted into support threads, and is readable by anyone who can decode
        /// base64 - which is everyone. The code tag identifies the customer to
        /// the vendor, against this store and the outbox, without putting a
        /// customer's email address in a string that travels. It is also written
        /// into the exchange file that goes to the signing machine, which is a
        /// second reason for it to say as little as it can.
        /// </summary>
        public static string LicenseeFor(string codeHash)
        {
            return "code:" + RedemptionCode.LogTag(codeHash);
        }

        /// <summary>
        /// Everything waiting to be signed, oldest first, for the file the admin
        /// page hands the operator.
        /// </summary>
        public IReadOnlyList<SigningRequestRow> WaitingToBeSigned(int limit)
        {
            using var connection = Open();

            using var command = connection.CreateCommand();

            command.CommandText = @"
SELECT request_id, activation_id, licensee, server_id, issued_at_utc, expires_utc, requested_utc
  FROM signing_requests
 WHERE signed_utc IS NULL
 ORDER BY requested_utc, id
 LIMIT $limit;";
            command.Parameters.AddWithValue("$limit", limit);

            var rows = new List<SigningRequestRow>();

            using var reader = command.ExecuteReader();

            while (reader.Read())
            {
                rows.Add(new SigningRequestRow(
                    reader.GetString(0),
                    reader.GetInt64(1),
                    reader.GetString(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.GetString(5),
                    reader.GetString(6),
                    null,
                    null,
                    null,
                    null));
            }

            return rows;
        }

        public int CountWaitingToBeSigned()
        {
            using var connection = Open();
            using var command = connection.CreateCommand();

            command.CommandText = "SELECT COUNT(*) FROM signing_requests WHERE signed_utc IS NULL;";

            return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
        }

        /// <summary>The one row an upload claims to answer, or null if there is no such request.</summary>
        public SigningRequestRow FindSigningRequest(string requestId)
        {
            using var connection = Open();

            return ReadSigningRequestById(connection, null, requestId);
        }

        /// <summary>
        /// Stores a signed licence against the request it answers.
        ///
        /// Refuses a request that is already signed rather than overwriting it.
        /// A customer's licence is a live credential that has already been
        /// handed out; replacing it would silently invalidate the one they are
        /// using, and doing that by re-uploading yesterday's file by mistake is
        /// far too easy. Reissuing is a deliberate act - see the admin page.
        /// </summary>
        public StoreSignedResult StoreSignedLicence(
            string requestId,
            string licence,
            string keyId,
            string fingerprint,
            DateTimeOffset now)
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction(deferred: false);

            var row = ReadSigningRequestById(connection, transaction, requestId);

            if (row == null)
            {
                return StoreSignedResult.NoSuchRequest;
            }

            if (row.Licence != null)
            {
                return string.Equals(row.Licence, licence, StringComparison.Ordinal)
                    ? StoreSignedResult.AlreadyTheSame
                    : StoreSignedResult.AlreadySigned;
            }

            Update(
                connection,
                transaction,
                @"UPDATE signing_requests
                     SET licence = $l, key_id = $k, fingerprint = $f, signed_utc = $t
                   WHERE request_id = $r AND signed_utc IS NULL;",
                ("$l", licence),
                ("$k", keyId),
                ("$f", fingerprint),
                ("$t", LicenceFormat.Iso(now)),
                ("$r", requestId));

            Update(
                connection,
                transaction,
                "UPDATE activations SET last_fingerprint = $f WHERE id = $id;",
                ("$f", fingerprint),
                ("$id", row.ActivationId));

            transaction.Commit();

            return StoreSignedResult.Stored;
        }

        private static SigningRequestRow ReadSigningRequest(SqliteConnection connection, SqliteTransaction transaction, long activationId)
        {
            using var command = connection.CreateCommand();

            command.Transaction = transaction;
            command.CommandText = @"
SELECT request_id, activation_id, licensee, server_id, issued_at_utc, expires_utc, requested_utc,
       licence, key_id, fingerprint, signed_utc
  FROM signing_requests WHERE activation_id = $a;";
            command.Parameters.AddWithValue("$a", activationId);

            return ReadOneSigningRequest(command);
        }

        private static SigningRequestRow ReadSigningRequestById(SqliteConnection connection, SqliteTransaction transaction, string requestId)
        {
            using var command = connection.CreateCommand();

            command.Transaction = transaction;
            command.CommandText = @"
SELECT request_id, activation_id, licensee, server_id, issued_at_utc, expires_utc, requested_utc,
       licence, key_id, fingerprint, signed_utc
  FROM signing_requests WHERE request_id = $r;";
            command.Parameters.AddWithValue("$r", requestId ?? string.Empty);

            return ReadOneSigningRequest(command);
        }

        private static SigningRequestRow ReadOneSigningRequest(SqliteCommand command)
        {
            using var reader = command.ExecuteReader();

            if (!reader.Read())
            {
                return null;
            }

            return new SigningRequestRow(
                reader.GetString(0),
                reader.GetInt64(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.IsDBNull(8) ? null : reader.GetString(8),
                reader.IsDBNull(9) ? null : reader.GetString(9),
                reader.IsDBNull(10) ? null : reader.GetString(10));
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
            return VoidBy("paypal_capture_id", captureId, "PayPal reversed capture " + captureId, now) == VoidOutcome.Voided;
        }

        /// <summary>
        /// The `void-code` command's void, by the hash of the code the operator
        /// was given. Exactly the same statement the refund path takes - see
        /// <see cref="VoidBy"/> - so there is one definition of what voided
        /// means, and a change to it cannot apply to refunds but not to the
        /// command or the other way round.
        ///
        /// It reports which of the three things happened, because the command
        /// has to distinguish "there is no such code" from "it was already
        /// void", and the second of those is a success.
        /// </summary>
        public VoidOutcome VoidCodeByHash(string codeHash, string reason, DateTimeOffset now)
        {
            return VoidBy("code_hash", codeHash, reason, now);
        }

        /// <summary>
        /// The one place a code becomes void.
        ///
        /// <paramref name="column"/> is never operator input: it is one of two
        /// literals passed by the two methods above, which is why it can be
        /// concatenated into the statement while every value stays a parameter.
        ///
        /// This does NOT revoke licences already minted from the code: the
        /// plugin verifies offline against an embedded public key and never
        /// calls home, so nothing here or anywhere can. A voided code stops the
        /// next activation; the servers already activated keep working until the
        /// licence expires. Both callers say so in their own output.
        /// </summary>
        private VoidOutcome VoidBy(string column, object value, string reason, DateTimeOffset now)
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction(deferred: false);

            string status;

            using (var read = connection.CreateCommand())
            {
                read.Transaction = transaction;
                read.CommandText = "SELECT status FROM codes WHERE " + column + " = $v;";
                read.Parameters.AddWithValue("$v", value);

                var found = read.ExecuteScalar();

                status = found == null || found == DBNull.Value ? null : Convert.ToString(found, CultureInfo.InvariantCulture);
            }

            if (status == null)
            {
                transaction.Commit();

                return VoidOutcome.NoSuchCode;
            }

            if (string.Equals(status, CodeStatus.Void, StringComparison.Ordinal))
            {
                transaction.Commit();

                return VoidOutcome.AlreadyVoid;
            }

            Update(
                connection,
                transaction,
                "UPDATE codes SET status = $s, voided_utc = $t, void_reason = $r WHERE " + column + " = $v;",
                ("$s", CodeStatus.Void),
                ("$t", LicenceFormat.Iso(now)),
                ("$r", (object)reason ?? DBNull.Value),
                ("$v", value));

            transaction.Commit();

            return VoidOutcome.Voided;
        }

        /// <summary>
        /// Creates a code that no payment bought: a comp for a tester, a
        /// replacement for one that could not be delivered, a licence sold some
        /// other way. Recorded with source 'manual' so the vendor can tell those
        /// apart from sales when reconciling against PayPal.
        ///
        /// Reached from `issue-code` on the command line, and from the admin
        /// page's Issue form when one is configured - both through
        /// Management.CodeIssuing, which is the only caller that should exist.
        /// The command needs a shell on this box; the page needs the admin
        /// password, which is the whole barrier in front of it and is why
        /// Admin.AdminEndpoints is written the way it is.
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

        /// <summary>
        /// Every code, with its activation count, for `list-codes`. One query
        /// and a correlated count rather than a row per activation: the vendor's
        /// whole customer list is a few hundred rows at most, and reading it in
        /// one go means the table cannot show two codes as of different moments.
        /// </summary>
        public IReadOnlyList<CodeSummary> ListCodes()
        {
            using var connection = Open();
            using var command = connection.CreateCommand();

            command.CommandText = CodeSummarySelect + " ORDER BY c.created_utc, c.id;";

            return ReadSummaries(command);
        }

        /// <summary>Everything about one code, found by the hash of the code the customer typed.</summary>
        public CodeSummary FindCodeByHash(string codeHash)
        {
            using var connection = Open();
            using var command = connection.CreateCommand();

            command.CommandText = CodeSummarySelect + " WHERE c.code_hash = $h;";
            command.Parameters.AddWithValue("$h", codeHash);

            var rows = ReadSummaries(command);

            return rows.Count == 1 ? rows[0] : null;
        }

        /// <summary>
        /// Codes whose hash starts with <paramref name="prefix"/> - how the log
        /// tag in `code=9f2a1c3e5b7d` is turned back into a code. A list rather
        /// than one row because a short enough prefix can match more than one,
        /// and the caller must say so rather than picking one.
        /// </summary>
        public IReadOnlyList<CodeSummary> FindCodesByHashPrefix(string prefix)
        {
            using var connection = Open();
            using var command = connection.CreateCommand();

            // ESCAPE, because a prefix is operator input and LIKE would
            // otherwise read % and _ in it as wildcards.
            command.CommandText = CodeSummarySelect
                + " WHERE c.code_hash LIKE $p ESCAPE '\\' ORDER BY c.created_utc, c.id;";
            command.Parameters.AddWithValue(
                "$p",
                prefix.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%");

            return ReadSummaries(command);
        }

        private const string CodeSummarySelect = @"
SELECT c.id, c.code_hash, c.created_utc, c.status, c.licensee, c.activations_allowed, c.licence_days,
       c.expires_utc, c.first_activated_utc, c.source, c.paypal_event_id, c.paypal_capture_id,
       c.buyer_email, c.origin_server_id, c.voided_utc, c.void_reason,
       (SELECT COUNT(*) FROM activations a WHERE a.code_id = c.id) AS activations_used
  FROM codes c";

        private static IReadOnlyList<CodeSummary> ReadSummaries(SqliteCommand command)
        {
            var rows = new List<CodeSummary>();

            using var reader = command.ExecuteReader();

            while (reader.Read())
            {
                rows.Add(new CodeSummary
                {
                    Id = reader.GetInt64(0),
                    CodeHash = reader.GetString(1),
                    CreatedUtc = ParseIso(reader.GetString(2)),
                    Status = reader.GetString(3),
                    Licensee = reader.GetString(4),
                    ActivationsAllowed = reader.GetInt32(5),
                    LicenceDays = reader.GetInt32(6),
                    ExpiresUtc = reader.IsDBNull(7) ? (DateTimeOffset?)null : ParseIso(reader.GetString(7)),
                    FirstActivatedUtc = reader.IsDBNull(8) ? (DateTimeOffset?)null : ParseIso(reader.GetString(8)),
                    Source = reader.GetString(9),
                    PayPalEventId = reader.IsDBNull(10) ? null : reader.GetString(10),
                    PayPalCaptureId = reader.IsDBNull(11) ? null : reader.GetString(11),
                    BuyerEmailOrNote = reader.IsDBNull(12) ? null : reader.GetString(12),
                    OriginServerId = reader.IsDBNull(13) ? null : reader.GetString(13),
                    VoidedUtc = reader.IsDBNull(14) ? (DateTimeOffset?)null : ParseIso(reader.GetString(14)),
                    VoidReason = reader.IsDBNull(15) ? null : reader.GetString(15),
                    ActivationsUsed = reader.GetInt32(16),
                });
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

    /// <summary>How a <see cref="LicenceStore"/> may touch the file it points at.</summary>
    public enum StoreAccess
    {
        /// <summary>The service and `issue-code`: create the database and the schema if they are not there.</summary>
        CreateIfMissing,

        /// <summary>`void-code`: writes, but will not bring a store into existence.</summary>
        ExistingOnly,

        /// <summary>`list-codes`, `show-code`, `list-outbox`: cannot create and cannot write.</summary>
        ReadOnly,
    }

    public enum VoidOutcome
    {
        /// <summary>Nothing in this store has that hash.</summary>
        NoSuchCode,

        /// <summary>It was already void. Voiding again changes nothing, and that is not a failure.</summary>
        AlreadyVoid,

        /// <summary>It was usable and now is not.</summary>
        Voided,
    }

    /// <summary>
    /// One code as the management commands see it: every column of the row plus
    /// the number of servers it has been activated onto.
    ///
    /// It carries the code's HASH and never the code. There is no field here for
    /// one and there cannot be: the store has never held it.
    /// </summary>
    public sealed class CodeSummary
    {
        public long Id { get; set; }

        public string CodeHash { get; set; }

        public DateTimeOffset CreatedUtc { get; set; }

        public string Status { get; set; }

        public string Licensee { get; set; }

        public int ActivationsAllowed { get; set; }

        public int ActivationsUsed { get; set; }

        public int LicenceDays { get; set; }

        public DateTimeOffset? ExpiresUtc { get; set; }

        public DateTimeOffset? FirstActivatedUtc { get; set; }

        public string Source { get; set; }

        public string PayPalEventId { get; set; }

        public string PayPalCaptureId { get; set; }

        /// <summary>
        /// The buyer's address for a PayPal code - and, for a code from
        /// `issue-code`, the `--note`, because that command has always written
        /// its note into this column. Rendered under the right heading for each
        /// source rather than being labelled "buyer email" for a comp that has
        /// no buyer.
        /// </summary>
        public string BuyerEmailOrNote { get; set; }

        public string OriginServerId { get; set; }

        public DateTimeOffset? VoidedUtc { get; set; }

        public string VoidReason { get; set; }

        public bool IsManual => string.Equals(Source, "manual", StringComparison.Ordinal);

        public string Tag => RedemptionCode.LogTag(CodeHash);
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

        /// <summary>
        /// The activation is allowed and recorded, and there is no licence to
        /// hand over yet because nothing on this host can sign one. Somebody
        /// with the key has to. See <see cref="LicenceStore.Activate"/>.
        /// </summary>
        AwaitingSignature,
    }

    public sealed class ActivationOutcome
    {
        private ActivationOutcome(
            ActivationStatus status,
            SigningRequestRow request,
            int used,
            int allowed,
            DateTimeOffset? expires,
            bool first)
        {
            Status = status;
            Request = request;
            ActivationsUsed = used;
            ActivationsAllowed = allowed;
            ExpiresUtc = expires;
            IsFirstActivation = first;
        }

        public ActivationStatus Status { get; }

        /// <summary>
        /// The row this activation is answered by, whether or not it has been
        /// signed yet. Null on every refusal.
        /// </summary>
        public SigningRequestRow Request { get; }

        /// <summary>
        /// The licence itself, and ONLY when one has been signed and stored. A
        /// caller that hands out whatever is here cannot hand out a placeholder
        /// by mistake.
        /// </summary>
        public string Licence => Request?.Licence;

        public int ActivationsUsed { get; }

        public int ActivationsAllowed { get; }

        public DateTimeOffset? ExpiresUtc { get; }

        /// <summary>Whether this activation used up one of the code's allowance.</summary>
        public bool IsFirstActivation { get; }

        public static ActivationOutcome Unknown(ActivationStatus status)
        {
            return new ActivationOutcome(status, null, 0, 0, null, false);
        }

        public static ActivationOutcome Refused(ActivationStatus status, int used, int allowed, DateTimeOffset expires)
        {
            return new ActivationOutcome(status, null, used, allowed, expires, false);
        }

        public static ActivationOutcome Waiting(
            SigningRequestRow request,
            int used,
            int allowed,
            DateTimeOffset expires,
            bool first)
        {
            return new ActivationOutcome(ActivationStatus.AwaitingSignature, request, used, allowed, expires, first);
        }

        public static ActivationOutcome Issued(
            ActivationStatus status,
            SigningRequestRow request,
            int used,
            int allowed,
            DateTimeOffset expires)
        {
            if (request?.Licence == null)
            {
                throw new ArgumentException("an issued activation must carry a signed licence", nameof(request));
            }

            return new ActivationOutcome(status, request, used, allowed, expires, status == ActivationStatus.NewActivation);
        }
    }

    /// <summary>One row of signing_requests: what has to be signed, and what came back.</summary>
    public sealed class SigningRequestRow
    {
        public SigningRequestRow(
            string requestId,
            long activationId,
            string licensee,
            string serverId,
            string issuedAt,
            string expires,
            string requested,
            string licence,
            string keyId,
            string fingerprint,
            string signed)
        {
            RequestId = requestId;
            ActivationId = activationId;
            Licensee = licensee;
            ServerId = serverId;
            IssuedAt = issuedAt;
            Expires = expires;
            Requested = requested;
            Licence = licence;
            KeyId = keyId;
            Fingerprint = fingerprint;
            Signed = signed;
        }

        public string RequestId { get; }

        public long ActivationId { get; }

        public string Licensee { get; }

        public string ServerId { get; }

        public string IssuedAt { get; }

        public string Expires { get; }

        public string Requested { get; }

        /// <summary>Null until somebody with the key has signed and uploaded it.</summary>
        public string Licence { get; }

        public string KeyId { get; }

        public string Fingerprint { get; }

        public string Signed { get; }

        public bool IsSigned => Licence != null;

        /// <summary>The shape this row takes in the file the signing machine reads.</summary>
        public SigningRequest ToExchange()
        {
            return new SigningRequest
            {
                RequestId = RequestId,
                Licensee = Licensee,
                ServerId = ServerId,
                IssuedAt = IssuedAt,
                Expires = Expires,
            };
        }
    }

    /// <summary>What happened when a signed licence was uploaded.</summary>
    public enum StoreSignedResult
    {
        /// <summary>The upload names a request this service has never made. Refused.</summary>
        NoSuchRequest = 0,

        /// <summary>Stored, and the customer gets it on their next activation.</summary>
        Stored = 1,

        /// <summary>
        /// This request already holds a DIFFERENT licence. Refused rather than
        /// overwritten: the customer is already using the one that is there.
        /// </summary>
        AlreadySigned = 2,

        /// <summary>
        /// The same licence again - the operator uploaded the same file twice.
        /// Not an error; nothing changed and nothing is broken.
        /// </summary>
        AlreadyTheSame = 3,
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

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Emby.Sso.Licensing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.LicenceTool
{
    /// <summary>
    /// Mints the licences the plugin checks. The vendor runs this; an operator
    /// never sees it.
    ///
    /// It is a separate program on purpose. The private key it holds is the only
    /// thing the whole scheme rests on, and the smallest possible amount of code
    /// should be able to touch it - certainly not a plugin that gets copied onto
    /// other people's servers.
    ///
    /// The three constants below are duplicated from
    /// <c>Emby.Sso.Protocol.LicenceCheck</c> rather than shared, because sharing
    /// them would mean this project referencing the plugin and the plugin's
    /// dependency graph. They must stay character-identical to it: a mismatch
    /// makes every licence this tool issues fail validation with "wrong issuer",
    /// which is at least a loud failure rather than a quiet one.
    /// </summary>
    internal static class Program
    {
        private const string Issuer = "urn:emby-sso:licence";
        private const string Algorithm = SecurityAlgorithms.RsaSha256;

        /// <summary>
        /// Duplicated from <c>LicenceCheck.ClockSkew</c>, for the same reason as
        /// the two constants above. Only <c>show</c> reads it, and only so that
        /// this tool calls a licence expired at the same moment the plugin does.
        /// </summary>
        private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);

        private const string PrivateKeyFileName = "licence-signing-key.private.json";

        /// <summary>
        /// The ledger `issue` appends to, alongside the private key by default.
        /// One JSON object per line: appending a record never rewrites the ones
        /// already there, a half-written line costs one record rather than the
        /// file, and it stays readable with `cat` on a day when this tool is the
        /// thing that is broken.
        /// </summary>
        private const string LedgerFileName = "licences-issued.jsonl";

        /// <summary>
        /// The default for <c>list --soon</c>, matching
        /// <c>LicenceCheck.ExpiryWarningWindow</c>: 21 days before expiry is
        /// when the customer's own server starts warning them in its log, so it
        /// is when the vendor wants to have already acted.
        /// </summary>
        private const int DefaultSoonDays = 21;

        private const string Usage = @"Emby SSO licence tool

  keygen --out <directory> [--allow-git]
      Generates a 3072-bit RSA signing keypair. Writes the PRIVATE key to
      <directory>/" + PrivateKeyFileName + @" and prints the PUBLIC key as a
      one-line JWK to paste into src/Emby.Sso/Protocol/LicencePublicKey.cs.
      Run this ONCE. Every licence already issued dies with the key.

  issue --key <private key file> --server-id <id> --licensee <name> --days <n>
        [--ledger <file>] [--allow-git]
      Prints a licence for one Emby server. The server id is the ServerId
      Emby logs at startup (IApplicationHost.SystemId). Appends a record to
      the ledger, which defaults to " + LedgerFileName + @" beside the key.

  list --ledger <file> [--soon <days>] [--all]
      Who holds a licence, soonest expiry first. --soon sets how many days
      ahead counts as lapsing (default 21 - the same window in which the
      customer's own server has started warning them). --all lists
      superseded records too.

  sign --requests <file> --key <private key file> [--out <file>]
       [--ledger <file>] [--allow-git]
      THE NORMAL WAY LICENCES ARE MADE. Signs every request in the file the
      licence service's admin page handed you, and writes a file to upload
      back to it. Run this on the machine the key lives on - the service
      cannot sign, because it does not have the key. --out defaults to the
      requests file with -signed before its extension.

  sign-release --dll <file> --version <x.y.z> --url <https address>
               --key <release key file> [--out <file>] [--allow-git]
      Signs a plugin release: this version, this file's SHA-256, at this
      address. THE RELEASE KEY IS NOT THE LICENCE KEY - a manifest authorises
      CODE to run on every customer's server, so it is signed with a key that
      never goes near a server or a CI variable. Upload the result on the
      service's admin page, under Release.

  show --key <key file> [--licence <file>] [--server-id <id>]
      Reads a licence from --licence or stdin, VERIFIES ITS SIGNATURE against
      the public half of --key, and prints what it says. Prints nothing out of
      a licence that does not verify. --key takes the private key file or a
      public JWK; the private half is never used or printed.

See README.md in this directory for where the private key and the ledger live.";

        private static async Task<int> Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    Console.WriteLine(Usage);
                    return 1;
                }

                switch (args[0])
                {
                    case "keygen":
                        return KeyGen(Parse(args));

                    case "issue":
                        return Issue(Parse(args));

                    case "list":
                        return List(Parse(args));

                    case "sign":
                        return Sign(Parse(args));

                    case "sign-release":
                        return SignRelease(Parse(args));

                    case "show":
                        return await Show(Parse(args)).ConfigureAwait(false);

                    default:
                        Console.Error.WriteLine("unknown command '" + args[0] + "'");
                        Console.WriteLine(Usage);
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        }

        private static int KeyGen(IDictionary<string, string> options)
        {
            var directory = Required(options, "out");

            // 3072 bits, not 2048. This key signs for years, it is verified on a
            // machine that does it once per sign-in, and the only cost of the
            // larger key is a longer licence string - which an operator pastes
            // once. There is no reason to pick the smaller one.
            using var rsa = RSA.Create(3072);

            var path = Path.GetFullPath(Path.Combine(directory, PrivateKeyFileName));

            RefuseToWriteInsideAGitRepository(
                path,
                options.ContainsKey("allow-git"),
                "a signing key",
                "A private key that reaches a commit has to be treated as leaked.");

            if (File.Exists(path))
            {
                // Never overwrite. Every licence ever issued is verified against
                // the public half of the key that is already there; replacing it
                // by accident invalidates all of them at once.
                throw new InvalidOperationException(
                    path + " already exists. Refusing to overwrite a signing key - "
                    + "every licence issued with it would stop validating.");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path));

            var p = rsa.ExportParameters(true);

            File.WriteAllText(path, Json(new Dictionary<string, string>
            {
                ["kty"] = "RSA",
                ["n"] = Base64UrlEncoder.Encode(p.Modulus),
                ["e"] = Base64UrlEncoder.Encode(p.Exponent),
                ["d"] = Base64UrlEncoder.Encode(p.D),
                ["p"] = Base64UrlEncoder.Encode(p.P),
                ["q"] = Base64UrlEncoder.Encode(p.Q),
                ["dp"] = Base64UrlEncoder.Encode(p.DP),
                ["dq"] = Base64UrlEncoder.Encode(p.DQ),
                ["qi"] = Base64UrlEncoder.Encode(p.InverseQ),
            }));

            // Owner-only. Not a substitute for keeping the file somewhere
            // sensible, but it stops the obvious accident of a world-readable
            // signing key in a shared home directory.
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            var publicKey = Json(new Dictionary<string, string>
            {
                ["kty"] = "RSA",
                ["n"] = Base64UrlEncoder.Encode(p.Modulus),
                ["e"] = Base64UrlEncoder.Encode(p.Exponent),
            });

            Console.WriteLine("Private key written to " + path);
            Console.WriteLine("  Back it up. Losing it means no further licence can ever be issued");
            Console.WriteLine("  for the builds that carry the matching public key.");
            Console.WriteLine("  Keep it OFF any machine that serves traffic. Nothing on the internet");
            Console.WriteLine("  needs this file: the licence service signs nothing.");
            Console.WriteLine();
            Console.WriteLine("Key id   : " + LicenceFormat.KeyId(publicKey));
            Console.WriteLine("  Every licence this key signs carries that name in its `kid` header, so a");
            Console.WriteLine("  build can trust several keys at once and retire one without invalidating");
            Console.WriteLine("  licences signed by the others. That is how a rotation is survivable.");
            Console.WriteLine();
            Console.WriteLine("ADD this PUBLIC key to the trusted set in");
            Console.WriteLine("src/Emby.Sso/Protocol/LicencePublicKey.cs, and to LICENCE_PUBLIC_KEYS on");
            Console.WriteLine("the licence service. ADD - removing the key that is there is what revokes");
            Console.WriteLine("it, and every licence it signed dies with it.");
            Console.WriteLine();
            Console.WriteLine(publicKey);
            Console.WriteLine();

            return 0;
        }

        private static int Issue(IDictionary<string, string> options)
        {
            var keyFile = Required(options, "key");
            var serverId = Required(options, "server-id").Trim();
            var licensee = Required(options, "licensee").Trim();
            var days = int.Parse(Required(options, "days"), CultureInfo.InvariantCulture);

            if (days <= 0)
            {
                throw new ArgumentException("--days must be a positive number; a licence must expire");
            }

            if (serverId.Length == 0 || licensee.Length == 0)
            {
                throw new ArgumentException("--server-id and --licensee must not be empty");
            }

            var key = new JsonWebKey(File.ReadAllText(keyFile));

            if (string.IsNullOrEmpty(key.D))
            {
                throw new ArgumentException(
                    keyFile + " carries no private key material - this is the PUBLIC half, which cannot sign.");
            }

            // Names the key in the licence's `kid` header. Without it the
            // licence cannot be told apart from one signed by any other key the
            // plugin trusts, and retiring a key would mean guessing.
            key.Kid = LicenceFormat.KeyId(LicenceFormat.PublicJwk(key.N, key.E));

            var now = DateTime.UtcNow;
            var expires = now.AddDays(days);

            // `sub` is the licensee, `aud` the one server this is good for, and
            // exp/iat/nbf are the standard lifetime claims - all of them
            // registered claims, so the plugin's validator enforces them through
            // the library rather than by re-reading the payload itself.
            var payload = Json(new Dictionary<string, object>
            {
                ["iss"] = Issuer,
                ["sub"] = licensee,
                ["aud"] = serverId,
                ["iat"] = EpochTime.GetIntDate(now),
                ["nbf"] = EpochTime.GetIntDate(now),
                ["exp"] = EpochTime.GetIntDate(expires),
            });

            var licence = new JsonWebTokenHandler().CreateToken(
                payload,
                new SigningCredentials(key, Algorithm));

            // The record goes in before the licence is printed, so that a
            // problem with the ledger is on screen above the thing the operator
            // is about to copy out - not scrolled off the top by it.
            var ledgerPath = LedgerPathFor(options, keyFile);
            var recorded = Record(ledgerPath, options.ContainsKey("allow-git"), new Dictionary<string, object>
            {
                ["issued_at"] = Iso(now),
                ["expires_at"] = Iso(expires),
                ["days"] = days,
                ["licensee"] = licensee,
                ["server_id"] = serverId,

                // Identifies the licence without being one. See the note on
                // Fingerprint: the ledger deliberately does not hold the licence
                // itself, so this is what matches a string a tester emails back
                // (`show` prints the same fingerprint) to a row in the ledger.
                ["fingerprint"] = Fingerprint(licence),
            });

            Console.Error.WriteLine("Licensee : " + licensee);
            Console.Error.WriteLine("Server   : " + serverId);
            Console.Error.WriteLine("Key      : " + key.Kid);
            Console.Error.WriteLine("Expires  : " + expires.ToString("u", CultureInfo.InvariantCulture));
            Console.Error.WriteLine("Ledger   : " + (recorded ? ledgerPath : "NOT RECORDED - see above"));
            Console.Error.WriteLine();

            // The licence itself goes to stdout alone, so it can be redirected
            // to a file or piped without the summary above coming with it.
            Console.WriteLine(licence);

            return 0;
        }

        /// <summary>
        /// Signs a batch of licences the service asked for, on a machine the
        /// service cannot reach.
        ///
        /// WHY THIS COMMAND EXISTS. The licence service used to hold the private
        /// key and mint licences itself, which meant the key that signs for
        /// every customer sat on a host with a port open to the internet: one
        /// container escape, one dependency CVE, one stolen deploy token, and
        /// the whole scheme is gone with no way to tell which licences were
        /// genuine. It does not hold the key any more. It records what was paid
        /// for and hands out a file of requests; this turns that file into
        /// licences; the operator uploads the result. The service can be
        /// compromised completely without a single forgeable licence coming out
        /// of it, because there is nothing there to forge with.
        ///
        /// The cost is honest and worth stating: a customer's activation is no
        /// longer instant. It waits for a person to run this.
        ///
        /// Every request is signed or the file is refused. A partial batch would
        /// mean an operator uploading a file they believe is complete while some
        /// customers keep waiting with nothing on screen to say which.
        /// </summary>
        private static int Sign(IDictionary<string, string> options)
        {
            var requestsPath = Path.GetFullPath(Required(options, "requests"));
            var keyFile = Required(options, "key");

            if (!File.Exists(requestsPath))
            {
                throw new FileNotFoundException(
                    "No requests file at " + requestsPath + "." + Environment.NewLine
                    + "It is the file the licence service's admin page downloads, under Signing.");
            }

            // The same loader the service used to use at startup: owner-only
            // permissions, private half present, and never inside a git working
            // tree. A signing machine deserves those checks more than a server
            // did, not less.
            var key = SigningKeyFile.Load(keyFile);
            var requests = SigningExchange.ReadRequests(File.ReadAllText(requestsPath));

            if (requests.Requests.Count == 0)
            {
                Console.Error.WriteLine("That file asks for nothing. Nobody is waiting.");

                return 0;
            }

            var issuer = new LicenceIssuer(key.Key);
            var signed = new SignedLicenceFile
            {
                SignedUtc = LicenceFormat.Iso(DateTimeOffset.UtcNow),
                KeyId = key.Thumbprint,
            };

            var ledgerPath = LedgerPathFor(options, keyFile);
            // Fully qualified: this file has its own LedgerRecord, read by
            // `list`, and the two are different types for the same lines.
            var ledger = new Emby.Sso.Licensing.LicenceLedger(ledgerPath);
            var recorded = 0;

            foreach (var request in requests.Requests)
            {
                var licence = issuer.Issue(
                    request.Licensee,
                    request.ServerId,
                    request.IssuedAtUtc,
                    request.ExpiresUtc);

                signed.Licences.Add(new SignedLicence
                {
                    RequestId = request.RequestId,
                    Licence = licence.Token,
                });

                // Not fatal. The licence is already made and the customer is
                // waiting for it; what is lost if this fails is the vendor's own
                // `list` view, and that is worth a warning rather than a refusal
                // to hand over what somebody paid for.
                if (ledger.TryAppend(new Emby.Sso.Licensing.LedgerRecord(licence), out var error))
                {
                    recorded++;
                }
                else
                {
                    Console.Error.WriteLine("WARNING: the ledger at " + ledgerPath + " was not appended to: " + error);
                }
            }

            var outPath = options.TryGetValue("out", out var given) && !string.IsNullOrWhiteSpace(given)
                ? Path.GetFullPath(given)
                : DefaultSignedPath(requestsPath);

            RefuseToWriteInsideAGitRepository(
                outPath,
                options.ContainsKey("allow-git"),
                "signed licences",
                "Every licence in it is a live credential.");

            File.WriteAllText(outPath, SigningExchange.Write(signed));

            if (!OperatingSystem.IsWindows())
            {
                // Owner-only: this file is a stack of live credentials until it
                // has been uploaded, and it usually lands in a downloads folder.
                File.SetUnixFileMode(outPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            Console.Error.WriteLine("Signed   : " + signed.Licences.Count.ToString(CultureInfo.InvariantCulture)
                + " licence(s) with key " + key.Thumbprint);
            Console.Error.WriteLine("Ledger   : " + recorded.ToString(CultureInfo.InvariantCulture) + " recorded in " + ledgerPath);
            Console.Error.WriteLine();
            Console.Error.WriteLine("Upload this file on the service's admin page, under Signing:");
            Console.Error.WriteLine();
            Console.WriteLine(outPath);
            Console.Error.WriteLine();
            Console.Error.WriteLine("Then delete it. Until it is uploaded it is the only copy of those licences;");
            Console.Error.WriteLine("afterwards it is a stack of somebody else's credentials in your downloads.");

            return 0;
        }

        /// <summary>
        /// <c>requests.json</c> becomes <c>requests-signed.json</c>, beside it.
        /// Never the same name: overwriting the requests with the answer to them
        /// loses the only record of what was asked for if the upload fails.
        /// </summary>
        private static string DefaultSignedPath(string requestsPath)
        {
            var directory = Path.GetDirectoryName(requestsPath);
            var name = Path.GetFileNameWithoutExtension(requestsPath);
            var extension = Path.GetExtension(requestsPath);

            return Path.Combine(directory ?? ".", name + "-signed" + (string.IsNullOrEmpty(extension) ? ".json" : extension));
        }

        /// <summary>
        /// Signs a plugin release.
        ///
        /// THIS IS THE MOST DANGEROUS COMMAND IN THIS TOOL. What it signs will
        /// be downloaded by every customer's Emby server, written into the
        /// plugins directory, and executed. A mistake here is not a lost sale;
        /// it is somebody else's media server running whatever was named.
        ///
        /// So it hashes the file ITSELF rather than taking a hash on the command
        /// line. A hash somebody typed or pasted is a hash that can be the wrong
        /// one - copied from a different build, from a stale release note, from
        /// a terminal that wrapped a line - and the resulting manifest would be
        /// signed, valid, and point at bytes nobody checked.
        ///
        /// The key must be the RELEASE key. Nothing here can tell one keypair
        /// from another, so that is the operator's discipline and the reason the
        /// two live in different directories.
        /// </summary>
        private static int SignRelease(IDictionary<string, string> options)
        {
            var dllPath = Path.GetFullPath(Required(options, "dll"));
            var version = Required(options, "version").Trim();
            var url = Required(options, "url").Trim();
            var keyFile = Required(options, "key");

            if (!File.Exists(dllPath))
            {
                throw new FileNotFoundException("No file at " + dllPath + " to sign for.");
            }

            if (!System.Version.TryParse(version, out _))
            {
                throw new ArgumentException(
                    "--version must be a version the plugin can compare, like 1.0.3. It is what stops an older "
                    + "release being offered as an update.");
            }

            var key = SigningKeyFile.Load(keyFile);

            string hash;

            using (var sha = SHA256.Create())
            using (var file = File.OpenRead(dllPath))
            {
                hash = Convert.ToHexString(sha.ComputeHash(file)).ToLowerInvariant();
            }

            var manifest = ReleaseManifest.Issue(key.Key, version, hash, url, DateTimeOffset.UtcNow);

            var outPath = options.TryGetValue("out", out var given) && !string.IsNullOrWhiteSpace(given)
                ? Path.GetFullPath(given)
                : null;

            Console.Error.WriteLine("Version  : " + version);
            Console.Error.WriteLine("File     : " + dllPath);
            Console.Error.WriteLine("SHA-256  : " + hash);
            Console.Error.WriteLine("URL      : " + url);
            Console.Error.WriteLine("Signed by: " + key.Thumbprint + "  (this must be the RELEASE key, not the licence key)");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Upload this on the service's admin page, under Release. Customers are");
            Console.Error.WriteLine("offered it on their next daily check, and install it when they choose.");
            Console.Error.WriteLine();

            if (outPath == null)
            {
                // stdout alone, so it can be redirected or piped without the
                // summary above coming with it.
                Console.WriteLine(manifest);
            }
            else
            {
                RefuseToWriteInsideAGitRepository(outPath, options.ContainsKey("allow-git"), "a release manifest", "It is not secret, but it does not belong in a commit either.");
                File.WriteAllText(outPath, manifest);
                Console.WriteLine(outPath);
            }

            return 0;
        }

        private static int List(IDictionary<string, string> options)
        {
            var path = Path.GetFullPath(Required(options, "ledger"));
            var soon = TimeSpan.FromDays(OptionalDays(options, "soon", DefaultSoonDays));
            var now = DateTimeOffset.UtcNow;

            if (!File.Exists(path))
            {
                throw new FileNotFoundException(
                    "No ledger at " + path + "." + Environment.NewLine
                    + "Nothing has been issued yet, or --ledger points somewhere other than beside the signing key.");
            }

            var records = ReadLedger(path);

            if (records.Count == 0)
            {
                Console.WriteLine("Ledger " + path + " holds no records.");
                return 0;
            }

            // A reissue - a tester who lost their licence, or one renewed before
            // it lapsed - is a second record for the same holder. The vendor
            // wants one line per holder showing the licence that is actually
            // live, so the newest expiry wins and the older ones are counted
            // rather than listed. --all shows every record instead.
            var rows = options.ContainsKey("all")
                ? records.Select(r => new Row(r, 0)).ToList()
                : records
                    .GroupBy(r => r.Licensee + " " + r.ServerId, StringComparer.OrdinalIgnoreCase)
                    .Select(g => new Row(g.OrderByDescending(r => r.ExpiresAt).First(), g.Count() - 1))
                    .ToList();

            // Soonest expiry first: everything that needs attention - already
            // lapsed, then lapsing next - is at the top, and the long tail of
            // licences that are fine is what scrolls off the bottom.
            rows = rows.OrderBy(r => r.Record.ExpiresAt).ThenBy(r => r.Record.Licensee, StringComparer.OrdinalIgnoreCase).ToList();

            var lapsed = 0;
            var lapsing = 0;

            Console.WriteLine("Ledger : " + path);
            Console.WriteLine("As of  : " + Iso(now.UtcDateTime) + "   lapsing = within " + soon.TotalDays.ToString("0", CultureInfo.InvariantCulture) + " days");
            Console.WriteLine();
            // Built with the same padding as the rows below it, so a change to
            // one column cannot leave the header describing a different one.
            Console.WriteLine(
                "STATUS".PadRight(9) + "EXPIRES".PadRight(12) + "IN DAYS".PadLeft(7)
                + "  " + "LICENSEE".PadRight(24) + "  SERVER");

            foreach (var row in rows)
            {
                var remaining = row.Record.ExpiresAt - now;
                var status = "active";

                if (remaining < TimeSpan.Zero)
                {
                    status = "LAPSED";
                    lapsed++;
                }
                else if (remaining <= soon)
                {
                    status = "LAPSING";
                    lapsing++;
                }

                // Truncating towards zero, so "0" means today rather than a day
                // either side of it being rounded into the wrong bucket.
                var inDays = (int)remaining.TotalDays;

                Console.WriteLine(
                    status.PadRight(9)
                    + row.Record.ExpiresAt.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture).PadRight(12)
                    + inDays.ToString(CultureInfo.InvariantCulture).PadLeft(7)
                    + "  " + row.Record.Licensee.PadRight(24)
                    + "  " + row.Record.ServerId
                    + (row.Superseded > 0
                        ? "  (+" + row.Superseded.ToString(CultureInfo.InvariantCulture) + " earlier)"
                        : string.Empty));
            }

            Console.WriteLine();
            Console.WriteLine(
                rows.Count.ToString(CultureInfo.InvariantCulture) + (options.ContainsKey("all") ? " records" : " holders")
                + ": " + lapsed.ToString(CultureInfo.InvariantCulture) + " lapsed, "
                + lapsing.ToString(CultureInfo.InvariantCulture) + " lapsing, "
                + (rows.Count - lapsed - lapsing).ToString(CultureInfo.InvariantCulture) + " active.");

            if (!options.ContainsKey("all"))
            {
                Console.WriteLine("There is no revocation: a lapsed holder is fixed by issuing again, not by editing this file.");
            }

            return 0;
        }

        /// <summary>
        /// Answers "is this person's licence genuine, and what does it say?" for
        /// a string a tester emailed back.
        ///
        /// THE POINT OF THIS COMMAND IS THE SIGNATURE CHECK. Anyone can write a
        /// JWT payload that says whatever they like and base64 it; a tool that
        /// decodes and prints one is a tool that teaches its operator to believe
        /// forgeries. So this runs the same validation the plugin runs - the
        /// signature against the vendor's public key, `alg` pinned to RS256 so
        /// the public key cannot be turned into an HMAC secret, unsigned tokens
        /// refused outright - and prints NOTHING out of a token that fails it.
        ///
        /// It differs from the plugin's check in exactly two places, both
        /// deliberate and neither weakening the signature:
        ///
        ///   * the audience is reported rather than enforced, because this tool
        ///     has no server of its own to be the audience. `--server-id`
        ///     compares it when the caller knows what it should be.
        ///   * expiry is reported rather than enforced, because "your licence
        ///     expired three weeks ago" is the answer the operator came for, and
        ///     it can only be given by reading a token that failed on lifetime.
        ///     A signature failure is never reported this way.
        /// </summary>
        private static async Task<int> Show(IDictionary<string, string> options)
        {
            var keyFile = Required(options, "key");
            var licence = ReadLicence(options);
            var publicKey = PublicHalfOf(keyFile);
            var now = DateTimeOffset.UtcNow;

            var parameters = new TokenValidationParameters
            {
                IssuerSigningKey = publicKey,
                ValidIssuer = Issuer,

                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,

                // See the method comment. Reported below, not enforced here.
                ValidateAudience = false,
                ValidateLifetime = false,

                // These two are the whole guarantee, and are the same fixed
                // values the plugin uses. ValidAlgorithms must stay a
                // one-element array: an EMPTY ValidAlgorithms is read by the
                // handler as "no restriction".
                ValidAlgorithms = new[] { Algorithm },
                RequireSignedTokens = true,
            };

            TokenValidationResult result;

            try
            {
                result = await new JsonWebTokenHandler().ValidateTokenAsync(licence, parameters).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return Refuse(null, "this is not a readable JWT at all (" + ex.GetType().Name + ")");
            }

            if (!result.IsValid)
            {
                return Refuse(result.Exception, "the token failed validation");
            }

            if (!(result.SecurityToken is JsonWebToken token))
            {
                // Cannot happen for a JWT string. A refusal rather than a cast
                // exception if the library ever changes what it hands back.
                return Refuse(null, "the token validated to something that is not a JWT");
            }

            var expires = token.TryGetClaim(JwtRegisteredClaimNames.Exp, out _) ? (DateTimeOffset?)token.ValidTo : null;
            var issued = token.TryGetClaim(JwtRegisteredClaimNames.Iat, out _) ? (DateTimeOffset?)token.IssuedAt : null;
            var audience = token.Audiences == null ? null : token.Audiences.FirstOrDefault();

            Console.WriteLine("Signature   : VERIFIED against " + Path.GetFullPath(keyFile));
            Console.WriteLine("Licensee    : " + Or(token.Subject, "(none - not a licence this tool issued)"));
            Console.WriteLine("Server      : " + Or(audience, "(none - not a licence this tool issued)"));
            Console.WriteLine("Issued      : " + (issued.HasValue ? Iso(issued.Value.UtcDateTime) : "(none)"));
            Console.WriteLine("Expires     : " + (expires.HasValue ? Iso(expires.Value.UtcDateTime) : "(none)"));
            Console.WriteLine("Fingerprint : " + Fingerprint(licence));

            // Every reason the plugin would refuse this licence, in the order
            // the plugin would find them, so that "it says my licence is
            // invalid" gets a specific answer rather than "looks fine to me".
            var problems = new List<string>();

            if (!expires.HasValue)
            {
                problems.Add("it carries no expiry, which the plugin refuses");
            }
            else if (expires.Value < now - ClockSkew)
            {
                problems.Add("it EXPIRED " + Days(now - expires.Value) + " ago");
            }

            if (issued.HasValue && issued.Value > now + ClockSkew)
            {
                problems.Add("it is dated in the future, which the plugin refuses");
            }

            if (token.ValidFrom != DateTime.MinValue && ToOffset(token.ValidFrom) > now + ClockSkew)
            {
                problems.Add("it is not valid until " + Iso(token.ValidFrom));
            }

            var expected = options.TryGetValue("server-id", out var serverId) && !string.IsNullOrWhiteSpace(serverId)
                ? serverId.Trim()
                : null;

            if (string.IsNullOrEmpty(audience))
            {
                problems.Add("it names no server, so no server would accept it");
            }
            else if (expected != null && !string.Equals(expected, audience, StringComparison.Ordinal))
            {
                problems.Add("it is for another server, not " + expected);
            }

            Console.WriteLine();

            if (problems.Count == 0)
            {
                Console.WriteLine(
                    "VALID"
                    + (expires.HasValue ? " - expires in " + Days(expires.Value - now) : string.Empty)
                    + (expected != null ? ", and is for that server." : "."));

                if (expected == null)
                {
                    Console.WriteLine(
                        "The server binding was not checked: pass --server-id <id> to confirm it is the"
                        + Environment.NewLine
                        + "server the customer is actually running it on.");
                }

                return 0;
            }

            Console.WriteLine("NOT USABLE, though it is genuinely signed by this key:");

            foreach (var problem in problems)
            {
                Console.WriteLine("  - " + problem);
            }

            Console.WriteLine();
            Console.WriteLine("Issue a new licence for the same server id; there is nothing to revoke.");

            return 1;
        }

        /// <summary>
        /// The refusal path. It prints no claim from the token, on purpose: the
        /// contents of a token whose signature did not verify are whatever its
        /// author chose to write, and showing them next to the word "licensee"
        /// is how an operator ends up believing one.
        /// </summary>
        private static int Refuse(Exception ex, string fallback)
        {
            // The library's own message runs to a dozen lines about kids and
            // PII redaction, none of which answers the operator's question. Say
            // which of the refusals this was in one line, and keep the library's
            // first line under it for the case where it is something else.
            string headline;

            // Two banners, because the difference matters to whoever reads this
            // over the operator's shoulder: "someone forged this" and "this is
            // signed but is not a licence" are not the same accusation.
            var banner = "SIGNATURE NOT VERIFIED - this was not issued with this key.";

            switch (ex)
            {
                // SecurityTokenSignatureKeyNotFoundException derives from this
                // one, so both the "wrong key" and the "no signature" refusals
                // land here, which is right: they mean the same thing.
                case SecurityTokenInvalidSignatureException _:
                    headline = "the signature does not match this key, or there is no signature at all";
                    break;

                case SecurityTokenInvalidAlgorithmException _:
                    headline = "it is signed with an algorithm this scheme does not accept - only RS256 is";
                    break;

                case SecurityTokenInvalidIssuerException _:
                    banner = "REFUSED - this is signed by this key, but it is not a licence.";
                    headline = "the issuer claim is not " + Issuer;
                    break;

                default:
                    headline = ex == null ? fallback : ex.GetType().Name;
                    break;
            }

            Console.Error.WriteLine(banner);
            Console.Error.WriteLine("  " + headline);

            if (ex != null)
            {
                Console.Error.WriteLine("  (" + FirstLine(ex.Message) + ")");
            }

            Console.Error.WriteLine();
            Console.Error.WriteLine("Nothing inside it is printed. An unverified token says whatever its author");
            Console.Error.WriteLine("chose to put in it, including someone else's name and any expiry date.");
            return 1;
        }

        private static string FirstLine(string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                return "no detail";
            }

            var end = message.IndexOfAny(new[] { '\r', '\n' });

            return end < 0 ? message : message.Substring(0, end);
        }

        private static string ReadLicence(IDictionary<string, string> options)
        {
            var licence = options.TryGetValue("licence", out var file) && !string.IsNullOrWhiteSpace(file)
                ? File.ReadAllText(file)
                : Console.In.ReadToEnd();

            // A licence arrives pasted out of an email, so it comes with
            // whatever whitespace and line ending came with it.
            licence = licence.Trim();

            if (licence.Length == 0)
            {
                throw new ArgumentException("no licence given - pass --licence <file>, or pipe one in on stdin");
            }

            return licence;
        }

        /// <summary>
        /// Reads the verifying key out of either half of the keypair: the
        /// private key file `keygen` wrote, or a public JWK. Only `n` and `e`
        /// are carried across, so the private exponent is never handed to the
        /// verifier and cannot be printed by anything downstream of here.
        /// </summary>
        private static JsonWebKey PublicHalfOf(string keyFile)
        {
            var key = new JsonWebKey(File.ReadAllText(keyFile));

            if (string.IsNullOrEmpty(key.N) || string.IsNullOrEmpty(key.E))
            {
                throw new ArgumentException(keyFile + " is not an RSA JWK - it carries no modulus and exponent.");
            }

            return new JsonWebKey(Json(new Dictionary<string, string>
            {
                ["kty"] = "RSA",
                ["n"] = key.N,
                ["e"] = key.E,
            }));
        }

        /// <summary>
        /// Where the ledger goes: beside the signing key unless told otherwise.
        /// The key is already somewhere the vendor decided was safe for a
        /// credential, and the ledger needs the same place for the same reason.
        /// </summary>
        private static string LedgerPathFor(IDictionary<string, string> options, string keyFile)
        {
            if (options.TryGetValue("ledger", out var explicitPath) && !string.IsNullOrWhiteSpace(explicitPath))
            {
                return Path.GetFullPath(explicitPath);
            }

            var directory = Path.GetDirectoryName(Path.GetFullPath(keyFile));

            return Path.Combine(directory, LedgerFileName);
        }

        /// <summary>
        /// Appends one record and returns whether it landed.
        ///
        /// EVERY failure here is a warning, not an error: losing the record of a
        /// licence is bad, and failing to issue one because a log file is
        /// unwritable is worse. The licence has already been signed by the time
        /// this runs, so throwing would lose it entirely. But nothing is
        /// swallowed - each failure says what happened and what the operator
        /// should write down by hand.
        /// </summary>
        private static bool Record(string path, bool allowGit, IDictionary<string, object> record)
        {
            try
            {
                // The ledger is a list of who holds a credential for which
                // server. That is not a thing to commit, for the same reason the
                // key is not, so the same refusal applies to it.
                RefuseToWriteInsideAGitRepository(
                    path,
                    allowGit,
                    "the licence ledger",
                    "It records who holds a licence for which server, which is not a thing to publish.");

                Directory.CreateDirectory(Path.GetDirectoryName(path));

                var line = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record) + "\n");

                var stream = new FileStreamOptions
                {
                    Mode = FileMode.Append,
                    Access = FileAccess.Write,

                    // Another `issue` may be appending at the same moment. Append
                    // mode plus a single write of one short line is what keeps
                    // the two from interleaving; the file is never opened for
                    // truncation, so a concurrent run cannot cost more than its
                    // own record.
                    Share = FileShare.ReadWrite,
                };

                if (!OperatingSystem.IsWindows())
                {
                    // Set at creation rather than chmod-ed afterwards, so there
                    // is no moment when the file exists at the umask default.
                    stream.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                }

                using (var file = new FileStream(path, stream))
                {
                    file.Write(line, 0, line.Length);
                }

                WarnIfReadableByAnyoneElse(path);

                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("WARNING: the licence below was NOT recorded in the ledger.");
                Console.Error.WriteLine("  " + path);
                Console.Error.WriteLine("  " + ex.Message);
                Console.Error.WriteLine("  Write down the licensee, server id and expiry by hand: there is no other");
                Console.Error.WriteLine("  record of this licence anywhere, and no way to ask a server what it holds.");
                Console.Error.WriteLine();

                return false;
            }
        }

        /// <summary>
        /// A ledger created before the mode above was set, or copied about with
        /// a permissive umask, is still a customer list readable by every
        /// account on the machine. Say so; do not silently fix it, because
        /// changing the mode of a file the operator deliberately shared is not
        /// this tool's decision to make.
        /// </summary>
        private static void WarnIfReadableByAnyoneElse(string path)
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            const UnixFileMode Others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

            if ((File.GetUnixFileMode(path) & Others) != 0)
            {
                Console.Error.WriteLine("WARNING: " + path + " is readable by other accounts on this machine.");
                Console.Error.WriteLine("  It lists who holds a licence for which server. chmod 600 it.");
                Console.Error.WriteLine();
            }
        }

        /// <summary>
        /// Reads the ledger back, skipping anything unreadable rather than
        /// failing on it - one corrupt line must not hide the other two hundred
        /// records - but naming every line it skipped on stderr, because a
        /// record that silently vanished from a list of who holds what is worse
        /// than a noisy one.
        /// </summary>
        private static IList<LedgerRecord> ReadLedger(string path)
        {
            var records = new List<LedgerRecord>();
            var lineNumber = 0;

            foreach (var line in File.ReadLines(path))
            {
                lineNumber++;

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    using var document = JsonDocument.Parse(line);
                    var root = document.RootElement;

                    records.Add(new LedgerRecord(
                        Text(root, "licensee"),
                        Text(root, "server_id"),
                        Time(root, "issued_at"),
                        Time(root, "expires_at"),
                        Text(root, "fingerprint")));
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(
                        "WARNING: skipping unreadable ledger line " + lineNumber.ToString(CultureInfo.InvariantCulture)
                        + " of " + path + ": " + ex.Message);
                }
            }

            return records;
        }

        private static string Text(JsonElement root, string name)
        {
            if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            {
                throw new FormatException("no '" + name + "' string in this record");
            }

            return value.GetString();
        }

        private static DateTimeOffset Time(JsonElement root, string name)
        {
            return DateTimeOffset.ParseExact(
                Text(root, name),
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        }

        /// <summary>
        /// What the ledger stores in place of the licence itself: a SHA-256 of
        /// the licence string.
        ///
        /// THE LICENCE IS DELIBERATELY NOT STORED. It is a live credential, and
        /// a file holding every credential ever issued is a much worse thing to
        /// lose than a list of names - while the only thing storing them buys is
        /// resending one to a tester who lost theirs, which `issue` already does
        /// in one command against the same server id. A fingerprint is one-way,
        /// so it is not a credential, and it still answers the question the
        /// ledger has to answer about a string someone emails back: which row is
        /// this, and did we issue it at all.
        /// </summary>
        private static string Fingerprint(string licence)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(licence));

            return "sha256:" + Convert.ToHexString(hash).ToLowerInvariant();
        }

        /// <summary>
        /// A signing key inside a git working tree is one <c>git add -A</c> away
        /// from being published, and there is no undoing that - a key in any
        /// commit that ever left the machine has to be treated as leaked, and
        /// every licence issued with it reissued. So this refuses rather than
        /// warns. The ledger goes through the same check for the same reason:
        /// it is a record of credentials, and the repository is public.
        ///
        /// <c>--allow-git</c> exists for the one legitimate case: a home
        /// directory that is itself a dotfiles repository. It is not an
        /// override to reach for otherwise, and the repository's own .gitignore
        /// covers both file names either way.
        /// </summary>
        private static void RefuseToWriteInsideAGitRepository(string path, bool allowed, string what, string why)
        {
            if (allowed)
            {
                return;
            }

            for (var directory = new DirectoryInfo(Path.GetDirectoryName(path)); directory != null; directory = directory.Parent)
            {
                var git = Path.Combine(directory.FullName, ".git");

                if (!Directory.Exists(git) && !File.Exists(git))
                {
                    continue;
                }

                throw new InvalidOperationException(
                    "Refusing to write " + what + " inside the git working tree at " + directory.FullName + "."
                    + Environment.NewLine
                    + why + " Choose a directory outside any repository - see "
                    + "tools/Emby.Sso.LicenceTool/README.md - or pass --allow-git if this directory really is "
                    + "not tracked.");
            }
        }

        private static string Json<T>(IDictionary<string, T> values)
        {
            return JsonSerializer.Serialize(values);
        }

        /// <summary>
        /// One timestamp format everywhere: UTC, seconds, no offset. It is what
        /// the ledger is parsed back with, so it has to be exact rather than
        /// whatever the machine's culture prints.
        /// </summary>
        private static string Iso(DateTime moment)
        {
            return moment.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        }

        private static string Days(TimeSpan span)
        {
            var days = (int)Math.Abs(span.TotalDays);

            return days == 1
                ? "1 day"
                : days.ToString(CultureInfo.InvariantCulture) + " days";
        }

        private static DateTimeOffset ToOffset(DateTime moment)
        {
            return new DateTimeOffset(DateTime.SpecifyKind(moment, DateTimeKind.Utc));
        }

        private static string Or(string value, string fallback)
        {
            return string.IsNullOrEmpty(value) ? fallback : value;
        }

        /// <summary>
        /// The smallest thing that reads <c>--name value</c> pairs. Flags with no
        /// value (<c>--allow-git</c>) are recorded as present with an empty
        /// value. Deliberately not a command-line library: one more dependency
        /// on the machine that holds the signing key is one more than this needs.
        /// </summary>
        private static IDictionary<string, string> Parse(string[] args)
        {
            var options = new Dictionary<string, string>(StringComparer.Ordinal);

            for (var i = 1; i < args.Length; i++)
            {
                if (!args[i].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException("unexpected argument '" + args[i] + "'");
                }

                var name = args[i].Substring(2);
                var hasValue = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal);

                options[name] = hasValue ? args[++i] : string.Empty;
            }

            return options;
        }

        private static string Required(IDictionary<string, string> options, string name)
        {
            if (!options.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("--" + name + " is required" + Environment.NewLine + Environment.NewLine + Usage);
            }

            return value;
        }

        private static int OptionalDays(IDictionary<string, string> options, string name, int fallback)
        {
            if (!options.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
            {
                return fallback;
            }

            var days = int.Parse(value, CultureInfo.InvariantCulture);

            if (days < 0)
            {
                throw new ArgumentException("--" + name + " must not be negative");
            }

            return days;
        }

        /// <summary>
        /// One line of the ledger. Every field is read, including the two
        /// `list` does not print: a record missing its issue time or its
        /// fingerprint was not written by `issue`, and saying so is more useful
        /// than quietly listing half a record.
        /// </summary>
        private sealed class LedgerRecord
        {
            public LedgerRecord(string licensee, string serverId, DateTimeOffset issuedAt, DateTimeOffset expiresAt, string fingerprint)
            {
                Licensee = licensee;
                ServerId = serverId;
                IssuedAt = issuedAt;
                ExpiresAt = expiresAt;
                Fingerprint = fingerprint;
            }

            public string Licensee { get; }

            public string ServerId { get; }

            public DateTimeOffset IssuedAt { get; }

            public DateTimeOffset ExpiresAt { get; }

            public string Fingerprint { get; }
        }

        /// <summary>
        /// A record as `list` prints it, with the number of earlier licences for
        /// the same holder that this one supersedes.
        /// </summary>
        private sealed class Row
        {
            public Row(LedgerRecord record, int superseded)
            {
                Record = record;
                Superseded = superseded;
            }

            public LedgerRecord Record { get; }

            public int Superseded { get; }
        }
    }
}

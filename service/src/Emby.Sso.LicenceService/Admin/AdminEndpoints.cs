using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.Management;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Emby.Sso.LicenceService.Admin
{
    /// <summary>
    /// /admin - the four management commands and `issue-code`, with a browser in
    /// front of them.
    ///
    /// READ THIS BEFORE CHANGING ANYTHING HERE. This is the first
    /// internet-facing door to a host that holds the private signing key.
    /// Whoever gets through it can mint a licence for any Emby server, for any
    /// duration, and nothing recalls one: the plugin verifies offline against a
    /// key compiled into it and never calls home. The password is the entire
    /// barrier. The operator was offered a loopback-only page reached over an
    /// SSH tunnel, and an IP allowlist at the proxy, and chose this with the
    /// trade-off explained.
    ///
    /// THE PAGE DOES NOT EXIST UNLESS IT IS CONFIGURED. <see cref="Map"/> is
    /// only called when a password is set, so with none set there is no route,
    /// no login form and no 401 - /admin answers exactly what /nonsense answers,
    /// and nothing about this service tells a scanner that an admin page is one
    /// configuration change away.
    ///
    /// WHAT GUARDS EACH REQUEST, in the order it runs:
    ///
    ///   1. A session cookie that names server-side state. No state, no request:
    ///      there is nothing in the cookie to forge.
    ///   2. For anything that changes something, a CSRF token bound to that
    ///      session, compared in constant time. SameSite=Strict is set as well
    ///      and is not what is relied on - see AdminSession.CsrfToken.
    ///   3. For issuing and revealing, a one-shot form nonce, so a double-tapped
    ///      button cannot mint two credentials.
    ///   4. On the login itself, a budget of its own that has nothing to do with
    ///      /v1/activate's - see <see cref="AdminLoginThrottle"/>.
    ///
    /// AND WHAT NEVER HAPPENS HERE: no redemption code goes into a URL, a
    /// redirect, a log line or the audit trail. The two pages that show a code
    /// show one that has just been created or just been read back out of the
    /// outbox, carried from the POST that produced it in server-side session
    /// state that the first render consumes.
    /// </summary>
    internal static class AdminEndpoints
    {
        private const string CodesPath = "/admin/codes";

        /// <summary>
        /// The most a signed-licence upload may be. A batch is capped at 500
        /// licences by SigningExchange and a licence is under a kilobyte, so
        /// this is generous - it exists so that an authenticated operator with a
        /// wrong file cannot make the service read an arbitrary amount into
        /// memory.
        /// </summary>
        private const long MaximumUploadBytes = 4 * 1024 * 1024;

        /// <summary>
        /// The most a plugin upload may be. The merged DLL is single-figure
        /// megabytes; this is room to grow and still small enough that the
        /// container cannot be made to hold an unreasonable amount, because the
        /// file is read whole in order to hash it.
        /// </summary>
        private const long MaximumReleaseBytes = 32 * 1024 * 1024;

        /// <summary>
        /// Multipart framing, the other fields, and the boundary markers, on top
        /// of the file itself. Small and fixed: the limit exists to bound the
        /// request, not to be exact about it.
        /// </summary>
        private const long UploadOverheadBytes = 64 * 1024;

        public static void Map(WebApplication app, ServiceOptions options, AdminPassword password, AdminAccessGate gate)
        {
            var sessions = app.Services.GetRequiredService<AdminSessions>();
            var throttle = app.Services.GetRequiredService<AdminLoginThrottle>();
            var verificationGate = app.Services.GetRequiredService<PasswordVerificationGate>();
            var audit = app.Services.GetRequiredService<AdminAudit>();
            var store = app.Services.GetRequiredService<LicenceStore>();
            var clock = app.Services.GetRequiredService<TimeProvider>();
            var desk = app.Services.GetRequiredService<Signing.SigningDesk>();
            var backups = app.Services.GetRequiredService<Backup.BackupService>();
            var releases = app.Services.GetRequiredService<Release.ReleaseStore>();
            var facts = new ChromeFacts(desk, backups.IsConfigured);

            string Client(HttpContext context) => Program.ClientKey(context, options.TrustedProxyHops);

            // BEFORE EVERYTHING. Not part of a route, not after the session
            // lookup, not after the throttle: a caller who is not allowed to see
            // this page at all must not be able to spend the login throttle's
            // budget or make this service do PBKDF2 work. See AdminAccessGate
            // for what it checks and why a refusal is a 404 rather than a 403.
            if (!gate.IsOpen)
            {
                app.Use(async (context, next) =>
                {
                    if (context.Request.Path.StartsWithSegments("/admin"))
                    {
                        var header = gate.HeaderName == null
                            ? null
                            : context.Request.Headers[gate.HeaderName].ToString();

                        if (!gate.Admits(
                                context.Connection.RemoteIpAddress,
                                context.Request.Headers["X-Forwarded-For"].ToString(),
                                header))
                        {
                            // Exactly what an unmapped path answers. A scanner
                            // learns nothing, including that there is a page here
                            // worth coming back to from somewhere else.
                            context.Response.StatusCode = StatusCodes.Status404NotFound;

                            return;
                        }
                    }

                    await next(context).ConfigureAwait(false);
                });
            }

            // ------------------------------------------------------- sign in

            app.MapGet("/admin", (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session != null)
                {
                    return SeeOther(context, CodesPath);
                }

                return Html(AdminPages.Login(new LoginModel()));
            });

            app.MapPost("/admin/login", async (HttpContext context) =>
            {
                var client = Client(context);
                var decision = throttle.Check(client);

                if (!decision.IsAllowed)
                {
                    // Refused before the password is looked at, so a guesser
                    // cannot make this service spend PBKDF2 time either. The
                    // wait is told to the operator plainly: a mysterious refusal
                    // is one they would answer by trying harder.
                    var seconds = (int)Math.Ceiling(decision.RetryAfter.TotalSeconds);

                    audit.Record(
                        AdminAudit.LoginThrottled,
                        client,
                        (AdminSession)null,
                        "waiting " + seconds.ToString(CultureInfo.InvariantCulture) + "s (" + decision.Scope + ")");

                    context.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);

                    return Html(
                        AdminPages.Login(new LoginModel
                        {
                            Message = "Too many attempts. Wait "
                                + seconds.ToString(CultureInfo.InvariantCulture)
                                + " seconds and try again. Nothing is locked; the wait always expires.",
                        }),
                        429);
                }

                var form = await ReadFormAsync(context).ConfigureAwait(false);
                var submitted = form == null ? null : form["password"].ToString();

                // Bound how many PBKDF2 verifications run at once. throttle.Check
                // above is deliberately non-consuming, so a burst of requests all
                // pass it before any of them fails and advances the counter; this
                // is what stops that burst turning into parallel PBKDF2 on the
                // signing-key host. A real operator takes one slot and never
                // notices. See PasswordVerificationGate.
                if (!verificationGate.TryEnter())
                {
                    audit.Record(AdminAudit.LoginThrottled, client, (AdminSession)null, "verification slots full");

                    context.Response.Headers.RetryAfter = "1";

                    return Html(
                        AdminPages.Login(new LoginModel
                        {
                            Message = "Too many attempts at once. Wait a moment and try again. "
                                + "Nothing is locked.",
                        }),
                        429);
                }

                bool verified;

                try
                {
                    verified = submitted != null && password.Verify(submitted);
                }
                finally
                {
                    verificationGate.Exit();
                }

                if (!verified)
                {
                    throttle.Failed(client);

                    audit.Record(AdminAudit.LoginFailed, client, (AdminSession)null, "wrong password");

                    return Html(
                        AdminPages.Login(new LoginModel { Message = "That is not the password." }),
                        401);
                }

                throttle.Succeeded(client);

                var session = sessions.Create(client);

                context.Response.Cookies.Append(AdminSessions.CookieName, session.Id, CookieAttributes());

                audit.Record(AdminAudit.LoggedIn, client, session, "signed in");

                return SeeOther(context, CodesPath);
            });

            app.MapPost("/admin/logout", async (HttpContext context) =>
            {
                var client = Client(context);
                var session = Authenticate(context, sessions, audit, client);

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var form = await ReadFormAsync(context).ConfigureAwait(false);

                if (!Csrf(form, session))
                {
                    audit.Record(AdminAudit.CsrfRefused, client, session, "logout");

                    return Refused(session, facts, "Signing out was refused.");
                }

                // The state that authorises a request is destroyed here, on the
                // server. Clearing the cookie as well is tidiness; the session
                // being gone is the logout, and a copy of the cookie taken
                // earlier is worth nothing from this moment.
                sessions.Destroy(session.Id);
                context.Response.Cookies.Delete(AdminSessions.CookieName, CookieAttributes());

                audit.Record(AdminAudit.LoggedOut, client, session, "signed out");

                return SeeOther(context, "/admin");
            });

            // --------------------------------------------------------- codes

            app.MapGet(CodesPath, (HttpContext context) =>
            {
                var client = Client(context);
                var session = Authenticate(context, sessions, audit, client);

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var now = clock.GetUtcNow();
                var soon = Whole(context.Request.Query["soon"].ToString(), CodeInventory.DefaultSoonDays);
                var search = context.Request.Query["for"].ToString();
                var attention = context.Request.Query["attention"].ToString() == "1";

                var outbox = OutboxLog.Read(options.OutboxPath, null);
                var all = CodeInventory.Build(store.ListCodes(), outbox, now, soon);
                var rows = CodeInventory.Filter(all, attention, search);
                var needing = all.Count(code => code.NeedsAttention);

                return Html(AdminPages.Codes(new CodesModel
                {
                    SignedIn = true,
                    CsrfToken = session.CsrfToken,
                    Rows = rows,
                    Filter = search,
                    OnlyAttention = attention,
                    SoonDays = soon,
                    Summary = CodeText.Count(all.Count, "code") + " in the store, "
                        + (needing == 0
                            ? "none needing attention"
                            : needing.ToString(CultureInfo.InvariantCulture) + " needing attention")
                        + (rows.Count == all.Count
                            ? "."
                            : "; " + rows.Count.ToString(CultureInfo.InvariantCulture) + " shown."),
                    EmptyMessage = all.Count == 0
                        ? "There are no codes yet. Nothing has been sold or issued."
                        : "None of the " + CodeText.Count(all.Count, "code") + " match that.",
                }));
            });

            // A code the customer typed, submitted as a form and never as a
            // link. It is normalised, hashed and used to find a row; what comes
            // back is a redirect to the row's TAG, so the code is not in the
            // address bar, the history, the Referer of the next page or this
            // service's own access log.
            app.MapPost("/admin/find", async (HttpContext context) =>
            {
                var client = Client(context);
                var session = Authenticate(context, sessions, audit, client);

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var form = await ReadFormAsync(context).ConfigureAwait(false);

                if (!Csrf(form, session))
                {
                    audit.Record(AdminAudit.CsrfRefused, client, session, "find");

                    return Refused(session, facts, "That lookup was refused.");
                }

                var result = CodeLookup.ByCode(store, form["code"].ToString());

                if (result.Found)
                {
                    return SeeOther(context, "/admin/code/" + Uri.EscapeDataString(result.Code.Tag));
                }

                return Html(
                    AdminPages.Notice(
                        Chrome(session, facts),
                        "Not found",
                        "That code was not found",
                        result.Explain()),
                    404);
            });

            app.MapGet("/admin/code/{tag}", (HttpContext context, string tag) =>
            {
                var client = Client(context);
                var session = Authenticate(context, sessions, audit, client);

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var found = CodeLookup.ByTag(store, tag);

                if (!found.Found)
                {
                    return Html(
                        AdminPages.Notice(Chrome(session, facts), "Not found", "No such code", found.Explain()),
                        404);
                }

                return Html(AdminPages.Detail(DetailFor(
                    session,
                    facts,
                    options,
                    store,
                    found.Code,
                    clock.GetUtcNow(),
                    context.Request.Query["voided"].ToString() == "1"
                        ? "Voided. It will not activate again."
                        : null)));
            });

            // ---------------------------------------------------------- void

            app.MapGet("/admin/code/{tag}/void", (HttpContext context, string tag) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var found = CodeLookup.ByTag(store, tag);

                if (!found.Found)
                {
                    return Html(
                        AdminPages.Notice(Chrome(session, facts), "Not found", "No such code", found.Explain()),
                        404);
                }

                return Html(AdminPages.VoidConfirm(
                    DetailFor(session, facts, options, store, found.Code, clock.GetUtcNow(), null)));
            });

            app.MapPost("/admin/void", async (HttpContext context) =>
            {
                var client = Client(context);
                var session = Authenticate(context, sessions, audit, client);

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var form = await ReadFormAsync(context).ConfigureAwait(false);

                if (!Csrf(form, session))
                {
                    audit.Record(AdminAudit.CsrfRefused, client, session, "void");

                    return Refused(session, facts, "That void was refused and nothing was changed.");
                }

                var found = CodeLookup.ByTag(store, form["tag"].ToString());

                if (!found.Found)
                {
                    return Html(
                        AdminPages.Notice(Chrome(session, facts), "Not found", "No such code", found.Explain()),
                        404);
                }

                var reason = form["reason"].ToString();

                if (string.IsNullOrWhiteSpace(reason))
                {
                    reason = "voided from the admin page (no reason given)";
                }
                else if (reason.Length > CodeIssuing.MaximumTextLength)
                {
                    reason = reason.Substring(0, CodeIssuing.MaximumTextLength);
                }

                // The same method the refund webhook and `void-code` call, so
                // what "voided" means cannot drift between the three of them.
                var outcome = store.VoidCodeByHash(found.Code.CodeHash, reason, clock.GetUtcNow());

                audit.Record(
                    AdminAudit.Voided,
                    client,
                    session,
                    outcome == VoidOutcome.AlreadyVoid
                        ? "already void; nothing changed. reason offered: " + reason
                        : "voided: " + reason,
                    found.Code.Tag);

                return SeeOther(context, "/admin/code/" + Uri.EscapeDataString(found.Code.Tag) + "?voided=1");
            });

            // --------------------------------------------------------- issue

            app.MapGet("/admin/issue", (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                return Html(AdminPages.IssueForm(new IssueModel
                {
                    SignedIn = true,
                    CsrfToken = session.CsrfToken,
                    Nonce = session.IssueNonce(),
                    Activations = options.ActivationsAllowed.ToString(CultureInfo.InvariantCulture),
                    Days = options.LicenceDays.ToString(CultureInfo.InvariantCulture),
                }));
            });

            app.MapPost("/admin/issue", async (HttpContext context) =>
            {
                var client = Client(context);
                var session = Authenticate(context, sessions, audit, client);

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var form = await ReadFormAsync(context).ConfigureAwait(false);

                if (!Csrf(form, session))
                {
                    audit.Record(AdminAudit.CsrfRefused, client, session, "issue");

                    return Refused(session, facts, "That was refused and NO CODE WAS CREATED.");
                }

                // Spent before anything is created, and spent whatever happens
                // next: a form that has been submitted once cannot mint a second
                // credential, whether the second arrival is a double tap, a
                // refresh of the POST, or the back button and Submit again.
                if (!session.ConsumeNonce(form["nonce"].ToString()))
                {
                    return Html(
                        AdminPages.Notice(
                            Chrome(session, facts),
                            "Already submitted",
                            "That form had already been submitted",
                            new[]
                            {
                                "NO SECOND CODE WAS CREATED. This form can be used once, so that a double tap, a "
                                + "refresh or the back button cannot quietly mint a credential you did not mean to "
                                + "create.",
                                "If the first one worked, it is in the list of codes. If you meant to issue another, "
                                + "start again from the Issue page.",
                            }),
                        409);
                }

                var request = new CodeIssuing.Request
                {
                    Licensee = form["licensee"].ToString(),
                    ActivationsAllowed = Whole(form["activations"].ToString(), -1),
                    LicenceDays = Whole(form["days"].ToString(), -1),
                    Note = form["note"].ToString(),
                };

                var problems = CodeIssuing.Problems(request);

                if (problems.Count > 0)
                {
                    return Html(
                        AdminPages.IssueForm(new IssueModel
                        {
                            SignedIn = true,
                            CsrfToken = session.CsrfToken,
                            Nonce = session.IssueNonce(),
                            Licensee = request.Licensee,
                            Activations = form["activations"].ToString(),
                            Days = form["days"].ToString(),
                            Note = request.Note,
                            Problems = problems,
                        }),
                        400);
                }

                var issued = CodeIssuing.Issue(store, request, clock.GetUtcNow());

                // The tag and the terms, never the code.
                audit.Record(
                    AdminAudit.Issued,
                    client,
                    session,
                    "issued to '" + request.Licensee.Trim() + "', "
                    + request.ActivationsAllowed.ToString(CultureInfo.InvariantCulture) + " activations, "
                    + request.LicenceDays.ToString(CultureInfo.InvariantCulture) + " days",
                    issued.Tag);

                session.Flash = new AdminFlash
                {
                    Code = issued.Code,
                    Tag = issued.Tag,
                    Licensee = request.Licensee.Trim(),
                    ActivationsAllowed = request.ActivationsAllowed,
                    LicenceDays = request.LicenceDays,
                };

                // Redirect after POST, with the code in server memory rather
                // than in the URL: refreshing the page it lands on re-runs a GET
                // that has nothing left to show, not the POST that made a code.
                return SeeOther(context, "/admin/issued");
            });

            app.MapGet("/admin/issued", (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var flash = session.TakeFlash();

                if (flash == null)
                {
                    return Html(
                        AdminPages.Notice(
                            Chrome(session, facts),
                            "Shown once",
                            "That code has already been shown",
                            new[]
                            {
                                "A code is shown exactly once, and this page has already shown it. A refresh, the "
                                + "back button and a second tab all land here.",
                                "If it was a code you issued, only its SHA-256 was kept and nothing on this service "
                                + "can recover it: issue another and void the one you lost. If it was read from the "
                                + "outbox, it is still in the outbox file and the button beside its line will read "
                                + "it back again.",
                            }),
                        410);
                }

                return Html(AdminPages.ShowCodeOnce(Chrome(session, facts), flash));
            });

            // -------------------------------------------------------- outbox

            app.MapGet("/admin/outbox", (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var warnings = new List<string>();
                var outbox = OutboxLog.Read(options.OutboxPath, warning => warnings.Add(warning));
                var showAll = context.Request.Query["all"].ToString() == "1";
                var byTag = store.ListCodes().ToDictionary(row => row.Tag, StringComparer.OrdinalIgnoreCase);

                var shown = outbox.Records.Where(record => showAll || !record.Delivered).ToList();
                var outstanding = outbox.Records.Count(record => !record.Delivered);

                return Html(AdminPages.Outbox(new OutboxModel
                {
                    SignedIn = true,
                    CsrfToken = session.CsrfToken,
                    Nonce = session.IssueNonce(),
                    Warnings = warnings,
                    Rows = shown.Select(record => Row(record, byTag)).ToList(),
                    Summary = CodeText.Count(outstanding, "code") + " with no delivery receipt"
                        + (showAll
                            ? "; " + CodeText.Count(shown.Count, "line") + " shown."
                            : "."),
                    EmptyMessage = outbox.Records.Count == 0
                        ? "Nothing is waiting to be sent. Either nothing has been sold, or every line has been "
                            + "pruned after sending - which is what pruning means."
                        : "Every line in the outbox has a delivery receipt beside it.",
                }));
            });

            app.MapPost("/admin/outbox/reveal", async (HttpContext context) =>
            {
                var client = Client(context);
                var session = Authenticate(context, sessions, audit, client);

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var form = await ReadFormAsync(context).ConfigureAwait(false);

                if (!Csrf(form, session))
                {
                    audit.Record(AdminAudit.CsrfRefused, client, session, "outbox reveal");

                    return Refused(session, facts, "That was refused and nothing was shown.");
                }

                if (!session.ConsumeNonce(form["nonce"].ToString()))
                {
                    return SeeOther(context, "/admin/outbox");
                }

                var tag = form["tag"].ToString();
                var outbox = OutboxLog.Read(options.OutboxPath, null);

                if (!outbox.TryFind(tag, out var record) || string.IsNullOrWhiteSpace(record.Code))
                {
                    return Html(
                        AdminPages.Notice(
                            Chrome(session, facts),
                            "Nothing to show",
                            "There is no code on that line",
                            new[] { "The line has been pruned, or it never carried a code." }),
                        404);
                }

                // The TAG is audited, never the code. What is recorded is that
                // somebody read a live credential off the disk, which is the
                // thing worth being able to ask about later.
                audit.Record(AdminAudit.Revealed, client, session, "read one code back out of the outbox", record.CodeTag);

                session.Flash = new AdminFlash
                {
                    Code = record.Code,
                    Tag = record.CodeTag,
                    Licensee = record.Licensee ?? record.BuyerEmail,
                    FromOutbox = true,
                };

                return SeeOther(context, "/admin/issued");
            });

            // --------------------------------------------------------- audit

            // ------------------------------------------------------- signing

            app.MapGet("/admin/signing", (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                return Html(AdminPages.Signing(SigningPage(session, facts, desk, options)));
            });

            app.MapPost("/admin/signing/download", async (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var form = await ReadFormAsync(context).ConfigureAwait(false);

                if (!Csrf(form, session))
                {
                    return Refused(session, facts, "That download was refused.");
                }

                var file = desk.Download();

                // Recorded, because it is a list of every customer waiting -
                // server ids and all - leaving the machine.
                audit.Record(
                    AdminAudit.SigningDownloaded,
                    Client(context),
                    session,
                    file.Requests.Count.ToString(CultureInfo.InvariantCulture) + " request(s)");

                context.Response.Headers.ContentDisposition =
                    "attachment; filename=\"emby-sso-signing-requests.json\"";

                return Results.Text(SigningExchange.Write(file), "application/json", Encoding.UTF8);
            });

            app.MapPost("/admin/signing/upload", async (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                AllowUploadOf(context, MaximumUploadBytes + UploadOverheadBytes);

                var form = await ReadFormAsync(context).ConfigureAwait(false);

                if (!Csrf(form, session))
                {
                    return Refused(session, facts, "That upload was refused and nothing was stored.");
                }

                var file = form.Files.GetFile("file");

                if (file == null || file.Length == 0)
                {
                    return Html(AdminPages.Signing(SigningPage(
                        session,
                        facts,
                        desk,
                        options,
                        "Choose the file `licencetool sign` wrote.",
                        bad: true)));
                }

                if (file.Length > MaximumUploadBytes)
                {
                    return Html(AdminPages.Signing(SigningPage(
                        session,
                        facts,
                        desk,
                        options,
                        "That file is larger than an upload of signed licences can be.",
                        bad: true)));
                }

                string json;

                using (var reader = new StreamReader(file.OpenReadStream(), Encoding.UTF8))
                {
                    json = await reader.ReadToEndAsync().ConfigureAwait(false);
                }

                var report = await desk.UploadAsync(json).ConfigureAwait(false);

                audit.Record(
                    AdminAudit.SigningUploaded,
                    Client(context),
                    session,
                    report.Summary());

                var problems = new List<string>();

                foreach (var rejection in report.Rejected)
                {
                    problems.Add(rejection.RequestId + ": " + rejection.Why);
                }

                return Html(AdminPages.Signing(SigningPage(
                    session,
                    facts,
                    desk,
                    options,
                    report.Summary(),
                    report.AnythingWrong,
                    problems)));
            });

            // ------------------------------------------------------- release

            app.MapGet("/admin/release", (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                return Html(AdminPages.Release(ReleasePage(session, facts, releases)));
            });

            app.MapPost("/admin/release", async (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                AllowUploadOf(context, MaximumReleaseBytes + UploadOverheadBytes);

                var form = await ReadFormAsync(context).ConfigureAwait(false);

                if (!Csrf(form, session))
                {
                    return Refused(session, facts, "That was refused and nothing was published.");
                }

                var plugin = form.Files.GetFile("plugin");

                byte[] content = null;

                if (plugin != null && plugin.Length > 0)
                {
                    if (plugin.Length > MaximumReleaseBytes)
                    {
                        return Html(AdminPages.Release(ReleasePage(
                            session,
                            facts,
                            releases,
                            "That file is larger than a plugin build can be. Nothing was published.",
                            bad: true)));
                    }

                    // Read whole, because it has to be hashed whole before any
                    // of it is trusted enough to keep.
                    using var buffer = new MemoryStream();

                    await plugin.OpenReadStream().CopyToAsync(buffer, context.RequestAborted).ConfigureAwait(false);

                    content = buffer.ToArray();
                }

                var problem = await releases
                    .PublishAsync(form["manifest"].ToString(), content)
                    .ConfigureAwait(false);

                // Recorded either way. This is the one control on this page that
                // causes code to run on other people's machines.
                audit.Record(
                    AdminAudit.ReleasePublished,
                    Client(context),
                    session,
                    problem ?? ("published " + (releases.PublishedVersion() ?? "?")));

                return Html(AdminPages.Release(ReleasePage(
                    session,
                    facts,
                    releases,
                    problem ?? ("Published " + releases.PublishedVersion() + "."),
                    problem != null)));
            });

            // -------------------------------------------------------- backup

            app.MapGet("/admin/backup", (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var model = Chrome(session, facts);

                return Html(AdminPages.Backup(new BackupModel
                {
                    SignedIn = true,
                    CsrfToken = model.CsrfToken,
                    Waiting = model.Waiting,
                    BackupsOn = model.BackupsOn,
                    Configured = backups.IsConfigured,
                }));
            });

            app.MapPost("/admin/backup/download", async (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                var form = await ReadFormAsync(context).ConfigureAwait(false);

                if (!Csrf(form, session))
                {
                    return Refused(session, facts, "That backup was refused.");
                }

                if (!backups.IsConfigured)
                {
                    return SeeOther(context, "/admin/backup");
                }

                byte[] blob;

                try
                {
                    blob = backups.Create();
                }
                catch (Exception ex) when (ex is InvalidOperationException || ex is IOException)
                {
                    var chrome = Chrome(session, facts);

                    return Html(AdminPages.Backup(new BackupModel
                    {
                        SignedIn = true,
                        CsrfToken = chrome.CsrfToken,
                        Waiting = chrome.Waiting,
                        BackupsOn = chrome.BackupsOn,
                        Configured = true,
                        Notice = ex.Message,
                    }));
                }

                // The single most sensitive thing this service ever hands out -
                // the whole customer store - so it is recorded with who and from
                // where, like every other act on this page.
                audit.Record(
                    AdminAudit.BackupTaken,
                    Client(context),
                    session,
                    blob.Length.ToString(CultureInfo.InvariantCulture) + " bytes, encrypted");

                context.Response.Headers.ContentDisposition =
                    "attachment; filename=\"" + backups.FileName() + "\"";

                return Results.Bytes(blob, "application/octet-stream");
            });

            app.MapGet("/admin/audit", (HttpContext context) =>
            {
                var session = Authenticate(context, sessions, audit, Client(context));

                if (session == null)
                {
                    return SeeOther(context, "/admin");
                }

                return Html(AdminPages.Audit(new AuditModel
                {
                    SignedIn = true,
                    CsrfToken = session.CsrfToken,
                    Lines = audit.Recent(500),
                    Path = audit.Path,
                }));
            });
        }

        // ------------------------------------------------------------ shared

        /// <summary>
        /// The cookie's attributes, in one place so that no route can set them
        /// differently. Secure and HttpOnly and SameSite=Strict and Path=/ and
        /// no Domain - and the `__Host-` prefix on the name means a browser
        /// enforces the last three itself and refuses the cookie outright if
        /// this ever stops being true.
        ///
        /// No Expires and no Max-Age: it is a session cookie, so it is not
        /// written to disk and it does not outlive the browser.
        /// </summary>
        private static CookieOptions CookieAttributes()
        {
            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                IsEssential = true,
            };
        }

        private static AdminSession Authenticate(
            HttpContext context,
            AdminSessions sessions,
            AdminAudit audit,
            string client)
        {
            if (!context.Request.Cookies.TryGetValue(AdminSessions.CookieName, out var id))
            {
                return null;
            }

            var session = sessions.Find(id);

            if (session == null)
            {
                return null;
            }

            if (!string.Equals(session.ClientKey, client, StringComparison.Ordinal))
            {
                // Recorded, not refused. Tying a session to an address signs out
                // an operator whose phone changed cell, and locking the only
                // person who can fix this service out of it is a worse failure
                // than the one it would prevent. The audit line is what makes a
                // moved session answerable afterwards.
                audit.Record(
                    AdminAudit.SessionMoved,
                    client,
                    session,
                    "this session was created from " + session.ClientKey);

                session.ClientKey = client;
            }

            return session;
        }

        /// <summary>
        /// The CSRF check. A token bound to this session, compared in constant
        /// time, on every request that changes anything.
        ///
        /// A missing form, a missing token, an empty token and a token from
        /// another session all fail here, and they fail identically.
        /// </summary>
        private static bool Csrf(IFormCollection form, AdminSession session)
        {
            if (form == null || session == null)
            {
                return false;
            }

            var submitted = form["csrf"].ToString();

            if (string.IsNullOrEmpty(submitted) || string.IsNullOrEmpty(session.CsrfToken))
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(submitted),
                Encoding.UTF8.GetBytes(session.CsrfToken));
        }

        /// <summary>
        /// Raises the request body limit for THIS REQUEST ONLY.
        ///
        /// Kestrel is configured globally to refuse a body over 64 KB, which is
        /// right for every public endpoint here - they take a JSON object or a
        /// short form and nothing else. Two authenticated admin uploads are not
        /// like that: a batch of signed licences, and a plugin DLL. Without this
        /// they are refused by the server before any handler sees them, with a
        /// 413 and no explanation on the page.
        ///
        /// It is raised per request rather than globally on purpose. The global
        /// limit is what stops an unauthenticated caller making this process
        /// read anything large, and it should keep doing that.
        /// </summary>
        private static void AllowUploadOf(HttpContext context, long bytes)
        {
            var limit = context.Features.Get<IHttpMaxRequestBodySizeFeature>();

            if (limit != null && !limit.IsReadOnly)
            {
                limit.MaxRequestBodySize = bytes;
            }
        }

        private static async Task<IFormCollection> ReadFormAsync(HttpContext context)
        {
            if (!context.Request.HasFormContentType)
            {
                return null;
            }

            try
            {
                return await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is InvalidDataException || ex is IOException)
            {
                return null;
            }
        }

        /// <summary>
        /// The two facts every page's navigation shows, gathered once per
        /// request rather than threaded through every model by hand.
        ///
        /// <see cref="Waiting"/> is deliberately live rather than captured at
        /// startup: it is the count of customers who have paid and are being
        /// told to come back later, and an operator should see it drop as they
        /// work rather than after a restart.
        /// </summary>
        private sealed class ChromeFacts
        {
            private readonly Signing.SigningDesk _desk;

            public ChromeFacts(Signing.SigningDesk desk, bool backups)
            {
                _desk = desk;
                BackupsOn = backups;
            }

            public bool BackupsOn { get; }

            public int Waiting
            {
                get
                {
                    try
                    {
                        return _desk.Waiting;
                    }
                    catch (Microsoft.Data.Sqlite.SqliteException)
                    {
                        // A badge is not worth a 500. The Signing page itself
                        // will fail loudly if the store is really unreadable.
                        return 0;
                    }
                }
            }
        }

        private static ChromeModel Chrome(AdminSession session, ChromeFacts facts)
        {
            return new ChromeModel
            {
                SignedIn = true,
                CsrfToken = session.CsrfToken,
                Waiting = facts.Waiting,
                BackupsOn = facts.BackupsOn,
            };
        }

        private static SigningModel SigningPage(
            AdminSession session,
            ChromeFacts facts,
            Signing.SigningDesk desk,
            ServiceOptions options,
            string notice = null,
            bool bad = false,
            IReadOnlyList<string> problems = null)
        {
            var chrome = Chrome(session, facts);

            return new SigningModel
            {
                SignedIn = true,
                CsrfToken = chrome.CsrfToken,
                Waiting = chrome.Waiting,
                BackupsOn = chrome.BackupsOn,
                TrustedKeys = desk.TrustedKeyNames,
                Notice = notice,
                Bad = bad,
                Problems = problems ?? Array.Empty<string>(),
                Rows = desk.Download().Requests,
            };
        }

        private static ReleaseModel ReleasePage(
            AdminSession session,
            ChromeFacts facts,
            Release.ReleaseStore releases,
            string notice = null,
            bool bad = false)
        {
            var chrome = Chrome(session, facts);

            return new ReleaseModel
            {
                SignedIn = true,
                CsrfToken = chrome.CsrfToken,
                Waiting = chrome.Waiting,
                BackupsOn = chrome.BackupsOn,
                PublishedVersion = releases.PublishedVersion(),
                CanAccept = releases.CanAccept,
                HostedUrl = releases.HostedUrl,
                Notice = notice,
                Bad = bad,
            };
        }

        private static IResult Refused(AdminSession session, ChromeFacts facts, string what)
        {
            return Html(
                AdminPages.Notice(
                    Chrome(session, facts),
                    "Refused",
                    "Refused",
                    new[]
                    {
                        what,
                        "The form did not carry the token that proves it came from this page in this session. That "
                        + "is what a request made by another site on your behalf looks like, and it is also what a "
                        + "page left open across a sign-out looks like.",
                        "If you were doing this yourself, go back to the page you started from and try again.",
                    }),
                400);
        }

        private static DetailModel DetailFor(
            AdminSession session,
            ChromeFacts facts,
            ServiceOptions options,
            LicenceStore store,
            CodeSummary code,
            DateTimeOffset now,
            string notice)
        {
            var outbox = OutboxLog.Read(options.OutboxPath, null);

            outbox.TryFind(code.Tag, out var delivery);

            var state = CodeInventory.Classify(code, delivery, now, CodeInventory.DefaultSoonDays);

            return new DetailModel
            {
                SignedIn = true,
                CsrfToken = session.CsrfToken,
                Code = code,
                Delivery = delivery,
                StateText = new ManagedCode { Code = code, Delivery = delivery, State = state }.StateText,
                Activations = store.ActivationsFor(code.Id),
                Now = now,
                Notice = notice,
            };
        }

        private static OutboxRow Row(OutboxRecord record, IDictionary<string, CodeSummary> byTag)
        {
            return new OutboxRow
            {
                Tag = CodeText.Empty(record.CodeTag),
                CreatedUtc = CodeText.Empty(record.CreatedUtc),
                Buyer = CodeText.Empty(record.BuyerEmail),
                Sent = record.Delivered ? CodeText.Empty(record.DeliveredUtc) : "NO",
                ActivationsAllowed = record.ActivationsAllowed.ToString(CultureInfo.InvariantCulture),
                LicenceDays = record.LicenceDays.ToString(CultureInfo.InvariantCulture),
                Capture = CodeText.Empty(record.PayPalCaptureId),
                StoreNote = StoreNote(byTag, record),
                HasCode = !string.IsNullOrWhiteSpace(record.Code),
            };
        }

        private static string StoreNote(IDictionary<string, CodeSummary> byTag, OutboxRecord record)
        {
            if (!byTag.TryGetValue(record.CodeTag ?? string.Empty, out var code))
            {
                return "NO SUCH CODE";
            }

            if (string.Equals(code.Status, CodeStatus.Void, StringComparison.Ordinal))
            {
                return "void - do not send";
            }

            if (code.ActivationsUsed > 0)
            {
                return "already activated " + code.ActivationsUsed.ToString(CultureInfo.InvariantCulture) + "x";
            }

            return "waiting";
        }

        private static int Whole(string value, int fallback)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return fallback;
            }

            return int.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var number)
                ? number
                : -1;
        }

        private static IResult Html(string html, int status = 200)
        {
            // "text/html" plus the encoding, not a content type that already
            // names a charset: passing both to Results.Content is how you get an
            // argument exception at runtime instead of a page.
            return Results.Content(html, "text/html", Encoding.UTF8, status);
        }

        /// <summary>
        /// 303, not 302: every redirect here follows a POST, and 303 is the one
        /// that tells the browser to GET what comes next rather than repeating
        /// the POST - which is what stops a refresh re-submitting a void or an
        /// issue.
        /// </summary>
        private static IResult SeeOther(HttpContext context, string location)
        {
            context.Response.Headers.Location = location;

            return Results.StatusCode(303);
        }
    }
}

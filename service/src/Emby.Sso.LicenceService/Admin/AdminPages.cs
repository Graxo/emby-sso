using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;
using Emby.Sso.LicenceService.Management;
using Emby.Sso.LicenceService.Storage;

namespace Emby.Sso.LicenceService.Admin
{
    /// <summary>
    /// The admin pages, as HTML built on the server. No JavaScript, no
    /// framework, no CDN, nothing loaded from anywhere - see
    /// Http.SecurityHeaders for the policy that enforces it.
    ///
    /// EVERY VALUE THAT REACHES THESE PAGES IS HOSTILE UNTIL ESCAPED. A licensee
    /// name arrives from a PayPal payer, a note from whoever ran `issue-code`, a
    /// server id from an activation request, an audit detail from all of them.
    /// There is exactly one way a string gets into a page here - <see cref="E"/>
    /// - and one way it gets into a URL - <see cref="U"/>. A test feeds a script
    /// tag through every field on every page and asserts none of them comes back
    /// unescaped.
    ///
    /// NO REDEMPTION CODE IS RENDERED ANYWHERE, with exactly one exception that
    /// is not one: <see cref="ShowCodeOnce"/>, which shows a code that has just
    /// been created, or read back from the outbox file that holds it in the
    /// clear, at the single moment it exists in readable form. Every other page
    /// is handed types with no field a code could live in - <see
    /// cref="ManagedCode"/>, <see cref="CodeSummary"/>, <see cref="OutboxRow"/>,
    /// <see cref="AdminAuditLine"/> - so rendering one is not something a future
    /// edit can do by accident.
    /// </summary>
    internal static class AdminPages
    {
        // ------------------------------------------------------------- login

        public static string Login(LoginModel model)
        {
            var page = Head("Sign in", null);

            page.Append("<main class=\"narrow\">");
            page.Append("<h1>Licence administration</h1>");

            if (model.Message != null)
            {
                page.Append("<p class=\"bad\">").Append(E(model.Message)).Append("</p>");
            }

            page.Append("<form method=\"post\" action=\"/admin/login\">");
            page.Append("<label for=\"password\">Password</label>");
            page.Append("<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" ");
            page.Append("autofocus required>");
            page.Append("<button type=\"submit\">Sign in</button>");
            page.Append("</form>");

            page.Append("<p class=\"muted\">This page can issue and void licences. Every attempt to sign in, ");
            page.Append("successful or not, is recorded with the address it came from.</p>");

            page.Append("</main>");

            return Tail(page);
        }

        // ------------------------------------------------------------- codes

        public static string Codes(CodesModel model)
        {
            var page = Head("Codes", model);

            page.Append("<h1>Codes</h1>");

            page.Append("<form method=\"get\" action=\"/admin/codes\" class=\"filters\">");
            page.Append("<label for=\"for\">Licensee, buyer or tag</label>");
            page.Append("<input id=\"for\" name=\"for\" value=\"").Append(E(model.Filter)).Append("\">");
            page.Append("<label class=\"check\"><input type=\"checkbox\" name=\"attention\" value=\"1\"");

            if (model.OnlyAttention)
            {
                page.Append(" checked");
            }

            page.Append("> needing attention only</label>");
            page.Append("<label for=\"soon\">Lapsing within (days)</label>");
            page.Append("<input id=\"soon\" name=\"soon\" size=\"4\" value=\"")
                .Append(E(model.SoonDays.ToString(CultureInfo.InvariantCulture)))
                .Append("\">");
            page.Append("<button type=\"submit\">Filter</button>");
            page.Append("</form>");

            if (model.Rows.Count == 0)
            {
                page.Append("<p>").Append(E(model.EmptyMessage ?? "Nothing matches that.")).Append("</p>");
            }
            else
            {
                page.Append("<table><thead><tr>");
                Headings(page, "STATE", "CREATED", "TAG", "SOURCE", "USED", "DAYS", "EXPIRES", "FOR");
                page.Append("</tr></thead><tbody>");

                foreach (var row in model.Rows)
                {
                    page.Append("<tr class=\"").Append(E(StateClass(row.State))).Append("\">");
                    Cell(page, row.StateText);
                    Cell(page, CodeText.Date(row.Code.CreatedUtc));

                    page.Append("<td><a href=\"/admin/code/").Append(U(row.Tag)).Append("\"><code>")
                        .Append(E(row.Tag)).Append("</code></a></td>");

                    Cell(page, row.Code.Source);
                    Cell(
                        page,
                        row.Code.ActivationsUsed.ToString(CultureInfo.InvariantCulture) + "/"
                        + row.Code.ActivationsAllowed.ToString(CultureInfo.InvariantCulture));
                    Cell(page, row.Code.LicenceDays.ToString(CultureInfo.InvariantCulture));
                    Cell(page, row.Code.ExpiresUtc.HasValue ? CodeText.Date(row.Code.ExpiresUtc.Value) : "-");
                    Cell(page, CodeText.Describe(row.Code));
                    page.Append("</tr>");
                }

                page.Append("</tbody></table>");
                page.Append("<p class=\"muted\">").Append(E(model.Summary)).Append("</p>");
            }

            page.Append("<p class=\"muted\">No code appears above and none can: this store holds only their ");
            page.Append("SHA-256 hashes. TAG is the first twelve characters of that hash - the same thing the log ");
            page.Append("lines record. UNDELIVERED means a line in the outbox with no delivery receipt beside it.</p>");

            page.Append("<h2>Find a code a customer has sent you</h2>");
            page.Append("<form method=\"post\" action=\"/admin/find\">");
            Csrf(page, model);
            page.Append("<label for=\"code\">The code as they typed it</label>");
            page.Append("<input id=\"code\" name=\"code\" autocomplete=\"off\" spellcheck=\"false\">");
            page.Append("<button type=\"submit\">Look it up</button>");
            page.Append("</form>");
            page.Append("<p class=\"muted\">Submitted as a form, never as a link: a code in an address bar ends up ");
            page.Append("in browser history, in a proxy log and in the next page's Referer header. It is hashed, ");
            page.Append("looked up, and not shown back to you.</p>");

            return Tail(page, model);
        }

        // ------------------------------------------------------------ detail

        public static string Detail(DetailModel model)
        {
            var page = Head("Code " + model.Code.Tag, model);

            page.Append("<h1>Code <code>").Append(E(model.Code.Tag)).Append("</code></h1>");

            if (model.Notice != null)
            {
                page.Append("<p class=\"good\">").Append(E(model.Notice)).Append("</p>");
            }

            page.Append("<dl>");
            Field(page, "State", model.StateText);
            Field(page, "Source", model.Code.IsManual ? "issue-code (no payment)" : model.Code.Source);
            Field(page, "Licensee", CodeText.Empty(model.Code.Licensee));
            Field(page, model.Code.IsManual ? "Note" : "Buyer", CodeText.Empty(model.Code.BuyerEmailOrNote));

            if (!model.Code.IsManual)
            {
                Field(
                    page,
                    "PayPal",
                    "capture " + CodeText.Empty(model.Code.PayPalCaptureId)
                    + ", event " + CodeText.Empty(model.Code.PayPalEventId));
                Field(
                    page,
                    "Bought from",
                    CodeText.Empty(model.Code.OriginServerId) + "  (the server id on the /buy link; it binds nothing)");
            }

            Field(page, "Created", Licensing.LicenceFormat.Iso(model.Code.CreatedUtc));
            Field(
                page,
                "Licence",
                model.Code.LicenceDays.ToString(CultureInfo.InvariantCulture) + " days from first activation");
            Field(
                page,
                "Expires",
                model.Code.ExpiresUtc.HasValue
                    ? Licensing.LicenceFormat.Iso(model.Code.ExpiresUtc.Value)
                        + "  (" + CodeText.Relative(model.Code.ExpiresUtc.Value, model.Now) + ")"
                    : "-  (fixed at first activation, which has not happened)");
            Field(
                page,
                "Activations",
                model.Code.ActivationsUsed.ToString(CultureInfo.InvariantCulture) + " of "
                + model.Code.ActivationsAllowed.ToString(CultureInfo.InvariantCulture) + " used");
            Field(page, "Delivery", CodeText.DescribeDelivery(model.Code, model.Delivery));

            if (model.Code.VoidedUtc.HasValue
                || string.Equals(model.Code.Status, CodeStatus.Void, StringComparison.Ordinal))
            {
                Field(
                    page,
                    "Voided",
                    (model.Code.VoidedUtc.HasValue
                        ? Licensing.LicenceFormat.Iso(model.Code.VoidedUtc.Value)
                        : "(before this was recorded)")
                    + "  " + CodeText.Empty(model.Code.VoidReason));
            }

            page.Append("</dl>");

            page.Append("<h2>Servers this code has been activated onto</h2>");

            if (model.Activations.Count == 0)
            {
                page.Append("<p>No server has ever activated this code.</p>");
            }
            else
            {
                page.Append("<table><thead><tr>");
                Headings(page, "SERVER", "FIRST SEEN", "LAST SEEN", "ISSUES", "PLUGIN", "LAST LICENCE");
                page.Append("</tr></thead><tbody>");

                foreach (var activation in model.Activations)
                {
                    page.Append("<tr>");
                    Cell(page, activation.ServerId);
                    Cell(page, activation.FirstSeenUtc);
                    Cell(page, activation.LastSeenUtc);
                    Cell(page, activation.IssueCount.ToString(CultureInfo.InvariantCulture));
                    Cell(page, CodeText.Empty(activation.PluginVersion));
                    Cell(page, CodeText.Empty(activation.LastFingerprint));
                    page.Append("</tr>");
                }

                page.Append("</tbody></table>");
                page.Append("<p class=\"muted\">LAST LICENCE is the fingerprint <code>licencetool show</code> prints ");
                page.Append("for a licence somebody emails back, so a token in an inbox can be matched to a row ");
                page.Append("above.</p>");
            }

            if (!string.Equals(model.Code.Status, CodeStatus.Void, StringComparison.Ordinal))
            {
                page.Append("<p><a class=\"danger\" href=\"/admin/code/").Append(U(model.Code.Tag))
                    .Append("/void\">Void this code&hellip;</a></p>");
            }

            page.Append("<p class=\"muted\">This page confirms a code you already had. It cannot reveal one: the ");
            page.Append("store holds a SHA-256 and never the code itself.</p>");

            return Tail(page, model);
        }

        // -------------------------------------------------------------- void

        /// <summary>
        /// The confirmation. What voiding cannot do is stated BEFORE the button,
        /// in the interface, in the same words the command line uses - see
        /// <see cref="VoidExplanation"/>, which is where both get it from.
        /// </summary>
        public static string VoidConfirm(DetailModel model)
        {
            var page = Head("Void code " + model.Code.Tag, model);

            page.Append("<h1>Void code <code>").Append(E(model.Code.Tag)).Append("</code>?</h1>");
            page.Append("<p>").Append(E(CodeText.Describe(model.Code))).Append(" &mdash; ")
                .Append(E(model.Code.ActivationsUsed.ToString(CultureInfo.InvariantCulture)))
                .Append(" of ")
                .Append(E(model.Code.ActivationsAllowed.ToString(CultureInfo.InvariantCulture)))
                .Append(" activations used.</p>");

            page.Append("<div class=\"warning\"><h2>").Append(E(VoidExplanation.Headline)).Append("</h2>");

            foreach (var paragraph in VoidExplanation.Paragraphs(model.Code))
            {
                page.Append("<p>").Append(E(paragraph)).Append("</p>");
            }

            page.Append("</div>");

            page.Append("<form method=\"post\" action=\"/admin/void\">");
            Csrf(page, model);
            page.Append("<input type=\"hidden\" name=\"tag\" value=\"").Append(E(model.Code.Tag)).Append("\">");
            page.Append("<label for=\"reason\">Why (recorded, and shown here forever after)</label>");
            page.Append("<input id=\"reason\" name=\"reason\" value=\"\" maxlength=\"200\" ");
            page.Append("placeholder=\"refunded, ticket 1234\">");
            page.Append("<button class=\"danger\" type=\"submit\">Void it. It will not activate again.</button>");
            page.Append("</form>");

            page.Append("<p><a href=\"/admin/code/").Append(U(model.Code.Tag)).Append("\">No, go back.</a></p>");

            return Tail(page, model);
        }

        // ------------------------------------------------------------- issue

        public static string IssueForm(IssueModel model)
        {
            var page = Head("Issue a code", model);

            page.Append("<h1>Issue a code</h1>");
            page.Append("<p>A code no payment bought &mdash; a tester, a comp, a refund gone wrong, or a sale ");
            page.Append("whose code could not be delivered.</p>");

            if (model.Problems.Count > 0)
            {
                page.Append("<div class=\"warning\"><h2>Nothing was created</h2><ul>");

                foreach (var problem in model.Problems)
                {
                    page.Append("<li>").Append(E(problem)).Append("</li>");
                }

                page.Append("</ul></div>");
            }

            page.Append("<div class=\"warning\"><h2>THIS CREATES A CREDENTIAL WORTH THE PRICE OF THE PRODUCT.</h2>");
            page.Append("<p>The code is shown once, on the next page, and never again: this service keeps only its ");
            page.Append("SHA-256. Copy it before you leave that page. Nothing here can recover it afterwards and ");
            page.Append("the only remedy for a lost one is to issue another and void this one.</p></div>");

            page.Append("<form method=\"post\" action=\"/admin/issue\">");
            Csrf(page, model);
            page.Append("<input type=\"hidden\" name=\"nonce\" value=\"").Append(E(model.Nonce)).Append("\">");

            page.Append("<label for=\"licensee\">Licensee (who it is for)</label>");
            page.Append("<input id=\"licensee\" name=\"licensee\" maxlength=\"200\" required value=\"")
                .Append(E(model.Licensee)).Append("\">");

            page.Append("<label for=\"activations\">Activations allowed</label>");
            page.Append("<input id=\"activations\" name=\"activations\" size=\"6\" value=\"")
                .Append(E(model.Activations)).Append("\">");

            page.Append("<label for=\"days\">Licence days</label>");
            page.Append("<input id=\"days\" name=\"days\" size=\"6\" value=\"").Append(E(model.Days)).Append("\">");

            page.Append("<label for=\"note\">Note (why this exists &mdash; a ticket number, a name)</label>");
            page.Append("<input id=\"note\" name=\"note\" maxlength=\"200\" value=\"").Append(E(model.Note))
                .Append("\">");

            page.Append("<button type=\"submit\">Issue it</button>");
            page.Append("</form>");

            return Tail(page, model);
        }

        /// <summary>
        /// The one page in this service that renders a redemption code, and it
        /// renders one that has just been created or just been read out of the
        /// outbox file - a code that is in the clear for this one moment either
        /// way. The flash it comes from is consumed by the caller BEFORE this is
        /// called, so a refresh, a back button and a second tab all get the
        /// "already shown" page instead.
        /// </summary>
        public static string ShowCodeOnce(ChromeModel chrome, AdminFlash flash)
        {
            var page = Head(flash.FromOutbox ? "Code from the outbox" : "Code issued", chrome);

            page.Append("<h1>").Append(flash.FromOutbox ? "From the outbox" : "Code issued").Append("</h1>");

            page.Append("<div class=\"warning\"><h2>THIS IS THE ONLY TIME THIS CODE IS SHOWN.</h2>");
            page.Append("<p>Copy it now. Refreshing this page, going back to it, or opening it in another tab ");
            page.Append("will not show it again");
            page.Append(flash.FromOutbox
                ? " &mdash; it stays in the outbox file, which is where this one was read from."
                : ", and nothing on this service can recover it: only its SHA-256 was stored.");
            page.Append("</p></div>");

            // Selected as one block by a triple-click, and large enough to read
            // off a screen while typing it into a phone.
            page.Append("<p class=\"code\">").Append(E(flash.Code)).Append("</p>");

            page.Append("<dl>");
            Field(page, "Tag", flash.Tag + "  (what the logs and the audit trail record)");
            Field(page, "Licensee", CodeText.Empty(flash.Licensee));

            if (!flash.FromOutbox)
            {
                Field(page, "Activations", flash.ActivationsAllowed.ToString(CultureInfo.InvariantCulture));
                Field(
                    page,
                    "Licence",
                    flash.LicenceDays.ToString(CultureInfo.InvariantCulture) + " days from first activation");
            }

            page.Append("</dl>");

            page.Append("<p><a href=\"/admin/code/").Append(U(flash.Tag)).Append("\">Everything else about it</a> ");
            page.Append("&mdash; that page never shows the code.</p>");

            return Tail(page, chrome);
        }

        // ------------------------------------------------------------ outbox

        public static string Outbox(OutboxModel model)
        {
            var page = Head("Outbox", model);

            page.Append("<h1>Outbox</h1>");
            page.Append("<p>Sales whose code has not reached the buyer. ");
            page.Append("A line stays here until you delete it, and deleting it is how a code stops sitting on ");
            page.Append("the disk in the clear.</p>");

            foreach (var warning in model.Warnings)
            {
                page.Append("<p class=\"bad\">").Append(E(warning)).Append("</p>");
            }

            if (model.Rows.Count == 0)
            {
                page.Append("<p>").Append(E(model.EmptyMessage)).Append("</p>");
            }
            else
            {
                page.Append("<table><thead><tr>");
                Headings(page, "CREATED", "TAG", "BUYER", "SENT", "ACTS", "DAYS", "CAPTURE", "IN THE STORE", "");
                page.Append("</tr></thead><tbody>");

                foreach (var row in model.Rows)
                {
                    page.Append("<tr>");
                    Cell(page, row.CreatedUtc);

                    page.Append("<td><a href=\"/admin/code/").Append(U(row.Tag)).Append("\"><code>")
                        .Append(E(row.Tag)).Append("</code></a></td>");

                    Cell(page, row.Buyer);
                    Cell(page, row.Sent);
                    Cell(page, row.ActivationsAllowed);
                    Cell(page, row.LicenceDays);
                    Cell(page, row.Capture);
                    Cell(page, row.StoreNote);

                    page.Append("<td>");

                    if (row.HasCode)
                    {
                        page.Append("<form method=\"post\" action=\"/admin/outbox/reveal\">");
                        Csrf(page, model);
                        page.Append("<input type=\"hidden\" name=\"nonce\" value=\"").Append(E(model.Nonce))
                            .Append("\">");
                        page.Append("<input type=\"hidden\" name=\"tag\" value=\"").Append(E(row.Tag)).Append("\">");
                        page.Append("<button type=\"submit\">Show the code once</button>");
                        page.Append("</form>");
                    }
                    else
                    {
                        page.Append("<span class=\"muted\">no code on this line</span>");
                    }

                    page.Append("</td></tr>");
                }

                page.Append("</tbody></table>");
                page.Append("<p class=\"muted\">").Append(E(model.Summary)).Append("</p>");
            }

            page.Append("<div class=\"warning\"><h2>Showing a code is a deliberate act, and it is recorded.</h2>");
            page.Append("<p>The codes are not in the table above. They are in the outbox file in the clear - it is ");
            page.Append("the one place they exist in readable form - and the button beside a line reads one back, ");
            page.Append("one at a time, onto a page that shows it once. The audit trail records which line was ");
            page.Append("read and when. It never records the code.</p>");
            page.Append("<p>SENT stays &lsquo;NO&rsquo; until a successful email appends a receipt. With SMTP_HOST ");
            page.Append("unset no receipt is ever written, so send each code and then delete its line from the ");
            page.Append("file: a pruned line is how this page knows a code is finished with.</p></div>");

            return Tail(page, model);
        }

        // ------------------------------------------------------------- audit

        public static string Audit(AuditModel model)
        {
            var page = Head("Audit", model);

            page.Append("<h1>Audit</h1>");
            page.Append("<p>Every sign-in, every failed sign-in, every code issued and every code voided, with the ");
            page.Append("address it came from. Written to <code>").Append(E(model.Path)).Append("</code> as well as ");
            page.Append("to the service log, because container logs do not survive a rebuild and a refund dispute ");
            page.Append("arrives months later.</p>");

            if (model.Lines.Count == 0)
            {
                page.Append("<p>Nothing has been recorded yet.</p>");
            }
            else
            {
                page.Append("<table><thead><tr>");
                Headings(page, "WHEN (UTC)", "WHAT", "FROM", "SESSION", "TAG", "DETAIL");
                page.Append("</tr></thead><tbody>");

                foreach (var line in model.Lines)
                {
                    page.Append("<tr>");
                    Cell(page, line.Utc);
                    Cell(page, line.Event);
                    Cell(page, line.Client);
                    Cell(page, line.Session);
                    Cell(page, line.Tag);
                    Cell(page, line.Detail);
                    page.Append("</tr>");
                }

                page.Append("</tbody></table>");
            }

            page.Append("<p class=\"muted\">SESSION is a twelve-character fingerprint of the session id, not the id ");
            page.Append("itself: two lines from one sign-in can be tied together, and nothing here would authorise ");
            page.Append("a request if this file leaked. No redemption code appears, including on the lines about ");
            page.Append("issuing one.</p>");

            return Tail(page, model);
        }

        // ------------------------------------------------------------ notice

        /// <summary>A refusal, a dead end, or a message. Used for every error the operator can cause.</summary>
        public static string Notice(ChromeModel chrome, string title, string heading, IEnumerable<string> paragraphs)
        {
            var page = Head(title, chrome);

            page.Append(chrome != null && chrome.SignedIn ? "<h1>" : "<main class=\"narrow\"><h1>");
            page.Append(E(heading)).Append("</h1>");

            foreach (var paragraph in paragraphs)
            {
                page.Append("<p>").Append(E(paragraph)).Append("</p>");
            }

            if (chrome == null || !chrome.SignedIn)
            {
                page.Append("</main>");

                return Tail(page);
            }

            return Tail(page, chrome);
        }

        // ------------------------------------------------------------ chrome

        private static StringBuilder Head(string title, ChromeModel chrome)
        {
            var page = new StringBuilder();

            page.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            page.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            page.Append("<meta name=\"robots\" content=\"noindex,nofollow,noarchive\">");
            page.Append("<title>").Append(E(title)).Append(" &middot; licences</title>");
            page.Append("<style>").Append(Style).Append("</style></head><body>");

            if (chrome != null && chrome.SignedIn)
            {
                page.Append("<nav><a href=\"/admin/codes\">Codes</a><a href=\"/admin/issue\">Issue a code</a>");
                page.Append("<a href=\"/admin/outbox\">Outbox</a><a href=\"/admin/audit\">Audit</a>");
                page.Append("<form method=\"post\" action=\"/admin/logout\">");
                Csrf(page, chrome);
                page.Append("<button type=\"submit\">Sign out</button></form></nav>");
                page.Append("<main>");
            }

            return page;
        }

        private static string Tail(StringBuilder page, ChromeModel chrome = null)
        {
            if (chrome != null && chrome.SignedIn)
            {
                page.Append("</main>");
            }

            page.Append("</body></html>");

            return page.ToString();
        }

        private static void Csrf(StringBuilder page, ChromeModel chrome)
        {
            page.Append("<input type=\"hidden\" name=\"csrf\" value=\"")
                .Append(E(chrome == null ? string.Empty : chrome.CsrfToken))
                .Append("\">");
        }

        private static void Headings(StringBuilder page, params string[] headings)
        {
            foreach (var heading in headings)
            {
                page.Append("<th>").Append(E(heading)).Append("</th>");
            }
        }

        private static void Cell(StringBuilder page, string value)
        {
            page.Append("<td>").Append(E(value)).Append("</td>");
        }

        private static void Field(StringBuilder page, string name, string value)
        {
            page.Append("<dt>").Append(E(name)).Append("</dt><dd>").Append(E(value)).Append("</dd>");
        }

        private static string StateClass(CodeState state)
        {
            switch (state)
            {
                case CodeState.Undelivered:
                case CodeState.Unpaid:
                case CodeState.Lapsed:
                case CodeState.Lapsing:
                    return "attention";

                case CodeState.Void:
                    return "gone";

                default:
                    return string.Empty;
            }
        }

        /// <summary>
        /// The only way a value gets into a page. HtmlEncode covers &lt;, &gt;,
        /// &amp;, " and ' - which is the whole set that matters in both element
        /// text and a double-quoted attribute, and every interpolation here is
        /// one or the other.
        /// </summary>
        private static string E(string value)
        {
            return WebUtility.HtmlEncode(value ?? string.Empty);
        }

        /// <summary>
        /// The only way a value gets into a URL. Separate from <see cref="E"/>
        /// because HTML-encoding a URL segment is not the same job, and doing
        /// one where the other is needed is how a link becomes a hole.
        /// </summary>
        private static string U(string value)
        {
            return E(Uri.EscapeDataString(value ?? string.Empty));
        }

        private const string Style =
            "body{font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7f9;"
            + "color:#16191d;}"
            + "nav{display:flex;gap:.75rem;align-items:center;background:#16191d;padding:.6rem 1rem;flex-wrap:wrap;}"
            + "nav a{color:#fff;text-decoration:none;font-weight:600;}"
            + "nav a:hover{text-decoration:underline;}"
            + "nav form{margin:0 0 0 auto;}"
            + "nav button{background:none;border:1px solid #6b7480;color:#dfe3e8;border-radius:4px;padding:.25rem .6rem;"
            + "cursor:pointer;font:inherit;}"
            + "main{max-width:64rem;margin:0 auto;padding:1.5rem 1.25rem 4rem;}"
            + "main.narrow{max-width:26rem;background:#fff;border:1px solid #dfe3e8;border-radius:10px;"
            + "margin:3rem auto;padding:1.75rem;}"
            + "h1{font-size:1.35rem;margin:0 0 1rem;}h2{font-size:1.05rem;margin:1.5rem 0 .5rem;}"
            + "table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #dfe3e8;margin:.5rem 0;}"
            + "th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #eceff2;font-size:.9rem;"
            + "vertical-align:top;}"
            + "th{background:#eceff2;font-size:.75rem;letter-spacing:.04em;}"
            + "tr.attention td:first-child{font-weight:700;color:#a1240f;}"
            + "tr.gone td{color:#6b7480;}"
            + "dl{background:#fff;border:1px solid #dfe3e8;margin:.5rem 0;padding:.75rem 1rem;display:grid;"
            + "grid-template-columns:max-content 1fr;gap:.25rem 1rem;}"
            + "dt{font-weight:600;color:#5b6672;}dd{margin:0;overflow-wrap:anywhere;}"
            + "form{margin:1rem 0;}"
            + "label{display:block;font-weight:600;margin:.6rem 0 .2rem;}"
            + "label.check{display:inline-block;font-weight:400;margin-right:1rem;}"
            + "input{font:inherit;padding:.4rem .5rem;border:1px solid #b6bec7;border-radius:4px;max-width:24rem;"
            + "width:100%;}"
            + "input[type=checkbox]{width:auto;}"
            + "button{font:inherit;font-weight:600;background:#16191d;color:#fff;border:0;border-radius:5px;"
            + "padding:.5rem 1rem;cursor:pointer;margin-top:.75rem;}"
            + "button.danger,a.danger{background:#a1240f;color:#fff;}"
            + "a.danger{display:inline-block;padding:.5rem 1rem;border-radius:5px;text-decoration:none;}"
            + ".filters{display:flex;gap:.75rem;align-items:flex-end;flex-wrap:wrap;background:#fff;"
            + "border:1px solid #dfe3e8;padding:.5rem 1rem 1rem;}"
            + ".filters label{margin-bottom:0;}.filters input{width:auto;}"
            + ".filters button{margin-top:0;}"
            + ".warning{background:#fdf0ec;border:2px solid #a1240f;border-radius:6px;padding:.25rem 1rem 1rem;"
            + "margin:1.25rem 0;}"
            + ".warning h2{color:#a1240f;margin-top:1rem;}"
            + ".code{font:700 1.5rem/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#fff;"
            + "border:2px dashed #16191d;border-radius:6px;padding:1rem;text-align:center;overflow-wrap:anywhere;"
            + "user-select:all;}"
            + ".muted{color:#5b6672;font-size:.85rem;}"
            + ".bad{color:#a1240f;font-weight:600;}"
            + ".good{background:#eef7ee;border:1px solid #9ec69e;padding:.5rem .75rem;border-radius:5px;}"
            + "code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}";
    }

    /// <summary>What every signed-in page needs: the CSRF token, and whether there is a session at all.</summary>
    internal class ChromeModel
    {
        public bool SignedIn { get; set; }

        public string CsrfToken { get; set; }
    }

    internal sealed class LoginModel
    {
        public string Message { get; set; }
    }

    internal sealed class CodesModel : ChromeModel
    {
        public IReadOnlyList<ManagedCode> Rows { get; set; } = Array.Empty<ManagedCode>();

        public string Filter { get; set; }

        public bool OnlyAttention { get; set; }

        public int SoonDays { get; set; }

        public string Summary { get; set; }

        public string EmptyMessage { get; set; }
    }

    internal sealed class DetailModel : ChromeModel
    {
        public CodeSummary Code { get; set; }

        public Delivery.OutboxRecord Delivery { get; set; }

        public string StateText { get; set; }

        public IReadOnlyList<ActivationRow> Activations { get; set; } = Array.Empty<ActivationRow>();

        public DateTimeOffset Now { get; set; }

        public string Notice { get; set; }
    }

    internal sealed class IssueModel : ChromeModel
    {
        public string Nonce { get; set; }

        public string Licensee { get; set; }

        public string Activations { get; set; }

        public string Days { get; set; }

        public string Note { get; set; }

        public IReadOnlyList<string> Problems { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// One outbox line as the page shows it.
    ///
    /// THERE IS NO FIELD HERE A CODE COULD LIVE IN, on purpose and by the same
    /// argument as <see cref="ManagedCode"/>: the outbox file holds codes in the
    /// clear, so the page that lists it is handed a projection that does not,
    /// and revealing one has to go through the deliberate, audited, one-at-a-time
    /// route rather than being one careless column away.
    /// </summary>
    internal sealed class OutboxRow
    {
        public string Tag { get; set; }

        public string CreatedUtc { get; set; }

        public string Buyer { get; set; }

        public string Sent { get; set; }

        public string ActivationsAllowed { get; set; }

        public string LicenceDays { get; set; }

        public string Capture { get; set; }

        public string StoreNote { get; set; }

        /// <summary>Whether the line has a code on it to be revealed at all.</summary>
        public bool HasCode { get; set; }
    }

    internal sealed class OutboxModel : ChromeModel
    {
        public IReadOnlyList<OutboxRow> Rows { get; set; } = Array.Empty<OutboxRow>();

        public IReadOnlyList<string> Warnings { get; set; } = Array.Empty<string>();

        public string Summary { get; set; }

        public string EmptyMessage { get; set; }

        public string Nonce { get; set; }
    }

    internal sealed class AuditModel : ChromeModel
    {
        public IReadOnlyList<AdminAuditLine> Lines { get; set; } = Array.Empty<AdminAuditLine>();

        public string Path { get; set; }
    }
}

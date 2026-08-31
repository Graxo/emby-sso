using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Admin;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.Management;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The five jobs the page does - list, show, void, issue, outbox - and the
    /// two rules that hold across all of them:
    ///
    ///   1. no redemption code the store knows only by hash is ever rendered,
    ///      anywhere, including in an audit line;
    ///   2. the void confirmation says, in the interface and before the button,
    ///      that it cannot recall a licence already issued.
    ///
    /// Plus the one the operator will hit by accident: a double-tapped Issue
    /// button must not mint two credentials.
    /// </summary>
    public class AdminManagementPageTests
    {
        private const string Hostile = "<script>alert('licensee')</script>";

        // ------------------------------------------------------------- lists

        [Fact]
        public async Task The_codes_page_lists_what_is_in_the_store_and_never_a_code()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = host.Service.GiveOutACode();
            var tag = RedemptionCode.LogTag(HashOf(code));

            var page = await host.BodyOfAsync("/admin/codes");

            Assert.Contains(tag, page, StringComparison.Ordinal);
            AssertNoCode(page, code);
        }

        [Fact]
        public async Task The_filter_narrows_the_list_the_same_way_the_command_does()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            host.Service.Store.CreateManualCode(Hash('1'), "Alice Ashford", 3, 365, null, host.Clock.GetUtcNow());
            host.Service.Store.CreateManualCode(Hash('2'), "Bruno Bell", 3, 365, null, host.Clock.GetUtcNow());

            var page = await host.BodyOfAsync("/admin/codes?for=alice");

            Assert.Contains("Alice Ashford", page, StringComparison.Ordinal);
            Assert.DoesNotContain("Bruno Bell", page, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_code_a_customer_sends_is_looked_up_by_a_form_and_never_by_a_link()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = host.Service.GiveOutACode();
            var csrf = AdminTestHost.CsrfIn(await host.BodyOfAsync("/admin/codes"));

            using var response = await host.PostAsync("/admin/find", ("csrf", csrf), ("code", code));

            Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

            // The redirect names the TAG. The code is not in the Location, so it
            // is not in the address bar, the history or the next Referer.
            Assert.Equal("/admin/code/" + RedemptionCode.LogTag(HashOf(code)), response.LocationOf());
            AssertNoCode(response.LocationOf(), code);
        }

        [Fact]
        public async Task A_code_this_store_never_held_is_told_apart_from_one_that_is_not_a_code()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var csrf = AdminTestHost.CsrfIn(await host.BodyOfAsync("/admin/codes"));
            var stranger = RedemptionCode.Format(RedemptionCode.Generate());

            using (var unknown = await host.PostAsync("/admin/find", ("csrf", csrf), ("code", stranger)))
            {
                Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
                Assert.Contains(
                    "never held it",
                    await unknown.Content.ReadAsStringAsync(),
                    StringComparison.Ordinal);
            }

            using var nonsense = await host.PostAsync("/admin/find", ("csrf", csrf), ("code", "banana"));

            Assert.Equal(HttpStatusCode.NotFound, nonsense.StatusCode);
            Assert.Contains(
                "not a well-formed redemption code",
                await nonsense.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_detail_page_shows_the_activations_and_never_the_code()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = host.Service.GiveOutACode();

            Assert.True(host.Service.Activations.Activate(
                new Activation.ActivationRequest { Code = code, ServerId = "c5bc6e91458540caa295c4efdda1a58a" },
                "10.0.0.1").IsSuccess);

            var page = await host.BodyOfAsync("/admin/code/" + RedemptionCode.LogTag(HashOf(code)));

            Assert.Contains("c5bc6e91458540caa295c4efdda1a58a", page, StringComparison.Ordinal);
            Assert.Contains("1 of 3 used", page, StringComparison.Ordinal);
            AssertNoCode(page, code);
        }

        // -------------------------------------------------------------- void

        /// <summary>
        /// The rule that is absolute. The words come from
        /// <see cref="VoidExplanation"/>, which is also where the command line
        /// gets them, so the two cannot drift.
        /// </summary>
        [Fact]
        public async Task The_void_confirmation_says_it_cannot_recall_a_licence_already_issued()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = host.Service.GiveOutACode();

            host.Service.Activations.Activate(
                new Activation.ActivationRequest { Code = code, ServerId = "c5bc6e91458540caa295c4efdda1a58a" },
                "10.0.0.1");

            var page = await host.BodyOfAsync("/admin/code/" + RedemptionCode.LogTag(HashOf(code)) + "/void");

            Assert.Contains(VoidExplanation.Headline, page, StringComparison.Ordinal);
            Assert.Contains("1 server(s) have already been given a licence from it", page, StringComparison.Ordinal);
            Assert.Contains("never calls this service", page, StringComparison.Ordinal);

            // Before the button, not after it. Someone reaching for this after
            // a refund needs it while they are still deciding.
            Assert.True(
                page.IndexOf(VoidExplanation.Headline, StringComparison.Ordinal)
                < page.IndexOf("Void it.", StringComparison.Ordinal),
                "the warning came after the button");
        }

        [Fact]
        public async Task The_warning_appears_even_when_nothing_has_been_activated_yet()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = host.Service.GiveOutACode();
            var page = await host.BodyOfAsync("/admin/code/" + RedemptionCode.LogTag(HashOf(code)) + "/void");

            Assert.Contains(VoidExplanation.Headline, page, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Voiding_from_the_page_stops_the_next_activation_and_is_audited_by_tag()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = host.Service.GiveOutACode();
            var tag = RedemptionCode.LogTag(HashOf(code));

            var confirm = await host.BodyOfAsync("/admin/code/" + tag + "/void");

            using (var response = await host.PostAsync(
                "/admin/void",
                ("csrf", AdminTestHost.CsrfIn(confirm)),
                ("tag", tag),
                ("reason", "refunded, ticket 4471")))
            {
                Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
            }

            Assert.Equal(CodeStatus.Void, host.Service.Store.FindCodeByHash(HashOf(code)).Status);

            var afterwards = host.Service.Activations.Activate(
                new Activation.ActivationRequest { Code = code, ServerId = "aaaa1111bbbb2222cccc3333dddd4444" },
                "10.0.0.1");

            Assert.False(afterwards.IsSuccess);

            var audit = host.AuditFile();

            Assert.Contains("\"event\":\"" + AdminAudit.Voided + "\"", audit, StringComparison.Ordinal);
            Assert.Contains(tag, audit, StringComparison.Ordinal);
            Assert.Contains("refunded, ticket 4471", audit, StringComparison.Ordinal);
            AssertNoCode(audit, code);
        }

        [Fact]
        public async Task Voiding_twice_from_the_page_is_not_an_error_and_keeps_the_first_reason()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = host.Service.GiveOutACode();
            var tag = RedemptionCode.LogTag(HashOf(code));
            var csrf = AdminTestHost.CsrfIn(await host.BodyOfAsync("/admin/code/" + tag + "/void"));

            using (var first = await host.PostAsync("/admin/void", ("csrf", csrf), ("tag", tag), ("reason", "the first reason")))
            {
                Assert.Equal(HttpStatusCode.SeeOther, first.StatusCode);
            }

            using (var second = await host.PostAsync("/admin/void", ("csrf", csrf), ("tag", tag), ("reason", "a later reason")))
            {
                Assert.Equal(HttpStatusCode.SeeOther, second.StatusCode);
            }

            Assert.Equal("the first reason", host.Service.Store.FindCodeByHash(HashOf(code)).VoidReason);
        }

        // ------------------------------------------------------------- issue

        [Fact]
        public async Task Issuing_a_code_shows_it_exactly_once()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var form = await host.BodyOfAsync("/admin/issue");

            using (var posted = await host.PostAsync(
                "/admin/issue",
                ("csrf", AdminTestHost.CsrfIn(form)),
                ("nonce", AdminTestHost.NonceIn(form)),
                ("licensee", "Jane Tester"),
                ("activations", "2"),
                ("days", "90"),
                ("note", "comp for the beta")))
            {
                Assert.Equal(HttpStatusCode.SeeOther, posted.StatusCode);
                Assert.Equal("/admin/issued", posted.LocationOf());

                // The code is not in the redirect. It is in server-side session
                // state; the URL is the same one every issue redirects to.
                Assert.DoesNotContain("-", posted.LocationOf().Substring("/admin/".Length), StringComparison.Ordinal);
            }

            var shown = await host.BodyOfAsync("/admin/issued");
            var code = CodeIn(shown);

            Assert.NotNull(code);
            Assert.Contains("ONLY TIME THIS CODE IS SHOWN", shown, StringComparison.Ordinal);

            // The store holds it, by hash.
            var stored = host.Service.Store.FindCodeByHash(HashOf(code));

            Assert.NotNull(stored);
            Assert.Equal("Jane Tester", stored.Licensee);
            Assert.Equal(2, stored.ActivationsAllowed);
            Assert.Equal(90, stored.LicenceDays);

            // And a refresh, a back button or a second tab gets nothing.
            using var again = await host.GetAsync("/admin/issued");

            Assert.Equal(HttpStatusCode.Gone, again.StatusCode);
            AssertNoCode(await again.Content.ReadAsStringAsync(), code);
        }

        /// <summary>
        /// The operator double-taps the button. Exactly one credential must
        /// exist afterwards. Remove the one-shot nonce and this creates two.
        /// </summary>
        [Fact]
        public async Task A_double_tapped_issue_button_creates_exactly_one_code()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var before = host.Service.Store.ListCodes().Count;
            var form = await host.BodyOfAsync("/admin/issue");

            var fields = new (string, string)[]
            {
                ("csrf", AdminTestHost.CsrfIn(form)),
                ("nonce", AdminTestHost.NonceIn(form)),
                ("licensee", "Double Tap"),
                ("activations", "3"),
                ("days", "365"),
            };

            using (var first = await host.PostAsync("/admin/issue", fields))
            {
                Assert.Equal(HttpStatusCode.SeeOther, first.StatusCode);
            }

            using (var second = await host.PostAsync("/admin/issue", fields))
            {
                Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
                Assert.Contains(
                    "NO SECOND CODE WAS CREATED",
                    await second.Content.ReadAsStringAsync(),
                    StringComparison.Ordinal);
            }

            Assert.Equal(before + 1, host.Service.Store.ListCodes().Count);
            Assert.Single(host.Service.Store.ListCodes(), row => row.Licensee == "Double Tap");
        }

        [Fact]
        public async Task Issuing_records_who_and_when_but_never_the_code()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var form = await host.BodyOfAsync("/admin/issue");

            await host.PostAsync(
                "/admin/issue",
                ("csrf", AdminTestHost.CsrfIn(form)),
                ("nonce", AdminTestHost.NonceIn(form)),
                ("licensee", "Audited Person"),
                ("activations", "3"),
                ("days", "365"));

            var code = CodeIn(await host.BodyOfAsync("/admin/issued"));
            var audit = host.AuditFile();

            Assert.Contains("\"event\":\"" + AdminAudit.Issued + "\"", audit, StringComparison.Ordinal);
            Assert.Contains("Audited Person", audit, StringComparison.Ordinal);
            Assert.Contains(RedemptionCode.LogTag(HashOf(code)), audit, StringComparison.Ordinal);
            AssertNoCode(audit, code);
        }

        [Fact]
        public async Task A_bad_issue_form_creates_nothing_and_says_everything_that_is_wrong()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var before = host.Service.Store.ListCodes().Count;
            var form = await host.BodyOfAsync("/admin/issue");

            using var response = await host.PostAsync(
                "/admin/issue",
                ("csrf", AdminTestHost.CsrfIn(form)),
                ("nonce", AdminTestHost.NonceIn(form)),
                ("licensee", "   "),
                ("activations", "0"),
                ("days", "-4"));

            var html = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("Licensee is required", html, StringComparison.Ordinal);
            Assert.Contains("Activations must be at least 1", html, StringComparison.Ordinal);
            Assert.Contains("Days must be at least 1", html, StringComparison.Ordinal);
            Assert.Equal(before, host.Service.Store.ListCodes().Count);
        }

        [Fact]
        public async Task The_page_and_the_command_issue_the_same_kind_of_code()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var form = await host.BodyOfAsync("/admin/issue");

            await host.PostAsync(
                "/admin/issue",
                ("csrf", AdminTestHost.CsrfIn(form)),
                ("nonce", AdminTestHost.NonceIn(form)),
                ("licensee", "From the page"),
                ("activations", "3"),
                ("days", "365"));

            var code = CodeIn(await host.BodyOfAsync("/admin/issued"));

            // It activates, which is the only test of "the same kind" that
            // matters: it went through CodeIssuing, the way `issue-code` does.
            var outcome = host.Service.Activations.Activate(
                new Activation.ActivationRequest { Code = code, ServerId = "c5bc6e91458540caa295c4efdda1a58a" },
                "10.0.0.1");

            Assert.True(outcome.IsSuccess);
        }

        // ------------------------------------------------------------ outbox

        [Fact]
        public async Task The_outbox_page_lists_the_lines_and_shows_no_codes()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = Sold(host, "buyer@example.com");
            var page = await host.BodyOfAsync("/admin/outbox");

            Assert.Contains("buyer@example.com", page, StringComparison.Ordinal);
            Assert.Contains(RedemptionCode.LogTag(RedemptionCode.Hash(code)), page, StringComparison.Ordinal);
            AssertNoCode(page, RedemptionCode.Format(code));
        }

        [Fact]
        public async Task Revealing_one_outbox_code_is_deliberate_shown_once_and_audited_without_the_code()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = Sold(host, "buyer@example.com");
            var tag = RedemptionCode.LogTag(RedemptionCode.Hash(code));
            var page = await host.BodyOfAsync("/admin/outbox");

            using (var revealed = await host.PostAsync(
                "/admin/outbox/reveal",
                ("csrf", AdminTestHost.CsrfIn(page)),
                ("nonce", AdminTestHost.NonceIn(page)),
                ("tag", tag)))
            {
                Assert.Equal(HttpStatusCode.SeeOther, revealed.StatusCode);
                AssertNoCode(revealed.LocationOf(), RedemptionCode.Format(code));
            }

            var shown = await host.BodyOfAsync("/admin/issued");

            Assert.Contains(RedemptionCode.Format(code), shown, StringComparison.Ordinal);

            var audit = host.AuditFile();

            Assert.Contains("\"event\":\"" + AdminAudit.Revealed + "\"", audit, StringComparison.Ordinal);
            Assert.Contains(tag, audit, StringComparison.Ordinal);
            AssertNoCode(audit, RedemptionCode.Format(code));

            // Shown once, like everything else that shows a code.
            using var again = await host.GetAsync("/admin/issued");

            Assert.Equal(HttpStatusCode.Gone, again.StatusCode);
        }

        [Fact]
        public async Task Revealing_without_the_csrf_token_shows_nothing()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = Sold(host, "buyer@example.com");
            var page = await host.BodyOfAsync("/admin/outbox");

            using var response = await host.PostAsync(
                "/admin/outbox/reveal",
                ("nonce", AdminTestHost.NonceIn(page)),
                ("tag", RedemptionCode.LogTag(RedemptionCode.Hash(code))));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            AssertNoCode(await response.Content.ReadAsStringAsync(), RedemptionCode.Format(code));
        }

        /// <summary>
        /// The same argument <see cref="ManagedCode"/> makes: the type the
        /// outbox page is handed has no field a code could live in, so listing
        /// one is not something a careless column can do. The outbox FILE holds
        /// codes in the clear; the projection the page renders does not.
        /// </summary>
        [Fact]
        public void The_type_the_outbox_page_renders_has_no_field_a_code_could_live_in()
        {
            var names = typeof(OutboxRow)
                .GetProperties()
                .Select(property => property.Name)
                .ToList();

            Assert.DoesNotContain(names, name => name.Equals("Code", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(names, name => name == "Tag");
        }

        // ------------------------------------------------------------- audit

        [Fact]
        public async Task The_audit_page_shows_what_happened_and_never_a_code()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var form = await host.BodyOfAsync("/admin/issue");

            await host.PostAsync(
                "/admin/issue",
                ("csrf", AdminTestHost.CsrfIn(form)),
                ("nonce", AdminTestHost.NonceIn(form)),
                ("licensee", "Someone"),
                ("activations", "3"),
                ("days", "365"));

            var code = CodeIn(await host.BodyOfAsync("/admin/issued"));
            var page = await host.BodyOfAsync("/admin/audit");

            Assert.Contains(AdminAudit.LoggedIn, page, StringComparison.Ordinal);
            Assert.Contains(AdminAudit.Issued, page, StringComparison.Ordinal);
            AssertNoCode(page, code);
        }

        /// <summary>
        /// The audit trail's own guard: even if a caller one day passes a code
        /// into a detail field, it does not reach the disk. Remove
        /// <see cref="AdminAudit.Scrub"/> and this fails.
        /// </summary>
        [Fact]
        public void A_code_handed_to_the_audit_trail_by_mistake_is_redacted()
        {
            var code = RedemptionCode.Format(RedemptionCode.Generate());

            Assert.DoesNotContain(code, AdminAudit.Scrub("the code is " + code), StringComparison.Ordinal);
            Assert.Contains("redacted", AdminAudit.Scrub("the code is " + code), StringComparison.Ordinal);

            // And a tag, which is hexadecimal and twelve characters, survives.
            Assert.Equal("0123456789ab", AdminAudit.Scrub("0123456789ab"));
        }

        // ---------------------------------------------------------- escaping

        [Fact]
        public async Task A_hostile_licensee_and_note_are_escaped_on_every_page_they_reach()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var form = await host.BodyOfAsync("/admin/issue");

            await host.PostAsync(
                "/admin/issue",
                ("csrf", AdminTestHost.CsrfIn(form)),
                ("nonce", AdminTestHost.NonceIn(form)),
                ("licensee", Hostile),
                ("activations", "3"),
                ("days", "365"),
                ("note", "<img src=x onerror=alert(2)>"));

            var code = CodeIn(await host.BodyOfAsync("/admin/issued"));
            var tag = RedemptionCode.LogTag(HashOf(code));

            foreach (var path in new[] { "/admin/codes", "/admin/code/" + tag, "/admin/code/" + tag + "/void", "/admin/audit" })
            {
                var page = await host.BodyOfAsync(path);

                AssertEscaped(page, path);
            }

            // And it IS on the page - escaped, readable, and inert. A page that
            // dropped the field entirely would pass the assertions above.
            var detail = await host.BodyOfAsync("/admin/code/" + tag);

            Assert.Contains("&lt;script&gt;", detail, StringComparison.Ordinal);
            Assert.Contains("&lt;img src=x onerror=alert(2)&gt;", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_hostile_void_reason_is_escaped_where_it_is_shown_afterwards()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var code = host.Service.GiveOutACode();
            var tag = RedemptionCode.LogTag(HashOf(code));
            var confirm = await host.BodyOfAsync("/admin/code/" + tag + "/void");

            await host.PostAsync(
                "/admin/void",
                ("csrf", AdminTestHost.CsrfIn(confirm)),
                ("tag", tag),
                ("reason", Hostile));

            AssertEscaped(await host.BodyOfAsync("/admin/code/" + tag), "detail");
            AssertEscaped(await host.BodyOfAsync("/admin/audit"), "audit");
        }

        [Fact]
        public async Task A_hostile_filter_is_escaped_back_into_the_form_field_it_came_from()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            var page = await host.BodyOfAsync("/admin/codes?for=%22%20onmouseover%3Dalert(3)%20x%3D%22");

            Assert.DoesNotContain("\" onmouseover", page, StringComparison.Ordinal);
            Assert.Contains("&quot;", page, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_hostile_buyer_address_in_the_outbox_is_escaped()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            Sold(host, Hostile);

            AssertEscaped(await host.BodyOfAsync("/admin/outbox"), "outbox");
        }

        [Fact]
        public async Task A_tag_that_is_not_a_tag_is_refused_rather_than_reflected()
        {
            await using var host = await AdminTestHost.StartAsync();

            await host.LoginAsync();

            using var response = await host.GetAsync("/admin/code/%3Cscript%3Ealert(4)%3C%2Fscript%3E");
            var page = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            AssertEscaped(page, "detail of a nonsense tag");
        }

        // ----------------------------------------------------------- helpers

        /// <summary>
        /// What escaped means: the hostile value may appear as TEXT - it is a
        /// licensee's name and the operator has to be able to read it - but
        /// never as a tag the browser would act on. So no opening tag of any
        /// kind that this service did not write, and no javascript: URL.
        /// </summary>
        private static void AssertEscaped(string page, string where)
        {
            // Not "<style": this page has one of its own, in the head, which
            // is the whole of its styling and the reason the content security
            // policy allows an inline stylesheet and nothing else.
            foreach (var attempt in new[] { "<script", "<img", "<svg", "<iframe", "javascript:", "<object", "<embed" })
            {
                Assert.DoesNotContain(attempt, page, StringComparison.OrdinalIgnoreCase);
            }

            _ = where;
        }

        /// <summary>
        /// The code, in either shape it could appear in, and its unformatted
        /// form too - a page that stripped the hyphens would still have leaked
        /// it.
        /// </summary>
        private static void AssertNoCode(string text, string code)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }

            RedemptionCode.TryNormalise(code, out var normalised);

            Assert.DoesNotContain(code, text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(normalised, text, StringComparison.OrdinalIgnoreCase);
        }

        private static string CodeIn(string html)
        {
            var match = System.Text.RegularExpressions.Regex.Match(
                html,
                "<p class=\"code\">([^<]+)</p>",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant);

            return match.Success ? match.Groups[1].Value.Trim() : null;
        }

        /// <summary>A sale: a code in the store and a line in the outbox, the way the webhook leaves one.</summary>
        private static string Sold(AdminTestHost host, string buyer)
        {
            var code = RedemptionCode.Generate();

            host.Service.Store.CreateManualCode(
                RedemptionCode.Hash(code),
                buyer,
                3,
                365,
                buyer,
                host.Clock.GetUtcNow());

            host.Service.Outbox.Append(new OutboxEntry
            {
                CreatedUtc = host.Clock.GetUtcNow(),
                Code = code,
                Licensee = buyer,
                BuyerEmail = buyer,
                ActivationsAllowed = 3,
                LicenceDays = 365,
                PayPalCaptureId = "CAPTURE-1",
                PayPalEventId = "EVENT-1",
            });

            return code;
        }

        private static string Hash(char filler)
        {
            return new string(filler, 64);
        }

        private static string HashOf(string code)
        {
            RedemptionCode.TryNormalise(code, out var normalised);

            return RedemptionCode.Hash(normalised);
        }
    }
}

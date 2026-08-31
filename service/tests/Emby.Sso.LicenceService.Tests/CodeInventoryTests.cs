using System;
using System.Linq;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.LicenceService.Management;
using Emby.Sso.LicenceService.Storage;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// What state a code is in, and in what order an operator is shown them.
    ///
    /// This is the judgement in `list-codes` - the table itself is padding - so
    /// it is tested here without a database, a file or a real clock. Each test
    /// is named after the sentence in the README it holds up.
    /// </summary>
    public class CodeInventoryTests
    {
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

        [Fact]
        public void A_paid_code_nobody_has_activated_yet_is_unused()
        {
            Assert.Equal(CodeState.Unused, Classify(Code()));
        }

        [Fact]
        public void A_code_with_one_of_three_activations_is_active()
        {
            Assert.Equal(CodeState.Active, Classify(Code(used: 1, expires: Now.AddDays(300))));
        }

        [Fact]
        public void A_code_with_a_line_in_the_outbox_and_no_receipt_is_undelivered()
        {
            Assert.Equal(CodeState.Undelivered, Classify(Code(), Sent(delivered: false)));
        }

        [Fact]
        public void A_code_whose_outbox_line_has_a_receipt_beside_it_is_not_undelivered()
        {
            Assert.Equal(CodeState.Unused, Classify(Code(), Sent(delivered: true)));
        }

        /// <summary>
        /// The README tells the operator to send a code and then delete its
        /// line, so no line is the normal end state of a finished sale. Calling
        /// that undelivered would make the command cry wolf on every code the
        /// operator has already dealt with - and on every code `issue-code`
        /// ever made, which never goes near the outbox.
        /// </summary>
        [Fact]
        public void A_code_with_no_outbox_line_at_all_is_not_called_undelivered()
        {
            Assert.Equal(CodeState.Unused, Classify(Code(), delivery: null));
        }

        [Fact]
        public void A_code_already_activated_is_not_called_undelivered_whatever_the_outbox_says()
        {
            // They plainly received it. An unpruned line is then untidiness, not
            // a sale that failed to arrive.
            Assert.Equal(
                CodeState.Active,
                Classify(Code(used: 1, expires: Now.AddDays(300)), Sent(delivered: false)));
        }

        [Fact]
        public void A_refunded_code_reads_as_void_even_though_it_never_went_out()
        {
            // Void outranks undelivered deliberately: chasing the delivery of a
            // code whose buyer has their money back is the wrong action.
            Assert.Equal(
                CodeState.Void,
                Classify(Code(status: CodeStatus.Void), Sent(delivered: false)));
        }

        [Fact]
        public void An_unpaid_code_reads_as_unpaid()
        {
            Assert.Equal(CodeState.Unpaid, Classify(Code(status: CodeStatus.Unpaid)));
        }

        [Fact]
        public void A_licence_past_its_expiry_has_lapsed()
        {
            Assert.Equal(CodeState.Lapsed, Classify(Code(used: 1, expires: Now.AddDays(-1))));
        }

        [Fact]
        public void A_licence_inside_the_window_is_lapsing()
        {
            Assert.Equal(CodeState.Lapsing, Classify(Code(used: 1, expires: Now.AddDays(10))));
        }

        [Fact]
        public void The_window_is_what_soon_says_it_is()
        {
            var code = Code(used: 1, expires: Now.AddDays(30));

            Assert.Equal(CodeState.Active, CodeInventory.Classify(code, null, Now, soonDays: 21));
            Assert.Equal(CodeState.Lapsing, CodeInventory.Classify(code, null, Now, soonDays: 60));
        }

        [Fact]
        public void A_code_with_every_activation_used_is_exhausted()
        {
            Assert.Equal(CodeState.Exhausted, Classify(Code(used: 3, expires: Now.AddDays(300))));
        }

        [Fact]
        public void An_exhausted_code_whose_licence_has_lapsed_reads_as_lapsed()
        {
            // The licence running out is the thing the customer is about to ask
            // about; having used all three servers is not news.
            Assert.Equal(CodeState.Lapsed, Classify(Code(used: 3, expires: Now.AddDays(-2))));
        }

        [Fact]
        public void Only_undelivered_unpaid_lapsed_and_lapsing_need_attention()
        {
            var needy = Enum.GetValues(typeof(CodeState))
                .Cast<CodeState>()
                .Where(state => new ManagedCode { Code = Code(), State = state }.NeedsAttention)
                .ToArray();

            Assert.Equal(
                new[] { CodeState.Undelivered, CodeState.Unpaid, CodeState.Lapsed, CodeState.Lapsing },
                needy);
        }

        [Fact]
        public void What_needs_attention_is_at_the_top_and_what_is_finished_with_is_at_the_bottom()
        {
            var outbox = OutboxWith("aaaaaaaaaaaa", delivered: false);

            var built = CodeInventory.Build(
                new[]
                {
                    Code(id: 1, hash: New('b'), used: 2, expires: Now.AddDays(300)),
                    Code(id: 2, hash: New('c'), status: CodeStatus.Void),
                    Code(id: 3, hash: New('a')),
                    Code(id: 4, hash: New('d'), used: 1, expires: Now.AddDays(-5)),
                    Code(id: 5, hash: New('e'), status: CodeStatus.Unpaid),
                },
                outbox,
                Now,
                CodeInventory.DefaultSoonDays);

            Assert.Equal(
                new[] { CodeState.Undelivered, CodeState.Unpaid, CodeState.Lapsed, CodeState.Active, CodeState.Void },
                built.Select(code => code.State).ToArray());
        }

        [Fact]
        public void Inside_one_state_the_oldest_sale_is_first()
        {
            var built = CodeInventory.Build(
                new[]
                {
                    Code(id: 1, hash: New('a'), created: Now.AddDays(-1)),
                    Code(id: 2, hash: New('b'), created: Now.AddDays(-40)),
                    Code(id: 3, hash: New('c'), created: Now.AddDays(-9)),
                },
                OutboxLog.Empty,
                Now,
                CodeInventory.DefaultSoonDays);

            Assert.Equal(new long[] { 2, 3, 1 }, built.Select(code => code.Code.Id).ToArray());
        }

        [Fact]
        public void Inside_a_lapsing_group_the_soonest_expiry_is_first()
        {
            var built = CodeInventory.Build(
                new[]
                {
                    Code(id: 1, hash: New('a'), created: Now.AddDays(-100), used: 1, expires: Now.AddDays(14)),
                    Code(id: 2, hash: New('b'), created: Now.AddDays(-200), used: 1, expires: Now.AddDays(3)),
                },
                OutboxLog.Empty,
                Now,
                CodeInventory.DefaultSoonDays);

            Assert.Equal(new long[] { 2, 1 }, built.Select(code => code.Code.Id).ToArray());
        }

        [Fact]
        public void Nothing_on_a_listed_code_can_be_the_code_itself()
        {
            // The type `list-codes` renders has no field a code could be put in,
            // and the row it wraps has only a hash. This asserts that shape
            // rather than the wording of any one line of output.
            var properties = typeof(CodeSummary).GetProperties().Select(property => property.Name).ToArray();

            Assert.Contains("CodeHash", properties);
            Assert.DoesNotContain(properties, name => name.Equals("Code", StringComparison.Ordinal));
            Assert.DoesNotContain(
                typeof(ManagedCode).GetProperties().Select(property => property.Name),
                name => name.Equals("PlainCode", StringComparison.Ordinal));
        }

        private static CodeState Classify(CodeSummary code, OutboxRecord delivery = null)
        {
            return CodeInventory.Classify(code, delivery, Now, CodeInventory.DefaultSoonDays);
        }

        private static OutboxRecord Sent(bool delivered)
        {
            return new OutboxRecord { CodeTag = "aaaaaaaaaaaa", Delivered = delivered, LineNumber = 1 };
        }

        private static OutboxLog OutboxWith(string tag, bool delivered)
        {
            var path = System.IO.Path.Combine(TestKeys.TempDirectory(), "codes-outbox.jsonl");

            System.IO.File.WriteAllText(
                path,
                "{\"code_tag\":\"" + tag + "\",\"code\":\"AAAAA\",\"buyer_email\":\"b@example.com\"}\n"
                    + (delivered ? "{\"record\":\"delivered\",\"code_tag\":\"" + tag + "\"}\n" : string.Empty));

            return OutboxLog.Read(path, null);
        }

        private static string New(char first)
        {
            return first + new string('a', 63);
        }

        private static CodeSummary Code(
            long id = 1,
            string hash = null,
            string status = null,
            int used = 0,
            int allowed = 3,
            DateTimeOffset? expires = null,
            DateTimeOffset? created = null)
        {
            return new CodeSummary
            {
                Id = id,
                CodeHash = hash ?? new string('a', 64),
                CreatedUtc = created ?? Now.AddDays(-30),
                Status = status ?? CodeStatus.Active,
                Licensee = "Someone",
                ActivationsAllowed = allowed,
                ActivationsUsed = used,
                LicenceDays = 365,
                ExpiresUtc = expires,
                Source = "paypal",
            };
        }
    }
}

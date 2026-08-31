using System;
using System.IO;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.Delivery;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// What the buyer actually reads.
    ///
    /// These assertions are about a person, not a protocol: somebody who has just
    /// paid has to be able to work out from this one message what to type, where
    /// to type it, what they have bought, and who to shout at. Each of those is
    /// asserted, because each of them is the thing a support email would
    /// otherwise be about.
    /// </summary>
    public class CodeMessageTests
    {
        [Fact]
        public void The_message_carries_the_code_in_the_form_the_buyer_will_retype()
        {
            var entry = Entry(out var code);
            var message = CodeMessage.Build(Mail(), entry, CodeMessage.DefaultTemplate);

            Assert.Contains(RedemptionCode.Format(code), message.Body, StringComparison.Ordinal);

            // The grouped form, because that is what the outbox holds and what a
            // human reads back over a phone.
            Assert.Contains("-", RedemptionCode.Format(code), StringComparison.Ordinal);
        }

        [Fact]
        public void The_message_says_where_to_put_the_code_and_which_button_to_press()
        {
            var message = CodeMessage.Build(Mail(), Entry(out _), CodeMessage.DefaultTemplate);

            Assert.Contains("Plugins", message.Body, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Emby SSO", message.Body, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Activate", message.Body, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void The_message_says_what_the_code_is_worth()
        {
            var entry = Entry(out _);

            entry.LicenceDays = 365;
            entry.ActivationsAllowed = 3;

            var message = CodeMessage.Build(Mail(), entry, CodeMessage.DefaultTemplate);

            Assert.Contains("365", message.Body, StringComparison.Ordinal);
            Assert.Contains("3 Emby servers", message.Body, StringComparison.Ordinal);

            // The term starts at first activation, not at purchase. Getting this
            // wrong generates a support email from everyone who waits a week.
            Assert.Contains("first time you activate", message.Body, StringComparison.OrdinalIgnoreCase);

            // Re-activating the same server is free, which is the other question.
            Assert.Contains("does not use", message.Body, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void The_message_says_who_to_ask_for_help()
        {
            var mail = Mail();

            mail.SupportContact = "support@example.com";

            var message = CodeMessage.Build(mail, Entry(out _), CodeMessage.DefaultTemplate);

            Assert.Contains("support@example.com", message.Body, StringComparison.Ordinal);
        }

        [Fact]
        public void The_message_tells_the_buyer_the_code_is_a_secret()
        {
            var message = CodeMessage.Build(Mail(), Entry(out _), CodeMessage.DefaultTemplate);

            Assert.Contains("password", message.Body, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void The_envelope_is_built_from_the_configuration()
        {
            var mail = Mail();

            mail.FromAddress = "licences@example.com";
            mail.FromName = "Example licences";
            mail.ReplyTo = "help@example.com";
            mail.Subject = "Your code";

            var message = CodeMessage.Build(mail, Entry(out _), CodeMessage.DefaultTemplate);

            Assert.Equal("licences@example.com", message.FromAddress);
            Assert.Equal("Example licences", message.FromName);
            Assert.Equal("help@example.com", message.ReplyTo);
            Assert.Equal("Your code", message.Subject);
            Assert.Equal("buyer@example.com", message.ToAddress);
        }

        [Fact]
        public void The_subject_never_contains_the_code()
        {
            // Subjects are what shows in a notification on a lock screen, in a
            // mail server's logs, and in every bounce message.
            var entry = Entry(out var code);
            var message = CodeMessage.Build(Mail(), entry, CodeMessage.DefaultTemplate);

            Assert.DoesNotContain(RedemptionCode.Format(code), message.Subject, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(code, message.Subject, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void With_no_buyer_address_there_is_no_message_to_send()
        {
            // PayPal does not always give us a payer email. Inventing a recipient
            // for a bearer credential is not a thing to do, so this returns null
            // and the caller leaves it in the outbox.
            var entry = Entry(out _);

            entry.BuyerEmail = null;

            Assert.Null(CodeMessage.Build(Mail(), entry, CodeMessage.DefaultTemplate));

            entry.BuyerEmail = "   ";

            Assert.Null(CodeMessage.Build(Mail(), entry, CodeMessage.DefaultTemplate));
        }

        [Fact]
        public void An_operators_template_replaces_the_built_in_wording()
        {
            var entry = Entry(out var code);

            var message = CodeMessage.Build(
                Mail(),
                entry,
                "Codigo: {code}\nServidores: {activations_allowed}\nDias: {licence_days}\nAyuda: {support}");

            Assert.StartsWith("Codigo: " + RedemptionCode.Format(code), message.Body, StringComparison.Ordinal);
            Assert.Contains("Servidores: 3", message.Body, StringComparison.Ordinal);
            Assert.Contains("Dias: 365", message.Body, StringComparison.Ordinal);
            Assert.Contains("Ayuda: licences@example.com", message.Body, StringComparison.Ordinal);
        }

        [Fact]
        public void A_brace_that_is_not_a_placeholder_is_left_alone()
        {
            var message = CodeMessage.Build(Mail(), Entry(out _), "{code} {not_a_placeholder} {}");

            Assert.Contains("{not_a_placeholder}", message.Body, StringComparison.Ordinal);
        }

        [Fact]
        public void No_template_path_means_the_built_in_wording()
        {
            Assert.Equal(CodeMessage.DefaultTemplate, CodeMessage.LoadTemplate(null));
            Assert.Equal(CodeMessage.DefaultTemplate, CodeMessage.LoadTemplate("   "));
        }

        [Fact]
        public void A_template_with_no_code_placeholder_is_refused()
        {
            // It would send every buyer a friendly message containing no code,
            // which is worse than sending nothing, so it stops the service at
            // startup instead.
            var path = Path.Combine(TestKeys.TempDirectory(), "template.txt");

            File.WriteAllText(path, "Thanks for your purchase. Enjoy!");

            var ex = Assert.Throws<MailTemplateException>(() => CodeMessage.LoadTemplate(path));

            Assert.Contains("{code}", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_empty_or_missing_template_file_is_refused()
        {
            var path = Path.Combine(TestKeys.TempDirectory(), "template.txt");

            File.WriteAllText(path, "   \n");

            Assert.Throws<MailTemplateException>(() => CodeMessage.LoadTemplate(path));
            Assert.Throws<MailTemplateException>(() => CodeMessage.LoadTemplate(path + ".missing"));
        }

        [Fact]
        public void A_usable_template_file_is_read_verbatim()
        {
            var path = Path.Combine(TestKeys.TempDirectory(), "template.txt");

            File.WriteAllText(path, "here: {code}");

            Assert.Equal("here: {code}", CodeMessage.LoadTemplate(path));
        }

        internal static MailOptions Mail()
        {
            return new MailOptions
            {
                Host = "smtp.example.com",
                Port = 587,
                Security = MailOptions.StartTls,
                Username = "licences@example.com",
                Password = "hunter2",
                FromAddress = "licences@example.com",
                FromName = MailOptions.DefaultFromName,
                Subject = MailOptions.DefaultSubject,
                SupportContact = "licences@example.com",
                ProductName = "Emby SSO plugin licence",
                MaxAttempts = 4,
                RetrySeconds = 30,
            };
        }

        internal static OutboxEntry Entry(out string code)
        {
            code = RedemptionCode.Generate();

            return new OutboxEntry
            {
                CreatedUtc = new DateTimeOffset(2026, 1, 5, 12, 0, 0, TimeSpan.Zero),
                Code = code,
                Licensee = "buyer@example.com",
                BuyerEmail = "buyer@example.com",
                ActivationsAllowed = 3,
                LicenceDays = 365,
                PayPalEventId = "WH-EVENT-1",
                PayPalCaptureId = "CAPTURE-1",
            };
        }
    }
}

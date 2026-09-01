using System;
using System.Collections.Generic;
using System.IO;
using Emby.Sso.LicenceService.Configuration;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// Mail is the part of this service an operator turns on months after
    /// deploying it, by editing a compose file at speed, so every way of getting
    /// it wrong should stop the service at startup rather than at the first sale.
    ///
    /// The most important test in here is the first one: with no SMTP_HOST the
    /// configuration is valid, mail is off, and the service is the one that was
    /// working yesterday.
    /// </summary>
    public class MailOptionsTests
    {
        [Fact]
        public void With_no_smtp_host_mail_is_off_and_the_configuration_is_still_valid()
        {
            var options = Read(Complete());

            Assert.False(options.Mail.Configured);
            Assert.Empty(options.Problems());
        }

        [Fact]
        public void Turning_mail_on_is_one_variable_plus_a_from_address()
        {
            var options = Read(WithMail());

            Assert.True(options.Mail.Configured);
            Assert.Empty(options.Problems());
        }

        [Fact]
        public void The_default_transport_security_is_starttls_on_587()
        {
            var environment = WithMail();

            environment.Remove("SMTP_SECURITY");
            environment.Remove("SMTP_PORT");

            var options = Read(environment);

            Assert.Equal(MailOptions.StartTls, options.Mail.Security);
            Assert.Equal(587, options.Mail.Port);
            Assert.True(options.Mail.IsEncrypted);
        }

        [Theory]
        [InlineData("tls", 465)]
        [InlineData("starttls", 587)]
        [InlineData("none", 25)]
        public void Each_security_mode_brings_its_own_default_port(string security, int port)
        {
            var environment = WithMail();

            environment["SMTP_SECURITY"] = security;
            environment.Remove("SMTP_PORT");

            if (security == MailOptions.NoEncryption)
            {
                // Cleartext plus a login is refused; see below.
                environment.Remove("SMTP_USERNAME");
                environment.Remove("SMTP_PASSWORD");
            }

            var options = Read(environment);

            Assert.Equal(security, options.Mail.Security);
            Assert.Equal(port, options.Mail.Port);
            Assert.Empty(options.Problems());
        }

        [Fact]
        public void An_explicit_port_wins_over_the_mode_default()
        {
            var environment = WithMail();

            environment["SMTP_SECURITY"] = "tls";
            environment["SMTP_PORT"] = "2465";

            Assert.Equal(2465, Read(environment).Mail.Port);
        }

        [Fact]
        public void Only_the_three_real_modes_are_accepted()
        {
            var environment = WithMail();

            environment["SMTP_SECURITY"] = "ssl";

            Assert.Contains(Read(environment).Problems(), p => p.Contains("SMTP_SECURITY", StringComparison.Ordinal));
        }

        [Fact]
        public void No_encryption_is_allowed_because_local_relays_exist()
        {
            var environment = WithMail();

            environment["SMTP_SECURITY"] = "none";
            environment.Remove("SMTP_USERNAME");
            environment.Remove("SMTP_PASSWORD");

            var options = Read(environment);

            Assert.Empty(options.Problems());
            Assert.False(options.Mail.IsEncrypted);
        }

        [Fact]
        public void A_password_over_a_cleartext_connection_is_a_refusal_to_start()
        {
            // SMTP AUTH on an unencrypted socket puts the relay password on the
            // wire on every message. An operator who genuinely wants an
            // unauthenticated local relay only has to unset the username.
            var environment = WithMail();

            environment["SMTP_SECURITY"] = "none";

            Assert.Contains(
                Read(environment).Problems(),
                p => p.Contains("in the clear", StringComparison.Ordinal));
        }

        [Fact]
        public void Smtp_variables_without_a_host_are_a_refusal_rather_than_a_silent_no_op()
        {
            // The failure mode this prevents: an operator fills in a username and
            // a password, misses SMTP_HOST, and the service starts and quietly
            // emails nobody. That looks exactly like working.
            var environment = Complete();

            environment["SMTP_USERNAME"] = "licences@example.com";
            environment["SMTP_PASSWORD"] = "hunter2";

            Assert.Contains(Read(environment).Problems(), p => p.Contains("SMTP_HOST", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData("SMTP_FROM_ADDRESS", "")]
        [InlineData("SMTP_FROM_ADDRESS", "licences at example.com")]
        [InlineData("SMTP_FROM_ADDRESS", "licences@localhost")]
        [InlineData("SMTP_REPLY_TO", "not an address")]
        [InlineData("SMTP_PORT", "0")]
        [InlineData("SMTP_PORT", "70000")]
        [InlineData("SMTP_PORT", "five eight seven")]
        [InlineData("SMTP_TIMEOUT_SECONDS", "0")]
        [InlineData("SMTP_TIMEOUT_SECONDS", "9000")]
        [InlineData("SMTP_MAX_ATTEMPTS", "0")]
        [InlineData("SMTP_MAX_ATTEMPTS", "99")]
        [InlineData("SMTP_RETRY_SECONDS", "0")]
        [InlineData("SMTP_TEMPLATE_PATH", "/no/such/template.txt")]
        public void A_mail_setting_that_cannot_be_honoured_is_a_refusal_to_start(string name, string value)
        {
            var environment = WithMail();

            if (value.Length == 0)
            {
                environment.Remove(name);
            }
            else
            {
                environment[name] = value;
            }

            Assert.NotEmpty(Read(environment).Problems());
        }

        [Fact]
        public void A_username_without_a_password_is_a_refusal_to_start()
        {
            var environment = WithMail();

            environment.Remove("SMTP_PASSWORD");

            Assert.Contains(Read(environment).Problems(), p => p.Contains("SMTP_PASSWORD", StringComparison.Ordinal));
        }

        [Fact]
        public void A_password_that_begins_or_ends_with_a_space_is_kept_intact()
        {
            // App passwords get pasted with whitespace around them and some
            // relays really do have one in the middle. Trimming it turns a
            // working relay into an authentication failure with no visible cause.
            var environment = WithMail();

            environment["SMTP_PASSWORD"] = " abcd efgh ";

            Assert.Equal(" abcd efgh ", Read(environment).Mail.Password);
        }

        [Fact]
        public void There_is_no_environment_variable_that_weakens_the_mail_connection()
        {
            // The same assertion PayPalOptions gets: no property may look like a
            // way to accept an untrusted certificate or fall back to cleartext.
            // The three security modes are a choice the operator makes once, not
            // a downgrade that can happen at send time.
            var suspicious = new[] { "skip", "disable", "insecure", "unsafe", "bypass", "nocheck", "trustall", "allowinvalid", "whenavailable" };

            foreach (var property in typeof(MailOptions).GetProperties())
            {
                foreach (var word in suspicious)
                {
                    Assert.False(
                        property.Name.Contains(word, StringComparison.OrdinalIgnoreCase),
                        "MailOptions." + property.Name + " looks like a way to weaken the connection");
                }
            }
        }

        [Fact]
        public void The_description_that_goes_in_a_log_line_has_no_password_in_it()
        {
            var options = Read(WithMail());
            var description = options.Mail.Describe();

            Assert.DoesNotContain("hunter2", description, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("smtp.example.com", description, StringComparison.Ordinal);
        }

        [Fact]
        public void An_unconfigured_description_says_so_rather_than_being_empty()
        {
            Assert.Contains("outbox", Read(Complete()).Mail.Describe(), StringComparison.Ordinal);
        }

        [Fact]
        public void The_support_contact_falls_back_to_the_reply_to_then_the_sender()
        {
            var environment = WithMail();

            Assert.Equal("licences@example.com", Read(environment).Mail.SupportContact);

            environment["SMTP_REPLY_TO"] = "help@example.com";

            Assert.Equal("help@example.com", Read(environment).Mail.SupportContact);

            environment["SMTP_SUPPORT_CONTACT"] = "support@example.com";

            Assert.Equal("support@example.com", Read(environment).Mail.SupportContact);
        }

        [Fact]
        public void The_product_name_in_the_email_is_the_one_on_the_paypal_receipt()
        {
            var environment = WithMail();

            environment["PAYPAL_PRODUCT_NAME"] = "Emby SSO plugin, one year";

            Assert.Equal("Emby SSO plugin, one year", Read(environment).Mail.ProductName);
        }

        [Fact]
        public void A_template_file_that_exists_is_accepted()
        {
            var path = Path.Combine(TestKeys.TempDirectory(), "template.txt");

            File.WriteAllText(path, "your code is {code}");

            try
            {
                var environment = WithMail();

                environment["SMTP_TEMPLATE_PATH"] = path;

                Assert.Empty(Read(environment).Problems());
            }
            finally
            {
                File.Delete(path);
            }
        }

        private static ServiceOptions Read(IDictionary<string, string> environment)
        {
            return ServiceOptions.FromEnvironment(name => environment.TryGetValue(name, out var value) ? value : null);
        }

        private static Dictionary<string, string> Complete()
        {
            return new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["LICENCE_PUBLIC_KEYS"] = TestKeys.SamplePublicJwk,
                ["LICENCE_DATA_DIR"] = "/data",
                ["PAYPAL_ENV"] = "sandbox",
                ["PAYPAL_WEBHOOK_ID"] = "WH-1",
                ["PAYPAL_CURRENCY"] = "GBP",
                ["PAYPAL_PRICE"] = "19.00",
            };
        }

        private static Dictionary<string, string> WithMail()
        {
            var environment = Complete();

            environment["SMTP_HOST"] = "smtp.example.com";
            environment["SMTP_SECURITY"] = "starttls";
            environment["SMTP_PORT"] = "587";
            environment["SMTP_USERNAME"] = "licences@example.com";
            environment["SMTP_PASSWORD"] = "hunter2";
            environment["SMTP_FROM_ADDRESS"] = "licences@example.com";

            return environment;
        }
    }
}

using System;
using Emby.Sso.LicenceService.Admin;
using Emby.Sso.LicenceService.Configuration;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The one credential in front of a page that can mint licences.
    ///
    /// Every test here is about a refusal rather than about the happy path,
    /// because the happy path is one line and the refusals are the product:
    /// what the environment is allowed to hold, what a stored verifier is
    /// allowed to be, and what a password is allowed to be.
    /// </summary>
    public class AdminPasswordTests
    {
        private const string Good = "correct-horse-battery-staple-9142";

        [Fact]
        public void A_password_verifies_against_its_own_encoded_form()
        {
            Assert.True(AdminPassword.TryParse(AdminPassword.Encode(Good), out var password, out _));
            Assert.True(password.Verify(Good));
        }

        [Fact]
        public void A_wrong_password_does_not()
        {
            AdminPassword.TryParse(AdminPassword.Encode(Good), out var password, out _);

            Assert.False(password.Verify("correct-horse-battery-staple-9143"));
            Assert.False(password.Verify(Good.ToUpperInvariant()));
            Assert.False(password.Verify(string.Empty));
            Assert.False(password.Verify(null));
        }

        /// <summary>
        /// The comparison is over the derived bytes and is not a prefix match: a
        /// candidate sharing all but the last character is exactly as wrong as
        /// one sharing nothing. This fails if <c>Verify</c> is ever rewritten to
        /// compare strings with StartsWith or ==.
        /// </summary>
        [Fact]
        public void A_password_that_is_a_prefix_of_the_right_one_is_refused()
        {
            AdminPassword.TryParse(AdminPassword.Encode(Good), out var password, out _);

            Assert.False(password.Verify(Good.Substring(0, Good.Length - 1)));
            Assert.False(password.Verify(Good + "x"));
        }

        [Fact]
        public void The_encoded_form_does_not_contain_the_password()
        {
            var encoded = AdminPassword.Encode(Good);

            Assert.DoesNotContain(Good, encoded, StringComparison.OrdinalIgnoreCase);
            Assert.StartsWith(AdminPassword.Algorithm + "$" + AdminPassword.DefaultIterations, encoded, StringComparison.Ordinal);
        }

        [Fact]
        public void Two_encodings_of_one_password_differ_because_the_salt_is_fresh()
        {
            Assert.NotEqual(AdminPassword.Encode(Good), AdminPassword.Encode(Good));
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("not-a-hash")]
        [InlineData("pbkdf2-sha256$210000$onlythree")]
        [InlineData("pbkdf2-sha256$210000$c2FsdA==$aGFzaA==$extra")]
        [InlineData("bcrypt$210000$c2FsdHNhbHRzYWx0c2E=$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGE=")]
        [InlineData("pbkdf2-sha256$notanumber$c2FsdHNhbHRzYWx0c2E=$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGE=")]
        [InlineData("pbkdf2-sha256$1000$c2FsdHNhbHRzYWx0c2E=$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGE=")]
        [InlineData("pbkdf2-sha256$210000$not base64$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGE=")]
        [InlineData("pbkdf2-sha256$210000$c2FsdA==$c2hvcnQ=")]
        public void A_stored_verifier_this_service_did_not_make_is_refused_with_a_reason(string encoded)
        {
            Assert.False(AdminPassword.TryParse(encoded, out var password, out var problem));
            Assert.Null(password);
            Assert.False(string.IsNullOrWhiteSpace(problem));
        }

        /// <summary>
        /// A verifier made with a weak iteration count is refused rather than
        /// quietly accepted. Remove the MinimumIterations check and this fails.
        /// </summary>
        [Fact]
        public void A_verifier_made_with_too_few_iterations_is_refused()
        {
            var weak = AdminPassword.Encode(Good, AdminPassword.MinimumIterations - 1);

            Assert.False(AdminPassword.TryParse(weak, out _, out var problem));
            Assert.Contains("iterations", problem, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData(null, "empty")]
        [InlineData("", "empty")]
        [InlineData("                    ", "whitespace")]
        [InlineData("short", "16")]
        [InlineData("fifteen-chars12", "16")]
        [InlineData("password-of-great-length", "password")]
        [InlineData("changeme-changeme-changeme", "changeme")]
        [InlineData("adminadminadminadmin", "admin")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaa", "repeated")]
        public void A_weak_plaintext_password_is_named_and_refused(string password, string expected)
        {
            var weakness = AdminPassword.Weakness(password);

            Assert.NotNull(weakness);
            Assert.Contains(expected, weakness, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void A_long_unobvious_password_is_accepted_and_derives_a_working_verifier()
        {
            Assert.Null(AdminPassword.Weakness(Good));

            var password = AdminPassword.FromPlaintext(Good);

            Assert.True(password.Verify(Good));
            Assert.False(password.Verify("something else entirely"));
            Assert.Equal(AdminPassword.DefaultIterations, password.Iterations);
        }

        // ------------------------------------------------- the configuration

        [Fact]
        public void With_nothing_set_the_admin_page_is_simply_off_and_that_is_not_a_problem()
        {
            var options = new AdminOptions();

            Assert.False(options.Configured);
            Assert.Empty(options.Problems());
            Assert.Contains("does not exist", options.Describe(), StringComparison.Ordinal);
        }

        [Fact]
        public void Setting_both_forms_of_the_password_refuses_to_start()
        {
            var options = new AdminOptions
            {
                PasswordHash = AdminPassword.Encode(Good),
                Password = Good,
            };

            Assert.Contains(options.Problems(), problem => problem.Contains("both set", StringComparison.Ordinal));
        }

        [Fact]
        public void A_weak_plaintext_in_the_environment_refuses_to_start()
        {
            var options = new AdminOptions { Password = "hunter2" };

            Assert.True(options.Configured);
            Assert.Contains(options.Problems(), problem => problem.Contains("ADMIN_PASSWORD is not acceptable", StringComparison.Ordinal));
        }

        [Fact]
        public void An_unreadable_hash_in_the_environment_refuses_to_start()
        {
            var options = new AdminOptions { PasswordHash = "pbkdf2-sha256$3$x$y" };

            Assert.NotEmpty(options.Problems());
        }

        /// <summary>
        /// The line that goes in the startup log names how the page is
        /// configured and neither the password nor the verifier. There is no
        /// overload that puts them there, the way MailOptions.Describe has none.
        /// </summary>
        [Fact]
        public void What_the_log_says_about_the_admin_page_holds_no_secret()
        {
            var encoded = AdminPassword.Encode(Good);

            var hashed = new AdminOptions { PasswordHash = encoded };
            var plain = new AdminOptions { Password = Good };

            Assert.DoesNotContain(encoded, hashed.Describe(), StringComparison.Ordinal);
            Assert.DoesNotContain(Good, plain.Describe(), StringComparison.Ordinal);
            Assert.Contains("plaintext", plain.Describe(), StringComparison.Ordinal);
        }

        [Fact]
        public void The_session_timeouts_must_make_sense_together()
        {
            var options = new AdminOptions
            {
                Password = Good,
                IdleMinutes = 60,
                AbsoluteMinutes = 30,
            };

            Assert.Contains(options.Problems(), problem => problem.Contains("absolute", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void The_environment_is_read_into_the_admin_options()
        {
            var encoded = AdminPassword.Encode(Good);

            var options = ServiceOptions.FromEnvironment(name => name switch
            {
                "LICENCE_SIGNING_KEY_PATH" => "/run/secrets/key.json",
                "LICENCE_DATA_DIR" => "/data",
                "PAYPAL_WEBHOOK_ID" => "WH-1",
                "PAYPAL_PRICE" => "19.00",
                "ADMIN_PASSWORD_HASH" => encoded,
                "ADMIN_SESSION_IDLE_MINUTES" => "5",
                "ADMIN_SESSION_ABSOLUTE_MINUTES" => "60",
                "ADMIN_LOGIN_DELAY_SECONDS" => "3",
                "ADMIN_LOGIN_MAX_DELAY_SECONDS" => "90",
                _ => null,
            });

            Assert.True(options.Admin.Configured);
            Assert.Equal(encoded, options.Admin.PasswordHash);
            Assert.Equal(5, options.Admin.IdleMinutes);
            Assert.Equal(60, options.Admin.AbsoluteMinutes);
            Assert.Equal(3, options.Admin.LoginDelaySeconds);
            Assert.Equal(90, options.Admin.LoginMaxDelaySeconds);
            Assert.Empty(options.Problems());
        }

        /// <summary>
        /// The same assertion ServiceOptionsTests makes about the webhook
        /// verifier: there is no switch. Nothing here turns the password off,
        /// makes the cookie insecure, skips the CSRF check or opens the page to
        /// a network. A future edit that adds one has to delete this test.
        /// </summary>
        [Fact]
        public void There_is_no_configuration_that_weakens_the_admin_page()
        {
            var forbidden = new[]
            {
                "skip", "disable", "insecure", "bypass", "allowhttp", "nocsrf", "nologin", "noauth", "open", "public",
            };

            foreach (var property in typeof(AdminOptions).GetProperties())
            {
                var name = property.Name.ToLowerInvariant();

                Assert.DoesNotContain(forbidden, bad => name.Contains(bad, StringComparison.Ordinal));
            }
        }

        /// <summary>
        /// A password may legitimately begin or end with a space, and eating one
        /// turns a correct password into a wrong one with no visible cause. The
        /// same rule SMTP_PASSWORD already follows.
        /// </summary>
        [Fact]
        public void A_plaintext_password_is_not_trimmed_on_the_way_in()
        {
            var padded = "  " + Good + "  ";

            var options = ServiceOptions.FromEnvironment(name => name == "ADMIN_PASSWORD" ? padded : null);

            Assert.Equal(padded, options.Admin.Password);
        }
    }
}

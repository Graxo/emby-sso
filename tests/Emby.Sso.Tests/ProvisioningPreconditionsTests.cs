using System;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The order of the guards on the provisioning branch, which is the security
    /// argument of that branch and was, until this type existed, only ever
    /// described in a comment.
    ///
    /// The two properties these tests exist to pin: a configuration refusal is
    /// decided before the throttle is consulted and before anything is sent, and
    /// evaluating preconditions never consumes throttle budget.
    /// </summary>
    public class ProvisioningPreconditionsTests
    {
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

        private static ProvisioningSettings Ready()
        {
            return new ProvisioningSettings
            {
                EnableAutoCreate = true,
                TemplateUserName = "sso-template",
                EnableDirectGrant = true,
                AllowInsecureHttp = false,
                RequiredGroup = "emby-users",
            };
        }

        private static ProvisioningPreconditionOutcome Evaluate(
            ProvisioningSettings settings,
            ProvisioningThrottle throttle = null,
            string username = "alice")
        {
            return ProvisioningPreconditions.Evaluate(
                settings,
                username,
                throttle ?? new ProvisioningThrottle(),
                Now);
        }

        [Fact]
        public void A_fully_configured_server_may_contact_the_provider()
        {
            Assert.Equal(ProvisioningPreconditionOutcome.MayContactProvider, Evaluate(Ready()));
        }

        [Fact]
        public void A_null_configuration_refuses()
        {
            Assert.Equal(ProvisioningPreconditionOutcome.AutoCreateDisabled, Evaluate(null));
        }

        [Fact]
        public void The_zero_outcome_is_a_refusal()
        {
            // Default-initialised state must not be an admission. The caller
            // tests for MayContactProvider explicitly, but this keeps the enum
            // honest for anyone who forgets.
            Assert.NotEqual(ProvisioningPreconditionOutcome.MayContactProvider, default(ProvisioningPreconditionOutcome));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void An_unset_required_group_refuses(string requiredGroup)
        {
            var settings = Ready();
            settings.RequiredGroup = requiredGroup;

            Assert.Equal(ProvisioningPreconditionOutcome.RequiredGroupNotConfigured, Evaluate(settings));
        }

        [Fact]
        public void An_unset_required_group_is_refused_before_the_throttle_is_consulted()
        {
            // The ordering that matters, stated as a test rather than a comment:
            // with BOTH an unset required group and a throttle that is already
            // closed, the answer must be the configuration refusal. If the group
            // check ever moves below the throttle read, this flips to Throttled
            // - and in the real caller it would also move below the credential
            // forward, which is what sends every user's real password to the
            // identity provider on a misconfigured upgrade.
            var throttle = new ProvisioningThrottle();

            for (var i = 0; i < ProvisioningThrottle.MaxFailuresPerUsername; i++)
            {
                throttle.RecordFailure("alice", Now);
            }

            Assert.True(throttle.IsThrottled("alice", Now));

            var settings = Ready();
            settings.RequiredGroup = string.Empty;

            Assert.Equal(
                ProvisioningPreconditionOutcome.RequiredGroupNotConfigured,
                Evaluate(settings, throttle));
        }

        [Fact]
        public void No_configuration_refusal_ever_consumes_throttle_budget()
        {
            // The failure this whole reordering exists to prevent: a hundred
            // refusals across a hundred DIFFERENT usernames - the shape of a
            // mass first sign-in against a server whose operator has not set the
            // required group - closing the global bucket for everybody, and
            // keeping it closed for fifteen minutes after the setting is fixed.
            //
            // Evaluate reads the throttle and never writes to it. Ten times the
            // global budget, spread over that many distinct names, must leave it
            // wide open.
            var throttle = new ProvisioningThrottle();
            var settings = Ready();
            settings.RequiredGroup = string.Empty;

            for (var i = 0; i < ProvisioningThrottle.MaxFailuresGlobally * 10; i++)
            {
                Assert.Equal(
                    ProvisioningPreconditionOutcome.RequiredGroupNotConfigured,
                    Evaluate(settings, throttle, "user-" + i));
            }

            Assert.False(throttle.IsThrottled("someone-who-never-tried", Now));
            Assert.False(throttle.IsThrottled("user-0", Now));

            // And once the operator sets the group, provisioning works
            // immediately rather than fifteen minutes later.
            Assert.Equal(
                ProvisioningPreconditionOutcome.MayContactProvider,
                Evaluate(Ready(), throttle, "user-0"));
        }

        [Fact]
        public void Every_other_refusal_leaves_the_throttle_untouched_too()
        {
            var throttle = new ProvisioningThrottle();

            var autoCreateOff = Ready();
            autoCreateOff.EnableAutoCreate = false;

            var noTemplate = Ready();
            noTemplate.TemplateUserName = " ";

            var directGrantOff = Ready();
            directGrantOff.EnableDirectGrant = false;

            var insecure = Ready();
            insecure.AllowInsecureHttp = true;

            for (var i = 0; i < ProvisioningThrottle.MaxFailuresGlobally + 1; i++)
            {
                Evaluate(autoCreateOff, throttle, "a-" + i);
                Evaluate(noTemplate, throttle, "b-" + i);
                Evaluate(directGrantOff, throttle, "c-" + i);
                Evaluate(insecure, throttle, "d-" + i);
                Evaluate(null, throttle, "e-" + i);
            }

            Assert.False(throttle.IsThrottled("a-0", Now));
            Assert.Equal(ProvisioningPreconditionOutcome.MayContactProvider, Evaluate(Ready(), throttle));
        }

        [Fact]
        public void Auto_create_off_is_refused_first()
        {
            // Indistinguishable to the caller from the account not existing, and
            // it must stay the first answer: a server that is not provisioning
            // at all should not be reporting which of its other settings are
            // also unset.
            var settings = new ProvisioningSettings
            {
                EnableAutoCreate = false,
                TemplateUserName = null,
                EnableDirectGrant = false,
                AllowInsecureHttp = true,
                RequiredGroup = null,
            };

            Assert.Equal(ProvisioningPreconditionOutcome.AutoCreateDisabled, Evaluate(settings));
        }

        [Fact]
        public void A_missing_template_is_refused_before_direct_grant_and_the_group()
        {
            var settings = Ready();
            settings.TemplateUserName = null;
            settings.EnableDirectGrant = false;
            settings.RequiredGroup = null;

            Assert.Equal(ProvisioningPreconditionOutcome.TemplateNotConfigured, Evaluate(settings));
        }

        [Fact]
        public void Direct_grant_off_is_refused_before_the_group_check()
        {
            var settings = Ready();
            settings.EnableDirectGrant = false;
            settings.RequiredGroup = null;

            Assert.Equal(ProvisioningPreconditionOutcome.DirectGrantDisabled, Evaluate(settings));
        }

        [Fact]
        public void Plain_http_plus_direct_grant_is_refused_without_contacting_anything()
        {
            // The combination that would have this server relay a native
            // client's real password in cleartext. It is refused as a
            // precondition - above the throttle, above the credential forward -
            // rather than being allowed to reach the identity provider at all.
            var settings = Ready();
            settings.AllowInsecureHttp = true;

            Assert.Equal(ProvisioningPreconditionOutcome.InsecureHttpWithDirectGrant, Evaluate(settings));
        }

        [Fact]
        public void Plain_http_alone_does_not_refuse_when_direct_grant_is_off()
        {
            // The refusal is about the pair. With direct grant off, the branch
            // refuses for that reason instead - and an operator reading the log
            // should be told the setting they actually have to change.
            var settings = Ready();
            settings.AllowInsecureHttp = true;
            settings.EnableDirectGrant = false;

            Assert.Equal(ProvisioningPreconditionOutcome.DirectGrantDisabled, Evaluate(settings));
        }

        [Fact]
        public void A_closed_throttle_is_the_last_refusal_and_only_on_a_fully_configured_server()
        {
            var throttle = new ProvisioningThrottle();

            for (var i = 0; i < ProvisioningThrottle.MaxFailuresPerUsername; i++)
            {
                throttle.RecordFailure("alice", Now);
            }

            Assert.Equal(ProvisioningPreconditionOutcome.Throttled, Evaluate(Ready(), throttle));
            Assert.Equal(
                ProvisioningPreconditionOutcome.MayContactProvider,
                Evaluate(Ready(), throttle, "bob"));
        }

        [Fact]
        public void A_missing_throttle_is_a_programming_error_not_a_silent_pass()
        {
            Assert.Throws<ArgumentNullException>(
                () => ProvisioningPreconditions.Evaluate(Ready(), "alice", null, Now));
        }
    }
}

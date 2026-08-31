using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// Finding F3: the throttle must brake an attacker without becoming one.
    ///
    /// <see cref="ProvisioningThrottleTests"/> pins the throttle's own answers.
    /// This file pins the thing an operator actually cares about, by walking the
    /// WHOLE ordered chain the provisioning branch walks - preconditions,
    /// credential validation against a real (in-process) identity provider,
    /// identity/username agreement, the group gate, the subject binding - while
    /// an unauthenticated stranger floods the same throttle with invented
    /// usernames, and asserting that a first-time user with the right password
    /// and the required group still gets in.
    ///
    /// WHAT THIS DOES NOT COVER, and cannot. The chain is re-walked here in the
    /// same order <c>SsoAuthenticationProvider.ProvisionOrRefuse</c> walks it,
    /// but it is not that method: <c>Auth/</c> and <c>Api/</c> reference
    /// <c>MediaBrowser.*</c> types and are not compiled into this test project,
    /// so no test on this project can execute the real branch, and that the
    /// order here still matches the order there is maintained by reading, not by
    /// measurement. <see cref="ProvisioningPreconditionsTests"/> pins the part
    /// of that order which does live in Protocol/.
    /// </summary>
    public sealed class ThrottleAvailabilityTests : IDisposable
    {
        private const string RequiredGroup = "bios-only";

        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);

        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();
        private readonly ProvisioningThrottle _throttle = new ProvisioningThrottle();
        private readonly string _directory;
        private readonly SubjectBindingStore _bindings;

        public ThrottleAvailabilityTests()
        {
            _directory = Path.Combine(Path.GetTempPath(), "emby-sso-tests-" + Guid.NewGuid().ToString("N"));
            _bindings = new SubjectBindingStore(
                Path.Combine(_directory, "subject-bindings.json"),
                () => Now);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_directory))
                {
                    Directory.Delete(_directory, true);
                }
            }
            catch (IOException)
            {
                // A leftover temp directory is not worth failing a test over.
            }
        }

        /// <summary>How far a sign-in attempt got through the provisioning chain.</summary>
        private enum Attempt
        {
            /// <summary>Refused by the throttle without a credential being sent.</summary>
            RefusedByThrottle,

            /// <summary>Refused for a configuration reason - nothing was sent either.</summary>
            RefusedByConfiguration,

            /// <summary>The credential was forwarded and the provider did not accept it.</summary>
            RefusedByProvider,

            /// <summary>Forwarded, accepted, and refused after the fact by the gate or the binding.</summary>
            RefusedAfterProvider,

            /// <summary>Every guard passed: Emby would create the account.</summary>
            Provisioned,
        }

        private static ProvisioningSettings Settings()
        {
            return new ProvisioningSettings
            {
                EnableAutoCreate = true,
                TemplateUserName = "template_user",
                EnableDirectGrant = true,
                AllowInsecureHttp = false,
                RequiredGroup = RequiredGroup,
            };
        }

        private SsoCredentialValidator Validator()
        {
            return new SsoCredentialValidator(
                new HandoffSecretStore(() => Now, TimeSpan.FromSeconds(30)),
                new SignInPinStore(() => Now, SignInPinStore.DefaultTtl),
                () => new OidcClient(new HttpClient(_idp), new OidcOptions
                {
                    IssuerUrl = FakeIdentityProvider.Issuer,
                    ClientId = FakeIdentityProvider.ClientId,
                    ClientSecret = FakeIdentityProvider.ClientSecret,
                    Scopes = "openid profile email",
                    RedirectUri = "https://emby.test/emby/Sso/Callback",
                    UsernameClaim = "preferred_username",
                }),
                () => true,
                () => false);
        }

        /// <summary>
        /// The provisioning branch's ordered chain, re-walked. Mirrors
        /// <c>SsoAuthenticationProvider.ProvisionOrRefuse</c> step for step,
        /// including which exits record a failure and which do not.
        /// </summary>
        private async Task<Attempt> SignIn(string username, string password)
        {
            var precondition = ProvisioningPreconditions.Evaluate(Settings(), username, _throttle, Now);

            if (precondition == ProvisioningPreconditionOutcome.Throttled)
            {
                // Nothing tried, nothing recorded - see ProvisioningThrottle.
                return Attempt.RefusedByThrottle;
            }

            if (precondition != ProvisioningPreconditionOutcome.MayContactProvider)
            {
                return Attempt.RefusedByConfiguration;
            }

            var result = await Validator().ValidateAsync(username, password, CancellationToken.None);

            if (result.Outcome != SsoCredentialOutcome.DirectGrantAccepted)
            {
                _throttle.RecordFailure(username, result, Now);
                return Attempt.RefusedByProvider;
            }

            if (result.Identity == null || !UsernameMatcher.Matches(result.Identity.Username, username))
            {
                _throttle.RecordFailure(username, Now);
                return Attempt.RefusedAfterProvider;
            }

            if (GroupGate.Evaluate(result.Identity, RequiredGroup) != GroupGateOutcome.Allowed)
            {
                _throttle.RecordFailure(username, Now);
                return Attempt.RefusedAfterProvider;
            }

            var binding = _bindings.Bind(result.Identity.Subject, result.Identity.Username.Trim());

            if (!SubjectBindingStore.Permits(binding))
            {
                if (binding != SubjectBindingOutcome.StoreUnavailable)
                {
                    _throttle.RecordFailure(username, Now);
                }

                return Attempt.RefusedAfterProvider;
            }

            _throttle.RecordSuccess(username, Now);
            return Attempt.Provisioned;
        }

        /// <summary>The provider rejects whatever is presented, as it does for an invented name.</summary>
        private void ProviderRejectsEverything()
        {
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";
        }

        /// <summary>The provider accepts, and issues a token for a member of the required group.</summary>
        private void ProviderAccepts(string username, string subject)
        {
            _idp.TokenResponseStatus = HttpStatusCode.OK;
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(subject: subject, username: username, groups: new[] { RequiredGroup }));
        }

        /// <summary>
        /// The flood: an unauthenticated stranger, holding no credential at all,
        /// spending attempts on names nobody has. This is what used to close the
        /// branch for everybody after a hundred requests.
        /// </summary>
        private async Task Flood(int attempts)
        {
            ProviderRejectsEverything();

            for (var index = 0; index < attempts; index++)
            {
                Assert.NotEqual(Attempt.Provisioned, await SignIn("invented-" + index, "not-a-password"));
            }
        }

        [Fact]
        public async Task An_invented_username_flood_cannot_stop_a_legitimate_first_sign_in()
        {
            // Ten times what used to be the whole global budget.
            await Flood(ProvisioningThrottle.GlobalSurgeThreshold * 10);

            Assert.True(_throttle.IsGlobalSurge(Now));

            ProviderAccepts("newcomer", "sub-newcomer");

            Assert.Equal(Attempt.Provisioned, await SignIn("newcomer", "correct horse battery staple"));
        }

        [Fact]
        public async Task A_newcomer_who_mistypes_under_a_flood_still_gets_in()
        {
            // The realistic version: the first-time user is fumbling their own
            // password on a phone keyboard while the flood is running. The
            // tightened surge allowance still has to leave room for that.
            await Flood(ProvisioningThrottle.GlobalSurgeThreshold * 2);

            Assert.True(_throttle.IsGlobalSurge(Now));

            ProviderRejectsEverything();

            for (var typo = 0; typo < ProvisioningThrottle.SurgeFailuresPerUsername - 1; typo++)
            {
                Assert.Equal(Attempt.RefusedByProvider, await SignIn("newcomer", "wrong-" + typo));
            }

            ProviderAccepts("newcomer", "sub-newcomer");

            Assert.Equal(Attempt.Provisioned, await SignIn("newcomer", "correct horse battery staple"));
        }

        [Fact]
        public async Task The_flood_still_costs_the_attacker_its_own_budget()
        {
            // The brake is not gone: a name the attacker keeps using runs out,
            // and under a surge it runs out sooner. Asserted through the same
            // chain, so it is the branch that closes and not just a counter.
            await Flood(ProvisioningThrottle.GlobalSurgeThreshold);

            ProviderRejectsEverything();

            for (var attempt = 0; attempt < ProvisioningThrottle.SurgeFailuresPerUsername; attempt++)
            {
                Assert.Equal(Attempt.RefusedByProvider, await SignIn("one-name", "guess-" + attempt));
            }

            Assert.Equal(Attempt.RefusedByThrottle, await SignIn("one-name", "guess-again"));

            // ...and the account the attacker was guessing at cannot be signed
            // into by the attacker even if they later learn the password, until
            // the window rolls over. That is the brake working as intended.
            ProviderAccepts("one-name", "sub-one-name");

            Assert.Equal(Attempt.RefusedByThrottle, await SignIn("one-name", "correct horse battery staple"));
        }
    }
}

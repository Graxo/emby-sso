using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The provisioning throttle's one exemption: a failure that never reached
    /// the identity provider tested no credential, so it must not spend anyone's
    /// budget - while every failure that says something about the caller still
    /// must.
    ///
    /// Every result here is produced by the real <see cref="SsoCredentialValidator"/>
    /// driving a real <see cref="OidcClient"/> over a transport that fails the
    /// way a live outage does, and is then handed to the real
    /// <see cref="ProvisioningThrottle"/> exactly as
    /// <c>SsoAuthenticationProvider.ProvisionOrRefuse</c> hands it over. Nothing
    /// here constructs the flag by hand, because a test that sets the flag it is
    /// checking would pass against a plugin that never sets it at all.
    /// </summary>
    public class UnreachableProviderTests
    {
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();

        private readonly HandoffSecretStore _handoff =
            new HandoffSecretStore(() => Now, TimeSpan.FromSeconds(30));

        private bool _directGrantEnabled = true;
        private bool _configured = true;

        /// <summary>The transport the client talks to. Defaults to a working provider.</summary>
        private HttpMessageHandler _transport;

        private OidcClient Client()
        {
            if (!_configured)
            {
                return null;
            }

            return new OidcClient(new HttpClient(_transport ?? _idp), new OidcOptions
            {
                IssuerUrl = FakeIdentityProvider.Issuer,
                ClientId = FakeIdentityProvider.ClientId,
                ClientSecret = FakeIdentityProvider.ClientSecret,
                Scopes = "openid profile email",
                RedirectUri = "https://emby.test/emby/Sso/Callback",
                UsernameClaim = "preferred_username",
            });
        }

        private Task<SsoCredentialResult> Validate(string username = "alice", string password = "correct horse") =>
            new SsoCredentialValidator(
                    _handoff,
                    new SignInPinStore(() => DateTimeOffset.UtcNow, SignInPinStore.DefaultTtl),
                    Client,
                    () => _directGrantEnabled,
                    () => false)
                .ValidateAsync(username, password, CancellationToken.None);

        /// <summary>The provider's own verdict: this password is wrong.</summary>
        private void ProviderRejectsTheCredential()
        {
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";
        }

        // ---- what the validator produces --------------------------------

        [Fact]
        public async Task A_provider_that_cannot_be_reached_at_all_is_marked_unreachable()
        {
            // Nothing answers, so discovery fails before a credential is sent.
            _transport = new ThrowingHandler();

            var result = await Validate();

            Assert.True(result.ProviderUnreachable);
        }

        [Fact]
        public async Task A_token_request_that_never_completes_is_marked_unreachable()
        {
            // Discovery works; the token POST - the request carrying the
            // password - gets no answer.
            _transport = new TokenPostFailureHandler(_idp);

            var result = await Validate();

            Assert.True(result.ProviderUnreachable);
        }

        [Fact]
        public async Task A_token_response_that_breaks_mid_flight_is_marked_unreachable()
        {
            // The request went out and its answer never arrived intact, so no
            // verdict on the password was ever learned. Measured, not assumed:
            // a body that throws while being read surfaces from HttpClient.Send
            // itself, which is the "token endpoint request failed" case - the
            // same one an outage produces.
            _transport = new TokenReadFailureHandler(_idp);

            var result = await Validate();

            Assert.True(result.ProviderUnreachable);
        }

        [Fact]
        public async Task A_response_that_arrived_but_could_not_be_decoded_still_counts()
        {
            // The other side of the fail-closed line. Here the provider DID
            // answer; this process just could not read the answer - a response
            // declaring a character set it cannot use. The user-facing sentence
            // is the same "could not be reached" one, which is exactly why the
            // decision is not taken from that string: the provider was reached,
            // so the failure is not certainly transport-level, so it costs
            // budget like any other.
            _transport = new UndecodableResponseHandler(_idp);
            var throttle = new ProvisioningThrottle();

            for (var attempt = 0; attempt < ProvisioningThrottle.MaxFailuresPerUsername; attempt++)
            {
                var result = await Validate();
                Assert.False(result.ProviderUnreachable);
                Assert.Equal(SsoErrors.ProviderUnreachable, result.Reason);
                throttle.RecordFailure("alice", result, Now);
            }

            Assert.True(throttle.IsThrottled("alice", Now));
        }

        [Fact]
        public async Task A_credential_the_provider_rejected_is_not_marked_unreachable()
        {
            ProviderRejectsTheCredential();

            var result = await Validate();

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Equal(SsoErrors.ProviderRejected, result.Reason);
            Assert.False(result.ProviderUnreachable);
        }

        [Fact]
        public async Task No_other_refusal_is_marked_unreachable()
        {
            // These never reach the provider either, and they must still count:
            // the flag says "the provider could not be reached", not "cheap to
            // produce". All three are free for an attacker to generate.
            var empty = await Validate(password: "");
            Assert.False(empty.ProviderUnreachable);

            _directGrantEnabled = false;
            Assert.False((await Validate()).ProviderUnreachable);

            _directGrantEnabled = true;
            _configured = false;
            Assert.False((await Validate()).ProviderUnreachable);

            // The provider answered, and named somebody else.
            _configured = true;
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "mallory"));
            var wrongIdentity = await Validate();
            Assert.Equal(SsoErrors.UnknownUser, wrongIdentity.Reason);
            Assert.False(wrongIdentity.ProviderUnreachable);
        }

        [Fact]
        public async Task An_accepted_credential_is_not_marked_unreachable()
        {
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "alice"));

            var result = await Validate();

            Assert.Equal(SsoCredentialOutcome.DirectGrantAccepted, result.Outcome);
            Assert.False(result.ProviderUnreachable);
        }

        // ---- what the caller can see ------------------------------------

        [Fact]
        public async Task An_unreachable_refusal_is_a_rejection_in_everything_the_caller_can_see()
        {
            // The refusal a caller receives must be exactly what it was before
            // this distinction existed: the same outcome and the same sentence
            // an unreachable provider has always produced. Pinned against a
            // plain rejection carrying that reason - every caller-visible member
            // matches, and only the flag differs.
            _transport = new ThrowingHandler();

            var unreachable = await Validate();
            var asItWasBefore = SsoCredentialResult.Reject(SsoErrors.ProviderUnreachable);

            Assert.Equal(asItWasBefore.Outcome, unreachable.Outcome);
            Assert.Equal(asItWasBefore.Reason, unreachable.Reason);
            Assert.Equal(asItWasBefore.DisplayName, unreachable.DisplayName);
            Assert.Equal(asItWasBefore.Identity, unreachable.Identity);

            Assert.NotEqual(asItWasBefore.ProviderUnreachable, unreachable.ProviderUnreachable);
        }

        [Fact]
        public async Task An_outage_and_a_wrong_password_refuse_identically_apart_from_the_counter()
        {
            // The two are told apart ONLY by the throttle. Whatever a caller can
            // read off a refusal - the outcome, the sentence, the absence of an
            // identity - the change must not have added to it. The two reasons
            // already differ from each other and did before this change; what is
            // pinned here is that nothing new was added on top.
            ProviderRejectsTheCredential();
            var rejected = await Validate();

            _transport = new ThrowingHandler();
            var unreachable = await Validate();

            Assert.Equal(rejected.Outcome, unreachable.Outcome);
            Assert.Equal(rejected.DisplayName, unreachable.DisplayName);
            Assert.Equal(rejected.Identity, unreachable.Identity);
            Assert.Equal(SsoErrors.ProviderRejected, rejected.Reason);
            Assert.Equal(SsoErrors.ProviderUnreachable, unreachable.Reason);
        }

        // ---- what the throttle does with them ---------------------------

        [Fact]
        public async Task An_unreachable_provider_never_consumes_a_username_budget()
        {
            _transport = new ThrowingHandler();
            var throttle = new ProvisioningThrottle();

            // Three times the per-username limit: a user retrying through an
            // outage, which is the ordinary way this is reached.
            for (var attempt = 0; attempt < ProvisioningThrottle.MaxFailuresPerUsername * 3; attempt++)
            {
                throttle.RecordFailure("alice", await Validate(), Now);
            }

            Assert.False(throttle.IsThrottled("alice", Now));

            // No bucket was even created, so the outage cannot fill the map either.
            Assert.Equal(0, throttle.TrackedUsernames(Now));
        }

        [Fact]
        public async Task An_outage_during_a_migration_does_not_tighten_the_branch_for_everybody()
        {
            // The scenario this exemption exists for: many people signing in for
            // the first time while the identity provider is down. Counting those
            // would raise a surge - the threshold is only a hundred - and hold
            // every newcomer's allowance down to three for a further fifteen
            // minutes after the provider came back, on a server where nobody had
            // done anything wrong.
            _transport = new ThrowingHandler();
            var throttle = new ProvisioningThrottle();

            for (var attempt = 0; attempt < ProvisioningThrottle.GlobalSurgeThreshold * 2; attempt++)
            {
                throttle.RecordFailure("user-" + attempt, await Validate("user-" + attempt), Now);
            }

            Assert.False(throttle.IsGlobalSurge(Now));
            Assert.Equal(ProvisioningThrottle.MaxFailuresPerUsername, throttle.AllowanceFor(Now));
            Assert.False(throttle.IsThrottled("someone-who-never-tried", Now));
        }

        [Fact]
        public async Task A_credential_the_provider_rejected_still_consumes_the_budget()
        {
            ProviderRejectsTheCredential();
            var throttle = new ProvisioningThrottle();

            for (var attempt = 0; attempt < ProvisioningThrottle.MaxFailuresPerUsername; attempt++)
            {
                Assert.False(throttle.IsThrottled("alice", Now));
                throttle.RecordFailure("alice", await Validate(), Now);
            }

            Assert.True(throttle.IsThrottled("alice", Now));
        }

        [Fact]
        public async Task Guesses_are_still_counted_when_they_are_mixed_into_an_outage()
        {
            // The hole this must not open: an attacker interleaving real guesses
            // with failures that cost nothing. The uncounted ones must not
            // dilute, reset or expire the counted ones.
            var throttle = new ProvisioningThrottle();

            for (var attempt = 0; attempt < ProvisioningThrottle.MaxFailuresPerUsername; attempt++)
            {
                _transport = new ThrowingHandler();

                for (var noise = 0; noise < 20; noise++)
                {
                    throttle.RecordFailure("alice", await Validate(), Now);
                }

                _transport = null;
                ProviderRejectsTheCredential();
                throttle.RecordFailure("alice", await Validate(), Now);
            }

            Assert.True(throttle.IsThrottled("alice", Now));
        }

        [Fact]
        public void A_result_the_throttle_cannot_read_is_counted()
        {
            // Fail closed. The overload exempts one thing and one thing only -
            // a result that explicitly says the provider was unreachable - so a
            // caller with no result to offer pays the same as any other failure.
            var throttle = new ProvisioningThrottle();

            for (var attempt = 0; attempt < ProvisioningThrottle.MaxFailuresPerUsername; attempt++)
            {
                throttle.RecordFailure("alice", null, Now);
            }

            Assert.True(throttle.IsThrottled("alice", Now));
        }

        // ---- transports that fail the way an outage does -----------------

        /// <summary>Nothing answers: every request throws, discovery included.</summary>
        private sealed class ThrowingHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                throw new HttpRequestException("simulated network failure reaching " + request.RequestUri);
            }
        }

        /// <summary>
        /// Discovery and JWKS succeed; the token request - the one carrying the
        /// password - gets no answer at all.
        /// </summary>
        private sealed class TokenPostFailureHandler : HttpMessageHandler
        {
            private readonly HttpMessageInvoker _inner;

            public TokenPostFailureHandler(HttpMessageHandler inner)
            {
                _inner = new HttpMessageInvoker(inner, disposeHandler: false);
            }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (request.RequestUri.AbsoluteUri.EndsWith("/token/", StringComparison.Ordinal))
                {
                    throw new HttpRequestException("simulated network failure posting the token request");
                }

                return await _inner.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// The token request completes but its body throws when read - a
        /// mid-response transport failure rather than a connect failure. Note
        /// where that surfaces: HttpClient buffers the body inside SendAsync, so
        /// the client sees it as the request failing, not as a response it
        /// could not read.
        /// </summary>
        private sealed class TokenReadFailureHandler : HttpMessageHandler
        {
            private readonly HttpMessageInvoker _inner;

            public TokenReadFailureHandler(HttpMessageHandler inner)
            {
                _inner = new HttpMessageInvoker(inner, disposeHandler: false);
            }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (request.RequestUri.AbsoluteUri.EndsWith("/token/", StringComparison.Ordinal))
                {
                    return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ThrowingContent() };
                }

                return await _inner.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }

            private sealed class ThrowingContent : HttpContent
            {
                protected override Task SerializeToStreamAsync(Stream stream, TransportContext context)
                {
                    throw new IOException("simulated failure reading the token response body");
                }

                protected override bool TryComputeLength(out long length)
                {
                    length = 0;
                    return false;
                }
            }
        }

        /// <summary>
        /// The provider answers, and the answer is intact on the wire, but it
        /// declares a character set this process cannot use - so the body cannot
        /// be turned into text. This is the ONLY way to reach OidcClient's
        /// "token endpoint response could not be read", and it is not an
        /// unreachable provider.
        /// </summary>
        private sealed class UndecodableResponseHandler : HttpMessageHandler
        {
            private readonly HttpMessageInvoker _inner;

            public UndecodableResponseHandler(HttpMessageHandler inner)
            {
                _inner = new HttpMessageInvoker(inner, disposeHandler: false);
            }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (request.RequestUri.AbsoluteUri.EndsWith("/token/", StringComparison.Ordinal))
                {
                    var content = new StringContent("{}");
                    content.Headers.ContentType =
                        new MediaTypeHeaderValue("application/json") { CharSet = "not-a-character-set" };

                    return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
                }

                return await _inner.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Auth;
using Emby.Sso.Protocol;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Model.Logging;
using MediaBrowser.Model.Services;

namespace Emby.Sso.Api
{
    /// <summary>
    /// The browser sign-in flow: /sso/start sends the user to the identity
    /// provider, /sso/callback brings them back and returns the page that
    /// completes the sign-in.
    ///
    /// /sso/pin is the same flow with a different ending. It redirects to
    /// the identity provider exactly as /Sso/Start does, comes back to the same
    /// callback, and passes every guard the ordinary sign-in passes; only at
    /// the very end, once all of them have, does it show a one-time PIN for a
    /// television instead of signing this browser in. It is deliberately not a
    /// second way to authenticate anybody - there is one flow here, with two
    /// endings.
    ///
    /// Every failure leaves through <see cref="Error"/>, which logs the detail and
    /// renders a fixed, user-safe sentence. Nothing the identity provider supplied
    /// is ever written into a page, and no exception is allowed to escape into
    /// Emby's error handling, where the message would become the response body.
    /// </summary>
    public class SsoService : IService, IRequiresRequest
    {
        private readonly ILogger _logger;
        private readonly IUserManager _userManager;
        private readonly IHttpResultFactory _resultFactory;
        private readonly UserProvisioner _provisioner;

        private const string BindingCookieName = "emby_sso_binding";

        /// <summary>
        /// Not in <c>SsoErrors</c>, which is in the frozen Protocol layer and knows
        /// nothing of browsers. Deliberately not <c>SessionExpired</c>: for a
        /// stripped cookie nothing has expired, and telling the user to wait or
        /// blame the provider would send them and their administrator the wrong
        /// way. It says what to do and reveals nothing about why.
        /// </summary>
        private const string BrowserBindingFailed =
            "This sign-in could not be completed in this browser. Please try signing in again.";

        // Property injection of IHttpResultFactory via IHasResultFactory leaves it
        // null on this server; the constructor is the only way that works.
        public SsoService(ILogManager logManager, IUserManager userManager, IHttpResultFactory resultFactory)
        {
            _logger = logManager.GetLogger("AuthentikSso");
            _userManager = userManager;
            _resultFactory = resultFactory;

            // Built here, from the constructor arguments Emby's DI already
            // supplies, rather than taken as an extra constructor parameter -
            // adding one would change the signature Emby reflects over to
            // construct this service.
            _provisioner = new UserProvisioner(userManager, _logger);
        }

        public IRequest Request { get; set; }

        public async Task<object> Get(SsoStart request)
        {
            try
            {
                return await HandleStartAsync(pinRequested: false).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Nothing escapes to Emby's error handling, which would put the
                // exception message in the response body.
                return Error(null, "unhandled failure starting the sign-in", ex);
            }
        }

        /// <summary>
        /// The PIN endpoint. It is the ordinary sign-in flow with one bit set
        /// on the pending login, NOT a second way in: no identity is learned
        /// here, no PIN is issued here, and the caller is simply sent to the
        /// identity provider. Everything that decides whether this person may
        /// have a PIN happens in the callback, below every guard.
        /// </summary>
        public async Task<object> Get(SsoPin request)
        {
            try
            {
                return await HandleStartAsync(pinRequested: true).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return Error(null, "unhandled failure starting the PIN sign-in", ex);
            }
        }

        public async Task<object> Get(SsoCallback request)
        {
            try
            {
                return await HandleCallbackAsync(request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return Error(null, "unhandled failure completing the sign-in", ex);
            }
        }

        /// <param name="pinRequested">
        /// True when this flow was started at <c>/Sso/Pin</c> and must end in a
        /// one-time PIN rather than in this browser being signed in. It changes
        /// NOTHING above this point - the same licence check, the same
        /// configuration refusals, the same redirect - and is recorded on the
        /// pending login so the callback cannot be talked into a different
        /// ending than the one that was started.
        /// </param>
        private async Task<object> HandleStartAsync(bool pinRequested)
        {
            // The licence, before anything else. Nothing has left this server at
            // this point - no discovery document is fetched until the
            // authorization URL is built - so an unlicensed server refuses here
            // rather than sending a user to the identity provider for a round
            // trip that was always going to be refused on the way back.
            //
            // The callback below carries the SAME check rather than trusting
            // this one. They are two separate doors, and a callback can arrive
            // with a live pending login that was created while the licence was
            // still valid.
            var licenceRefusal = await LicenceGate.RefusalAsync(_logger, "/Sso/Start").ConfigureAwait(false);

            if (licenceRefusal != null)
            {
                return Error(licenceRefusal, null);
            }

            var configuration = SsoRuntime.Configuration;

            if (configuration == null || !configuration.IsConfigured)
            {
                return Error(SsoErrors.NotConfigured, "sign-in started while the plugin was not configured");
            }

            if (!IsHttps(configuration.EmbyPublicBaseUrl) && !configuration.AllowInsecureHttp)
            {
                return Error(
                    SsoErrors.NotConfigured,
                    "refusing to start sign-in: the public base URL is not HTTPS and insecure HTTP is not allowed");
            }

            // Independent of the base-URL check above: a public base URL can be
            // HTTPS while the issuer is not, and it is the issuer's discovery
            // document and JWKS - fetched by the server, over the network - that
            // an on-path attacker could otherwise substitute to forge an id_token
            // for any username. SsoRuntime.GetClient() also enforces this deeper
            // in the stack (OidcOptions.RequireHttps), but refusing here means
            // the flow never even calls the provider, and the log line is
            // explicit about which URL failed the check.
            if (!IsHttps(configuration.IssuerUrl) && !configuration.AllowInsecureHttp)
            {
                return Error(
                    SsoErrors.NotConfigured,
                    "refusing to start sign-in: the issuer URL is not HTTPS and insecure HTTP is not allowed");
            }

            // The fourth configuration refusal, and the same reordering the
            // native path got: GroupGate answers NotConfigured for an unset
            // required group from configuration alone, so this flow can be
            // refused before it starts rather than after the user has been sent
            // to the identity provider, signed in there, and come back to a
            // callback that was always going to refuse them (the gate in
            // HandleCallbackAsync, which cannot move any earlier - it needs the
            // verified identity).
            //
            // Nobody's access changes: an unset required group refuses every SSO
            // sign-in either way. What changes is that the server stops
            // redirecting users to the provider for a round trip that cannot
            // succeed, and the log says so at the point an operator can act on
            // it. Nothing has left this server when it refuses here - the
            // discovery document is not fetched until the authorization URL is
            // built below.
            if (string.IsNullOrWhiteSpace(configuration.RequiredGroup))
            {
                return Error(
                    SsoErrors.NotConfigured,
                    "refusing to start sign-in: no required group is configured, so the callback could only refuse");
            }

            // The fifth configuration refusal, and it applies to the PIN
            // endpoint alone: a PIN is a credential this server issues, so an
            // operator who has not switched that on must not be able to have
            // one issued by anybody, and the refusal belongs here - before the
            // user is sent on a round trip to the identity provider that could
            // only end in a refusal. The callback checks the SAME setting again
            // rather than trusting this one, because a settings save can land
            // in between and the fail-closed direction is to refuse.
            //
            // Unlike the refusals above, this one says what it is. It is
            // decided from configuration alone, before anybody is identified,
            // so it reveals nothing about any account - and an administrator
            // who has not enabled the feature is the only person who can fix
            // it. See SsoErrors.PinSignInDisabled.
            if (pinRequested && !configuration.EnablePinSignIn)
            {
                return Error(
                    SsoErrors.PinSignInDisabled,
                    "refusing to start a PIN sign-in: PIN sign-in is not enabled");
            }

            try
            {
                var client = SsoRuntime.GetClient();

                if (client == null)
                {
                    return Error(SsoErrors.NotConfigured, "sign-in started while the plugin was not configured");
                }

                var login = SsoRuntime.PendingLogins.Create(pinRequested);
                var url = await client.BuildAuthorizationUrlAsync(login, CancellationToken.None).ConfigureAwait(false);

                // Bind the flow to this browser. Without it, state is a
                // server-global key and anyone holding a valid state and code can
                // complete the flow in someone else's browser.
                IssueBrowserBinding(login);

                // The redirect is the one response with no body of its own, and
                // the one the result factory gives no header dictionary for -
                // GetRedirectResult(string) takes nothing else (read from
                // MediaBrowser.Controller 4.9.1.90 by reflection). So its
                // headers go on the response object directly. It carries the
                // same set as the pages rather than an abbreviated one: a
                // reviewer should not have to work out which responses were
                // considered worth protecting.
                ApplySecurityHeadersToResponse(SecurityHeaders.ForRedirect());

                return _resultFactory.GetRedirectResult(url);
            }
            catch (SsoException ex)
            {
                return Error(ex.UserSafeReason, "could not build the authorization URL", ex);
            }
            catch (Exception ex)
            {
                // Not necessarily the provider's fault - a malformed issuer URL
                // lands here too - so the page says nothing more than that it
                // failed, and the log carries the exception.
                return Error(null, "unexpected failure building the authorization URL", ex);
            }
        }

        private async Task<object> HandleCallbackAsync(SsoCallback request)
        {
            // Consume first, unconditionally: a state is single-use whatever the
            // outcome, including the provider-error path below, which would
            // otherwise leave the pending login live for its whole TTL.
            var login = SsoRuntime.PendingLogins.Consume(request.State);

            // Then the licence, above every other decision here. This is the
            // door that issues the handoff secret an Emby session is minted
            // from, and the door that provisions accounts, so refusing here is
            // what actually stops an unlicensed server admitting anybody. The
            // check at /Sso/Start is the courtesy; this one is the enforcement.
            //
            // Above the code exchange in particular: an unlicensed server must
            // not spend a user's authorization code, which is single-use, on a
            // flow it is about to refuse.
            var licenceRefusal = await LicenceGate.RefusalAsync(_logger, "/Sso/Callback").ConfigureAwait(false);

            if (licenceRefusal != null)
            {
                return Error(licenceRefusal, null);
            }

            if (!string.IsNullOrEmpty(request.Error))
            {
                // Provider-supplied. It goes to the log and nowhere else - as an
                // argument, never as part of the format string, and flattened so
                // it cannot forge extra log lines.
                _logger.Error("SSO: the provider returned an error parameter: {0}", ForLog(request.Error));
                return Error(SsoErrors.ProviderRejected, null);
            }

            if (login == null)
            {
                return Error(SsoErrors.SessionExpired, "callback carried an unknown, expired or replayed state");
            }

            var bindingFailure = CheckBrowserBinding(login);

            if (bindingFailure != null)
            {
                // Deliberately without clearing the cookie. A callback that fails
                // the binding check is, by definition, in a browser that did not
                // start this login - quite possibly a victim's, mid-flow, with a
                // live cookie of their own. Expiring it here would let anyone
                // holding one valid state cancel other people's sign-ins.
                return Error(BrowserBindingFailed, bindingFailure);
            }

            // The binding did its job; this browser has no further use for it.
            ClearBrowserBinding();

            var client = SsoRuntime.GetClient();

            if (client == null)
            {
                return Error(SsoErrors.NotConfigured, "callback arrived while the plugin was not configured");
            }

            OidcIdentity identity;

            try
            {
                identity = await client.ExchangeCodeAsync(request.Code, login, CancellationToken.None).ConfigureAwait(false);
            }
            catch (SsoException ex)
            {
                return Error(ex.UserSafeReason, "code exchange failed", ex);
            }

            // GetClient() above already returning non-null means Configuration was
            // non-null and IsConfigured a moment ago; re-read and re-check rather
            // than trust that, since a settings save can race this call and clear
            // it in between - see SsoRuntime.GetClient()'s own note on the same race.
            var configuration = SsoRuntime.Configuration;

            if (configuration == null)
            {
                return Error(SsoErrors.NotConfigured, "callback arrived while the plugin was not configured");
            }

            // Evaluated before any user lookup, and unconditionally: a non-holder
            // must never cause an account to be created, and must not be able to
            // learn whether an Emby account already exists for their username.
            var gateOutcome = GroupGate.Evaluate(identity, configuration.RequiredGroup);

            switch (gateOutcome)
            {
                case GroupGateOutcome.Allowed:
                    // Falls through to provisioning below. Spelled out rather
                    // than left to the absence of a case, so that `default` can
                    // refuse.
                    break;

                case GroupGateOutcome.NotConfigured:
                    // No required group is set - an operator omission, not
                    // something a user did, so it maps to the same reason as an
                    // unconfigured plugin.
                    return Error(SsoErrors.NotConfigured, "callback arrived while no required group was configured");

                case GroupGateOutcome.GroupsClaimMissing:
                    // Deliberately distinct in the log, identical to UnknownUser
                    // in the browser: this is the provider not emitting the
                    // configured claim at all, an operator misconfiguration, not
                    // a user problem - but saying so to the browser would tell a
                    // stranger that a group check exists.
                    _logger.Info(
                        "SSO: rejected sign-in for '{0}': the token carried no '{1}' claim",
                        ForLog(identity.Username),
                        ForLog(configuration.GroupsClaim));
                    return Error(SsoErrors.GroupsClaimMissing, null);

                case GroupGateOutcome.GroupNotHeld:
                    _logger.Info(
                        "SSO: rejected sign-in for '{0}': required group not held",
                        ForLog(identity.Username));
                    return Error(SsoErrors.GroupNotHeld, null);

                default:
                    // An outcome this switch does not know about. Without this
                    // case a new GroupGateOutcome member would fall out of the
                    // switch and be treated exactly like Allowed - a fail-OPEN
                    // default on an authorisation decision, decided by whoever
                    // adds the enum member rather than by anyone reading this.
                    // Only the cases listed above may proceed.
                    _logger.Error("SSO: rejected sign-in: unrecognised group gate outcome {0}", (int)gateOutcome);
                    return Error(SsoErrors.NotConfigured, "the group gate returned an outcome this build does not handle");
            }

            // Checked BEFORE the account is looked up or created, and not
            // recorded yet. A subject already bound to a different account must
            // be refused before provisioning leaves a second, orphaned account
            // behind for it - one identity provider principal must not be able
            // to farm Emby accounts by editing its own username claim.
            //
            // The name checked here and the name bound below are the same key:
            // Emby's spelling and the claim's spelling are UsernameMatcher-equal
            // by the test just below, and the store keys accounts with that same
            // comparison.
            var precheck = SsoRuntime.SubjectBindings.Check(identity.Subject, identity.Username);

            if (!SubjectBindingStore.Permits(precheck))
            {
                LogSubjectBindingRefusal(precheck, identity.Username);
                return Error(SsoErrors.UnknownUser, null);
            }

            // The plugin never creates an Emby account on its own initiative. An
            // identity that passed the group gate still needs a resolvable Emby
            // user before any handoff secret exists, unless auto-create is on -
            // in which case one is provisioned below, after the gate, so a
            // non-holder can never trigger it.
            var user = _userManager.GetUserByName(identity.Username);

            // Decided BEFORE the provisioning block below, which reassigns
            // `user`: afterwards there is no way to tell an account this plugin
            // just created from one that was already there, and that difference
            // is the whole point of the log line at the end of this method.
            var adopting = user != null && UsernameMatcher.Matches(identity.Username, user.Name);

            if (adopting)
            {
                // The account already exists, so this plugin is being asked to
                // ADOPT it rather than create it - and it may only do that for
                // an account an operator has already pointed at this plugin.
                //
                // The same guard as SsoAuthenticationProvider's, on the other
                // door. Emby offers an account whose AuthenticationProviderId is
                // empty to every enabled provider (assessment F1 / S1a), and a
                // freshly created administrator that has never signed in is
                // exactly such an account - so without this, a group holder
                // whose username claim names that administrator receives its
                // session. Removing it from either path closes neither.
                if (!IsStampedToThisPlugin(user))
                {
                    // Same sentence as an unknown user: the browser must not be
                    // able to tell "no such account" from "that account is not
                    // mine to sign in". The helper has already logged which it
                    // was, with the account name as an ARGUMENT - it must never
                    // become part of a log format string, nor part of the
                    // logDetail this method passes to Error, which is a format
                    // string too.
                    return Error(SsoErrors.UnknownUser, null);
                }
            }

            if (!adopting)
            {
                if (!configuration.EnableAutoCreate)
                {
                    _logger.Info("SSO: rejected sign-in, no Emby user named '{0}'", ForLog(identity.Username));
                    return Error(SsoErrors.UnknownUser, null);
                }

                try
                {
                    user = await _provisioner.ProvisionAsync(identity.Username, configuration.TemplateUserName)
                        .ConfigureAwait(false);
                }
                catch (SsoException ex)
                {
                    // Renders an error page like any other failure - nothing
                    // provisioning-specific escapes to Emby's own error handling.
                    return Error(ex.UserSafeReason, "auto-provisioning failed", ex);
                }
                catch (ArgumentException ex)
                {
                    // IUserManager.CreateUser throws a plain ArgumentException on
                    // a duplicate username, which UserProvisioner deliberately
                    // does not translate. The realistic trigger is two concurrent
                    // first sign-ins for the same new user: both saw no account,
                    // both provisioned, one lost this race. That is not an
                    // operator or provider failure - by the time this is caught,
                    // the account exists - so it is logged at Info, not Error,
                    // with the framework's own message for detail. The browser
                    // gets the same generic sentence as any other unexpected
                    // failure, whose page already offers "Try again"; a retry
                    // finds the account the other request created and signs in
                    // normally.
                    _logger.Info(
                        "SSO: provisioning raced with a concurrent sign-in for '{0}': {1}",
                        ForLog(identity.Username),
                        ForLog(ex.Message));
                    return Error(null, null);
                }
            }

            // Record the binding - trust on first use - before any secret is
            // issued. Re-evaluated from scratch inside the store, so the
            // pre-check above is not carried forward: a concurrent first sign-in
            // may have claimed this account in between.
            //
            // This must stay above the handoff issue. The secret is the sign-in;
            // once it exists the browser can complete without ever coming back
            // through here, and the native provider that consumes it cannot
            // re-check a subject it is never given.
            var bound = SsoRuntime.SubjectBindings.Bind(identity.Subject, user.Name);

            if (!SubjectBindingStore.Permits(bound))
            {
                LogSubjectBindingRefusal(bound, user.Name);
                return Error(SsoErrors.UnknownUser, null);
            }

            LogAdoptionOfAnExistingAccount(bound, adopting, user.Name);

            // The two endings of one flow. EVERYTHING above this line is
            // shared, and that is the whole design of the PIN feature: the
            // licence check, the configuration refusals, the browser binding,
            // the code exchange, the group gate, the provider stamp, the
            // provisioning rules and the subject binding have all already run
            // and all already refused anybody they would refuse. A PIN is
            // issued at the same point, and only at the point, a handoff secret
            // would have been. If a future reader adds a third ending, it goes
            // HERE, below all of them, and nowhere else.
            //
            // The two endings are exclusive. A PIN flow issues no handoff
            // secret and signs this browser into nothing: the person asked for
            // a credential to carry to a television, not for a session in the
            // browser they are holding, and minting a session they did not ask
            // for is spare credential material lying around for no reason.
            if (login.PinRequested)
            {
                return IssuePin(configuration, user.Name);
            }

            // Keyed on Emby's own spelling of the name, which is what Emby will
            // hand the authentication provider when the page authenticates.
            var secret = SsoRuntime.HandoffSecrets.Issue(user.Name);
            _logger.Info("SSO: issued a sign-in handoff for {0}", user.Name);

            // The one page that holds a live credential, so the one whose
            // headers matter most - see SecurityHeaders.
            var nonce = SecurityHeaders.NewNonce();

            return Html(
                CompletionPage.Render(user.Name, secret, nonce),
                SecurityHeaders.ForScriptedPage(nonce));
        }

        /// <summary>
        /// Issues the one-time PIN and renders the page that shows it.
        ///
        /// Called from exactly one place: the very end of the callback, below
        /// every guard. It takes an account NAME rather than an identity on
        /// purpose - by this point the decision about who this is has been
        /// made, and nothing here may re-open it.
        ///
        /// The setting is read AGAIN here, from the configuration snapshot this
        /// callback has been deciding from. The /Sso/Pin endpoint refused
        /// already when PIN sign-in was off, but a settings save can land
        /// between the start of the flow and its callback, and a credential
        /// must not be issued under a setting that has since been withdrawn. It
        /// refuses with the ordinary generic page rather than the specific
        /// sentence the endpoint uses: by this point a real identity has been
        /// verified, and there is no reason to start telling a verified user
        /// about the administrator's settings mid-flow.
        ///
        /// The page carries the static-page security headers - no script at
        /// all, unframable, uncacheable. See <see cref="PinPage"/>.
        /// </summary>
        private object IssuePin(Configuration.PluginConfiguration configuration, string accountName)
        {
            if (configuration?.EnablePinSignIn != true)
            {
                return Error(SsoErrors.NotConfigured, "a PIN flow completed after PIN sign-in was switched off");
            }

            // Keyed on Emby's own spelling of the name, because that is the
            // name Emby will hand the authentication provider when the person
            // types it into their television - the same rule the handoff secret
            // follows.
            var pin = SsoRuntime.SignInPins.Issue(accountName);

            // The PIN itself is NEVER logged. It is a live credential for the
            // next five minutes and the log is the wrong place for it; the
            // account name is what an operator needs, and is already theirs.
            _logger.Info("SSO: issued a one-time sign-in PIN for {0}", ForLog(accountName));

            var nonce = SecurityHeaders.NewNonce();

            return Html(
                PinPage.Render(accountName, pin, (int)SignInPinStore.DefaultTtl.TotalMinutes, nonce),
                SecurityHeaders.ForStaticPage(nonce));
        }

        /// <summary>
        /// Says out loud, at Error, that an identity has just taken over an Emby
        /// account that ALREADY EXISTED - rather than one this sign-in created.
        ///
        /// Trust on first use is silent by design: the first subject to present
        /// an account's name owns it from then on, and nothing about that
        /// sign-in looks unusual. For an account being provisioned that is
        /// unremarkable. For an account that was already there, already stamped
        /// to this plugin, and until now unbound, it is the one moment an
        /// operator would want to see - the renamed-account window in
        /// <see cref="SubjectBindingStore"/>, or the first sign-in after this
        /// build was installed on a server whose accounts predate it. Cheap to
        /// emit, and it turns a silent claim into a line with a timestamp.
        ///
        /// Error rather than Info deliberately: it is not a failure, but it is
        /// the class of event that should never pass unread. The subject is NOT
        /// logged - subjects are stable per-person identifiers and this plugin
        /// keeps them out of the log everywhere else.
        ///
        /// The twin of <c>SsoAuthenticationProvider.LogAdoptionOfAnExistingAccount</c>;
        /// the two doors into an account each need their own.
        /// </summary>
        private void LogAdoptionOfAnExistingAccount(SubjectBindingOutcome outcome, bool adopting, string accountName)
        {
            // BoundOnFirstUse is the only outcome that WROTE a new binding.
            // Bound means the account was already this subject's, which is an
            // ordinary sign-in and must stay quiet or the log becomes noise.
            if (!adopting || outcome != SubjectBindingOutcome.BoundOnFirstUse)
            {
                return;
            }

            _logger.Error(
                "SSO: an Authentik identity has claimed the EXISTING Emby account {0} on first use - it had no "
                + "recorded binding. Expected right after installing this build, or after an account rename; "
                + "otherwise check who now owns that account.",
                ForLog(accountName));
        }

        /// <summary>
        /// Says in the log why a subject binding refused. The browser is always
        /// told the same indistinguishable sentence, so a stranger cannot learn
        /// whether the account exists, whether it is claimed, or by whom.
        ///
        /// The twin of <c>SsoAuthenticationProvider.RefuseBySubjectBinding</c>;
        /// the two must keep saying the same things about the same outcomes.
        /// Subject values are never logged - they are stable per-person
        /// identifiers from the identity provider, and the account name is what
        /// an operator needs.
        /// </summary>
        private void LogSubjectBindingRefusal(SubjectBindingOutcome outcome, string accountName)
        {
            switch (outcome)
            {
                case SubjectBindingOutcome.SubjectMissing:
                    _logger.Error(
                        "SSO: rejected sign-in for '{0}': the token carried no 'sub' claim, so the account cannot "
                        + "be bound to an identity",
                        ForLog(accountName));
                    break;

                case SubjectBindingOutcome.SubjectBoundToAnotherAccount:
                    _logger.Error(
                        "SSO: rejected sign-in for '{0}': this identity provider subject is already bound to a "
                        + "different Emby account. Either the username claim was reassigned, or the person was "
                        + "renamed and an operator must update the subject-binding store.",
                        ForLog(accountName));
                    break;

                case SubjectBindingOutcome.AccountBoundToAnotherSubject:
                    _logger.Error(
                        "SSO: rejected sign-in for '{0}': this Emby account is already bound to a different "
                        + "identity provider subject. A different principal is presenting a claim that names it.",
                        ForLog(accountName));
                    break;

                case SubjectBindingOutcome.StoreUnavailable:
                    _logger.Error(
                        "SSO: rejected sign-in for '{0}': the subject-binding store could not be read or written. "
                        + "Sign-in fails closed rather than falling back to matching on the username alone.",
                        ForLog(accountName));
                    break;

                default:
                    _logger.Error(
                        "SSO: rejected sign-in for '{0}': unrecognised subject binding outcome {1}",
                        ForLog(accountName),
                        (int)outcome);
                    break;
            }
        }

        /// <summary>
        /// Whether an ALREADY-EXISTING Emby account names this plugin as its
        /// authentication provider - the only accounts this flow may sign in.
        /// Logs the reason when it does not; the caller renders the ordinary
        /// indistinguishable refusal.
        ///
        /// See <see cref="ProviderStamp"/> for why an unstamped account must be
        /// refused rather than adopted, and
        /// <see cref="Auth.SsoAuthenticationProvider"/> for the twin of this
        /// check on the native path. The two must not diverge: an account
        /// refused here and admitted there is admitted.
        /// </summary>
        private bool IsStampedToThisPlugin(MediaBrowser.Controller.Entities.User user)
        {
            string providerId = null;

            try
            {
                providerId = _userManager.GetUserPolicy(user)?.AuthenticationProviderId;
            }
            catch (Exception ex)
            {
                // A policy that could not be read is not evidence the account is
                // ours. Null reads as Unstamped below, which refuses.
                _logger.ErrorException(
                    "SSO: could not read the policy for '{0}'; treating the account as not belonging to this plugin",
                    ex,
                    ForLog(user.Name));
            }

            var stamp = ProviderStamp.Evaluate(providerId, Auth.SsoAuthenticationProvider.ProviderId);

            if (ProviderStamp.Permits(stamp))
            {
                return true;
            }

            if (stamp == ProviderStampOutcome.Unstamped)
            {
                _logger.Error(
                    "SSO: rejected sign-in for '{0}': the account has no authentication provider assigned, so this "
                    + "plugin will not adopt it. Set its Login provider to '{1}' deliberately if it should use SSO.",
                    ForLog(user.Name),
                    Auth.SsoAuthenticationProvider.ProviderId);
            }
            else
            {
                _logger.Info(
                    "SSO: rejected sign-in for '{0}': the account belongs to another authentication provider",
                    ForLog(user.Name));
            }

            return false;
        }

        // ------------------------------------------------------------------
        // Browser binding
        //
        // The state parameter is a server-global key with no tie to a user agent.
        // An attacker can run their own sign-in, hold the resulting code and
        // state, and induce a victim's browser to load the callback inside the
        // pending login's TTL - the victim's web client is then signed in as the
        // attacker, with the attacker's token in the victim's localStorage. So
        // /Sso/Start also hands the browser a fresh high-entropy value in a
        // cookie, stores it with the pending login, and the callback requires it
        // back unchanged. Fails closed: no cookie, or a cookie that does not
        // match, ends the flow.
        // ------------------------------------------------------------------

        private void IssueBrowserBinding(PendingLogin login)
        {
            if (login == null || !HeaderSafety.IsCookieValueSafe(login.BrowserBinding))
            {
                return;
            }

            // Exactly as long as the pending login itself is good for.
            var remaining = login.ExpiresAt - DateTimeOffset.UtcNow;
            var seconds = remaining.TotalSeconds < 1 ? 1 : (long)Math.Ceiling(remaining.TotalSeconds);

            SetCookie(login.BrowserBinding, seconds);
        }

        private void ClearBrowserBinding()
        {
            SetCookie(string.Empty, 0);
        }

        /// <summary>
        /// Returns null when the browser presented the value this login was bound
        /// to, or a log detail naming which way it failed - a stripped cookie and
        /// a forged one need different things looked at.
        /// </summary>
        private string CheckBrowserBinding(PendingLogin login)
        {
            if (login == null || string.IsNullOrEmpty(login.BrowserBinding))
            {
                // Only reachable if a PendingLogin was built outside the store.
                return "the pending login carried no browser binding";
            }

            var presented = CookieBinding.ExtractCookieValues(CookieHeaderValues(), BindingCookieName);

            if (presented.Count == 0)
            {
                return "no browser-binding cookie was presented: the callback reached a different browser "
                    + "than the one that started, or something between the browser and Emby drops cookies";
            }

            return CookieBinding.BindingMatches(login.BrowserBinding, presented)
                ? null
                : "the browser-binding cookie did not match the pending login";
        }

        private void SetCookie(string value, long maxAgeSeconds)
        {
            var response = Request?.Response;

            if (response == null)
            {
                // IRequiresRequest injection has never been seen to fail, but if
                // it ever does, a sign-in that silently proceeds without a
                // binding cookie is worse than one that fails loudly - log it
                // rather than the previous silent return.
                _logger.Error("SSO: the request was not injected into the service; cannot set the browser-binding cookie");
                return;
            }

            var cookie = new System.Text.StringBuilder();
            cookie.Append(BindingCookieName).Append('=').Append(value);
            cookie.Append("; Path=").Append(CookiePath());
            cookie.Append("; Max-Age=").Append(maxAgeSeconds.ToString(CultureInfo.InvariantCulture));
            cookie.Append("; HttpOnly; SameSite=Lax");

            // Lax, not Strict: the callback is a top-level cross-site navigation
            // from the identity provider, and Strict would withhold the cookie
            // there and break every sign-in. Lax still withholds it from
            // cross-site subresources, forms and frames.
            if (IsHttps(SsoRuntime.Configuration?.EmbyPublicBaseUrl))
            {
                cookie.Append("; Secure");
            }

            response.AddHeader("Set-Cookie", cookie.ToString());
        }

        /// <summary>
        /// Every value of every <c>Cookie</c> header on the current request. The
        /// parsing that turns these into candidate binding-cookie values is pure
        /// string handling and lives in <see cref="CookieBinding"/> instead, so
        /// it can be tested without an <see cref="IRequest"/> to fake.
        /// </summary>
        private IEnumerable<string> CookieHeaderValues()
        {
            var headers = Request?.Headers;

            if (headers == null)
            {
                yield break;
            }

            foreach (var header in headers)
            {
                if (header != null
                    && string.Equals(header.Name, "Cookie", StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrEmpty(header.Value))
                {
                    yield return header.Value;
                }
            }
        }

        /// <summary>
        /// The cookie path in the BROWSER's terms, which is the redirect URI's
        /// directory - not Emby's own PathInfo, which a reverse proxy may have
        /// stripped a prefix from. Falls back to "/" rather than guessing.
        /// </summary>
        private static string CookiePath()
        {
            var redirectUri = SsoRuntime.RedirectUri();

            if (!string.IsNullOrEmpty(redirectUri) && Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri))
            {
                var path = uri.AbsolutePath;
                var lastSlash = path.LastIndexOf('/');

                if (lastSlash > 0 && HeaderSafety.IsPathSafe(path))
                {
                    return path.Substring(0, lastSlash);
                }
            }

            return "/";
        }

        /// <summary>
        /// Flattens an untrusted string for a single log line and caps its
        /// length. Delegates to the Protocol layer's copy of this policy so the
        /// Api and Protocol layers cannot drift apart on what "safe to log"
        /// means - see <see cref="OidcClient"/>'s use of the same policy for a
        /// provider's OAuth error code.
        /// </summary>
        private static string ForLog(string value)
        {
            return LogSafeText.Flatten(value);
        }

        private static bool IsHttps(string url)
        {
            return url != null && url.Trim().StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// The configured public base URL, trimmed, or an empty string when it is
        /// missing or is not an http(s) URL - so a bad setting cannot become the
        /// href of a link on the error page.
        /// </summary>
        private static string SafeBaseUrl()
        {
            return HeaderSafety.SanitizeBaseUrl(SsoRuntime.Configuration?.EmbyPublicBaseUrl);
        }

        private object Error(string userSafeReason, string logDetail, Exception exception = null)
        {
            if (!string.IsNullOrEmpty(logDetail))
            {
                // logDetail is only ever a literal from this file; anything
                // variable travels as an argument, so a brace in a provider
                // string can never be read as a format placeholder.
                if (exception == null)
                {
                    _logger.Error("SSO: {0}", logDetail);
                }
                else
                {
                    _logger.ErrorException("SSO: {0}", exception, logDetail);
                }
            }

            // Every failure in this service leaves through here, so this is
            // where the error page's headers are guaranteed - including for the
            // catch-all handlers around both endpoints, which is the path a
            // stranger reaches by malforming a request.
            var nonce = SecurityHeaders.NewNonce();

            return Html(
                ErrorPage.Render(userSafeReason, SafeBaseUrl(), nonce),
                SecurityHeaders.ForStaticPage(nonce));
        }

        /// <summary>
        /// Adds a header set to the response object itself, for the one response
        /// that is not built from a header dictionary.
        ///
        /// UNVERIFIED that Emby emits what is added here: <c>IResponse.AddHeader</c>
        /// is read from MediaBrowser.Model 4.9.1.90 by reflection, and this
        /// plugin runs on no reachable server, so nothing below has been seen on
        /// the wire. It is written defensively for that reason - a missing
        /// request, a missing response or a throw from the framework must not
        /// turn a working sign-in into a failed one, because a redirect without
        /// these headers is no worse than the redirect this build shipped
        /// before.
        /// </summary>
        private void ApplySecurityHeadersToResponse(IDictionary<string, string> headers)
        {
            var response = Request?.Response;

            if (response == null)
            {
                _logger.Error("SSO: no response object to set security headers on");
                return;
            }

            try
            {
                foreach (var header in headers)
                {
                    response.AddHeader(header.Key, header.Value);
                }
            }
            catch (Exception ex)
            {
                _logger.ErrorException("SSO: {0}", ex, "could not set the response security headers");
            }
        }

        private object Html(string body, IDictionary<string, string> headers)
        {
            var request = Request;

            if (request == null)
            {
                // IRequiresRequest injection has never been seen to fail, but this
                // is the last step of the handler that exists so nothing escapes
                // into Emby's error handling - it must not be the thing that
                // throws. There is a request-less overload; use it.
                _logger.Error("SSO: the request was not injected into the service; responding without it");
                return _resultFactory.GetResult(body.AsSpan(), "text/html", headers);
            }

            // The content type argument alone is not enough on this server: without
            // this line the response goes out as application/json.
            request.ResponseContentType = "text/html";

            return _resultFactory.GetResult(request, body.AsSpan(), "text/html", headers);
        }
    }
}

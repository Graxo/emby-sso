using System;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Logging;
using MediaBrowser.Model.Users;
using Newtonsoft.Json;

namespace Emby.Sso.Auth
{
    /// <summary>
    /// The single point Emby calls for both sign-in paths. A password is either
    /// a live browser handoff secret or a real password for the identity
    /// provider to check; SsoCredentialValidator decides which.
    ///
    /// Emby only ever invokes the three-argument (<see cref="IRequiresResolvedUser"/>)
    /// overload in practice, but both must apply the same guards: when Emby cannot
    /// resolve a username to an existing user it still calls this provider with
    /// resolvedUser == null, and if any enabled provider returns a success result
    /// for that call, Emby auto-creates the account.
    ///
    /// That branch used to throw unconditionally, and the throw was the only thing
    /// standing between an unauthenticated caller and account creation. It is now
    /// OPEN, narrowly. What guards it in its place is the ordered chain in
    /// <see cref="ProvisionOrRefuse"/>, in this order:
    ///
    /// 1. auto-create must be enabled;
    /// 2. a template user must be CONFIGURED (that it exists is checked at 9);
    /// 3. direct grant must be enabled;
    /// 4. plain HTTP must not be allowed, because that plus direct grant would
    ///    relay the caller's password in cleartext;
    /// 5. a required group must be configured;
    /// 6. the attempt must be within <see cref="ProvisioningThrottle"/>'s budget;
    /// 7. the identity provider must accept the supplied password;
    /// 8. the verified identity must name the very username that was asked for,
    ///    and must hold the operator's required group;
    /// 9. the configured template user must EXIST and its policy must clone.
    ///
    /// 1-6 are <see cref="ProvisioningPreconditions"/>, which is where that order
    /// is asserted by tests rather than only described in prose; 1-5 of them are
    /// decided from configuration alone, so a server that is not provisioning
    /// refuses before the throttle is consulted and before anything is sent
    /// anywhere. 9 is last deliberately: it is a lookup in Emby's user store, and
    /// an unauthenticated caller must not be able to drive one. It is still a
    /// guard, because it runs before the success return - if the template cannot
    /// be read, no account is created.
    ///
    /// Every one of those throws on failure, and the success return is reachable
    /// only after all of them have passed. A future reader must not weaken any
    /// link in that chain believing some other check makes it redundant - nothing
    /// else in Emby will stop the account being created.
    ///
    /// This provider does NOT create the account itself. Emby resolves the
    /// username once, before any provider runs, and then unconditionally calls its
    /// own CreateUser - a provider-created account makes that throw and the
    /// sign-in fail with HTTP 400. Instead the account is created by Emby with the
    /// policy this provider hands back from <see cref="IHasNewUserPolicy"/>, which
    /// Emby passes as a constructor argument to CreateUser, so the account never
    /// exists with Emby's default "every library" policy for even an instant. See
    /// docs/superpowers/spikes/2026-08-30-provisioning-mechanics.md §1, §4, §5, §9.
    /// </summary>
    public class SsoAuthenticationProvider : IAuthenticationProvider, IRequiresResolvedUser, IHasNewUserPolicy
    {
        /// <summary>
        /// How long an armed policy stays claimable. Emby calls GetNewUserPolicy()
        /// within the same millisecond as Authenticate() returning (spike §5.2), so
        /// this is roughly two orders of magnitude of slack; it exists only so a
        /// slot that is never claimed - a sign-in that failed after Authenticate
        /// returned, say - cannot linger.
        /// </summary>
        private static readonly TimeSpan PendingPolicyLifetime = TimeSpan.FromSeconds(10);

        /// <summary>
        /// The value Emby writes into a user's <c>Policy.AuthenticationProviderId</c>
        /// when this plugin authenticates them, and the value an account must
        /// already carry before this plugin will authenticate it
        /// (<see cref="ProviderStamp"/>). One definition, used by the two
        /// provisioners and by both stamp checks, so the name this plugin
        /// STAMPS and the name it REQUIRES cannot drift apart - if they ever
        /// did, either every account would be refused or every account would be
        /// admitted.
        ///
        /// The full type name is what Emby compares against; the project's
        /// provisioning spike (§5.4) established that, and the README documents
        /// the same string for operators setting the field by hand.
        /// </summary>
        public static readonly string ProviderId = typeof(SsoAuthenticationProvider).FullName;

        private readonly ILogger _logger;

        // Reads the template user whose policy a newly provisioned account is
        // created with. Emby resolves this from its own container at startup -
        // verified on 4.9.5.0, see
        // docs/superpowers/spikes/2026-08-30-provisioning-mechanics.md §8 - so the
        // dependency is taken here rather than reached for through a static.
        private readonly IUserManager _userManager;

        private readonly PendingPolicies _pendingPolicies = new PendingPolicies(PendingPolicyLifetime);

        // The brute-force brake on the provisioning branch, and only on that
        // branch: a resolved user already has a UserPolicy and Emby's own
        // InvalidLoginAttemptCount counting against it, while an unknown
        // username has no account for Emby to count against and is exactly the
        // case that forwards a stranger's guess to the identity provider.
        //
        // STATIC, and it must stay static. Emby's registration
        // (IUserManager.AddParts(IEnumerable<IAuthenticationProvider>, ...),
        // reflected from MediaBrowser.Controller 4.9.1.90) hands over provider
        // INSTANCES once, so one instance per server is very probably true - but
        // whether Emby materialises or re-enumerates that sequence is not
        // visible from the reference assemblies, and this is the one piece of
        // shared state in the plugin whose assumption fails OPEN. A second
        // instance would meet a zero-count throttle on every attempt: the brake
        // would be silently and completely absent, with no log line and no
        // failing test. (_pendingPolicies below is deliberately per-instance and
        // is safe either way - Emby recovers IHasNewUserPolicy from the very
        // object that authenticated, spike §1, and a miss fails closed.)
        //
        // Counters that must be shared across every sign-in to mean anything
        // belong to the process, not to whichever object Emby happened to build.
        private static readonly ProvisioningThrottle _throttle = new ProvisioningThrottle();

        public SsoAuthenticationProvider(ILogManager logManager, IUserManager userManager)
        {
            _logger = logManager.GetLogger("AuthentikSso");
            _userManager = userManager;
        }

        public string Name => "Authentik SSO";

        public bool IsEnabled => SsoRuntime.Configuration?.IsConfigured == true;

        public Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        {
            // Emby calls the resolved-user overload for this provider; this
            // overload only exists to satisfy IAuthenticationProvider. Route it
            // through the same resolvedUser == null path rather than duplicating
            // the guards - they must not diverge.
            return Authenticate(username, password, null);
        }

        public async Task<ProviderAuthenticationResult> Authenticate(string username, string password, User resolvedUser)
        {
            if (resolvedUser == null)
            {
                // Load-bearing, and no longer absolute: see the class comment.
                // Returning success here makes Emby create the account, so
                // everything that decides whether that may happen lives in the
                // method below and every failure there throws.
                return await ProvisionOrRefuse(username, password).ConfigureAwait(false);
            }

            // One read of Configuration for this whole call - the early refusal
            // below and the gate further down decide from the same snapshot, so
            // a settings save racing this sign-in cannot refuse against one
            // configuration and gate against another. It is not a snapshot of
            // the whole decision: SsoRuntime.Validator re-reads Configuration
            // independently, both to build the client (which is what fixes the
            // claim the groups are read OUT of) and to check whether a direct
            // grant is permitted at all.
            var configuration = SsoRuntime.Configuration;

            // Decided BEFORE the credential is forwarded, because it can be:
            // GroupGate answers NotConfigured for an unset required group from
            // configuration alone, needing no identity, no token and no network.
            // A server in that state refuses every SSO sign-in - the ratified
            // stance, unchanged here - so forwarding the password first would
            // hand the identity provider a real credential in a loop that cannot
            // succeed. Who is admitted does not change; only the order does.
            //
            // It applies to a handoff secret as well, which the gate below
            // cannot: a handoff carries no identity. That is not a hole being
            // opened, it is the same refusal arriving earlier - the browser
            // callback already refuses to issue a handoff secret at all while no
            // required group is configured (SsoService: GroupGateOutcome
            // .NotConfigured), so the only way to hold one here is for the
            // setting to have been cleared inside the secret's thirty-second
            // life, and refusing that is the fail-closed direction.
            if (string.IsNullOrWhiteSpace(configuration?.RequiredGroup))
            {
                _logger.Error(
                    "Rejecting sign-in for {0} without contacting the provider: no required group is configured",
                    ForLog(resolvedUser.Name));
                throw new Exception(SsoErrors.NotConfigured);
            }

            // Decided before the credential goes anywhere, for the same reason
            // the group check above is: it needs no identity, no token and no
            // network, and an account this plugin may not authenticate must not
            // cause a password to be forwarded on its behalf.
            //
            // This is the guard that closes the unstamped-account takeover
            // (assessment F1 / S1a). See ProviderStamp for the full reasoning;
            // in one line: Emby offers an account with an EMPTY
            // AuthenticationProviderId to every enabled provider, so without
            // this an administrator who has never signed in is reachable through
            // the identity provider by whoever can present their name.
            //
            // It must stay ABOVE ValidateAsync and it must stay on this path as
            // well as the browser callback's - the two are separate doors into
            // the same account and closing one is closing neither.
            RefuseUnlessStampedToThisPlugin(resolvedUser);

            var result = await SsoRuntime.Validator
                .ValidateAsync(resolvedUser.Name, password, CancellationToken.None)
                .ConfigureAwait(false);

            // Listed the other way round - refuse unless the outcome is one of
            // the two this build knows accepts - so that a future
            // SsoCredentialOutcome member cannot let anyone in by default.
            // `== Rejected` would have treated an unrecognised outcome as a
            // success, which is fail-open on an authentication decision decided
            // by whoever adds the enum member rather than by anyone reading
            // here. Behaviour for the three outcomes that exist is unchanged.
            if (result.Outcome != SsoCredentialOutcome.HandoffAccepted
                && result.Outcome != SsoCredentialOutcome.DirectGrantAccepted)
            {
                var reason = result.Reason ?? SsoErrors.UnknownUser;
                _logger.Info("Rejected sign-in for {0}: {1}", ForLog(resolvedUser.Name), reason);

                // Says out loud what the refusal above cannot. On this branch a
                // credential may be either a browser handoff secret or a real
                // password, and which one it was is only known inside the
                // validator - so the mutual exclusion of "Allow plain HTTP" and
                // native password sign-in is enforced there
                // (SsoRuntime.DirectGrantPermitted), where it surfaces as the
                // ordinary "password sign-in is disabled" refusal with no clue
                // as to why. Checked here rather than moved above ValidateAsync
                // because refusing this branch outright would also refuse the
                // browser handoff, which is legitimate on an insecure lab
                // server: the password never passes through this process there.
                if (configuration.AllowInsecureHttp && configuration.EnableDirectGrant)
                {
                    _logger.Error(
                        "Native password sign-in is refused while 'Allow plain HTTP' is on: it would send this "
                        + "password in cleartext. Turn one of the two settings off.");
                }

                throw new Exception(reason);
            }

            // The gate applies to accounts that already exist too: losing the
            // required group must lose access, not merely fail to gain it.
            //
            // Only when an identity is carried, which is the direct-grant path.
            // A handoff result deliberately carries none, because the browser
            // flow verified the identity and applied this same gate before it
            // issued the secret; re-checking here is impossible, not redundant.
            if (result.Identity != null)
            {
                // The same snapshot the early refusal above used. A null
                // configuration would have been refused there; if one somehow
                // reached here it leaves RequiredGroup null, which the gate
                // reports as NotConfigured - a refusal either way.
                var gate = GroupGate.Evaluate(result.Identity, configuration?.RequiredGroup);

                if (gate != GroupGateOutcome.Allowed)
                {
                    throw new Exception(RefuseByGate(gate, result.Identity.Username, configuration?.GroupsClaim));
                }

                // Bind this sign-in to the identity provider's `sub`, or refuse
                // it (assessment F1 / S1b). Like the gate above, this can only
                // be done where an identity is carried - the direct-grant path.
                // A handoff secret carries none, and needs none: the browser
                // callback applied this same binding check before it issued the
                // secret, and the secret is single-use, per-username and lives
                // thirty seconds.
                var binding = SsoRuntime.SubjectBindings.Bind(result.Identity.Subject, resolvedUser.Name);

                if (!SubjectBindingStore.Permits(binding))
                {
                    throw new Exception(RefuseBySubjectBinding(binding, resolvedUser.Name));
                }

                LogAdoptionOfAnExistingAccount(binding, resolvedUser.Name);
            }

            _logger.Info("Accepted {0} sign-in for {1}", result.Outcome, ForLog(resolvedUser.Name));

            return new ProviderAuthenticationResult
            {
                Username = resolvedUser.Name,
                DisplayName = result.DisplayName,
            };
        }

        /// <summary>
        /// Says out loud, at Error, that an identity has just taken over an
        /// account that ALREADY EXISTED in Emby.
        ///
        /// Every account reaching this method exists - it is the resolved-user
        /// path - and has passed <see cref="RefuseUnlessStampedToThisPlugin"/>,
        /// so a binding written here is by definition an adoption rather than a
        /// first provisioning. Trust on first use is otherwise silent: the first
        /// subject to present the name owns it from then on and the sign-in
        /// looks like any other. That is unremarkable for an account being
        /// created and is the one moment worth seeing for an account that was
        /// already there - the renamed-account window described in
        /// <see cref="SubjectBindingStore"/>, or the first sign-in after this
        /// build was installed on a server whose accounts predate it.
        ///
        /// Error rather than Info deliberately: not a failure, but the class of
        /// event that should never pass unread. The subject is NOT logged.
        ///
        /// The twin of <c>SsoService.LogAdoptionOfAnExistingAccount</c>; the two
        /// doors into an account each need their own.
        /// </summary>
        private void LogAdoptionOfAnExistingAccount(SubjectBindingOutcome outcome, string accountName)
        {
            // BoundOnFirstUse is the only outcome that WROTE a new binding.
            // Bound means the account was already this subject's, which is an
            // ordinary sign-in and must stay quiet or the log becomes noise.
            if (outcome != SubjectBindingOutcome.BoundOnFirstUse)
            {
                return;
            }

            _logger.Error(
                "An Authentik identity has claimed the EXISTING Emby account {0} on first use - it had no "
                + "recorded binding. Expected right after installing this build, or after an account rename; "
                + "otherwise check who now owns that account.",
                ForLog(accountName));
        }

        /// <summary>
        /// Throws unless the already-existing account names this plugin as its
        /// authentication provider.
        ///
        /// The refusal is the ordinary indistinguishable "not set up on this
        /// server" sentence - the same one an unknown username, a missing
        /// groups claim and a withheld group all get - because telling a
        /// stranger "that account exists but belongs to another provider"
        /// confirms the account exists. Only the log says which it was, and it
        /// says it at Error for an unstamped account because that one is an
        /// operator action waiting to happen: adopting an existing account into
        /// SSO means setting its Login provider deliberately.
        ///
        /// The policy is read through IUserManager rather than User.Policy so
        /// the dependency this class already declares is the one that answers,
        /// rather than the lazily-initialised static BaseItem.UserManager the
        /// property reaches for (verified by decompiling
        /// MediaBrowser.Controller.Entities.User 4.9.1.90).
        ///
        /// UNVERIFIED: that Emby routes an unstamped account to this provider
        /// at all is taken from the assessment's decompilation of the running
        /// server's GetAuthenticationProviders, not re-measured here - the
        /// plugin is installed on no server this project may sign into. The
        /// guard is safe either way: if Emby never offered unstamped accounts,
        /// this refusal would simply never fire.
        /// </summary>
        private void RefuseUnlessStampedToThisPlugin(User resolvedUser)
        {
            string providerId = null;

            try
            {
                providerId = _userManager.GetUserPolicy(resolvedUser)?.AuthenticationProviderId;
            }
            catch (Exception ex)
            {
                // A policy that cannot be read is not evidence that the account
                // is ours. Fall through with a null provider id, which
                // ProviderStamp reports as Unstamped, which refuses.
                _logger.ErrorException(
                    "Could not read the policy for {0}; treating the account as not belonging to this plugin",
                    ex,
                    ForLog(resolvedUser.Name));
            }

            var stamp = ProviderStamp.Evaluate(providerId, ProviderId);

            if (ProviderStamp.Permits(stamp))
            {
                return;
            }

            switch (stamp)
            {
                case ProviderStampOutcome.Unstamped:
                    _logger.Error(
                        "Rejecting sign-in for {0}: the account has no authentication provider assigned, so this "
                        + "plugin will not adopt it. Set its Login provider to '{1}' deliberately if it should use SSO.",
                        ForLog(resolvedUser.Name),
                        ProviderId);
                    break;

                case ProviderStampOutcome.StampedToAnotherProvider:
                    _logger.Info(
                        "Rejecting sign-in for {0}: the account belongs to another authentication provider",
                        ForLog(resolvedUser.Name));
                    break;

                default:
                    _logger.Error(
                        "Rejecting sign-in for {0}: unrecognised provider stamp outcome {1}",
                        ForLog(resolvedUser.Name),
                        (int)stamp);
                    break;
            }

            throw new Exception(SsoErrors.UnknownUser);
        }

        /// <summary>
        /// The only route from an unresolved username to a successful sign-in, and
        /// therefore to an account being created. Every guard below throws; the
        /// success return at the end is reachable only when all of them passed.
        /// The order is deliberate and lives in <see cref="ProvisioningPreconditions"/>
        /// - the five configuration checks come first, so a server that is not
        /// provisioning never sends a credential anywhere and never consumes
        /// throttle budget, and the throttle comes sixth, so a server that IS
        /// provisioning stops forwarding a stranger's guesses before it forwards
        /// them rather than after.
        /// </summary>
        private async Task<ProviderAuthenticationResult> ProvisionOrRefuse(string username, string password)
        {
            var configuration = SsoRuntime.Configuration;

            // 1-6. The configuration checks and then the brake, in that order,
            //      decided in Protocol/ where the order itself is under test.
            //      Nothing has been sent anywhere at this point, and nothing
            //      here records a failure: by this class's own rule, a refusal
            //      for something nobody tried must not cost budget.
            //
            //      UNVERIFIED end to end: the order, and that no refusal here
            //      touches the throttle, are measured (ProvisioningPreconditions
            //      Tests). What no test on this project can reach is a live
            //      sign-in - the plugin is installed on no reachable server and
            //      no identity provider is configured for one - so that a throw
            //      out of Authenticate reaches a native client as Emby's generic
            //      401 remains spike-sourced rather than re-measured here.
            var precondition = ProvisioningPreconditions.Evaluate(
                Settings(configuration),
                username,
                _throttle,
                DateTimeOffset.UtcNow);

            if (precondition != ProvisioningPreconditionOutcome.MayContactProvider)
            {
                throw new Exception(RefuseByPrecondition(precondition, username));
            }

            // 7. There is no resolved user, so the supplied username is all there
            //    is to check the password against.
            var result = await SsoRuntime.Validator
                .ValidateAsync(username, password, CancellationToken.None)
                .ConfigureAwait(false);

            if (result.Outcome != SsoCredentialOutcome.DirectGrantAccepted)
            {
                // Reason is null on an accepting outcome, and the only accepting
                // outcome that is not a direct grant is a handoff secret for a
                // username with no Emby account - which the browser path does not
                // produce, since it provisions before it issues one. Treat it as
                // an unknown user rather than throwing a null message.
                var reason = result.Reason ?? SsoErrors.UnknownUser;
                _logger.Info("Rejecting sign-in for unresolved '{0}': {1}", ForLog(username), reason);

                // The result-carrying overload, and this is the only exit that
                // may use it: it is the only one where the failure can be the
                // network's rather than the caller's. An identity provider that
                // could not be reached tested no password, so counting it would
                // let an outage plus ordinary retries hold provisioning shut
                // after the provider recovered - and with a global budget of
                // 100, hold it shut for everybody during exactly the mass
                // first-sign-in this branch exists to serve. Every other
                // failure, the provider's own rejection included, still counts.
                //
                // Nothing about the refusal changes: same outcome, same
                // sentence, same throw. Only the counter is spared.
                _throttle.RecordFailure(username, result, DateTimeOffset.UtcNow);

                throw new Exception(reason);
            }

            // 8. The identity the provider verified must be the one that was asked
            //    for. The validator checks this too; it is repeated here because
            //    this is the branch that creates accounts, and the name checked
            //    here is the name the account gets.
            if (result.Identity == null || !UsernameMatcher.Matches(result.Identity.Username, username))
            {
                _logger.Info("Rejecting sign-in: the verified identity does not name '{0}'", ForLog(username));
                RecordThrottledFailure(username);
                throw new Exception(SsoErrors.UnknownUser);
            }

            // 8 (continued). The group gate. A non-holder must never cause an
            //    account to exist. The required group was already established to
            //    be configured, at precondition 5; this is the part of the same
            //    decision that needs the verified identity.
            var gateOutcome = GroupGate.Evaluate(result.Identity, configuration.RequiredGroup);

            if (gateOutcome != GroupGateOutcome.Allowed)
            {
                // Counted like any other refusal on this branch. A caller who
                // holds a valid credential but not the group is still consuming
                // identity-provider round trips, and refusing to count them
                // would leave a budget-free way to probe the gate.
                RecordThrottledFailure(username);
                throw new Exception(RefuseByGate(gateOutcome, result.Identity.Username, configuration.GroupsClaim));
            }

            // 8 (continued). The subject binding, and the last thing decided
            //    from the identity itself. It goes ABOVE RecordSuccess
            //    deliberately: everything below that line is by this method's
            //    own rule "not the credential's fault", and a subject that
            //    contradicts a recorded binding very much is - it is either an
            //    identity provider reassigning a username or somebody claiming
            //    an account that is not theirs.
            //
            //    The account does not exist yet; Emby creates it after this
            //    method returns. Binding first is the right order anyway: if
            //    creation then fails, the sign-in is retried, the subject is
            //    already bound to that same name, and the retry reads as an
            //    ordinary Bound.
            var accountBinding = SsoRuntime.SubjectBindings.Bind(
                result.Identity.Subject,
                result.Identity.Username.Trim());

            if (!SubjectBindingStore.Permits(accountBinding))
            {
                // Counted like the gate refusal above - the provider answered,
                // so this is a caller-caused failure and must cost budget -
                // EXCEPT when the store itself is the problem. An unwritable or
                // unreadable store is the server's fault, exactly like the
                // template failures below, and charging it would turn a disk
                // problem into a fifteen-minute lockout for everybody.
                if (accountBinding != SubjectBindingOutcome.StoreUnavailable)
                {
                    RecordThrottledFailure(username);
                }

                throw new Exception(RefuseBySubjectBinding(accountBinding, result.Identity.Username));
            }

            // The credential was the caller's own and it was right, so the
            // failures under this username were somebody fumbling their own
            // password: clear that budget. Everything below this point can still
            // fail the sign-in, but none of those failures are the credential's
            // fault, so none of them is counted.
            //
            // Keyed on the name that was ASKED for, which is the name the check
            // above was keyed on. Step 6 has already established that it and the
            // identity's own spelling match under UsernameMatcher, and the
            // throttle's map is keyed by that same comparison, so the two names
            // cannot address different buckets. The global bucket is deliberately
            // left alone - see RecordSuccess.
            _throttle.RecordSuccess(username, DateTimeOffset.UtcNow);

            // Read the template before returning success, not after: if it cannot
            // be read there must be no account, and after the return it is too
            // late - Emby creates the account regardless of what happens next.
            var policyJson = BuildNewAccountPolicyJson(configuration.TemplateUserName);

            // Emby creates the account named by the result; use the identity
            // provider's own spelling, which is what the browser path provisions
            // under too, so the two paths cannot produce two differently spelled
            // accounts for one person. Trimmed because UsernameMatcher matched on
            // trimmed values and an account name with edge whitespace is a trap.
            var accountName = result.Identity.Username.Trim();

            try
            {
                _pendingPolicies.Arm(accountName, policyJson, DateTimeOffset.UtcNow);
            }
            catch (SsoException ex)
            {
                // The store is full - more first sign-ins are in flight at once
                // than it will hold. It refuses rather than evicting, so this is
                // the point at which that refusal becomes a failed sign-in.
                // Failing here is the whole intent: the alternative was to evict
                // an armed policy and let some other caller's account be created
                // from whatever the claim-failure path produced. ex.Message is
                // the operator-facing detail and stays in the log; only the
                // user-safe constant is thrown onward.
                _logger.Warn("Rejecting sign-in for unresolved '{0}': {1}", ForLog(accountName), ex.Message);
                throw new Exception(ex.UserSafeReason);
            }

            _logger.Info(
                "Accepted DirectGrantAccepted sign-in for unknown user '{0}'; Emby will create the account from template '{1}'",
                ForLog(accountName),
                ForLog(configuration.TemplateUserName));

            return new ProviderAuthenticationResult
            {
                Username = accountName,
                DisplayName = result.DisplayName,
            };
        }

        /// <summary>
        /// Emby calls this after <see cref="Authenticate"/> has already returned
        /// success for a username that did not resolve, and passes what it returns
        /// straight into its own CreateUser as a constructor argument. It takes no
        /// arguments, so the sign-in it belongs to is recovered from the slot armed
        /// at the end of <see cref="ProvisionOrRefuse"/>.
        ///
        /// Never returns null and never returns a substitute policy: when the
        /// pending sign-in cannot be identified unambiguously, it throws. See the
        /// comment at the throw site for why that is the safe direction, and for
        /// what about it is unverified.
        /// </summary>
        public UserPolicy GetNewUserPolicy()
        {
            var pending = _pendingPolicies.Take(DateTimeOffset.UtcNow);

            if (pending == null)
            {
                // Throwing rather than returning a locked-down policy, which is
                // what this did before.
                //
                // Emby calls this between assigning its `userPolicy` local and
                // calling its own CreateUser - spike §1, decompiled from the
                // running 4.9.5.0 server:
                //
                //     UserPolicy userPolicy = val != null ? val.GetNewUserPolicy()
                //                                        : new UserPolicy();
                //     user = await CreateUser(item.Username ?? username, userPolicy);
                //
                // so an exception here means CreateUser is never reached and NO
                // ACCOUNT IS CREATED AT ALL. Returning a disabled, no-access
                // policy instead let Emby create the account anyway, under the
                // user's real name, and that account is unrecoverable by the
                // user: Emby resolves the name from then on, so this provisioning
                // branch is never re-entered, and its AuthenticationProviderId
                // names this plugin, so Emby's default provider will not take it
                // either (spike §4 observed exactly that dead end). A failed
                // sign-in can be retried; a bricked account needs an operator.
                //
                // UNVERIFIED - this is reasoned from decompiled Emby source, not
                // measured. The plugin is not installed on any server that can be
                // signed into, so no live sign-in exercised it. Two specifics need
                // live confirmation: (a) that no account is left behind, and (b)
                // what the caller sees. Unlike a throw from Authenticate, which
                // Emby catches and reports as a generic 401, this call site is
                // outside AuthenticateLocalUser, so the exception most likely
                // reaches the HTTP layer the way CreateUser's own ArgumentException
                // was observed to (spike §4: HTTP 400 with the message in the
                // body). The message is therefore a user-safe SsoErrors constant
                // and must stay one.
                _logger.Warn("GetNewUserPolicy: no unambiguous pending provisioning; refusing to create the account");
                throw new Exception(SsoErrors.UnknownUser);
            }

            try
            {
                var policy = TemplateClone.PolicyFromJson(pending.PolicyJson);

                if (policy == null)
                {
                    _logger.Error("GetNewUserPolicy: the pending template policy did not deserialise; refusing to create the account");
                    throw new Exception(SsoErrors.NotConfigured);
                }

                // Indicative only: Take returns the oldest live entry, not one
                // matched to this claim, so under concurrent first sign-ins the
                // name below may belong to a different pending account. The policy
                // is not affected - a claim is only answered when every live entry
                // carries the same policy.
                _logger.Info("GetNewUserPolicy: supplying the template policy; oldest pending sign-in is '{0}' (indicative)", ForLog(pending.Username));
                return policy;
            }
            catch (JsonException)
            {
                _logger.Error("GetNewUserPolicy: the pending template policy could not be read; refusing to create the account");
                throw new Exception(SsoErrors.NotConfigured);
            }
        }

        public Task ChangePassword(User user, string newPassword)
        {
            // Passwords live in the identity provider. Accepting a change here
            // would create a local credential that bypasses it.
            throw new Exception("Passwords for this account are managed by the sign-in provider.");
        }

        public Task<bool> HasPassword(User user)
        {
            return Task.FromResult(true);
        }

        /// <summary>
        /// Serialised so that the object Emby stores on the new account can never
        /// alias the template user's live policy, and so that two crossed claims
        /// (see <see cref="PendingPolicies"/>) each get their own instance.
        /// Throws rather than returning a default: no template means no account.
        /// The clone and the two fields it forces live in
        /// <see cref="TemplateClone"/>, shared with the browser path so the
        /// demotion cannot drift between the two provisioners.
        /// </summary>
        private string BuildNewAccountPolicyJson(string templateUserName)
        {
            var template = _userManager.GetUserByName(templateUserName);

            if (template == null)
            {
                _logger.Error("Rejecting sign-in: the configured template user '{0}' does not exist", ForLog(templateUserName));
                throw new Exception(SsoErrors.NotConfigured);
            }

            try
            {
                return TemplateClone.PolicyToJson(TemplateClone.ClonePolicy(_userManager.GetUserPolicy(template)));
            }
            catch (SsoException ex)
            {
                // Deliberately does not carry ex.Message outward. Not because
                // Emby would show it - the project's earlier spike observed the
                // opposite, that a throw from this provider surfaces to the
                // client as HTTP 401 "Invalid username or password entered." and
                // the message reaches only the log
                // (docs/superpowers/spikes/2026-08-30-emby-api-findings.md §5).
                // The reason is narrower and does not depend on Emby's behaviour:
                // ex.Message is diagnostic text this code did not author, and the
                // only thing that should ever leave here is a fixed, user-safe
                // SsoErrors constant. Anything else is a leak waiting for the
                // day some caller does render it.
                _logger.Error("Rejecting sign-in: {0}", ex.Message);
                throw new Exception(ex.UserSafeReason);
            }
            catch (JsonException)
            {
                _logger.Error("Rejecting sign-in: the template user's policy could not be serialised");
                throw new Exception(SsoErrors.NotConfigured);
            }
        }

        /// <summary>
        /// The five settings the provisioning preconditions are decided from,
        /// lifted out of the plugin's configuration in one place. Null for a
        /// null configuration, which <see cref="ProvisioningPreconditions"/>
        /// treats as a server that is not provisioning.
        /// </summary>
        private static ProvisioningSettings Settings(Configuration.PluginConfiguration configuration)
        {
            if (configuration == null)
            {
                return null;
            }

            return new ProvisioningSettings
            {
                EnableAutoCreate = configuration.EnableAutoCreate,
                TemplateUserName = configuration.TemplateUserName,
                EnableDirectGrant = configuration.EnableDirectGrant,
                AllowInsecureHttp = configuration.AllowInsecureHttp,
                RequiredGroup = configuration.RequiredGroup,
            };
        }

        /// <summary>
        /// Logs why a precondition refused and returns the sentence to throw.
        /// Every arm refuses; the caller has already established that the
        /// outcome is not <see cref="ProvisioningPreconditionOutcome.MayContactProvider"/>.
        ///
        /// NONE of these record a failure against the throttle, and none may be
        /// made to. Four of the five are an operator's omission rather than a
        /// caller's attempt - nothing was tried, so there is nothing to count -
        /// and charging them is precisely what turns a misconfigured upgrade
        /// into a fifteen-minute outage for every user, including the fifteen
        /// minutes after the operator fixes it. The fifth, Throttled, is the
        /// brake's own refusal; counting that would let a locked-out caller keep
        /// their own lockout alive.
        /// </summary>
        private string RefuseByPrecondition(ProvisioningPreconditionOutcome outcome, string username)
        {
            switch (outcome)
            {
                case ProvisioningPreconditionOutcome.AutoCreateDisabled:
                    _logger.Info("Rejecting sign-in: no matching Emby user and auto-create is off");
                    return SsoErrors.UnknownUser;

                case ProvisioningPreconditionOutcome.TemplateNotConfigured:
                    _logger.Error("Rejecting sign-in: auto-create is on but no template user is configured");
                    return SsoErrors.NotConfigured;

                case ProvisioningPreconditionOutcome.DirectGrantDisabled:
                    _logger.Info("Rejecting sign-in: direct grant is disabled");
                    return SsoErrors.DirectGrantDisabled;

                case ProvisioningPreconditionOutcome.InsecureHttpWithDirectGrant:
                    _logger.Error(
                        "Rejecting sign-in for unresolved '{0}' without contacting the provider: "
                        + "'Allow plain HTTP' is on together with native password sign-in, which would send this "
                        + "password in cleartext. Turn one of the two off.",
                        ForLog(username));
                    return SsoErrors.DirectGrantDisabled;

                case ProvisioningPreconditionOutcome.RequiredGroupNotConfigured:
                    _logger.Error(
                        "Rejecting sign-in for unresolved '{0}' without contacting the provider: "
                        + "no required group is configured",
                        ForLog(username));
                    return SsoErrors.NotConfigured;

                case ProvisioningPreconditionOutcome.Throttled:
                    // The refusal is the same sentence an ordinary unknown
                    // username gets - see ProvisioningThrottle.RefusalReason for
                    // why it must stay that way - and only the log says a limit
                    // was involved.
                    _logger.Warn(
                        "Rejecting sign-in for unresolved '{0}' without contacting the provider: "
                        + "the provisioning throttle is closed",
                        ForLog(username));
                    return ProvisioningThrottle.RefusalReason;

                default:
                    // Including MayContactProvider, which the caller must never
                    // route here, and any future member. An outcome this method
                    // does not recognise refuses.
                    _logger.Error(
                        "Rejecting sign-in: unrecognised provisioning precondition outcome {0}",
                        (int)outcome);
                    return SsoErrors.UnknownUser;
            }
        }

        /// <summary>
        /// Logs why the gate refused and returns the sentence the browser sees.
        /// The three sentences are deliberately identical: only the log
        /// distinguishes "no groups claim at all" from "group not held", because
        /// telling a stranger which one it was leaks membership. Group values are
        /// never rendered - only the configured claim's name, which is the
        /// operator's own setting.
        ///
        /// Note that on THIS path nobody sees the sentence - Emby reports a
        /// generic 401 for any throw out of Authenticate. The constants earn
        /// their keep on the browser path, where SsoService renders them; they
        /// are returned here so the two paths cannot drift apart about who gets
        /// in and what they are told.
        /// </summary>
        private string RefuseByGate(GroupGateOutcome outcome, string identityUsername, string groupsClaim)
        {
            switch (outcome)
            {
                case GroupGateOutcome.GroupsClaimMissing:
                    _logger.Info(
                        "Rejected sign-in for '{0}': the token carried no '{1}' claim",
                        ForLog(identityUsername),
                        ForLog(groupsClaim));
                    return SsoErrors.GroupsClaimMissing;

                case GroupGateOutcome.GroupNotHeld:
                    _logger.Info("Rejected sign-in for '{0}': required group not held", ForLog(identityUsername));
                    return SsoErrors.GroupNotHeld;

                case GroupGateOutcome.NotConfigured:
                default:
                    // No required group configured is an operator omission, not
                    // something a user did - the same stance the browser callback
                    // takes, so the two paths cannot disagree about who gets in.
                    // `default` also catches a future GroupGateOutcome member: any
                    // outcome this method does not recognise refuses, and only the
                    // caller's explicit `== Allowed` test lets anyone in.
                    _logger.Error("Rejected sign-in for '{0}': no required group is configured", ForLog(identityUsername));
                    return SsoErrors.NotConfigured;
            }
        }

        /// <summary>
        /// Logs why the subject binding refused and returns the sentence to
        /// throw. Every sentence is the same indistinguishable "not set up on
        /// this server" the gate and the unknown-user refusal use, for the same
        /// reason: a stranger must not learn from the response whether the
        /// account exists, whether it is claimed, or by whom.
        ///
        /// The mismatches are logged at Error and say what an operator has to
        /// decide, because they are the two things this mechanism exists to
        /// surface: either an attack, or a legitimate rename in the identity
        /// provider that nobody recorded here. Neither may be resolved by this
        /// code guessing.
        ///
        /// Subject values are never written to the log. They are stable,
        /// unique, per-person identifiers from the identity provider; the
        /// account name is what an operator needs and is already theirs.
        /// </summary>
        private string RefuseBySubjectBinding(SubjectBindingOutcome outcome, string accountName)
        {
            switch (outcome)
            {
                case SubjectBindingOutcome.SubjectMissing:
                    _logger.Error(
                        "Rejecting sign-in for '{0}': the token carried no 'sub' claim, so the account cannot be "
                        + "bound to an identity",
                        ForLog(accountName));
                    break;

                case SubjectBindingOutcome.SubjectBoundToAnotherAccount:
                    _logger.Error(
                        "Rejecting sign-in for '{0}': this identity provider subject is already bound to a "
                        + "different Emby account. Either the username claim was reassigned, or the person was "
                        + "renamed and an operator must update the subject-binding store.",
                        ForLog(accountName));
                    break;

                case SubjectBindingOutcome.AccountBoundToAnotherSubject:
                    _logger.Error(
                        "Rejecting sign-in for '{0}': this Emby account is already bound to a different identity "
                        + "provider subject. A different principal is presenting a claim that names this account.",
                        ForLog(accountName));
                    break;

                case SubjectBindingOutcome.StoreUnavailable:
                    _logger.Error(
                        "Rejecting sign-in for '{0}': the subject-binding store could not be read or written. "
                        + "Sign-in fails closed rather than falling back to matching on the username alone.",
                        ForLog(accountName));
                    break;

                default:
                    // Including Refused, and any future member. An outcome this
                    // method does not recognise refuses; only the caller's
                    // explicit SubjectBindingStore.Permits lets anyone in.
                    _logger.Error(
                        "Rejecting sign-in for '{0}': unrecognised subject binding outcome {1}",
                        ForLog(accountName),
                        (int)outcome);
                    break;
            }

            return SsoErrors.UnknownUser;
        }

        /// <summary>
        /// One unconditionally counted failure of the provisioning branch.
        /// Called at the failing exits BELOW the throttle check that can only
        /// reflect the credential itself: an identity that names someone else,
        /// and a gate refusal. Both mean the provider answered, so neither has
        /// anything to weigh - hence no result argument and no exemption.
        ///
        /// The third such exit, a validator result that is not a direct grant,
        /// goes through the throttle's result-carrying overload instead, because
        /// that is the one place the failure may have been an unreachable
        /// provider rather than the caller. See the comment at that call.
        ///
        /// Nothing here is called for the configuration refusals above the check
        /// (nothing was tried, and an operator who has not switched provisioning
        /// on must not accumulate a lockout), nor for the throttle's own
        /// refusal, nor for the template and store failures after the gate,
        /// which are the server's fault and not the caller's.
        /// </summary>
        private void RecordThrottledFailure(string username)
        {
            _throttle.RecordFailure(username, DateTimeOffset.UtcNow);
        }

        private static string ForLog(string value)
        {
            return LogSafeText.Flatten(value);
        }
    }
}

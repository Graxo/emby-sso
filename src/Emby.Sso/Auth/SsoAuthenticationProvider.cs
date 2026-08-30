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
    /// <see cref="ProvisionOrRefuse"/>: auto-create must be enabled, a template
    /// user must be configured AND exist, direct grant must be enabled, the
    /// identity provider must accept the supplied password on the direct-grant
    /// path, the verified identity must name the very username that was asked for,
    /// and that identity must hold the operator's required group. Every one of
    /// those throws on failure, and the success return is reachable only after all
    /// of them have passed. A future reader must not weaken any link in that chain
    /// believing some other check makes it redundant - nothing else in Emby will
    /// stop the account being created.
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

        private readonly ILogger _logger;

        // Reads the template user whose policy a newly provisioned account is
        // created with. Emby resolves this from its own container at startup -
        // verified on 4.9.5.0, see
        // docs/superpowers/spikes/2026-08-30-provisioning-mechanics.md §8 - so the
        // dependency is taken here rather than reached for through a static.
        private readonly IUserManager _userManager;

        private readonly PendingPolicies _pendingPolicies = new PendingPolicies(PendingPolicyLifetime);

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

            var result = await SsoRuntime.Validator
                .ValidateAsync(resolvedUser.Name, password, CancellationToken.None)
                .ConfigureAwait(false);

            if (result.Outcome == SsoCredentialOutcome.Rejected)
            {
                _logger.Info("Rejected sign-in for {0}: {1}", ForLog(resolvedUser.Name), result.Reason);
                throw new Exception(result.Reason);
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
                // One read of Configuration for the two values THIS method
                // decides from - the required group and the claim name it logs -
                // so a settings save racing this call cannot gate against one
                // configuration and log against another. It is not a snapshot of
                // the whole decision: SsoRuntime.Validator re-reads Configuration
                // independently above, both to build the client (which is what
                // fixes the claim the groups are read OUT of) and to check
                // EnableDirectGrant. A null configuration leaves RequiredGroup
                // null, which the gate reports as NotConfigured - a refusal.
                var configuration = SsoRuntime.Configuration;
                var gate = GroupGate.Evaluate(result.Identity, configuration?.RequiredGroup);

                if (gate != GroupGateOutcome.Allowed)
                {
                    throw new Exception(RefuseByGate(gate, result.Identity.Username, configuration?.GroupsClaim));
                }
            }

            _logger.Info("Accepted {0} sign-in for {1}", result.Outcome, ForLog(resolvedUser.Name));

            return new ProviderAuthenticationResult
            {
                Username = resolvedUser.Name,
                DisplayName = result.DisplayName,
            };
        }

        /// <summary>
        /// The only route from an unresolved username to a successful sign-in, and
        /// therefore to an account being created. Every guard below throws; the
        /// success return at the end is reachable only when all of them passed.
        /// The order is deliberate - the three configuration checks come first, so
        /// a server that is not provisioning never sends a credential anywhere.
        /// </summary>
        private async Task<ProviderAuthenticationResult> ProvisionOrRefuse(string username, string password)
        {
            var configuration = SsoRuntime.Configuration;

            // 1. Auto-create off is the default, and is indistinguishable to the
            //    caller from the account simply not existing.
            if (configuration?.EnableAutoCreate != true)
            {
                _logger.Info("Rejecting sign-in: no matching Emby user and auto-create is off");
                throw new Exception(SsoErrors.UnknownUser);
            }

            // 2. Without a template there is no policy to create the account with,
            //    and Emby's default grants every library.
            if (string.IsNullOrWhiteSpace(configuration.TemplateUserName))
            {
                _logger.Error("Rejecting sign-in: auto-create is on but no template user is configured");
                throw new Exception(SsoErrors.NotConfigured);
            }

            // 3. Only a native sign-in reaches this branch: the browser path
            //    provisions in the callback handler and hands over a secret for an
            //    account that exists by then, so it never arrives here unresolved.
            //    A native sign-in is exactly what EnableDirectGrant governs.
            if (!configuration.EnableDirectGrant)
            {
                _logger.Info("Rejecting sign-in: direct grant is disabled");
                throw new Exception(SsoErrors.DirectGrantDisabled);
            }

            // 4. There is no resolved user, so the supplied username is all there
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
                throw new Exception(reason);
            }

            // 5. The identity the provider verified must be the one that was asked
            //    for. The validator checks this too; it is repeated here because
            //    this is the branch that creates accounts, and the name checked
            //    here is the name the account gets.
            if (result.Identity == null || !UsernameMatcher.Matches(result.Identity.Username, username))
            {
                _logger.Info("Rejecting sign-in: the verified identity does not name '{0}'", ForLog(username));
                throw new Exception(SsoErrors.UnknownUser);
            }

            // 6. The group gate. A non-holder must never cause an account to exist.
            var gateOutcome = GroupGate.Evaluate(result.Identity, configuration.RequiredGroup);

            if (gateOutcome != GroupGateOutcome.Allowed)
            {
                throw new Exception(RefuseByGate(gateOutcome, result.Identity.Username, configuration.GroupsClaim));
            }

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

        private static string ForLog(string value)
        {
            return LogSafeText.Flatten(value);
        }
    }
}

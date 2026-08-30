using System;
using System.Collections.Generic;
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
                _logger.Info("Rejected sign-in for {0}: {1}", resolvedUser.Name, result.Reason);
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
                // One read of Configuration for the whole decision, so a settings
                // save racing this call cannot gate against one configuration and
                // log against another. A null configuration leaves RequiredGroup
                // null, which the gate reports as NotConfigured - a refusal.
                var configuration = SsoRuntime.Configuration;
                var gate = GroupGate.Evaluate(result.Identity, configuration?.RequiredGroup);

                if (gate != GroupGateOutcome.Allowed)
                {
                    throw new Exception(RefuseByGate(gate, result.Identity.Username, configuration?.GroupsClaim));
                }
            }

            _logger.Info("Accepted {0} sign-in for {1}", result.Outcome, resolvedUser.Name);

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

            _pendingPolicies.Arm(accountName, policyJson, DateTimeOffset.UtcNow);

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
        /// Never returns null: Emby dereferences the result.
        /// </summary>
        public UserPolicy GetNewUserPolicy()
        {
            var pending = _pendingPolicies.Take(DateTimeOffset.UtcNow);

            if (pending == null)
            {
                // Deliberately NOT `new UserPolicy()`, which is what Emby would
                // have used and which grants every library. Reaching here means
                // Emby is about to create an account this provider cannot match to
                // a gated sign-in, so it is created with nothing: an operator can
                // widen an account, but nobody can un-see media handed out by
                // mistake. Not expected to happen - every success return from the
                // provisioning branch arms a slot first.
                _logger.Warn("GetNewUserPolicy: no unambiguous pending provisioning; creating a disabled account with no access");
                return LockedDownPolicy();
            }

            try
            {
                var policy = JsonConvert.DeserializeObject<UserPolicy>(pending.PolicyJson);

                if (policy == null)
                {
                    _logger.Error("GetNewUserPolicy: the pending template policy did not deserialise; creating a disabled account with no access");
                    return LockedDownPolicy();
                }

                _logger.Info("GetNewUserPolicy: supplying the template policy for new account '{0}'", ForLog(pending.Username));
                return policy;
            }
            catch (JsonException)
            {
                _logger.Error("GetNewUserPolicy: the pending template policy could not be read; creating a disabled account with no access");
                return LockedDownPolicy();
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
        /// </summary>
        private string BuildNewAccountPolicyJson(string templateUserName)
        {
            var template = _userManager.GetUserByName(templateUserName);

            if (template == null)
            {
                _logger.Error("Rejecting sign-in: the configured template user '{0}' does not exist", ForLog(templateUserName));
                throw new Exception(SsoErrors.NotConfigured);
            }

            UserPolicy clone;

            try
            {
                var templatePolicy = _userManager.GetUserPolicy(template);

                if (templatePolicy == null)
                {
                    _logger.Error("Rejecting sign-in: the template user '{0}' has no policy", ForLog(templateUserName));
                    throw new Exception(SsoErrors.NotConfigured);
                }

                clone = JsonConvert.DeserializeObject<UserPolicy>(JsonConvert.SerializeObject(templatePolicy));
            }
            catch (JsonException)
            {
                // Deliberately does not carry the serialiser's message outward:
                // Emby puts an exception message from here into the HTTP response.
                _logger.Error("Rejecting sign-in: the template user's policy could not be copied");
                throw new Exception(SsoErrors.NotConfigured);
            }

            if (clone == null)
            {
                _logger.Error("Rejecting sign-in: the template user's policy could not be copied");
                throw new Exception(SsoErrors.NotConfigured);
            }

            // Enforced here rather than trusted to the operator's choice of
            // template: a template that happens to be an administrator would
            // otherwise make every group holder an Emby administrator.
            clone.IsAdministrator = false;

            // The template almost certainly carries Emby's default provider id.
            // Copying that would make the account unreachable through SSO, and
            // pre-setting it here also makes Emby's post-creation stamping write a
            // no-op, so no second policy write ever races this one. Spike §5.4.
            clone.AuthenticationProviderId = typeof(SsoAuthenticationProvider).FullName;

            return JsonConvert.SerializeObject(clone);
        }

        /// <summary>
        /// The policy for an account Emby is about to create that this provider
        /// cannot account for. Disabled, no libraries, no channels, no remote
        /// access - visible to an operator and useless to whoever triggered it.
        /// </summary>
        private static UserPolicy LockedDownPolicy()
        {
            return new UserPolicy
            {
                IsAdministrator = false,
                IsDisabled = true,
                EnableAllFolders = false,
                EnabledFolders = new string[0],
                EnableAllChannels = false,
                EnabledChannels = new string[0],
                EnableRemoteAccess = false,
                EnableLiveTvAccess = false,
                EnableLiveTvManagement = false,
                EnablePublicSharing = false,
                AuthenticationProviderId = typeof(SsoAuthenticationProvider).FullName,
            };
        }

        /// <summary>
        /// Logs why the gate refused and returns the sentence the browser sees.
        /// The three sentences are deliberately identical: only the log
        /// distinguishes "no groups claim at all" from "group not held", because
        /// telling a stranger which one it was leaks membership. Group values are
        /// never rendered - only the configured claim's name, which is the
        /// operator's own setting.
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
                    _logger.Error("Rejected sign-in for '{0}': no required group is configured", ForLog(identityUsername));
                    return SsoErrors.NotConfigured;
            }
        }

        private static string ForLog(string value)
        {
            return LogSafeText.Flatten(value);
        }

        /// <summary>
        /// Correlates a gated sign-in with Emby's follow-up call to
        /// <see cref="GetNewUserPolicy"/>, which takes no arguments and so cannot
        /// say which sign-in it is asking about. An AsyncLocal set inside
        /// Authenticate does not flow back to Emby's continuation (spike §9), so
        /// the correlation has to be shared state; the probe used one static
        /// volatile string, which is not safe to ship.
        ///
        /// Every entry holds an already-serialised policy, a username for the log,
        /// and an expiry. Reads consume. Concurrency is handled by refusing to
        /// guess: a claim is answered only when every live entry carries the same
        /// policy, in which case which one it belongs to cannot matter, and
        /// otherwise the whole set is dropped and the caller gets nothing - two
        /// crossed sign-ins then produce two locked-down accounts an operator can
        /// see and fix, rather than one account holding the other's access.
        /// </summary>
        private sealed class PendingPolicies
        {
            /// <summary>
            /// A ceiling on entries that were armed but never claimed. Arming
            /// requires a full gate pass, so this is not an anonymous DoS surface;
            /// it is here so a pathological caller cannot grow the list without
            /// bound inside one expiry window.
            /// </summary>
            private const int Capacity = 32;

            private readonly List<PendingPolicy> _entries = new List<PendingPolicy>();
            private readonly object _lock = new object();
            private readonly TimeSpan _lifetime;

            public PendingPolicies(TimeSpan lifetime)
            {
                _lifetime = lifetime;
            }

            public void Arm(string username, string policyJson, DateTimeOffset now)
            {
                lock (_lock)
                {
                    Purge(now);

                    if (_entries.Count >= Capacity)
                    {
                        _entries.RemoveAt(0);
                    }

                    _entries.Add(new PendingPolicy
                    {
                        Username = username,
                        PolicyJson = policyJson,
                        ExpiresAt = now + _lifetime,
                    });
                }
            }

            /// <summary>
            /// The entry to create the account from, or null when this provider
            /// cannot say which sign-in the caller means. Null is the fail-closed
            /// answer, never an empty or default policy.
            /// </summary>
            public PendingPolicy Take(DateTimeOffset now)
            {
                lock (_lock)
                {
                    Purge(now);

                    if (_entries.Count == 0)
                    {
                        return null;
                    }

                    var candidate = _entries[0];

                    for (var index = 1; index < _entries.Count; index++)
                    {
                        if (!string.Equals(_entries[index].PolicyJson, candidate.PolicyJson, StringComparison.Ordinal))
                        {
                            // Not unanimous, so answering would mean picking one
                            // sign-in's policy for another's account. Drop them
                            // all: every racing claim in this burst fails closed.
                            _entries.Clear();
                            return null;
                        }
                    }

                    _entries.RemoveAt(0);
                    return candidate;
                }
            }

            private void Purge(DateTimeOffset now)
            {
                for (var index = _entries.Count - 1; index >= 0; index--)
                {
                    if (_entries[index].ExpiresAt <= now)
                    {
                        _entries.RemoveAt(index);
                    }
                }
            }
        }

        private sealed class PendingPolicy
        {
            /// <summary>For the log only. Nothing is ever decided from it.</summary>
            public string Username { get; set; }

            public string PolicyJson { get; set; }

            public DateTimeOffset ExpiresAt { get; set; }
        }
    }
}

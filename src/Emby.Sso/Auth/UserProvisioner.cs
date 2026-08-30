using System;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Logging;

namespace Emby.Sso.Auth
{
    /// <summary>
    /// Creates an Emby account by cloning a template user. The caller is
    /// responsible for having verified the identity and applied the group gate
    /// BEFORE calling this — nothing here re-checks either.
    ///
    /// This is the browser-path provisioner only (Task 7's callback handler).
    /// It must never be called from inside SsoAuthenticationProvider.Authenticate:
    /// Emby resolves the username once up front and unconditionally calls its own
    /// CreateUser for an unresolved name, which throws on the duplicate name this
    /// class would already have created. See
    /// docs/superpowers/spikes/2026-08-30-provisioning-mechanics.md §5 and §9 for
    /// why the native path uses IHasNewUserPolicy instead.
    /// </summary>
    public sealed class UserProvisioner
    {
        private readonly IUserManager _userManager;
        private readonly ILogger _logger;

        public UserProvisioner(IUserManager userManager, ILogger logger)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<User> ProvisionAsync(string username, string templateUserName)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new SsoException(SsoErrors.UnknownUser, "provisioning attempted with an empty username");
            }

            if (string.IsNullOrWhiteSpace(templateUserName))
            {
                throw new SsoException(SsoErrors.NotConfigured, "no template user is configured");
            }

            var template = _userManager.GetUserByName(templateUserName);

            if (template == null)
            {
                throw new SsoException(
                    SsoErrors.NotConfigured,
                    "the configured template user does not exist: '" + templateUserName + "'");
            }

            // UserData is deliberately excluded: watch history belongs to the
            // template's owner, not to every account cloned from it.
            var created = await _userManager.CreateUser(
                username,
                template,
                new[] { UserCopyOptions.UserPolicy, UserCopyOptions.UserConfiguration })
                .ConfigureAwait(false);

            var policy = created.Policy;

            // Enforced here rather than trusted to the operator's choice of
            // template: a template that happens to be an administrator would
            // otherwise make every group holder an Emby administrator.
            policy.IsAdministrator = false;

            // Stamp this provider at creation so the account is never offered
            // to any other provider on a later sign-in.
            policy.AuthenticationProviderId = typeof(SsoAuthenticationProvider).FullName;

            // created.InternalId is the Int64 identifier UpdateUserPolicy(long, UserPolicy)
            // expects - confirmed by reflecting over MediaBrowser.Controller.dll 4.9.1.90:
            // User inherits BaseItem.InternalId (Int64, get/set), and IUserManager's only
            // UpdateUserPolicy overload takes (System.Int64 userId, UserPolicy userPolicy).
            // User.Id is a Guid and would not compile against that overload.
            _userManager.UpdateUserPolicy(created.InternalId, policy);

            _logger.Info("Provisioned Emby account {0} from template {1}", created.Name, templateUserName);

            return created;
        }
    }
}

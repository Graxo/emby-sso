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

            // The policy is built BEFORE the account exists and handed to
            // CreateUser(name, policy) as a constructor argument, so the account
            // is never - not for one write, not for one instant - an
            // administrator, and never carries the template's
            // AuthenticationProviderId.
            //
            // The alternative overload, CreateUser(name, template, [UserPolicy,
            // UserConfiguration]), copies the template's policy verbatim and
            // would need a second write to demote. That is exactly the
            // return-then-patch shape the spike measured on the native path and
            // rejected (§4, §5, §6): between the two writes the account exists
            // with the template's rights and with a provider id that is not this
            // plugin's. UserPolicy.IsAdministrator is not a field to fix
            // afterwards.
            //
            // TemplateClone is shared with the native path deliberately: the
            // demotion must not be able to drift between the two provisioners.
            var policy = TemplateClone.ClonePolicy(_userManager.GetUserPolicy(template));

            var created = await _userManager.CreateUser(username, policy).ConfigureAwait(false);

            // Configuration is display preference and carries no access, so
            // unlike the policy it is safe to apply after creation - and it must
            // not be able to fail the sign-in. UserData is still deliberately not
            // copied: watch history belongs to the template's owner, not to every
            // account cloned from it.
            CopyConfigurationBestEffort(template, created);

            _logger.Info("Provisioned Emby account {0} from template {1}", created.Name, templateUserName);

            return created;
        }

        private void CopyConfigurationBestEffort(User template, User created)
        {
            try
            {
                var configuration = TemplateClone.CloneConfiguration(_userManager.GetUserConfiguration(template));

                if (configuration == null)
                {
                    return;
                }

                // created.InternalId is the Int64 identifier the
                // UpdateConfiguration(long, UserConfiguration) overload expects -
                // User inherits BaseItem.InternalId (Int64), confirmed by
                // reflecting over MediaBrowser.Controller.dll 4.9.1.90. User.Id is
                // a Guid and would not compile against it.
                _userManager.UpdateConfiguration(created.InternalId, configuration);
            }
            catch (Exception ex)
            {
                // Broad on purpose. The account exists and its access is already
                // correct; losing the template's display preferences is a cosmetic
                // regression and must never turn a successful sign-in into a
                // failed one.
                _logger.ErrorException(
                    "Provisioned account {0} but could not copy the template user's configuration",
                    ex,
                    LogSafeText.Flatten(created.Name));
            }
        }
    }
}

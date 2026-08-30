using Emby.Sso.Protocol;
using MediaBrowser.Model.Configuration;
using MediaBrowser.Model.Users;
using Newtonsoft.Json;

namespace Emby.Sso.Auth
{
    /// <summary>
    /// Copies a template user's settings onto a newly provisioned account.
    ///
    /// Both provisioning paths go through here — the browser path
    /// (<see cref="UserProvisioner"/>) and the native path
    /// (<see cref="SsoAuthenticationProvider"/>'s IHasNewUserPolicy hook) — so
    /// the two fields that must never be inherited cannot be forced on one path
    /// and forgotten on the other.
    ///
    /// Policy and configuration are treated differently on purpose, and the
    /// difference is not stylistic:
    ///
    /// - The <b>policy is access</b>. It must be correct at construction, because
    ///   Emby's CreateUser takes it as a constructor argument and the account is
    ///   reachable the moment CreateUser returns. Anything that fixes a policy
    ///   after the fact leaves a window in which the account exists with the
    ///   template's rights - including administrator, if the operator picked an
    ///   administrator as their template.
    /// - The <b>configuration is display preference</b> - subtitle mode, resume
    ///   offsets, which views are ordered where. It carries no access at all, so
    ///   applying it in a second write afterwards is safe where applying the
    ///   policy that way was not, and a failure to apply it must not fail the
    ///   sign-in.
    /// </summary>
    internal static class TemplateClone
    {
        /// <summary>
        /// Pinned rather than left to <c>JsonConvert.DefaultSettings</c>, which is
        /// process-wide static state this code does not own.
        ///
        /// It matters more than it looks: every restriction in a template policy
        /// is a <c>false</c> whose CLR default is also <c>false</c>, while
        /// UserPolicy's own property initializers are <c>true</c>
        /// (EnableAllFolders, EnableRemoteAccess, EnableAllChannels and six more).
        /// So a DefaultValueHandling.Ignore in force anywhere would drop the
        /// restrictions from the JSON and deserialisation would restore them
        /// <b>open</b>. ILRepack's Internalize gives this plugin a private
        /// Newtonsoft today, which makes that unreachable - but that is a property
        /// of the packaging step, one flag away from not holding, so the
        /// round-trip states what it needs rather than relying on it.
        /// </summary>
        internal static readonly JsonSerializerSettings SerializerSettings = new JsonSerializerSettings
        {
            DefaultValueHandling = DefaultValueHandling.Include,
            NullValueHandling = NullValueHandling.Include,
            TypeNameHandling = TypeNameHandling.None,
        };

        /// <summary>
        /// A private, hardened copy of the template's policy. Round-tripped
        /// through JSON so the object Emby stores on the new account can never
        /// alias the template user's live policy object.
        /// Throws <see cref="SsoException"/> rather than returning a default: an
        /// unreadable template means no account.
        /// </summary>
        public static UserPolicy ClonePolicy(UserPolicy templatePolicy)
        {
            if (templatePolicy == null)
            {
                throw new SsoException(SsoErrors.NotConfigured, "the template user has no policy");
            }

            UserPolicy clone;

            try
            {
                clone = JsonConvert.DeserializeObject<UserPolicy>(PolicyToJson(templatePolicy), SerializerSettings);
            }
            catch (JsonException ex)
            {
                // The serialiser's own message stays on the inner exception, for
                // the log; it never becomes the reason handed back to a caller.
                throw new SsoException(SsoErrors.NotConfigured, "the template user's policy could not be copied", ex);
            }

            if (clone == null)
            {
                throw new SsoException(SsoErrors.NotConfigured, "the template user's policy could not be copied");
            }

            // Enforced here rather than trusted to the operator's choice of
            // template: a template that happens to be an administrator would
            // otherwise make every group holder an Emby administrator.
            clone.IsAdministrator = false;

            // The template almost certainly carries Emby's default provider id.
            // Copying that would make the account unreachable through SSO, and
            // pre-setting it here also makes Emby's post-creation stamping write
            // a no-op, so no second policy write ever races this one. Spike §5.4.
            clone.AuthenticationProviderId = typeof(SsoAuthenticationProvider).FullName;

            return clone;
        }

        /// <summary>
        /// A private copy of the template's configuration, or null if there is
        /// nothing usable to copy. Round-tripped for the same aliasing reason as
        /// the policy. Never throws: the caller applies this best-effort.
        /// </summary>
        public static UserConfiguration CloneConfiguration(UserConfiguration templateConfiguration)
        {
            if (templateConfiguration == null)
            {
                return null;
            }

            try
            {
                return JsonConvert.DeserializeObject<UserConfiguration>(
                    JsonConvert.SerializeObject(templateConfiguration, SerializerSettings),
                    SerializerSettings);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        public static string PolicyToJson(UserPolicy policy)
        {
            return JsonConvert.SerializeObject(policy, SerializerSettings);
        }

        public static UserPolicy PolicyFromJson(string policyJson)
        {
            return JsonConvert.DeserializeObject<UserPolicy>(policyJson, SerializerSettings);
        }
    }
}

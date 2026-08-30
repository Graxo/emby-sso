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
    /// the fields that must never be inherited cannot be forced on one path and
    /// forgotten on the other.
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
    ///   offsets, which views are ordered where. It grants no library and no
    ///   right, so applying it in a second write afterwards is safe where
    ///   applying the policy that way was not, and a failure to apply it must
    ///   not fail the sign-in. It is not ENTIRELY preference, though: it also
    ///   carries two per-person authentication fields, and
    ///   <see cref="CloneConfiguration"/> clears both rather than handing every
    ///   provisioned account the template owner's. Anything added to
    ///   UserConfiguration by a future Emby release has to be read the same way
    ///   before it is assumed to be a preference.
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

            UserConfiguration clone;

            try
            {
                clone = JsonConvert.DeserializeObject<UserConfiguration>(
                    JsonConvert.SerializeObject(templateConfiguration, SerializerSettings),
                    SerializerSettings);
            }
            catch (JsonException)
            {
                return null;
            }

            if (clone == null)
            {
                return null;
            }

            // Everything else in UserConfiguration is a preference - subtitle
            // mode, resume offsets, which views are ordered where - and copying
            // it is the point of having a template. These two are not
            // preferences, they are the template OWNER's, and neither may be
            // inherited. Both are cleared to the value a normally created
            // account starts with, so a provisioned account is in exactly the
            // state Emby would have put it in.

            // ProfilePin is a per-person secret. Emby's own documentation
            // (emby.media/support/articles/Passwords.html) describes it as a
            // four-digit PIN that guards a user on a shared device: once that
            // device has authenticated the user, the PIN is asked for each time
            // someone returns to or switches into that profile. Copying the
            // template's PIN would give every provisioned account a shared
            // secret that its own owner never chose and does not know, and that
            // the template's owner does.
            //
            // UNVERIFIED: how 4.9.5.0 enforces it - which of the server and the
            // apps actually checks it - was not measured. MediaBrowser.Model
            // 4.9.1.90 only declares the property; nothing in the reference
            // assemblies reads it, so enforcement lives in code this project
            // cannot see, and the plugin is not installed on a server that can
            // be signed into. It does not change the decision: an inherited PIN
            // cannot be right either way. Enforced, it is a shared secret; not
            // enforced, it is a stale secret sitting on every account waiting
            // for a release that starts enforcing it.
            clone.ProfilePin = null;

            // EnableLocalPassword is the switch for Emby's old "easy password"
            // - the short local-network credential. The credential it pairs
            // with is User.EasyPassword, which lives on the user entity and is
            // NOT copied here (confirmed by decompiling
            // MediaBrowser.Controller.Entities.User 4.9.1.90), so inheriting
            // the switch alone would mark a new account as wanting a local
            // password it does not have. Obsolete on 4.9.1.90 and very possibly
            // ignored by the server, which is why the pragma is here rather
            // than the property being left alone: an obsolete authentication
            // switch is exactly the kind of thing that should be off on an
            // account nobody chose it for.
#pragma warning disable 612 // CS0612: the member is obsolete - deliberate, see above
            clone.EnableLocalPassword = false;
#pragma warning restore 612

            return clone;
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

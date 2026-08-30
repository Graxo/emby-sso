using System;
using System.Net.Http;
using Emby.Sso.Configuration;
using Emby.Sso.Protocol;

namespace Emby.Sso
{
    /// <summary>
    /// The process-wide state the plugin needs. Emby constructs authentication
    /// providers and API services independently, so the stores they must share
    /// live here.
    /// </summary>
    public static class SsoRuntime
    {
        private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        private static readonly object ClientLock = new object();

        private static OidcClient _client;
        private static (string IssuerUrl, string ClientId, string ClientSecret, string Scopes, string UsernameClaim, string EmbyPublicBaseUrl, bool AllowInsecureHttp, string GroupsClaim, string RequiredGroup) _clientKey;

        public static PendingLoginStore PendingLogins { get; } =
            new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

        public static HandoffSecretStore HandoffSecrets { get; } =
            new HandoffSecretStore(() => DateTimeOffset.UtcNow, TimeSpan.FromSeconds(30));

        public static SsoCredentialValidator Validator { get; } =
            new SsoCredentialValidator(
                HandoffSecrets,
                GetClient,
                DirectGrantPermitted);

        public static PluginConfiguration Configuration => Plugin.Instance?.Configuration;

        private static readonly object SubjectBindingLock = new object();
        private static SubjectBindingStore _subjectBindings;

        /// <summary>
        /// The durable map from identity-provider subject to Emby account, which
        /// both sign-in paths consult before they admit anybody. See
        /// <see cref="SubjectBindingStore"/> for what it defends and why every
        /// one of its failure modes is a refusal.
        ///
        /// Built lazily rather than in a static initialiser because the path
        /// comes from <see cref="Plugin"/>, and nothing in the reference
        /// assemblies promises that Emby has constructed the plugin before it
        /// constructs the authentication provider or the API service. Until it
        /// has, this hands back <see cref="SubjectBindingStore.Unavailable"/> -
        /// which refuses everything - and does NOT cache it, so a sign-in that
        /// arrives a moment later gets the real store.
        ///
        /// One instance per process once built, because a second instance would
        /// hold a second in-memory view of the same file and two concurrent
        /// first sign-ins could each bind the same account.
        /// </summary>
        public static SubjectBindingStore SubjectBindings
        {
            get
            {
                lock (SubjectBindingLock)
                {
                    if (_subjectBindings != null)
                    {
                        return _subjectBindings;
                    }

                    var path = Plugin.Instance?.SubjectBindingFilePath;

                    if (string.IsNullOrWhiteSpace(path))
                    {
                        return SubjectBindingStore.Unavailable;
                    }

                    _subjectBindings = new SubjectBindingStore(path, () => DateTimeOffset.UtcNow);

                    return _subjectBindings;
                }
            }
        }

        /// <summary>
        /// Whether a direct grant - a native client's real password, handed to
        /// this process and re-transmitted to the identity provider - may be
        /// performed at all.
        ///
        /// It is NOT simply EnableDirectGrant. "Allow plain HTTP (testing only)"
        /// switches off the scheme refusals that stand in front of the browser
        /// flow, and with both settings on this server would relay every native
        /// client's password in cleartext and fetch the id_token whose groups
        /// claim decides authorisation over an unauthenticated channel - the
        /// exact substitution attack /Sso/Start refuses to start a flow for. The
        /// browser flow's insecure mode is not the same bargain: there the
        /// password goes from the user's own browser to the identity provider
        /// and this server never sees it. So the two settings are mutually
        /// exclusive, and the direction of the refusal is the safe one - plain
        /// HTTP turns password sign-in OFF, it never turns a protection off.
        ///
        /// A single read of Configuration, so a settings save racing this call
        /// cannot have one clause read one configuration and the other another.
        /// Refusing here surfaces as the ordinary "password sign-in is
        /// disabled" refusal, which is what it is.
        /// </summary>
        private static bool DirectGrantPermitted()
        {
            var configuration = Configuration;

            return configuration != null
                && configuration.EnableDirectGrant
                && !configuration.AllowInsecureHttp;
        }

        /// <summary>The callback URL registered with the identity provider.</summary>
        public static string RedirectUri()
        {
            var configuration = Configuration;

            return configuration == null ? null : BuildRedirectUri(configuration);
        }

        /// <summary>Returns null when the plugin has not been configured.</summary>
        public static OidcClient GetClient()
        {
            var configuration = Configuration;

            if (configuration == null || !configuration.IsConfigured)
            {
                return null;
            }

            // Single read of Configuration for this call: everything below is derived
            // from this one snapshot, so a settings save racing this call cannot mix
            // fields from two different configurations into one OidcOptions.
            var redirectUri = BuildRedirectUri(configuration);

            // Rebuild whenever a setting that shapes the client changes. Compared as
            // individual fields (not a delimited string) so a delimiter appearing
            // inside one field - a ClientSecret containing '|', say - can never make
            // two different configurations collide onto the same key.
            var key = (
                configuration.IssuerUrl,
                configuration.ClientId,
                configuration.ClientSecret,
                configuration.Scopes,
                configuration.UsernameClaim,
                configuration.EmbyPublicBaseUrl,
                configuration.AllowInsecureHttp,
                configuration.GroupsClaim,
                configuration.RequiredGroup);

            lock (ClientLock)
            {
                if (_client != null && _clientKey.Equals(key))
                {
                    return _client;
                }

                _client = new OidcClient(Http, new OidcOptions
                {
                    IssuerUrl = configuration.IssuerUrl,
                    ClientId = configuration.ClientId,
                    ClientSecret = configuration.ClientSecret,
                    Scopes = configuration.Scopes,
                    RedirectUri = redirectUri,
                    UsernameClaim = configuration.UsernameClaim,
                    GroupsClaim = configuration.GroupsClaim,

                    // The flag, not the address: Protocol/ never reads
                    // configuration itself, and deriving this from whether the
                    // issuer URL happens to start with "https://" would make it
                    // impossible for this to ever refuse an http:// issuer - the
                    // exact tautology this replaces.
                    RequireHttps = !configuration.AllowInsecureHttp,
                });
                _clientKey = key;

                return _client;
            }
        }

        private static string BuildRedirectUri(PluginConfiguration configuration)
        {
            return configuration.EmbyPublicBaseUrl.TrimEnd('/') + "/emby" + SsoRoutes.CallbackPath;
        }
    }
}

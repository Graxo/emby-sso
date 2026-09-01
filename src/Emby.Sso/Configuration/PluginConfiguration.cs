using MediaBrowser.Model.Plugins;

namespace Emby.Sso.Configuration
{
    public class PluginConfiguration : BasePluginConfiguration
    {
        public string IssuerUrl { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string Scopes { get; set; } = "openid profile email";
        public string EmbyPublicBaseUrl { get; set; } = string.Empty;
        public string UsernameClaim { get; set; } = "preferred_username";
        public bool EnableDirectGrant { get; set; } = false;
        public bool EnableButtonInjection { get; set; } = false;
        public bool AllowInsecureHttp { get; set; } = false;

        /// <summary>
        /// Permits the plugin to fetch the discovery document, the JWKS and the
        /// token endpoint from a loopback, RFC1918 or carrier-grade-NAT address.
        /// Off by default, because an issuer URL an administrator was talked
        /// into pasting - or a discovery document from a provider that has been
        /// compromised - would otherwise let this server be used to reach
        /// services on its own network. On, because a great many people quite
        /// legitimately run their identity provider on exactly such an address.
        /// See <see cref="Protocol.OutboundAddressPolicy"/>; link-local
        /// addresses (169.254.0.0/16, which carries the cloud metadata service)
        /// stay refused either way.
        /// </summary>
        public bool AllowPrivateNetworkProvider { get; set; } = false;

        /// <summary>
        /// Whether a user may ask for a one-time sign-in PIN, and whether one
        /// may be redeemed.
        ///
        /// Off by default, and its OWN setting - deliberately not governed by
        /// <see cref="EnableDirectGrant"/>. The two look similar from the
        /// outside (both end with a native app signing in from its ordinary
        /// password field) and are not the same bargain at all: a direct grant
        /// hands this server a person's real identity-provider credential to
        /// re-transmit and cannot carry MFA, while a PIN is issued by this
        /// server at the end of a full browser sign-in that did carry MFA, is
        /// bound to one account, lives five minutes and works once. An operator
        /// who has quite reasonably refused the first should not have to accept
        /// it to get the second.
        ///
        /// See <see cref="Protocol.SignInPinStore"/> for what a PIN is worth
        /// and what defends it.
        /// </summary>
        public bool EnablePinSignIn { get; set; } = false;

        public bool EnableAutoCreate { get; set; } = false;
        public string RequiredGroup { get; set; } = string.Empty;
        public string TemplateUserName { get; set; } = string.Empty;
        public string GroupsClaim { get; set; } = "groups";

        /// <summary>
        /// The signed licence key the vendor issued for THIS Emby server,
        /// pasted in by an administrator the way Emby's own supporter key is.
        /// See <see cref="Protocol.LicenceCheck"/>.
        ///
        /// It is not a secret in any interesting sense - it is a signed
        /// assertion, readable by anyone who has it, and it is useless on any
        /// other server. It is stored in the plugin configuration XML like every
        /// other setting.
        ///
        /// Empty, or invalid, refuses NEW single sign-ons and account
        /// provisioning and nothing else: sessions that already hold an Emby
        /// access token keep working, and Emby's own local accounts are
        /// unaffected because they are not this plugin's to authenticate. An
        /// operator can always still reach their own server.
        /// </summary>
        public string LicenceKey { get; set; } = string.Empty;

        /// <summary>
        /// How many of the code's activations were used, and how many it allows,
        /// as the licensing service reported them at the last successful
        /// activation.
        ///
        /// STORED RATHER THAN ASKED FOR, because asking would mean a network
        /// call to render a settings page - and the one thing this feature must
        /// not do is put the vendor's service on any path but the Activate
        /// button. See Api.ActivationService. It is therefore a snapshot: it is
        /// right at the moment of activation and does not move afterwards, which
        /// is exactly what an operator wants to know ("did this code have room
        /// for this server?") and is not a live count of anything.
        ///
        /// Zero means no activation has been performed by this build - a licence
        /// pasted in by hand carries no such numbers, because it never went
        /// through a redemption.
        /// </summary>
        public int ActivationsUsed { get; set; }

        public int ActivationsAllowed { get; set; }

        /// <summary>
        /// An override for the vendor's activation service, for testing a
        /// service before it is live. Empty - the normal state - means
        /// <see cref="Protocol.ActivationEndpoint.DefaultServiceBase"/>, the
        /// address compiled into this build.
        ///
        /// DELIBERATELY NOT ON THE CONFIGURATION PAGE. It is a vendor's testing
        /// knob, not an operator setting, and the configuration page is the
        /// most fragile thing in this plugin; a field nobody needs is a field
        /// that can only break it. Set it by editing
        /// <c>plugins/configurations/Emby.Sso.xml</c> and restarting Emby. The
        /// page round-trips this value untouched, because it reads the whole
        /// configuration object, edits the fields it knows and writes the whole
        /// object back.
        ///
        /// An override IS SAFE, and that is not an accident: whatever address
        /// this names, the licence that comes back is verified against the
        /// public key compiled into this build and against this server's own id
        /// before it is stored (see <see cref="Protocol.ActivationClient"/>), so
        /// pointing it at a hostile server yields a refusal and nothing else.
        /// It must still be HTTPS - the redemption code is a bearer secret.
        /// </summary>
        public string ActivationServiceUrl { get; set; } = string.Empty;

        public bool IsConfigured =>
            !string.IsNullOrWhiteSpace(IssuerUrl) &&
            !string.IsNullOrWhiteSpace(ClientId) &&
            !string.IsNullOrWhiteSpace(EmbyPublicBaseUrl);
    }
}

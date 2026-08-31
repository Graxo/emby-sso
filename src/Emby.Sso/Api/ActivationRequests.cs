using MediaBrowser.Controller.Net;
using MediaBrowser.Model.Services;

namespace Emby.Sso.Api
{
    /// <summary>
    /// What the configuration page needs to show the licence area: this
    /// server's id, and the purchase link built from it.
    /// </summary>
    /// <remarks>
    /// ADMIN ONLY, and stated rather than inherited. Plugin endpoints are
    /// authenticated by default on this server - which is why the three
    /// browser-facing sign-in routes have to carry
    /// <see cref="UnauthenticatedAttribute"/> to work at all - but "a signed-in
    /// user" is not the bar for anything on the configuration page.
    /// <c>Authenticated(Roles = "Admin")</c> is: decompiled from Emby 4.9.5.0,
    /// <c>AuthService.Authenticate</c> rejects a request with no valid access
    /// token outright (none of <c>AllowLocal</c>, <c>AllowLocalOnly</c> or
    /// <c>AllowBeforeStartupWizard</c> is set here, so no exemption applies) and
    /// then <c>ValidateRoles</c> throws <c>SecurityException(ManageServer)</c>
    /// unless <c>user.Policy.IsAdministrator</c>. The role string is matched
    /// case-insensitively against "admin".
    ///
    /// Nothing secret is returned even so: the server id is written to Emby's
    /// own log at every startup, and the purchase URL is built from it.
    /// </remarks>
    [Route(SsoRoutes.ActivationInfoPath, "GET")]
    [Authenticated(Roles = "Admin")]
    public class SsoActivationInfo : IReturn<ActivationInfoResult>
    {
    }

    /// <summary>
    /// Redeems a code at the vendor's activation service. See
    /// <see cref="ActivationService"/>.
    /// </summary>
    /// <remarks>
    /// Admin only, for the reason given on <see cref="SsoActivationInfo"/>, and
    /// here it is load-bearing rather than tidiness: this endpoint spends a
    /// purchase and rewrites the plugin's licence.
    ///
    /// <see cref="Code"/> arrives in the request BODY, never in the query
    /// string. It is a bearer secret - whoever holds it can spend an activation
    /// - so it is treated the way the client secret is: not in a URL, where it
    /// would be written into access logs and proxy logs, and never written to
    /// the server log.
    /// </remarks>
    [Route(SsoRoutes.ActivatePath, "POST")]
    [Authenticated(Roles = "Admin")]
    public class SsoActivate : IReturn<ActivationResponse>
    {
        /// <summary>
        /// The redemption code, as the administrator typed it. NEVER LOGGED.
        /// The contract makes the service responsible for case and separators,
        /// so it is sent as typed.
        /// </summary>
        public string Code { get; set; }
    }

    /// <summary>What the configuration page renders in the licence area.</summary>
    public class ActivationInfoResult
    {
        /// <summary>
        /// <c>IApplicationHost.SystemId</c>. Not a secret: Emby writes it to its
        /// own log at startup, and it is the first thing anybody issuing a
        /// licence asks for. Empty when the host reported none.
        /// </summary>
        public string ServerId { get; set; }

        /// <summary>The purchase page, carrying the server id. Empty when one cannot be built.</summary>
        public string BuyUrl { get; set; }
    }

    /// <summary>The answer to an Activate press.</summary>
    public class ActivationResponse
    {
        /// <summary>
        /// True only when a licence came back AND this build verified it
        /// against its own public key and this server's own id AND it was
        /// saved.
        /// </summary>
        public bool Activated { get; set; }

        /// <summary>The machine-readable outcome, for the log and for support.</summary>
        public string Outcome { get; set; }

        /// <summary>One sentence for the administrator. Never contains the code.</summary>
        public string Message { get; set; }

        /// <summary>
        /// The saved licence, echoed back so the page can put it in the Licence
        /// key field - otherwise the next Save would write the stale field value
        /// over the licence that was just stored. Empty unless
        /// <see cref="Activated"/>.
        ///
        /// Not a secret: a licence is a signed assertion, readable by anyone who
        /// holds it and useless on any other server, and this response only ever
        /// reaches an administrator.
        /// </summary>
        public string LicenceKey { get; set; }

        /// <summary>The service's stated expiry, for display. Empty when it did not say.</summary>
        public string ExpiresUtc { get; set; }

        public int ActivationsUsed { get; set; }

        public int ActivationsAllowed { get; set; }
    }
}

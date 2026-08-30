using Emby.Sso;
using MediaBrowser.Controller.Net;
using MediaBrowser.Model.Services;

namespace Emby.Sso.Api
{
    /// <summary>
    /// Begins a browser sign-in. Redirects to the identity provider.
    /// </summary>
    /// <remarks>
    /// Plugin endpoints are authenticated by default and answer 401 without a
    /// session token, so the two browser-facing routes carry
    /// <see cref="UnauthenticatedAttribute"/>: a sign-in endpoint that requires
    /// an existing sign-in is useless. The attribute belongs on the request DTO,
    /// not on the service.
    /// </remarks>
    [Route(SsoRoutes.StartPath, "GET")]
    [Unauthenticated]
    public class SsoStart : IReturnVoid
    {
    }

    /// <summary>
    /// The identity provider's redirect target. Completes the sign-in.
    /// </summary>
    [Route(SsoRoutes.CallbackPath, "GET")]
    [Unauthenticated]
    public class SsoCallback : IReturnVoid
    {
        public string Code { get; set; }

        public string State { get; set; }

        /// <summary>
        /// Provider-supplied. Goes to the log only - never to the page.
        /// </summary>
        public string Error { get; set; }
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Auth;
using Emby.Sso.Protocol;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Model.Logging;
using MediaBrowser.Model.Services;

namespace Emby.Sso.Api
{
    /// <summary>
    /// The browser sign-in flow: /emby/Sso/Start sends the user to the identity
    /// provider, /emby/Sso/Callback brings them back and returns the page that
    /// completes the sign-in.
    ///
    /// Every failure leaves through <see cref="Error"/>, which logs the detail and
    /// renders a fixed, user-safe sentence. Nothing the identity provider supplied
    /// is ever written into a page, and no exception is allowed to escape into
    /// Emby's error handling, where the message would become the response body.
    /// </summary>
    public class SsoService : IService, IRequiresRequest
    {
        private readonly ILogger _logger;
        private readonly IUserManager _userManager;
        private readonly IHttpResultFactory _resultFactory;
        private readonly UserProvisioner _provisioner;

        private const string BindingCookieName = "emby_sso_binding";

        /// <summary>
        /// Not in <c>SsoErrors</c>, which is in the frozen Protocol layer and knows
        /// nothing of browsers. Deliberately not <c>SessionExpired</c>: for a
        /// stripped cookie nothing has expired, and telling the user to wait or
        /// blame the provider would send them and their administrator the wrong
        /// way. It says what to do and reveals nothing about why.
        /// </summary>
        private const string BrowserBindingFailed =
            "This sign-in could not be completed in this browser. Please try signing in again.";

        // Property injection of IHttpResultFactory via IHasResultFactory leaves it
        // null on this server; the constructor is the only way that works.
        public SsoService(ILogManager logManager, IUserManager userManager, IHttpResultFactory resultFactory)
        {
            _logger = logManager.GetLogger("AuthentikSso");
            _userManager = userManager;
            _resultFactory = resultFactory;

            // Built here, from the constructor arguments Emby's DI already
            // supplies, rather than taken as an extra constructor parameter -
            // adding one would change the signature Emby reflects over to
            // construct this service.
            _provisioner = new UserProvisioner(userManager, _logger);
        }

        public IRequest Request { get; set; }

        public async Task<object> Get(SsoStart request)
        {
            try
            {
                return await HandleStartAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Nothing escapes to Emby's error handling, which would put the
                // exception message in the response body.
                return Error(null, "unhandled failure starting the sign-in", ex);
            }
        }

        public async Task<object> Get(SsoCallback request)
        {
            try
            {
                return await HandleCallbackAsync(request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return Error(null, "unhandled failure completing the sign-in", ex);
            }
        }

        private async Task<object> HandleStartAsync()
        {
            var configuration = SsoRuntime.Configuration;

            if (configuration == null || !configuration.IsConfigured)
            {
                return Error(SsoErrors.NotConfigured, "sign-in started while the plugin was not configured");
            }

            if (!IsHttps(configuration.EmbyPublicBaseUrl) && !configuration.AllowInsecureHttp)
            {
                return Error(
                    SsoErrors.NotConfigured,
                    "refusing to start sign-in: the public base URL is not HTTPS and insecure HTTP is not allowed");
            }

            // Independent of the base-URL check above: a public base URL can be
            // HTTPS while the issuer is not, and it is the issuer's discovery
            // document and JWKS - fetched by the server, over the network - that
            // an on-path attacker could otherwise substitute to forge an id_token
            // for any username. SsoRuntime.GetClient() also enforces this deeper
            // in the stack (OidcOptions.RequireHttps), but refusing here means
            // the flow never even calls the provider, and the log line is
            // explicit about which URL failed the check.
            if (!IsHttps(configuration.IssuerUrl) && !configuration.AllowInsecureHttp)
            {
                return Error(
                    SsoErrors.NotConfigured,
                    "refusing to start sign-in: the issuer URL is not HTTPS and insecure HTTP is not allowed");
            }

            try
            {
                var client = SsoRuntime.GetClient();

                if (client == null)
                {
                    return Error(SsoErrors.NotConfigured, "sign-in started while the plugin was not configured");
                }

                var login = SsoRuntime.PendingLogins.Create();
                var url = await client.BuildAuthorizationUrlAsync(login, CancellationToken.None).ConfigureAwait(false);

                // Bind the flow to this browser. Without it, state is a
                // server-global key and anyone holding a valid state and code can
                // complete the flow in someone else's browser.
                IssueBrowserBinding(login);

                return _resultFactory.GetRedirectResult(url);
            }
            catch (SsoException ex)
            {
                return Error(ex.UserSafeReason, "could not build the authorization URL", ex);
            }
            catch (Exception ex)
            {
                // Not necessarily the provider's fault - a malformed issuer URL
                // lands here too - so the page says nothing more than that it
                // failed, and the log carries the exception.
                return Error(null, "unexpected failure building the authorization URL", ex);
            }
        }

        private async Task<object> HandleCallbackAsync(SsoCallback request)
        {
            // Consume first, unconditionally: a state is single-use whatever the
            // outcome, including the provider-error path below, which would
            // otherwise leave the pending login live for its whole TTL.
            var login = SsoRuntime.PendingLogins.Consume(request.State);

            if (!string.IsNullOrEmpty(request.Error))
            {
                // Provider-supplied. It goes to the log and nowhere else - as an
                // argument, never as part of the format string, and flattened so
                // it cannot forge extra log lines.
                _logger.Error("SSO: the provider returned an error parameter: {0}", ForLog(request.Error));
                return Error(SsoErrors.ProviderRejected, null);
            }

            if (login == null)
            {
                return Error(SsoErrors.SessionExpired, "callback carried an unknown, expired or replayed state");
            }

            var bindingFailure = CheckBrowserBinding(login);

            if (bindingFailure != null)
            {
                // Deliberately without clearing the cookie. A callback that fails
                // the binding check is, by definition, in a browser that did not
                // start this login - quite possibly a victim's, mid-flow, with a
                // live cookie of their own. Expiring it here would let anyone
                // holding one valid state cancel other people's sign-ins.
                return Error(BrowserBindingFailed, bindingFailure);
            }

            // The binding did its job; this browser has no further use for it.
            ClearBrowserBinding();

            var client = SsoRuntime.GetClient();

            if (client == null)
            {
                return Error(SsoErrors.NotConfigured, "callback arrived while the plugin was not configured");
            }

            OidcIdentity identity;

            try
            {
                identity = await client.ExchangeCodeAsync(request.Code, login, CancellationToken.None).ConfigureAwait(false);
            }
            catch (SsoException ex)
            {
                return Error(ex.UserSafeReason, "code exchange failed", ex);
            }

            // GetClient() above already returning non-null means Configuration was
            // non-null and IsConfigured a moment ago; re-read and re-check rather
            // than trust that, since a settings save can race this call and clear
            // it in between - see SsoRuntime.GetClient()'s own note on the same race.
            var configuration = SsoRuntime.Configuration;

            if (configuration == null)
            {
                return Error(SsoErrors.NotConfigured, "callback arrived while the plugin was not configured");
            }

            // Evaluated before any user lookup, and unconditionally: a non-holder
            // must never cause an account to be created, and must not be able to
            // learn whether an Emby account already exists for their username.
            var gateOutcome = GroupGate.Evaluate(identity, configuration.RequiredGroup);

            switch (gateOutcome)
            {
                case GroupGateOutcome.NotConfigured:
                    // No required group is set - an operator omission, not
                    // something a user did, so it maps to the same reason as an
                    // unconfigured plugin.
                    return Error(SsoErrors.NotConfigured, "callback arrived while no required group was configured");

                case GroupGateOutcome.GroupsClaimMissing:
                    // Deliberately distinct in the log, identical to UnknownUser
                    // in the browser: this is the provider not emitting the
                    // configured claim at all, an operator misconfiguration, not
                    // a user problem - but saying so to the browser would tell a
                    // stranger that a group check exists.
                    _logger.Info(
                        "SSO: rejected sign-in for '{0}': the token carried no '{1}' claim",
                        ForLog(identity.Username),
                        ForLog(configuration.GroupsClaim));
                    return Error(SsoErrors.GroupsClaimMissing, null);

                case GroupGateOutcome.GroupNotHeld:
                    _logger.Info(
                        "SSO: rejected sign-in for '{0}': required group not held",
                        ForLog(identity.Username));
                    return Error(SsoErrors.GroupNotHeld, null);
            }

            // The plugin never creates an Emby account on its own initiative. An
            // identity that passed the group gate still needs a resolvable Emby
            // user before any handoff secret exists, unless auto-create is on -
            // in which case one is provisioned below, after the gate, so a
            // non-holder can never trigger it.
            var user = _userManager.GetUserByName(identity.Username);

            if (user == null || !UsernameMatcher.Matches(identity.Username, user.Name))
            {
                if (!configuration.EnableAutoCreate)
                {
                    _logger.Info("SSO: rejected sign-in, no Emby user named '{0}'", ForLog(identity.Username));
                    return Error(SsoErrors.UnknownUser, null);
                }

                try
                {
                    user = await _provisioner.ProvisionAsync(identity.Username, configuration.TemplateUserName)
                        .ConfigureAwait(false);
                }
                catch (SsoException ex)
                {
                    // Renders an error page like any other failure - nothing
                    // provisioning-specific escapes to Emby's own error handling.
                    return Error(ex.UserSafeReason, "auto-provisioning failed", ex);
                }
                catch (ArgumentException ex)
                {
                    // IUserManager.CreateUser throws a plain ArgumentException on
                    // a duplicate username, which UserProvisioner deliberately
                    // does not translate. The realistic trigger is two concurrent
                    // first sign-ins for the same new user: both saw no account,
                    // both provisioned, one lost this race. That is not an
                    // operator or provider failure - by the time this is caught,
                    // the account exists - so it is logged at Info, not Error,
                    // with the framework's own message for detail. The browser
                    // gets the same generic sentence as any other unexpected
                    // failure, whose page already offers "Try again"; a retry
                    // finds the account the other request created and signs in
                    // normally.
                    _logger.Info(
                        "SSO: provisioning raced with a concurrent sign-in for '{0}': {1}",
                        ForLog(identity.Username),
                        ForLog(ex.Message));
                    return Error(null, null);
                }
            }

            // Keyed on Emby's own spelling of the name, which is what Emby will
            // hand the authentication provider when the page authenticates.
            var secret = SsoRuntime.HandoffSecrets.Issue(user.Name);
            _logger.Info("SSO: issued a sign-in handoff for {0}", user.Name);

            return Html(CompletionPage.Render(user.Name, secret));
        }

        // ------------------------------------------------------------------
        // Browser binding
        //
        // The state parameter is a server-global key with no tie to a user agent.
        // An attacker can run their own sign-in, hold the resulting code and
        // state, and induce a victim's browser to load the callback inside the
        // pending login's TTL - the victim's web client is then signed in as the
        // attacker, with the attacker's token in the victim's localStorage. So
        // /Sso/Start also hands the browser a fresh high-entropy value in a
        // cookie, stores it with the pending login, and the callback requires it
        // back unchanged. Fails closed: no cookie, or a cookie that does not
        // match, ends the flow.
        // ------------------------------------------------------------------

        private void IssueBrowserBinding(PendingLogin login)
        {
            if (login == null || !HeaderSafety.IsCookieValueSafe(login.BrowserBinding))
            {
                return;
            }

            // Exactly as long as the pending login itself is good for.
            var remaining = login.ExpiresAt - DateTimeOffset.UtcNow;
            var seconds = remaining.TotalSeconds < 1 ? 1 : (long)Math.Ceiling(remaining.TotalSeconds);

            SetCookie(login.BrowserBinding, seconds);
        }

        private void ClearBrowserBinding()
        {
            SetCookie(string.Empty, 0);
        }

        /// <summary>
        /// Returns null when the browser presented the value this login was bound
        /// to, or a log detail naming which way it failed - a stripped cookie and
        /// a forged one need different things looked at.
        /// </summary>
        private string CheckBrowserBinding(PendingLogin login)
        {
            if (login == null || string.IsNullOrEmpty(login.BrowserBinding))
            {
                // Only reachable if a PendingLogin was built outside the store.
                return "the pending login carried no browser binding";
            }

            var presented = CookieBinding.ExtractCookieValues(CookieHeaderValues(), BindingCookieName);

            if (presented.Count == 0)
            {
                return "no browser-binding cookie was presented: the callback reached a different browser "
                    + "than the one that started, or something between the browser and Emby drops cookies";
            }

            return CookieBinding.BindingMatches(login.BrowserBinding, presented)
                ? null
                : "the browser-binding cookie did not match the pending login";
        }

        private void SetCookie(string value, long maxAgeSeconds)
        {
            var response = Request?.Response;

            if (response == null)
            {
                // IRequiresRequest injection has never been seen to fail, but if
                // it ever does, a sign-in that silently proceeds without a
                // binding cookie is worse than one that fails loudly - log it
                // rather than the previous silent return.
                _logger.Error("SSO: the request was not injected into the service; cannot set the browser-binding cookie");
                return;
            }

            var cookie = new System.Text.StringBuilder();
            cookie.Append(BindingCookieName).Append('=').Append(value);
            cookie.Append("; Path=").Append(CookiePath());
            cookie.Append("; Max-Age=").Append(maxAgeSeconds.ToString(CultureInfo.InvariantCulture));
            cookie.Append("; HttpOnly; SameSite=Lax");

            // Lax, not Strict: the callback is a top-level cross-site navigation
            // from the identity provider, and Strict would withhold the cookie
            // there and break every sign-in. Lax still withholds it from
            // cross-site subresources, forms and frames.
            if (IsHttps(SsoRuntime.Configuration?.EmbyPublicBaseUrl))
            {
                cookie.Append("; Secure");
            }

            response.AddHeader("Set-Cookie", cookie.ToString());
        }

        /// <summary>
        /// Every value of every <c>Cookie</c> header on the current request. The
        /// parsing that turns these into candidate binding-cookie values is pure
        /// string handling and lives in <see cref="CookieBinding"/> instead, so
        /// it can be tested without an <see cref="IRequest"/> to fake.
        /// </summary>
        private IEnumerable<string> CookieHeaderValues()
        {
            var headers = Request?.Headers;

            if (headers == null)
            {
                yield break;
            }

            foreach (var header in headers)
            {
                if (header != null
                    && string.Equals(header.Name, "Cookie", StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrEmpty(header.Value))
                {
                    yield return header.Value;
                }
            }
        }

        /// <summary>
        /// The cookie path in the BROWSER's terms, which is the redirect URI's
        /// directory - not Emby's own PathInfo, which a reverse proxy may have
        /// stripped a prefix from. Falls back to "/" rather than guessing.
        /// </summary>
        private static string CookiePath()
        {
            var redirectUri = SsoRuntime.RedirectUri();

            if (!string.IsNullOrEmpty(redirectUri) && Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri))
            {
                var path = uri.AbsolutePath;
                var lastSlash = path.LastIndexOf('/');

                if (lastSlash > 0 && HeaderSafety.IsPathSafe(path))
                {
                    return path.Substring(0, lastSlash);
                }
            }

            return "/";
        }

        /// <summary>
        /// Flattens an untrusted string for a single log line and caps its
        /// length. Delegates to the Protocol layer's copy of this policy so the
        /// Api and Protocol layers cannot drift apart on what "safe to log"
        /// means - see <see cref="OidcClient"/>'s use of the same policy for a
        /// provider's OAuth error code.
        /// </summary>
        private static string ForLog(string value)
        {
            return LogSafeText.Flatten(value);
        }

        private static bool IsHttps(string url)
        {
            return url != null && url.Trim().StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// The configured public base URL, trimmed, or an empty string when it is
        /// missing or is not an http(s) URL - so a bad setting cannot become the
        /// href of a link on the error page.
        /// </summary>
        private static string SafeBaseUrl()
        {
            return HeaderSafety.SanitizeBaseUrl(SsoRuntime.Configuration?.EmbyPublicBaseUrl);
        }

        private object Error(string userSafeReason, string logDetail, Exception exception = null)
        {
            if (!string.IsNullOrEmpty(logDetail))
            {
                // logDetail is only ever a literal from this file; anything
                // variable travels as an argument, so a brace in a provider
                // string can never be read as a format placeholder.
                if (exception == null)
                {
                    _logger.Error("SSO: {0}", logDetail);
                }
                else
                {
                    _logger.ErrorException("SSO: {0}", exception, logDetail);
                }
            }

            return Html(ErrorPage.Render(userSafeReason, SafeBaseUrl()));
        }

        private object Html(string body)
        {
            var headers = new Dictionary<string, string>
            {
                ["Cache-Control"] = "no-store, no-cache, must-revalidate",
                ["Pragma"] = "no-cache",
            };

            var request = Request;

            if (request == null)
            {
                // IRequiresRequest injection has never been seen to fail, but this
                // is the last step of the handler that exists so nothing escapes
                // into Emby's error handling - it must not be the thing that
                // throws. There is a request-less overload; use it.
                _logger.Error("SSO: the request was not injected into the service; responding without it");
                return _resultFactory.GetResult(body.AsSpan(), "text/html", headers);
            }

            // The content type argument alone is not enough on this server: without
            // this line the response goes out as application/json.
            request.ResponseContentType = "text/html";

            return _resultFactory.GetResult(request, body.AsSpan(), "text/html", headers);
        }
    }
}

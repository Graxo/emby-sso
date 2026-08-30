using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
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

        // Property injection of IHttpResultFactory via IHasResultFactory leaves it
        // null on this server; the constructor is the only way that works.
        public SsoService(ILogManager logManager, IUserManager userManager, IHttpResultFactory resultFactory)
        {
            _logger = logManager.GetLogger("AuthentikSso");
            _userManager = userManager;
            _resultFactory = resultFactory;
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

            try
            {
                var client = SsoRuntime.GetClient();

                if (client == null)
                {
                    return Error(SsoErrors.NotConfigured, "sign-in started while the plugin was not configured");
                }

                var login = SsoRuntime.PendingLogins.Create();
                var url = await client.BuildAuthorizationUrlAsync(login, CancellationToken.None).ConfigureAwait(false);

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
            if (!string.IsNullOrEmpty(request.Error))
            {
                // Provider-supplied. It goes to the log and nowhere else - as an
                // argument, never as part of the format string, and flattened so
                // it cannot forge extra log lines.
                _logger.Error("SSO: the provider returned an error parameter: {0}", ForLog(request.Error));
                return Error(SsoErrors.ProviderRejected, null);
            }

            // Consume before anything else can fail: a state is single-use even
            // when the rest of the exchange goes wrong.
            var login = SsoRuntime.PendingLogins.Consume(request.State);

            if (login == null)
            {
                return Error(SsoErrors.SessionExpired, "callback carried an unknown, expired or replayed state");
            }

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

            // The plugin never creates an Emby account. An identity the provider
            // vouches for that has no Emby user ends the flow here - before any
            // handoff secret exists.
            var user = _userManager.GetUserByName(identity.Username);

            if (user == null || !UsernameMatcher.Matches(identity.Username, user.Name))
            {
                _logger.Info("SSO: rejected sign-in, no Emby user named '{0}'", ForLog(identity.Username));
                return Error(SsoErrors.UnknownUser, null);
            }

            // Keyed on Emby's own spelling of the name, which is what Emby will
            // hand the authentication provider when the page authenticates.
            var secret = SsoRuntime.HandoffSecrets.Issue(user.Name);
            _logger.Info("SSO: issued a sign-in handoff for {0}", user.Name);

            return Html(CompletionPage.Render(user.Name, secret));
        }

        /// <summary>
        /// Flattens an untrusted string for a single log line and caps its length.
        /// </summary>
        private static string ForLog(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            var builder = new System.Text.StringBuilder(Math.Min(value.Length, 200));

            foreach (var character in value)
            {
                if (builder.Length >= 200)
                {
                    break;
                }

                builder.Append(char.IsControl(character) ? ' ' : character);
            }

            return builder.ToString();
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
            var url = SsoRuntime.Configuration?.EmbyPublicBaseUrl;

            if (string.IsNullOrWhiteSpace(url))
            {
                return string.Empty;
            }

            url = url.Trim().TrimEnd('/');

            var acceptable = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                || url.StartsWith("http://", StringComparison.OrdinalIgnoreCase);

            return acceptable ? url : string.Empty;
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
            // The content type argument alone is not enough on this server: without
            // this line the response goes out as application/json.
            Request.ResponseContentType = "text/html";

            var headers = new Dictionary<string, string>
            {
                ["Cache-Control"] = "no-store, no-cache, must-revalidate",
                ["Pragma"] = "no-cache",
            };

            return _resultFactory.GetResult(Request, body.AsSpan(), "text/html", headers);
        }
    }
}

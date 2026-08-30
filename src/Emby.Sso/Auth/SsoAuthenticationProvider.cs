using System;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Model.Logging;

namespace Emby.Sso.Auth
{
    /// <summary>
    /// The single point Emby calls for both sign-in paths. A password is either
    /// a live browser handoff secret or a real password for the identity
    /// provider to check; SsoCredentialValidator decides which.
    ///
    /// Emby only ever invokes the three-argument (<see cref="IRequiresResolvedUser"/>)
    /// overload in practice, but both must reject rather than accept: this is the
    /// only thing standing between an unauthenticated caller and account creation.
    /// When Emby cannot resolve a username to an existing user it still calls this
    /// provider with resolvedUser == null, and if any enabled provider returns a
    /// success result for that call, Emby auto-creates the user. Returning a
    /// result here for a null resolvedUser (or for a validator Rejected outcome)
    /// would defeat the plugin's "never auto-create" guarantee, so both cases
    /// must always throw.
    /// </summary>
    public class SsoAuthenticationProvider : IAuthenticationProvider, IRequiresResolvedUser
    {
        private readonly ILogger _logger;

        public SsoAuthenticationProvider(ILogManager logManager)
        {
            _logger = logManager.GetLogger("AuthentikSso");
        }

        public string Name => "Authentik SSO";

        public bool IsEnabled => SsoRuntime.Configuration?.IsConfigured == true;

        public Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        {
            // Emby calls the resolved-user overload for this provider; this
            // overload only exists to satisfy IAuthenticationProvider. Route it
            // through the same resolvedUser == null path rather than duplicating
            // the reject logic.
            return Authenticate(username, password, null);
        }

        public async Task<ProviderAuthenticationResult> Authenticate(string username, string password, User resolvedUser)
        {
            if (resolvedUser == null)
            {
                // Load-bearing: an unresolved username reaches every enabled
                // provider, and returning success here would auto-create an
                // Emby user. Never do anything but throw in this branch.
                _logger.Info("Rejecting sign-in: no matching Emby user");
                throw new Exception(SsoErrors.UnknownUser);
            }

            var result = await SsoRuntime.Validator
                .ValidateAsync(resolvedUser.Name, password, CancellationToken.None)
                .ConfigureAwait(false);

            if (result.Outcome == SsoCredentialOutcome.Rejected)
            {
                _logger.Info("Rejected sign-in for {0}: {1}", resolvedUser.Name, result.Reason);
                throw new Exception(result.Reason);
            }

            _logger.Info("Accepted {0} sign-in for {1}", result.Outcome, resolvedUser.Name);

            return new ProviderAuthenticationResult
            {
                Username = resolvedUser.Name,
                DisplayName = result.DisplayName,
            };
        }

        public Task ChangePassword(User user, string newPassword)
        {
            // Passwords live in the identity provider. Accepting a change here
            // would create a local credential that bypasses it.
            throw new Exception("Passwords for this account are managed by the sign-in provider.");
        }

        public Task<bool> HasPassword(User user)
        {
            return Task.FromResult(true);
        }
    }
}

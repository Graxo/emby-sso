using System;

namespace Emby.Sso.Protocol
{
    public sealed class PendingLogin
    {
        public PendingLogin(string state, string nonce, string codeVerifier, DateTimeOffset expiresAt, string browserBinding)
        {
            State = state;
            Nonce = nonce;
            CodeVerifier = codeVerifier;
            CodeChallenge = SecureRandom.CreateCodeChallenge(codeVerifier);
            ExpiresAt = expiresAt;
            BrowserBinding = browserBinding;
        }

        public string State { get; }

        public string Nonce { get; }

        public string CodeVerifier { get; }

        public string CodeChallenge { get; }

        public DateTimeOffset ExpiresAt { get; }

        /// <summary>
        /// Binds this login to the browser that started it. The state parameter
        /// alone is a server-global key: anyone holding a valid state and code can
        /// drive the callback in any browser, which is a login CSRF - the victim
        /// ends up signed in as the attacker. The caller hands this value to the
        /// browser out of band (a cookie) and must require it back, unchanged, at
        /// the callback.
        ///
        /// Deliberately opaque here: this layer knows nothing about cookies or
        /// HTTP, and never compares the value itself.
        /// </summary>
        public string BrowserBinding { get; }
    }
}

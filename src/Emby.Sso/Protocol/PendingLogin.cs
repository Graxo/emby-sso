using System;

namespace Emby.Sso.Protocol
{
    internal sealed class PendingLogin
    {
        public PendingLogin(
            string state,
            string nonce,
            string codeVerifier,
            DateTimeOffset expiresAt,
            string browserBinding,
            bool pinRequested = false)
        {
            State = state;
            Nonce = nonce;
            CodeVerifier = codeVerifier;
            CodeChallenge = SecureRandom.CreateCodeChallenge(codeVerifier);
            ExpiresAt = expiresAt;
            BrowserBinding = browserBinding;
            PinRequested = pinRequested;
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

        /// <summary>
        /// Whether this browser sign-in was started at the PIN endpoint rather
        /// than the ordinary one, and should therefore end by showing a
        /// one-time PIN instead of signing this browser in.
        ///
        /// It is recorded HERE, on the pending login, and not read back off the
        /// callback request. The callback's query string is under the control
        /// of whoever sends the browser there; the pending login is server-side
        /// state created at /Sso/Start, single-use, and already bound to the
        /// browser that started the flow. So the intent cannot be changed
        /// half-way: a callback cannot be made to mint a PIN for a flow that
        /// did not ask for one, nor to mint a browser session for a flow that
        /// did.
        ///
        /// Defaults to false, which is the ordinary sign-in this plugin has
        /// always done - a flag that has to be set deliberately to get the new
        /// behaviour, never the other way round.
        /// </summary>
        public bool PinRequested { get; }
    }
}

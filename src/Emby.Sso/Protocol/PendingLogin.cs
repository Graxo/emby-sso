using System;

namespace Emby.Sso.Protocol
{
    public sealed class PendingLogin
    {
        public PendingLogin(string state, string nonce, string codeVerifier, DateTimeOffset expiresAt)
        {
            State = state;
            Nonce = nonce;
            CodeVerifier = codeVerifier;
            CodeChallenge = SecureRandom.CreateCodeChallenge(codeVerifier);
            ExpiresAt = expiresAt;
        }

        public string State { get; }

        public string Nonce { get; }

        public string CodeVerifier { get; }

        public string CodeChallenge { get; }

        public DateTimeOffset ExpiresAt { get; }
    }
}

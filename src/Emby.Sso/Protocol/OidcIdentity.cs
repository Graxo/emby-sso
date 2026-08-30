namespace Emby.Sso.Protocol
{
    public sealed class OidcIdentity
    {
        public OidcIdentity(string subject, string username, string displayName)
        {
            Subject = subject;
            Username = username;
            DisplayName = displayName;
        }

        public string Subject { get; }

        public string Username { get; }

        public string DisplayName { get; }
    }
}

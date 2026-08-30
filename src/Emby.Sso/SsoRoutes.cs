namespace Emby.Sso
{
    /// <summary>
    /// The two browser-facing route paths, named once instead of typed out at
    /// every site that needs them. <c>[Route]</c> attributes require a
    /// compile-time constant, which these are, so <c>Api/SsoRequests.cs</c> can
    /// reference them directly; so can <c>SsoRuntime</c>'s redirect-URI builder
    /// and <c>Api/ErrorPage.cs</c>'s retry link.
    ///
    /// Two more sites embed the same path inside a JavaScript string literal and
    /// cannot reference this constant: <c>Configuration/configPage.js</c> is a
    /// static embedded resource served verbatim, with no per-request rendering
    /// to inject a C# value into, and would need to become a generated page (like
    /// the completion page) to read this. <c>Api/CompletionPage.cs</c>'s inline
    /// script IS generated per request, so its retry link is built from these
    /// constants through compile-time string concatenation instead of
    /// duplicating the literal; its <c>CALLBACK_RE</c> pattern, however, matches
    /// both the bare and <c>/emby</c>-prefixed forms with an optional trailing
    /// slash, which is strictly more permissive than either constant alone, so
    /// it is left as its own regular expression rather than built from these.
    /// </summary>
    internal static class SsoRoutes
    {
        public const string StartPath = "/Sso/Start";

        public const string CallbackPath = "/Sso/Callback";
    }
}

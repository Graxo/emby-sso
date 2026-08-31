using System.Globalization;
using Emby.Sso.Protocol;

namespace Emby.Sso.Api
{
    /// <summary>
    /// The page <c>/emby/Sso/Pin</c>'s callback returns: the one-time PIN, and
    /// what to do with it on a television.
    ///
    /// It carries NO SCRIPT, deliberately. The completion page has to run one,
    /// because it exchanges a handoff secret for an Emby session inside the
    /// browser; this page only has to show eight characters to a human being.
    /// So it is served with <see cref="SecurityHeaders.ForStaticPage"/>, whose
    /// policy says <c>script-src 'none'</c> outright - a page that displays a
    /// live credential and needs no script should be one on which no script can
    /// run, and adding one later must be a visible break rather than a silent
    /// loosening. Like every other page this plugin serves it is unframable
    /// (<c>X-Frame-Options: DENY</c> and <c>frame-ancestors 'none'</c>) and
    /// uncacheable (<c>Cache-Control: no-store</c>), which matter more here
    /// than usual: a cached copy of this page is a cached copy of a live
    /// credential.
    ///
    /// The PIN and the username are written through <see cref="PageText.Html"/>
    /// like every other dynamic value in this namespace. The PIN cannot contain
    /// anything that needs escaping - <see cref="SignInPin.Alphabet"/> is
    /// thirty alphanumerics - and it is escaped anyway, because the rule in
    /// this namespace is that nothing dynamic reaches a page unescaped and a
    /// rule with one exception in it is not a rule.
    ///
    /// The PIN is never put in a URL, a redirect or a fragment, for the same
    /// reason the handoff secret is not: query strings reach access logs, proxy
    /// logs and Referer headers.
    /// </summary>
    internal static class PinPage
    {
        /// <param name="nonce">
        /// The per-response content-security-policy nonce, naming this page's
        /// single inline style block so the policy can refuse every other one.
        /// </param>
        public static string Render(string username, string pin, int minutes, string nonce)
        {
            var safeNonce = PageText.Html(nonce);

            return @"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta name='referrer' content='no-referrer'>
<title>Your sign-in PIN</title><style nonce='" + safeNonce + "'>" + PageText.BaseStyle + @"
.pin{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:2.5rem;
letter-spacing:.15em;font-weight:600;color:#fff;margin:1.5rem 0;user-select:all;word-break:break-all}
.who{color:#fff;font-weight:600}
ol{text-align:left;color:#bbb;line-height:1.6;max-width:24rem;margin:0 auto;padding-left:1.25rem}
.warn{color:#e6b800}
</style></head><body><main>
<h1>Your sign-in PIN</h1>
<p class='pin'>" + PageText.Html(SignInPin.Format(pin)) + @"</p>
<ol>
<li>Open the Emby app on your TV and choose to sign in manually.</li>
<li>Enter your username: <span class='who'>" + PageText.Html(username) + @"</span></li>
<li>Enter the PIN above where it asks for a password.</li>
</ol>
<p class='warn'>It expires in " + minutes.ToString(CultureInfo.InvariantCulture) + @" minutes, works once, and
is destroyed after three wrong entries &mdash; if you mistype it that often, come back here for a new one.</p>
<p>Do not read it out to anyone who is not standing at that television.</p>
</main></body></html>
";
        }
    }
}

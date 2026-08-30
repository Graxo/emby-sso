using Emby.Sso;

namespace Emby.Sso.Api
{
    /// <summary>
    /// The page /emby/Sso/Callback returns after a successful sign-in, and the
    /// one place the Emby web client's credential format is written down.
    ///
    /// Emby's login page cannot be scripted (no branding hook survives), but this
    /// page is served from the same origin as /web/, so its own inline script can
    /// do what an injected one would have: exchange the one-time handoff secret
    /// for a real Emby session through the ordinary
    /// POST /emby/Users/AuthenticateByName path - Emby's authentication provider
    /// is what accepts the secret, so Emby mints the session itself - and then
    /// leave the resulting token where the web client looks for it.
    ///
    /// The handoff secret is embedded here as a JavaScript string literal. It is
    /// never placed in a query string, a fragment, or a redirect, so it cannot
    /// reach an access log, a proxy log, or a Referer header.
    ///
    /// The credential format is read from the shipped 4.9.5.0 client source and
    /// has NOT been verified in a browser. Two details are load-bearing:
    ///   * the token belongs in Servers[].Users[], never Servers[].AccessToken,
    ///     which the client deletes and nothing reads; and
    ///   * ManualAddress must equal the address app.js computes for itself, or
    ///     a second, credential-less entry sorts ahead of ours and the user gets
    ///     the login screen.
    /// </summary>
    internal static class CompletionPage
    {
        public static string Render(string username, string handoffSecret)
        {
            return Head
                + "var USERNAME = " + PageText.JsString(username) + ";\n"
                + "var HANDOFF = " + PageText.JsString(handoffSecret) + ";\n"
                + Body;
        }

        private const string Head = @"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta name='referrer' content='no-referrer'>
<title>Signing in</title><style>" + PageText.BaseStyle + @"code{color:#888;font-size:.85em}
</style></head><body><main>
<div id='working' style='display:none'><h1>Signing you in</h1><p>One moment.</p></div>
<div id='failed' style='display:none'><h1>Sign-in failed</h1>
<p>Emby could not complete this sign-in. <code id='code'></code></p>
<p><a id='retry' href='#'>Try again</a></p></div>
<noscript><h1>Sign-in failed</h1><p>JavaScript is required to finish signing in.</p></noscript>
</main><script>
(function () {
'use strict';
";

        private const string Body = @"
var STORE_KEY = 'servercredentials3';
var DEVICE_KEY = 'emby-sso-device-id';

// This page is served at <base>/emby/Sso/Callback (the bare /Sso/Callback form
// also routes, so strip either). What remains has to equal what app.js computes
// for itself, which is location.href truncated at the last '/web' - so for a
// server published under a reverse-proxy sub-path, both end up as
// 'https://host/subpath' rather than the bare origin.
var CALLBACK_RE = /\/(?:emby\/)?sso\/callback\/?$/i;
var here = location.href.split('?')[0].split('#')[0];
var serverUrl = CALLBACK_RE.test(here)
  ? here.replace(CALLBACK_RE, '')
  : location.protocol + '//' + location.hostname + (location.port ? ':' + location.port : '');

// app.js lowercases its address and the comparison is case-insensitive, so the
// stored form is lowercased to match byte for byte. Our own requests use the
// address exactly as served.
var manualAddress = serverUrl.toLowerCase();

function show(id) { document.getElementById(id).style.display = ''; }
function hide(id) { document.getElementById(id).style.display = 'none'; }

// Both blocks start hidden so that with scripting off the <noscript> message is
// the only thing on the page, rather than a second heading under a claim that a
// sign-in is in progress.
show('working');

function fail(code) {
  var clean = String(code || 'unknown').replace(/[^A-Za-z0-9 _.:-]/g, '').slice(0, 60);
  hide('working');
  document.getElementById('code').textContent = clean;
  document.getElementById('retry').href = serverUrl + '/emby" + SsoRoutes.StartPath + @"';
  show('failed');
}

function deviceId() {
  var id = null;
  try { id = localStorage.getItem(DEVICE_KEY); } catch (e) { id = null; }
  if (!id) {
    id = (window.crypto && crypto.randomUUID)
      ? crypto.randomUUID()
      : Date.now().toString(16) + '-' + Math.random().toString(16).slice(2);
    try { localStorage.setItem(DEVICE_KEY, id); } catch (e) { /* private mode: a fresh id each time */ }
  }
  return id;
}

// Emby answers 400 'Value cannot be null. (Parameter appName)' without the four
// client-identity headers, so they are not optional.
function authenticate() {
  return fetch(serverUrl + '/emby/Users/AuthenticateByName', {
    method: 'POST',
    cache: 'no-store',
    credentials: 'omit',
    headers: {
      'Content-Type': 'application/json',
      'X-Emby-Client': 'Emby Web',
      'X-Emby-Device-Name': 'Browser',
      'X-Emby-Device-Id': deviceId(),
      'X-Emby-Client-Version': '4.9.5.0'
    },
    body: JSON.stringify({ Username: USERNAME, Pw: HANDOFF })
  }).then(function (response) {
    if (!response.ok) { throw new Error('auth-' + response.status); }
    return response.json();
  });
}

// Exactly the call the web client makes on startup against a stored token
// (only over a header here rather than the client's own ?api_key= query
// string, so the token never lands in Emby's own per-request access log). If
// it does not answer 2xx the client discards the token and shows the login
// screen, so checking here turns a silent bounce into a stated failure.
function verify(auth) {
  return fetch(serverUrl + '/emby/System/Info', {
    cache: 'no-store',
    credentials: 'omit',
    headers: { 'X-Emby-Token': auth.AccessToken }
  }).then(function (response) {
    if (!response.ok) { throw new Error('verify-' + response.status); }
    return response.json();
  }).then(function (info) { return { auth: auth, info: info }; });
}

function store(result) {
  var auth = result.auth;
  if (!auth || !auth.AccessToken || !auth.User || !auth.User.Id || !auth.ServerId) {
    throw new Error('auth-response-incomplete');
  }

  // Merge: other servers, and other users of this server, must survive.
  var creds;
  try { creds = JSON.parse(localStorage.getItem(STORE_KEY) || '{}'); } catch (e) { creds = null; }
  if (!creds || typeof creds !== 'object') { creds = {}; }
  if (!Array.isArray(creds.Servers)) { creds.Servers = []; }

  var entry = null;
  for (var i = 0; i < creds.Servers.length; i++) {
    var candidate = creds.Servers[i];
    if (!candidate || typeof candidate !== 'object') { continue; }
    if (candidate.Id === auth.ServerId ||
        String(candidate.ManualAddress || '').toLowerCase() === manualAddress) {
      entry = candidate;
      break;
    }
  }
  if (!entry) { entry = {}; creds.Servers.push(entry); }

  entry.Id = auth.ServerId;
  entry.Name = (result.info && result.info.ServerName) || entry.Name || 'Emby Server';
  entry.ManualAddress = manualAddress;
  entry.ManualAddressOnly = true;   // the server's advertised addresses are not reachable from here
  entry.IsLocalServer = true;
  entry.LastConnectionMode = 2;     // ConnectionMode_Manual
  entry.DateLastAccessed = Date.now();
  entry.UserId = auth.User.Id;

  // Nothing reads a server-level token and the client deletes it.
  delete entry.AccessToken;

  if (!Array.isArray(entry.Users)) { entry.Users = []; }
  var found = false;
  for (var j = 0; j < entry.Users.length; j++) {
    if (entry.Users[j] && entry.Users[j].UserId === auth.User.Id) {
      entry.Users[j].AccessToken = auth.AccessToken;
      found = true;
      break;
    }
  }
  if (!found) { entry.Users.push({ UserId: auth.User.Id, AccessToken: auth.AccessToken }); }

  localStorage.setItem(STORE_KEY, JSON.stringify(creds));
}

// authenticate() is called through the chain, not before it: a synchronous
// throw - no fetch, no Promise, a blocked API - has to reach the same handler,
// or the page sits on 'Signing you in' for ever.
try {
  Promise.resolve()
    .then(authenticate)
    .then(verify)
    .then(function (result) {
      store(result);
      location.replace(serverUrl + '/web/index.html');
    })
    .catch(function (error) {
      // Codes only. A response body could carry the access token.
      fail(error && error.message);
    });
} catch (error) {
  fail('unsupported-browser');
}
})();
</script></body></html>
";
    }
}

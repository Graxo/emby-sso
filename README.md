# Emby OIDC SSO Plugin

Lets existing Emby users sign in with an external OpenID Connect provider —
in particular [Authentik](https://goauthentik.io/). Emby has no native OIDC
support; this plugin implements the browser authorization-code flow (with
PKCE) and, optionally, the OIDC direct-grant flow for native apps.

**This plugin never creates Emby users.** The Emby account must already
exist, and an administrator must explicitly point that account's
authentication provider at this plugin. There is no auto-provisioning path.
Read the whole of this document — especially the next section — before you
install anything.

---

## Read this before you install

Emby's authentication pipeline behaves in ways that are easy to get wrong
and hard to undo. This was confirmed against a live Emby 4.9.5.0 server, not
assumed from documentation:

- **Emby stamps the provider that wins onto the user, permanently.** The
  first time a user signs in successfully, Emby writes that provider's ID
  into the user's `Policy.AuthenticationProviderId` on disk. From then on,
  **only that provider is consulted** for that user. A user who signs in
  through this plugin once can no longer use their Emby password — Emby
  will not even try the default provider for them again. The only way back
  is for an administrator to reset the field via the Emby API.
- **A user with no provider assigned is offered to every enabled provider.**
  If an account's `AuthenticationProviderId` has never been set, Emby tries
  every provider in turn (its own built-in password check first, then this
  plugin) and stamps whichever one succeeds. In practice this means: as
  soon as this plugin is installed and enabled, **every unstamped Emby
  account becomes reachable through Authentik**, and the very first
  successful Authentik sign-in for that account permanently strips its
  local Emby password.

**Consequences — do this before you install the plugin:**

1. For every Emby account you do **not** want migrated to SSO, explicitly
   set its authentication provider to the default one first (**Dashboard →
   Users → select the user → Login provider → Default**, or via the API —
   see below for why the dashboard selector doesn't work for
   administrators). Setting it explicitly, even to the value it already
   has, fixes it in place: Emby will no longer try this plugin for that
   account.
2. **Keep at least one administrator account permanently on the default
   provider as a break-glass account.** If Authentik is ever unreachable,
   this is the only account that can still get into Emby.
3. The dashboard's "Login provider" dropdown is only shown for
   **non-administrator** accounts, and only once more than one provider is
   registered. For an administrator account, saving the profile tab in the
   dashboard writes back the dropdown's value even though it's hidden,
   which silently defaults to the built-in provider unless you set it
   deliberately. To assign or fix an administrator's provider, use the API
   directly:

   ```
   POST /emby/Users/{userId}/Policy
   ```

   with the full `UserPolicy` JSON body and
   `"AuthenticationProviderId"` set to either
   `Emby.Server.Implementations.Library.DefaultAuthenticationProvider`
   (built-in password) or `Emby.Sso.Auth.SsoAuthenticationProvider` (this
   plugin).

None of this is a bug in the plugin — it is how Emby's own
`IAuthenticationProvider` pipeline works for every third-party provider,
including this one.

---

## How it works

- **Browser sign-in.** The user opens a bookmarkable URL
  (`https://<emby>/emby/Sso/Start`). The plugin redirects to Authentik,
  Authentik authenticates the user under its own flows (including MFA and
  passkeys), and redirects back to `https://<emby>/emby/Sso/Callback`. The
  plugin validates the response, checks that the username matches an
  existing Emby user, and completes the sign-in — the browser lands
  directly on the Emby home screen with no further clicks.
- **Native apps (phone, TV).** Off by default. When enabled, a native
  client's normal username/password screen is checked against Authentik
  using an OIDC direct grant instead of Emby's local password.
- **No account is ever created.** If the username from Authentik does not
  match an existing Emby user, the sign-in is rejected with a generic
  error and nothing is written to the log except the fact that it happened.

There is no button on Emby's login page, and there cannot be one — see
the next section.

**A browser that signs in through SSO gets its own device row.** The
completion page authenticates as an ordinary API client identified as
`Emby Web` with its own generated device ID (stored in that browser's
`localStorage`, separate from the web client's own device ID for the same
browser), so Dashboard → Devices ends up showing **two** "Emby Web" rows for
one browser: the one the web client itself registers on ordinary interactive
login, and this plugin's. They look like duplicates but are not — each
backs a live session. **Do not delete either one as a cleanup step**: deleting
the row this plugin's completion page created revokes the access token it
minted, which signs that browser out of its current SSO session immediately.

---

## Starting a sign-in: there is no button on the login page

Emby's web login page renders the "login disclaimer" setting as plain text
(`element.textContent`, not HTML) and loads custom CSS as an external
stylesheet (`<link rel="stylesheet">`), so neither field can execute a
script or render a clickable button. This was confirmed by reading the
shipped Emby 4.9.5.0 client and testing that the server passes both fields
through completely unsanitized to the client — the client itself is what
strips any markup.

So: **users start a sign-in from a bookmarkable URL**, not a button:

```
https://<your-emby-server>/emby/Sso/Start
```

The plugin's configuration page (Dashboard → Plugins → Authentik SSO)
displays this exact URL for your server under "Sign-in URL for users to
bookmark". A convenient way to surface it is to paste that URL as **plain
text** into Emby's own login disclaimer field (Dashboard → Settings →
General → "Login disclaimer") — it will render as visible instructions on
the login screen, just not as a clickable link.

The configuration page has a checkbox labelled "Reserve a sign-in button on
the login page" (`EnableButtonInjection`). It is reserved for a future
release and currently does nothing — leave it as you find it.

---

## Setting up Authentik

1. Create an **OAuth2/OpenID provider** in Authentik.
2. Set its **redirect URI** to exactly the value shown on the plugin's
   configuration page under "Redirect URI to configure in Authentik"
   (`https://<your-emby-server>/emby/Sso/Callback`). It must match exactly
   — scheme, host, and path.
3. Note the **client ID**, and the **client secret** if you configure a
   confidential client (leave the plugin's client secret field empty for a
   public client).
4. The plugin authenticates to the token endpoint using **HTTP Basic**
   (client ID and secret, each percent-encoded per RFC 6749 §2.3.1, then
   base64-encoded in the `Authorization` header) whenever a client secret
   is configured. Make sure the Authentik provider's client authentication
   method is compatible with that.
5. If you plan to enable **native app sign-in** (see below), also create a
   **direct-grant (Resource Owner Password) authentication flow** in
   Authentik and bind it to this provider. Without it, native sign-in will
   fail even with the checkbox enabled.
6. Bind an application to the provider, using scopes that include at least
   `openid`. The plugin defaults to `openid profile email`.

---

## Installing the plugin

The shipped artifact is a **single file**:

```
src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll
```

Do not install any other DLL from the build output. This file is
deliberately produced by merging (ILRepack) the plugin together with its
dependencies — `Microsoft.IdentityModel.*`, `System.IdentityModel.Tokens.Jwt`
and `Newtonsoft.Json` — and internalizing their types inside `Emby.Sso.dll`
itself. This is not a packaging convenience; it is required. Emby Server
already ships its own copy of `Microsoft.IdentityModel` (version 7.6.2 as
of Emby 4.9.5.0), a different version than the one this plugin builds
against (6.35.0). Dropping unmerged dependency DLLs next to the plugin
would put two incompatible assembly identities in the same load context
and fail at runtime. The merged build was verified on a live Emby 4.9.5.0
server: the merged types resolve out of `Emby.Sso.dll` itself, never
colliding with the server's own copies.

To install:

1. Copy `Emby.Sso.dll` into Emby's `plugins` directory (for example
   `/config/plugins` in the linuxserver.io Docker image).
2. Restart Emby Server.
3. Confirm it loaded: Dashboard → Plugins should list **Authentik SSO**.

---

## Configuring the plugin

Open Dashboard → Plugins → **Authentik SSO** and fill in:

| Field | Notes |
|---|---|
| Issuer URL | e.g. `https://auth.example.com/application/o/emby/`. Every other OIDC endpoint is read from its discovery document. |
| Client ID | from Authentik. |
| Client secret | leave empty for a public client. |
| Scopes | defaults to `openid profile email`. |
| Emby public base URL | the address users reach this server on, e.g. `https://emby.example.com`. Used to build the redirect URI and the post-login redirect. Required — Emby cannot infer this reliably behind a reverse proxy. |
| Username claim | defaults to `preferred_username`, matched case-insensitively against the Emby username. |
| Allow native apps to sign in with a password | off by default — see "Native app sign-in" below. |
| Reserve a sign-in button on the login page | reserved for future use; currently does nothing. |
| Allow plain HTTP | testing only. The browser flow refuses to start over plain HTTP unless this is set. |

After saving, the page displays the exact **redirect URI** to put in
Authentik and the **sign-in URL** to give your users — both computed from
the public base URL you just entered.

---

## Assign each user's authentication provider — required, and easy to miss

**Nothing works until this is done, per user.** Creating a matching
Authentik account and installing the plugin is not enough by itself:

- Dashboard → Users → select the user → **Login provider** → **Authentik
  SSO**. This selector only appears for non-administrator accounts, and
  only once more than one provider is registered (i.e., once this plugin
  is installed).
- For **administrator** accounts, the selector is hidden in the dashboard
  and must be set through the API — see "Read this before you install"
  above for the exact call and the reason the dashboard can't be trusted
  for admins.
- If you skip this step, the account is still reachable through this
  plugin as soon as it's installed (see "Read this before you install"),
  just not deliberately — assign it explicitly either way.

---

## Native app sign-in (direct grant)

**Off by default.** When enabled, native clients (phone apps, TV apps —
anything that only ever sends a raw username and password to Emby, never
a browser redirect) are authenticated by sending that password directly to
Authentik's token endpoint as an OIDC direct grant (Resource Owner
Password Credentials).

Trade-offs to weigh before turning this on:

- **It cannot perform multi-factor authentication.** Any MFA policy
  Authentik enforces on its interactive login flow does not apply to a
  direct grant — the credentials are checked once, synchronously, with no
  redirect and no second factor.
- It requires **a direct-grant authentication flow bound to the provider**
  in Authentik (see "Setting up Authentik" above); without that, enabling
  the checkbox has no effect and sign-in will fail.
- The OAuth 2.1 draft deprecates this grant type generally, for the same
  reason: it requires the client to handle the user's raw password.

Enable it only if you need TV/phone app access badly enough to accept the
loss of MFA on that path. Browser sign-in never uses this grant and is
unaffected either way.

---

## Troubleshooting

The plugin logs under the category **`AuthentikSso`**, in Emby's own
server log (Dashboard → Logs, or the log file in Emby's data directory —
`embyserver.txt` on the linuxserver.io image). Diagnostic detail —
exception messages, unreachable-endpoint causes, which validation step
failed — is written there and **only** there, by design. The browser only
ever sees one of a fixed set of short, generic sentences:

| Message shown to the user | What it means | What to check |
|---|---|---|
| "Single sign-on is not configured on this server." | The plugin isn't configured (issuer URL, client ID or base URL missing), or the public base URL isn't HTTPS and plain HTTP hasn't been explicitly allowed. | Dashboard → Plugins → Authentik SSO: all required fields set. If testing over HTTP, enable "Allow plain HTTP". |
| "The sign-in provider could not be reached." | Authentik's discovery document or token endpoint could not be fetched. | Issuer URL is correct and reachable from the Emby server itself (not just your browser); check DNS/TLS/firewall between Emby and Authentik. |
| "The sign-in provider rejected this sign-in." | Authentik returned an OAuth error on the callback, or an empty/malformed credential was submitted. | Check the Authentik provider/application logs for the same request; confirm the redirect URI matches exactly. |
| "The sign-in response could not be verified." | The ID token failed validation — bad signature, wrong issuer, wrong audience, expired, or a nonce mismatch. | Server clocks in sync (Emby and Authentik); client ID matches the token's audience; issuer URL matches the token's `iss` exactly. |
| "This sign-in attempt expired. Please try again." | The `state` value on the callback was unknown, already used, or too old (single-use, short TTL). | Usually a stale bookmark/back-button reuse — just start over from the sign-in URL. If it happens consistently, check for a reverse proxy caching or replaying the callback request. |
| "This account is not set up on this server." | The username claim from Authentik didn't match any existing Emby user (case-insensitively). | Confirm an Emby account with that exact username exists — the plugin never creates one. Check which claim is configured as "Username claim" and what Authentik actually sends in it. |
| "Password sign-in is disabled for this account." | A native app tried to sign in via direct grant, but "Allow native apps to sign in with a password" is off. | Enable it in the plugin configuration if you want native sign-in, understanding the MFA trade-off above. |
| "This sign-in could not be completed in this browser. Please try signing in again." | `/emby/Sso/Start` sets a short-lived binding cookie that must come back unchanged on `/emby/Sso/Callback`. A reverse proxy sitting in front of Emby stripped or rewrote cookies on that path, or rewrote the path so the cookie's `Path` no longer covers `/emby/Sso/Callback`. | Check the log line next to this error: it distinguishes no cookie presented at all from a cookie that was presented but did not match. Confirm the proxy forwards the `Cookie` and `Set-Cookie` headers unmodified on both `/emby/Sso/Start` and `/emby/Sso/Callback`, and that it does not rewrite either path in a way that changes the cookie's directory. |

**Note:** If the plugin's settings page renders oddly right after an update (for example, as an overlay on top of the plugin catalog instead of replacing the view), reload the Emby dashboard in your browser — Emby caches configuration pages, and the old version may still be in the browser's cache.

If a user reports being unable to sign in with their old Emby password
after using SSO once, that is expected — see "Emby stamps the provider...
permanently" above. An administrator must reset that user's
`AuthenticationProviderId` via `POST /emby/Users/{userId}/Policy`.

---

## Building from source

Requires the .NET SDK (matching `netstandard2.0`/`net8.0` tooling).

```
dotnet build -c Release
```

produces the merged, installable plugin at:

```
src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll
```

Run the protocol test suite (68 tests, no Emby server or network required —
they run against a fake identity provider built from a locally generated
RSA key):

```
dotnet test tests/Emby.Sso.Tests
```

---

## What hasn't been verified end-to-end

The plugin's callback page (`/emby/Sso/Callback`) finishes a browser
sign-in by writing an access token directly into the Emby web client's
`localStorage` credential store (key `servercredentials3`), in the exact
shape that store's own code produces, so the browser lands on the Emby
home screen without a second login step. That shape was determined by
reading Emby 4.9.5.0's shipped client JavaScript and verified end-to-end
against a live server with `curl` — the authentication call, the token,
and the token's acceptance by Emby's API were all directly observed. **The
one thing that was not observed is the browser/`localStorage` behavior
itself** — no browser was available in the environment where this was
tested.

**On first sign-in, check that you land on the Emby home screen, not the
login screen.** If you land on the login screen instead, the most likely
causes, in order, are: the plugin's public base URL not matching the
address your browser actually uses (reverse-proxy sub-paths are the usual
culprit), or a future Emby client update changing the credential store's
key or shape. Either way, sign-in through the plugin still completes on
the server side — the account is not locked out — it's only the automatic
hand-off into the already-signed-in home screen that would need a second
look.

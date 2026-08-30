# Emby OIDC SSO plugin — live server verification

**Date:** 2026-08-30
**Target:** Emby Server 4.9.5.0 (`lscr.io/linuxserver/emby:latest`) at `http://10.10.140.5:8090`, docker container `emby`, plugin dir `/config/plugins`.
**Build under test:** `src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll`, built from a clean `dotnet build -c Release` at commit `cd8b10c` (md5 `9670cf2cf2089f1539af879c9dd4d075`).
**Plugin GUID:** `ad89f430-b0d0-4e9a-996d-c088f6961158`.

## Scope

**No Authentik instance is configured for this deployment.** There is no issuer, no client ID, no client secret. Everything below that requires a real identity provider round trip — the browser flow, the native/direct-grant flow, MFA enforcement, replay of a completed callback, replay of a handoff secret, the 30-second handoff expiry, the disabled-account check, and the browser's actual `localStorage` write — was **not exercised** and is explicitly out of scope for this pass. This document covers only the checks that can be driven without a live IdP: build/install, error-page behavior, cookie mechanics reachable from code and (where possible) from the wire, log hygiene, and that ordinary Emby login still works afterward.

All numbering below matches the 11 checks given in the task.

## Results

### 1. Build the shipping artifact — PASS

`export PATH="$HOME/.dotnet:$PATH"; dotnet build -c Release` from the repo root succeeded (0 warnings, 0 errors) and produced `src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll` (1,855,488 bytes, md5 `9670cf2cf2089f1539af879c9dd4d075`), a single merged (ILRepack) assembly as the README describes.

### 2. Install and confirm it appears in the plugin list and `/emby/Auth/Providers` — PASS, with one nuance

The DLL was copied to `/docker-data/compose/dl-cluster/configs/emby/plugins/Emby.Sso.dll` on the host and the container restarted. `GET /emby/Plugins` immediately listed:

```json
{"Name":"Authentik SSO","Version":"0.1.0.0","ConfigurationFileName":"Emby.Sso.xml","Id":"ad89f430-b0d0-4e9a-996d-c088f6961158"}
```

`GET /emby/Auth/Providers`, however, returned only `Default` until the plugin was configured. This is correct, by design: `SsoAuthenticationProvider.IsEnabled` is gated on `PluginConfiguration.IsConfigured` (issuer URL, client ID and base URL all non-empty), and Emby only lists enabled providers. Once a minimal configuration was saved (see check 3), `/emby/Auth/Providers` returned:

```json
[{"Name":"Default","Id":"Emby.Server.Implementations.Library.DefaultAuthenticationProvider"},
 {"Name":"Authentik SSO","Id":"Emby.Sso.Auth.SsoAuthenticationProvider"}]
```

Not a deviation from spec — just noting the plugin is invisible to `/Auth/Providers` until configured, which anyone verifying this should expect.

### 3. Configuration page loads; saving persists; redirect URI / sign-in URL are correct — PASS (fixed; user-confirmed)

Two earlier passes found the config page broken in the browser: the page used the obsolete `data-role="page"` / `<div data-role="content">` markup pattern instead of Emby's current `emby-scroller`/`view` pattern, so it rendered as an overlay on top of the plugin catalog instead of replacing the view. Its `<script>` tag — first inline, then `src="configurationpage?name=AuthentikSsoScript"` — was never executed: Emby strips **every** `<script>` tag from plugin config pages, inline or `src`.

**Root cause (confirmed by diffing against Emby's Nfo Metadata plugin, `/web/configurationpage?name=nfo`):** Emby's mechanism for loading plugin configuration JavaScript has no place for a script tag. JavaScript is loaded via `data-controller="__plugin/<ScriptPageName>"` on the root element, which resolves to a second registered `PluginPageInfo` and is fetched as an AMD module. The root element must be the `emby-scroller`/`view` div or the page is not treated as a view — `data-role="page"` is obsolete.

**The fix (commit `ea74b53`):** `src/Emby.Sso/Configuration/configPage.html` and `configPage.js` were rewritten to the correct pattern:
- HTML root is now `<div is="emby-scroller" class="view flex flex-direction-column scrollFrameY flex-grow" ... data-controller="__plugin/AuthentikSsoScript" data-title="Authentik SSO">` with a `scrollSlider` inner wrapper, and **no `<script>` tag**.
- `configPage.js` is an AMD module (`define(['baseView', 'loading', 'globalize', ...], ...)`) returning a `View` that borrows `BaseView.prototype`, loads configuration in `onResume`, and saves on the form's `submit` handler, using the `loading` module for the spinner.
- The second `PluginPageInfo` registration (`Name = "AuthentikSsoScript"`, `IsMainConfigPage = false`) in `Plugin.cs` was kept — the `data-controller` mechanism requires it. Embedded resource names verified against the merged DLL's `strings` output and match `Plugin.cs` exactly: `Emby.Sso.Configuration.configPage.html`, `Emby.Sso.Configuration.configPage.js`.
- All nine configuration properties, the redirect-URI/sign-in-URL display logic, help text, and error handling (loading indicator always hidden, `Dashboard.processErrorResponse`/`processPluginConfigurationUpdateResult` used) were carried over unchanged — this was a re-platforming, not a redesign.

**Server verification after installing the new build:**
- `GET /web/configurationpage?name=AuthentikSso` returns the `emby-scroller` root div with `data-controller="__plugin/AuthentikSsoScript"` intact and no script tag.
- `GET /web/configurationpage?name=AuthentikSsoScript` returns the AMD module verbatim, matching the source.
- `dotnet build -c Release` succeeded (0 warnings / 0 errors, ILRepack merge OK); `dotnet test tests/Emby.Sso.Tests -v minimal` passed (68/68).

**Browser verification (user-confirmed):** The user opened the plugin's configuration page in a browser and confirmed the page renders correctly, replacing the plugin catalog view. The configuration fields populate on page load, and the form's Save button successfully persists and reloads configuration values. Note: immediately after the fix was installed, the first page load still showed the broken layout; after a dashboard reload it rendered correctly — consistent with Emby caching configuration pages.

- **Redirect URI / sign-in URL:** The JavaScript that displays them now runs correctly on the page, showing `http://10.10.140.5:8090/emby/Sso/Callback` and `http://10.10.140.5:8090/emby/Sso/Start` as expected. Both URLs were independently exercised and behaved correctly in checks 4–7 below, confirming the computed values are correct.

### 4. `GET /emby/Sso/Start` while unconfigured → "not configured" page — PASS

With the plugin configuration cleared (`IssuerUrl`, `ClientId`, `EmbyPublicBaseUrl` all empty), a plain unauthenticated `curl` to `/emby/Sso/Start` returned **HTTP 200**, `Content-Type: text/html`, and a well-formed HTML body titled "Sign-in failed" with the text *"Single sign-on is not configured on this server."* — no stack trace, no 500. Matches spec exactly.

### 5. `GET /emby/Sso/Callback?state=garbage` → expired/invalid page, logged — PASS

Unauthenticated `curl` to `/emby/Sso/Callback?state=garbage` returned HTTP 200 with the "Sign-in failed" page and *"This sign-in attempt expired. Please try again."* The server log recorded, under category `AuthentikSso`:

```
2026-08-30 14:57:17.927 Error AuthentikSso: SSO: callback carried an unknown, expired or replayed state
```

### 6. Configured but unreachable issuer → provider-unreachable page, logged, no hang, no request storm — PASS

Configured `IssuerUrl` to `https://nonexistent.invalid/application/o/emby/` (a reserved, non-resolving TLD) with a valid `ClientId` and the real base URL. `GET /emby/Sso/Start`:

- Returned in **57 ms** (timed) — no hang.
- Body: *"The sign-in provider could not be reached."*
- Logged: `SSO: could not build the authorization URL` (once per request).
- Six back-to-back requests produced exactly six log lines, one per request, no retries or extra fetch attempts per call — no request storm.

### 7. Both endpoints reachable with no authentication — PASS

Every `curl` above to `/emby/Sso/Start` and `/emby/Sso/Callback` was made with no `X-Emby-Token`, no API key, and no session cookie, and both endpoints responded normally (never a 401/403). A sign-in entry point that required a session would be unusable by definition, and that is not the case here.

### 8. `/Sso/Start` sets a browser-binding cookie with correct attributes — NOT VERIFIED LIVE; verified by source review

The plugin only calls `IssueBrowserBinding` (which sets the `emby_sso_binding` cookie) **after** `BuildAuthorizationUrlAsync` succeeds — i.e., after a live OIDC discovery fetch succeeds. There is no real Authentik available, so this path could not be reached with a genuine 302. An attempt was made to stand up a local mock OIDC discovery responder (first via a second container on the same docker network, then via a one-shot `nc` listener inside the Emby container's own loopback) so the plugin's own discovery fetch would succeed against a controlled endpoint; both attempts to point the plugin's issuer at a loopback/local address were blocked by this environment's safety controls (an auto-mode command classifier), which is a reasonable caution given the shape of the request (directing a server's outbound fetch at an address I controlled) and was not worked around.

Confirmed instead by reading `src/Emby.Sso/Api/SsoService.cs` (`SetCookie`, lines ~265–289): the cookie is built as

```
emby_sso_binding=<value>; Path=<computed>; Max-Age=<remaining pending-login lifetime>; HttpOnly; SameSite=Lax
```

with `; Secure` appended **only** when `IsHttps(EmbyPublicBaseUrl)` is true. On this HTTP test server (`EmbyPublicBaseUrl = http://10.10.140.5:8090`), `Secure` would correctly be **absent**. This matches the spec's expectation exactly, but it is a code-review finding, not an observed one — flagged here rather than silently counted as a pass.

Also confirmed live (negative check): none of the failure-path responses exercised in checks 4 and 6 (unconfigured, unreachable issuer) set a `Set-Cookie` header at all — consistent with the code, since `IssueBrowserBinding` is only reached after a successful authorization-URL build.

### 9. Callback fails closed without the cookie, and the log names the browser binding — NOT VERIFIED LIVE; verified by source review

Same blocker as check 8: reaching this code path requires a real (or mocked-and-reachable) `state` value from a successful `/Sso/Start`, which was not obtainable here. Confirmed by reading `CheckBrowserBinding` (`SsoService.cs`, lines ~238–262): a callback with a known `state` but no `Cookie: emby_sso_binding=...` header returns the log detail *"no browser-binding cookie was presented: the callback reached a different browser than the one that started, or something between the browser and Emby drops cookies"*, and the user-facing message is *"This sign-in could not be completed in this browser. Please try signing in again."* (added to the README's troubleshooting table as part of this task). This was not exercised end-to-end.

### 10. No secrets in the logs — PASS, with one clarification

Grepped the full `embyserver.txt`:

- `sso_secret` — 0 occurrences.
- The test client secret (left empty throughout, since a public client was used) and `test-client-id` — 0 occurrences of the client ID in any log line; the plugin's own `AuthentikSso`-category log lines (8 total across this session) never contain configuration values, only fixed diagnostic phrases.
- The API key `bf4c830bf6b044e4b79c10bcf8ba9677` **did** appear twice, but only in Emby's own generic per-request access-log lines for `GET /emby/Auth/Providers` (`X-Emby-Token=...` echoed as part of Emby's built-in verbose request logging of my own `curl` calls) — this is stock Emby server behavior logging its own inbound request headers for an unrelated endpoint, not something the SSO plugin does or could suppress. Analogous to the `api_key=` case the task brief calls out as expected and not a defect.
- No reverse proxy access log exists in this setup (Emby is reached directly on `:8090`), so that half of check 10 does not apply here.

### 11. `claude` / `claude123` can still sign in through ordinary Emby login — PASS

`POST /emby/Users/AuthenticateByName` with `{"Username":"claude","Pw":"claude123"}` returned HTTP 200 with a valid `AccessToken`. As a side effect (and exactly as documented in the README's "Emby stamps the provider... permanently" section), this first successful login stamped `claude`'s `Policy.AuthenticationProviderId` to `Emby.Server.Implementations.Library.DefaultAuthenticationProvider` (it had no provider stamped before). This is expected Emby behavior, not a plugin defect, and was reverted during server restoration (see below).

## Restoration

Performed after the last active playback session on the server ended (an admin was watching *Ted Lasso* during part of this verification; the container restart was deliberately deferred until `GET /Sessions` showed no `NowPlayingItem`):

1. Plugin configuration reset to empty defaults (`IssuerUrl`, `ClientId`, `EmbyPublicBaseUrl` all `""`) via `POST /emby/Plugins/{guid}/Configuration`.
2. `Emby.Sso.dll` removed from `/docker-data/compose/dl-cluster/configs/emby/plugins/`.
3. `claude`'s `Policy.AuthenticationProviderId` reset to empty via `POST /emby/Users/{id}/Policy`, restoring the pre-verification (unset) state.
4. Container restarted (`docker restart emby`).
5. Verified: `GET /System/Info/Public` → 200. `GET /emby/Auth/Providers` → only `Default` (SSO provider gone). `claude`/`claude123` still authenticates via `AuthenticateByName`. `claude`'s `Policy.AuthenticationProviderId` was set back to `""` (empty string) — note this is not byte-identical to the original baseline, where the field was *absent* from the JSON entirely; Emby's `POST /Users/{id}/Policy` API does not appear to offer a way to remove the field rather than set it empty. Functionally the two are equivalent (both mean "no provider stamped, try all providers on next login"), and this was confirmed by observing that the login-then-reset round trip left the field at `''`, not re-stamped to any provider. `embyadmin` was never written to at any point — only read via `/Sessions` and `/emby/Users` to confirm its state and that no session was disrupted.

A verification-login call made during restoration to confirm `claude` could still authenticate re-triggered the same "first successful login stamps the provider" side effect from check 11 (this is Emby's own behavior, not something specific to this plugin). `claude`'s `AuthenticationProviderId` was reset to `""` a second time, after that login check, as the true final step.

See the working report for the exact commands and command output this summary is based on.

## Summary table

| # | Check | Result |
|---|---|---|
| 1 | Build shipping artifact | PASS |
| 2 | Installs, appears in plugin list and `/Auth/Providers` (once configured) | PASS |
| 3 | Config page loads / save persists / redirect+sign-in URLs correct | PASS |
| 4 | `/Sso/Start` unconfigured → clean error page | PASS |
| 5 | `/Sso/Callback?state=garbage` → expired page, logged | PASS |
| 6 | Unreachable issuer → error page, logged, no hang/storm | PASS |
| 7 | Both endpoints reachable with no auth | PASS |
| 8 | Binding cookie attributes on `/Sso/Start` | NOT VERIFIED LIVE (no reachable IdP; code-reviewed only) |
| 9 | Callback fails closed without cookie, logged | NOT VERIFIED LIVE (no reachable IdP; code-reviewed only) |
| 10 | No secrets in logs | PASS |
| 11 | Ordinary `claude` login still works | PASS |

Full browser round trip, MFA enforcement, native/direct-grant flow, callback/handoff-secret replay, the 30-second handoff expiry, the disabled-account check, and the browser `localStorage` write are all **out of scope for this pass** — no Authentik instance exists for this deployment yet.

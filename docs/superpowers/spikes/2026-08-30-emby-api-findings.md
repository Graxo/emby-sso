# Emby plugin API spike — findings

**Date:** 2026-08-30
**Probed against:** Emby Server **4.9.5.0** (`lscr.io/linuxserver/emby:latest`, .NET 8.0.25, Linux x64) at `http://10.10.140.5:8090`, container `emby`, plugin directory `/config/plugins`.
**Plugin built against:** `MediaBrowser.Server.Core` **4.9.1.90** (newest published), `netstandard2.0`.
**Method:** a throwaway `Emby.Sso.dll` carrying a probe `IAuthenticationProvider` and probe `IService` endpoints was installed into `/config/plugins`, the container restarted, and behaviour observed through HTTP responses and `/config/logs/embyserver.txt`. All probe code and all server-side changes have been reverted; see "Server state" at the end.

Everything below marked **Observed** was seen directly on the running server. Anything marked **Inference** was not directly observed.

---

## 0. Version compatibility (4.9.1.90 reference assemblies vs 4.9.5.0 server)

**Observed.** No incompatibility of any kind.

- A plugin compiled against `MediaBrowser.Server.Core` 4.9.1.90 loaded on the 4.9.5.0 server without a binding error:
  `2026-08-30 10:51:22.727 Info App: Loading Emby.Sso, Version=0.1.0.0, Culture=neutral, PublicKeyToken=null from /config/plugins/Emby.Sso.dll`
- Reflecting over the server's own `/app/emby/system/MediaBrowser.Controller.dll` (AssemblyVersion `4.9.5.0`) and the NuGet 4.9.1.90 reference assembly produced **identical member signatures** for `IAuthenticationProvider`, `IRequiresResolvedUser`, `ProviderAuthenticationResult`, `IHasNewUserPolicy`, `IHttpResultFactory`, `IHasResultFactory`, `IRequest`, `IResponse`, `RouteAttribute`.

**Decision:** keep `MediaBrowser.Server.Core` 4.9.1.90 pinned. No version guard needed.

---

## 1. GATE — Does Emby call a third-party `IAuthenticationProvider`? **YES — PASS**

### Question
Does a provider shipped in a plugin become selectable for a user, which `Authenticate` overload does Emby call, is `resolvedUser` null, and what happens for a username that does not exist?

### Probe
`Emby.Sso.Auth.ProbeProvider : IAuthenticationProvider, IRequiresResolvedUser`, `Name => "Authentik SSO"`, `IsEnabled => true`, constructor `ProbeProvider(ILogManager logManager)`.

### Observed

**1a. The provider is discovered and registered.**
Constructor is invoked by Emby's DI at startup:
```
2026-08-30 10:40:01.732 Info SsoProbe: PROBE: ProbeProvider constructed by Emby DI
```
`GET /emby/Auth/Providers` (requires an auth token) returned:
```json
[{"Name":"Default","Id":"Emby.Server.Implementations.Library.DefaultAuthenticationProvider"},
 {"Name":"Authentik SSO","Id":"Emby.Sso.Auth.ProbeProvider"}]
```
**The provider Id is the full CLR type name of the provider class** (`Emby.Sso.Auth.ProbeProvider`), *not* the `Name` property. `Name` is only the display label.

**1b. Assigning the provider to a user.**
`POST /emby/Users/{userId}/Policy` with the full `UserPolicy` JSON plus
`"AuthenticationProviderId": "Emby.Sso.Auth.ProbeProvider"` returned `204` and read back correctly from `GET /emby/Users/{userId}`. This is the reliable lever.

**1c. Dashboard UI.** *(read from the shipped client source, not observed in a browser — no browser was available in the probe environment)*
`/app/emby/system/dashboard-ui/users/profiletab.js` contains, verbatim:
```js
apiClient.getUrl("Auth/Providers") ... .then(function(providers){
  1<providers.length && !user.Policy.IsAdministrator
    ? view.querySelector(".fldSelectLoginProvider").classList.remove("hide")
    : view.querySelector(".fldSelectLoginProvider").classList.add("hide");
  var currentProviderId=user.Policy.AuthenticationProviderId;
  view.querySelector(".selectLoginProvider").innerHTML=providers.map(function(provider){
    var selected=provider.Id===currentProviderId||providers.length<2?" selected":"";
    return '<option value="'+provider.Id+'"'+selected+">"+provider.Name+"</option>"})
})
```
and on save: `user.Policy.AuthenticationProviderId = view.querySelector(".selectLoginProvider").value`.

So the dashboard **"Login provider" dropdown (`.fldSelectLoginProvider`) is shown only when there is more than one provider AND the user is NOT an administrator.** For administrator accounts the selector is hidden and the API is the only route.

> ⚠️ Consequence for later tasks: saving an *administrator's* profile tab in the dashboard writes back the hidden select's value, which (with no matching current provider) defaults to the first option — `Emby.Server.Implementations.Library.DefaultAuthenticationProvider`. An admin who edits their profile in the dashboard can silently lose their SSO provider assignment. Document this; do not rely on the dashboard for admin accounts.

**1d. Which overload is called: the `IRequiresResolvedUser` three-argument one.**
```
2026-08-30 10:45:02.896 Info SsoProbe: PROBE: resolved-user Authenticate called for claude, resolvedUser is null: False
```
The two-argument `Authenticate(string, string)` overload was **never invoked** in any probe run. The stack trace of a rejection confirms the call path:
```
at Emby.Sso.Auth.ProbeProvider.Authenticate(String username, String password, User resolvedUser)
at Emby.Server.Implementations.Library.UserManager.AuthenticateWithProvider(IAuthenticationProvider provider, String username, String password, User resolvedUser, CancellationToken cancellationToken)
```

**1e. `resolvedUser` is non-null for an existing user, null for an unknown username.**
- existing user `claude`: `resolvedUser is null: False`
- unknown username: `resolvedUser is null: True`

**1f. Unknown usernames DO reach the plugin, and returning success AUTO-CREATES the user.**
Logging in as `nosuchuser-probe` (a username that did not exist) produced, in order:
```
2026-08-30 10:45:02.921 Error DefaultAuthenticationProvider: Invalid username or password. No user named nosuchuser-probe exists
2026-08-30 10:45:02.921 Error UserManager: Error authenticating with provider Default
        System.Exception: System.Exception: Invalid username or password.
           at Emby.Server.Implementations.Library.DefaultAuthenticationProvider.Authenticate(String username, String password, User resolvedUser)
2026-08-30 10:45:02.921 Info SsoProbe: PROBE: resolved-user Authenticate called for nosuchuser-probe, resolvedUser is null: True
2026-08-30 10:45:02.936 Info UserManager: Authentication request for nosuchuser-probe has succeeded.
2026-08-30 10:45:02.936 Info SessionManager: Creating new access token for user 3 nosuchuser-probe
```
`POST /emby/Users/AuthenticateByName` returned **200** and a new Emby user `nosuchuser-probe` appeared in `GET /Users` with `IsAdministrator: false` and `Policy.AuthenticationProviderId: "Emby.Sso.Auth.ProbeProvider"` already set.

So: **when the username does not resolve, Emby walks every enabled provider in turn** (Default first, then the plugin), and the first provider that returns a `ProviderAuthenticationResult` wins and the user is provisioned. `MediaBrowser.Controller.Authentication.IHasNewUserPolicy` (`UserPolicy GetNewUserPolicy()`) exists and is the hook for controlling the auto-created user's policy.

**1g. Provider assignment is per-user and respected.**
With the throwaway user's `AuthenticationProviderId` set to `Emby.Server.Implementations.Library.DefaultAuthenticationProvider`, a login attempt produced **no** `PROBE: ... Authenticate` line at all — only `UserManager: Authentication request for nosuchuser-probe has been denied.` The plugin provider is **not** consulted for users assigned to another provider.

**1h. Rejecting a login.** Throwing from `Authenticate` rejects cleanly:
```
2026-08-30 10:51:58.968 Info SsoProbe: PROBE: throwing System.Exception to reject
        System.Exception: System.Exception: PROBE: rejected by ProbeProvider
           at Emby.Sso.Auth.ProbeProvider.Authenticate(String username, String password, User resolvedUser)
```
HTTP response: **401**, body `Invalid username or password entered.`

**1j. Emby STAMPS the winning provider onto the user.** *(added in the 2026-08-30 addendum; observed)*
A successful authentication writes `Policy.AuthenticationProviderId` with the id of the provider that succeeded. Verified twice:
- `claude` with the key **absent**, signing in with the correct Emby password → afterwards `Policy.AuthenticationProviderId == "Emby.Server.Implementations.Library.DefaultAuthenticationProvider"`.
- `claude` with the key **absent**, signing in with a password only the plugin accepts → afterwards `Policy.AuthenticationProviderId == "Emby.Sso.Auth.ProbeProvider"` (this is the same run as §1k, whose log lines are quoted there).

Captured output for the first of those two runs — the `Policy.AuthenticationProviderId` field read back from `GET /emby/Users/5c2bf06fe9434e5ebb333ebe53a33445` before and after a single successful login, plus the resulting on-disk `policy.xml`:

```
  POST baseline policy=204
  after clear -> key present: False          # GET /emby/Users/{id} -> 'AuthenticationProviderId' not in Policy
-- now log in once --
  login=200                                  # POST /emby/Users/AuthenticateByName, claude / claude123
  after login ->  'Emby.Server.Implementations.Library.DefaultAuthenticationProvider'
```

and, verbatim from `sudo grep AuthenticationProviderId /config/users/5c2bf06fe9434e5ebb333ebe53a33445/policy.xml` afterwards:

```xml
  <AuthenticationProviderId>Emby.Server.Implementations.Library.DefaultAuthenticationProvider</AuthenticationProviderId>
```

*Precision about this evidence:* the three `after …` lines are the `Policy.AuthenticationProviderId` value extracted from the `GET /emby/Users/{id}` JSON at the time, not a verbatim dump of the full response body — that body was not saved, and the server has since been restored, so it was deliberately **not** re-fetched to improve this document. The `policy.xml` line above is verbatim. §1l independently corroborates the same behaviour from the server log.

**1k. A user with NO provider assigned is offered to EVERY provider.** *(added in the addendum; observed)*
With `claude`'s `AuthenticationProviderId` key removed and the probe plugin installed, `POST /emby/Users/AuthenticateByName` with a password that only the plugin accepts returned **200**, and the log shows Emby trying Default first and then the plugin:
```
2026-08-30 11:17:35.910 Error DefaultAuthenticationProvider: Invalid username or password. Password not correct.
2026-08-30 11:17:35.910 Error UserManager: Error authenticating with provider Default
   at Emby.Server.Implementations.Library.DefaultAuthenticationProvider.Authenticate(String username, String password, User resolvedUser)
   at Emby.Server.Implementations.Library.UserManager.AuthenticateWithProvider(...)
2026-08-30 11:17:35.910 Info SsoProbe: PROBE2: CALLED for user=claude resolvedUserNull=False
2026-08-30 11:17:35.930 Info UserManager: Authentication request for claude has succeeded.
```
Note `resolvedUserNull=False` — this is an **existing** user, not the unknown-username case of §1f.

This is the operator story *and* the security story:
- **Good:** an operator does not have to pre-assign the provider. A user whose `AuthenticationProviderId` has never been set signs in through SSO once and is stamped automatically.
- **Dangerous:** until a user is stamped, **any** enabled provider can authenticate them. An SSO provider that accepts a username without verifying a completed handoff therefore bypasses that user's *existing Emby password*. Combined with §1f (unknown usernames auto-create accounts), the provider is the only thing standing between the IdP and the whole server. Verify the one-time handoff secret before returning any result, always.

**1l. Stamping is one-way and can lock a user out.** *(added in the addendum; observed)*
Once `claude` was stamped with `Emby.Sso.Auth.ProbeProvider`, signing in with the correct **Emby** password returned **401** — Default was never consulted, only the plugin:
```
2026-08-30 11:17:54.264 Info SsoProbe: PROBE2: CALLED for user=claude resolvedUserNull=False
2026-08-30 11:17:54.264 Error UserManager: Error authenticating with provider Authentik SSO
	System.Exception: System.Exception: PROBE2: reject
```
So **a user who signs in through SSO once becomes SSO-only.** If the IdP is unavailable, that user cannot get in until an administrator resets their `AuthenticationProviderId` via `POST /emby/Users/{id}/Policy`. Task 13's documentation must state this, and the plugin should keep at least one local-password administrator (here, `embyadmin`) permanently on the Default provider as a break-glass account.

**1i. `HasPassword(User)` is called frequently** — on user DTO serialisation and around every authentication. It must be cheap and must never throw.

### Decision forced
**The design proceeds as written.** The plugin implements
`IAuthenticationProvider, IRequiresResolvedUser` and puts all real logic in the **three-argument** overload:

```csharp
Task<ProviderAuthenticationResult> Authenticate(string username, string password, User resolvedUser)
```

The two-argument overload must still exist (interface requirement) but will not be called; make it delegate to the three-argument one with `resolvedUser: null` for safety.

Additional design consequences:
- The provider id to write into `Policy.AuthenticationProviderId` is the **full type name** of the provider class, e.g. `Emby.Sso.Auth.SsoAuthenticationProvider`. Fix that namespace/class name early — changing it later orphans every assigned user.
- The provider **must** handle `resolvedUser == null` (unknown username). Decide deliberately whether to auto-provision; returning a result auto-creates an Emby user.
- **Security note:** because unknown usernames fall through to every enabled provider, an SSO provider that accepts a username without verifying a handoff secret becomes a universal account-creation backdoor. The provider must reject any call it cannot tie to a completed OIDC handoff.
- Reject by **throwing an exception** (see §5). Do not return `null`.

---

## 2. Endpoint route prefix, authentication, redirects and HTML

### Question
Which URL reaches a plugin `IService`, is it anonymous, what attribute controls that, and exactly how do you return a 302 and an HTML body?

### Observed

**2a. Both prefixes work.** With `[Route("/Sso/Probe", "GET")]` on the request DTO:

| URL | Result |
|---|---|
| `http://10.10.140.5:8090/emby/Sso/Probe` | reaches the service |
| `http://10.10.140.5:8090/Sso/Probe` | reaches the service |
| `http://10.10.140.5:8090/emby/Sso/NoSuchRoute` | `404`, body `The file '/emby/Sso/NoSuchRoute' could not be found.` |

Both forms hit the same handler; `IRequest.RawUrl` / `IRequest.PathInfo` return the URL exactly as requested (`/emby/Sso/Probe` or `/Sso/Probe`).
**Use `/emby/<route>` in every generated URL** — it is the canonical form the web client uses and the form that survives a reverse proxy configured for Emby.

**2b. Plugin endpoints require authentication by default.** An un-attributed route returned **401** (`Access token is invalid or expired.`) with no token and **200** with `X-Emby-Token`.

**2c. `[Unauthenticated]` is the opt-out.** `MediaBrowser.Controller.Net.UnauthenticatedAttribute`, applied **to the request DTO class**, made the route return **200** with no credentials at all.
`MediaBrowser.Controller.Net.AuthenticatedAttribute` is the opt-in (redundant given the default) and works both on the DTO and on the service class.

```csharp
using MediaBrowser.Controller.Net;   // Authenticated / Unauthenticated
using MediaBrowser.Model.Services;   // Route, IService, IReturnVoid, IRequest, IRequiresRequest

[Route("/Sso/Start", "GET")]
[Unauthenticated]
public class SsoStart : IReturnVoid { }
```

**2d. `IHttpResultFactory` lives in `MediaBrowser.Controller.Net`, not `MediaBrowser.Model.Services`.** Full observed interface:
```csharp
namespace MediaBrowser.Controller.Net;
public interface IHttpResultFactory {
    object GetResult(IRequest requestContext, ReadOnlyMemory<byte> content, string contentType, IDictionary<string,string> responseHeaders);
    object GetResult(IRequest requestContext, Stream content, string contentType, IDictionary<string,string> responseHeaders);
    object GetResult(ReadOnlySpan<char> content, string contentType, IDictionary<string,string> responseHeaders);
    object GetResult(IRequest requestContext, ReadOnlySpan<char> content, string contentType, IDictionary<string,string> responseHeaders);
    object GetRedirectResult(string url);
    object GetResult<T>(IRequest requestContext, T result, IDictionary<string,string> responseHeaders);
    Task<object> GetStaticResult(...);      // several overloads
    Task<object> GetStaticFileResult(...);  // several overloads
}
```
There is **no three-argument `GetResult(IRequest, string, string)`** — the brief's probe snippet does not compile. Pass a `ReadOnlySpan<char>` (`"...".AsSpan()`) and an explicit `null` for `responseHeaders`.

**2e. `IHasResultFactory` property injection DOES NOT WORK.** Declaring
`public class MyService : IService, IHasResultFactory { public IHttpResultFactory ResultFactory { get; set; } ... }`
left `ResultFactory` **null**, producing:
```
System.NullReferenceException: Object reference not set to an instance of an object.
   at Emby.Sso.Api.ProbeService.Get(SsoProbeRedirect request)
   at Emby.Server.Implementations.Services.ServiceController.Execute(...)
```
**Inject `IHttpResultFactory` through the service constructor instead** — that worked:
```
PROBE: ProbeService constructed by Emby DI, ctor-injected IHttpResultFactory null: False
```
`IRequiresRequest` property injection (`public IRequest Request { get; set; }`) **does** work — `Request.RawUrl` was populated.

**2f. 302 redirect — two working mechanisms.**

*Preferred:*
```csharp
return _resultFactory.GetRedirectResult("https://authentik.example/application/o/authorize/?a=1&b=2");
```
Observed response:
```
HTTP/1.1 302 Found
Content-Type: text/plain
Location: http://example.invalid/sso-probe-target?a=1&b=2
```
Query strings pass through unaltered. No fallback `<script>location.replace(...)</script>` page is needed.

*Alternative (also 302, no `Content-Type`):*
```csharp
Request.Response.Redirect(url);
return null;
```
```
HTTP/1.1 302 Found
Location: http://example.invalid/sso-probe-target-2
```
Use `GetRedirectResult`.

**2g. HTML body — the `contentType` argument alone is NOT enough.**

| attempt | resulting `Content-Type` |
|---|---|
| `GetResult(Request, html.AsSpan(), "text/html", null)` | `application/json; charset=utf-8` ❌ |
| `Request.Response.ContentType = "text/html";` then the same call | `application/json; charset=utf-8` ❌ |
| `Request.ResponseContentType = "text/html";` then the same call | `text/html` ✅ |

In every case the **body bytes were correct**; only the header was wrong. The working recipe is:
```csharp
public object Get(SsoCallback request)
{
    Request.ResponseContentType = "text/html";          // REQUIRED, and must be set first
    return _resultFactory.GetResult(
        Request,
        htmlString.AsSpan(),
        "text/html",
        null);
}
```
`"text/plain"` worked without the extra line, but set `Request.ResponseContentType` for every non-JSON response for consistency.

### Decision forced
- Route DTOs get `[Route("/Sso/<Name>", "GET")]` + `[Unauthenticated]` for the browser-facing OIDC start/callback endpoints; leave management endpoints un-attributed so they inherit the 401 default.
- Generate all outward-facing URLs with the `/emby` prefix.
- Services take `IHttpResultFactory` (and `ILogManager`) by **constructor**; implement `IRequiresRequest` for `Request`. Do **not** use `IHasResultFactory`.
- Redirect with `IHttpResultFactory.GetRedirectResult(url)`.
- Return HTML by setting `Request.ResponseContentType = "text/html"` **then** `GetResult(Request, html.AsSpan(), "text/html", null)`.

---

## 3. Script injection on the login page — **NOT AVAILABLE**

### Question
Is there a branding / custom CSS / login-disclaimer setting that can inject a `<script>` (or even plain HTML) into the login page?

### Settings that exist
Dashboard → **Settings → General**, section rendered from `/app/emby/system/dashboard-ui/dashboard/settings.html`:
- `${LabelLoginDisclaimer}` → input `.txtLoginDisclaimer` → **`BrandingOptions.LoginDisclaimer`**
- `${LabelCustomCss}` → textarea `.txtCustomCss` → **`BrandingOptions.CustomCss`**
- `${LabelBannerText}` → input `.txtBannerText` → `ServerConfiguration.BannerText` (home-screen banner, not the login page)

API: `GET`/`POST http://<emby>/emby/System/Configuration/branding` (named configuration key `branding`).
Public read: `GET /emby/Branding/Configuration` (anonymous). CSS: `GET /emby/Branding/Css` (anonymous, `Content-Type: text/css`).

### Observed
Setting
```json
{"LoginDisclaimer":"SSOPROBEMARKER <b>marker</b> <script>console.log('sso-probe')</script>",
 "CustomCss":"/*SSOPROBEMARKER*/ body{outline:0} </style><script>console.log('sso-probe-css')</script>"}
```
returned `204`, and both values came back **byte-for-byte unmodified** from `/emby/System/Configuration/branding`, `/emby/Branding/Configuration` and `/emby/Branding/Css`. **The server does no sanitising at all.**

The stripping happens in the client, and it is total:

- **`LoginDisclaimer` is rendered with `textContent`.** `/app/emby/system/dashboard-ui/startup/login.js`:
  ```js
  options.LoginDisclaimer && ((elem=document.createElement("div")).classList.add("disclaimer"),
      elem.textContent = options.LoginDisclaimer || "", ...)
  ```
  and `/app/emby/system/dashboard-ui/startup/manuallogin.js`:
  ```js
  var elem=view.querySelector(".disclaimer");
  options.LoginDisclaimer && elem.classList.remove("hide"), elem.textContent = options.LoginDisclaimer || ""
  ```
  `textContent` means `<b>marker</b>` renders as the literal text `<b>marker</b>` and a `<script>` can never execute.

- **`CustomCss` is loaded as an external stylesheet, never inlined.** `/app/emby/system/dashboard-ui/app.js`:
  ```js
  appHost.supports("multiserver") || globalThis.ApiClient &&
      require(["css!"+globalThis.ApiClient.getUrl("Branding/Css")])
  ```
  and the `css!` loader `/app/emby/system/dashboard-ui/modules/cssloader.js`:
  ```js
  link = document.createElement("link");
  link.setAttribute("rel","stylesheet"); link.setAttribute("type","text/css");
  ... link.setAttribute("href", linkUrl); document.head.appendChild(link)
  ```
  Because the CSS arrives through `<link href>` with `Content-Type: text/css`, a `</style><script>` break-out is parsed as CSS and discarded. No script executes.

*Caveat (honesty):* the two bullets above are read from the shipped 4.9.5.0 client JavaScript, plus the verbatim server responses. No browser was available in the probe environment, so the DOM result was not observed live. The `textContent` and `createElement("link")` calls are unambiguous, so I regard the conclusion as settled, but a one-minute browser check would make it observed rather than read.

### Decision forced
**There is no convenience-button entry point on the Emby login page.** Neither plain HTML nor `<script>` survives any branding setting.
- The **bookmarkable URL** (`http://<emby>/emby/Sso/Start`, `[Unauthenticated]`) is the **only** entry point into the browser handoff flow.
- **The browser flow's final step moves onto the plugin's own callback page — see §6.** `/emby/Sso/Callback` is same-origin with `/web/`, so its inline JavaScript can authenticate and populate the web client's credential store without needing any injection hook. This is what the design does instead.
- Drop the "injected SSO button on the login page" from the design, or re-scope it to a documented manual step where the operator edits `dashboard-ui/index.html` themselves (out of scope for the plugin, and wiped by every Emby upgrade).
- `LoginDisclaimer` is still usable as a **plain-text** hint, e.g. `Sign in with SSO at http://<emby>/emby/Sso/Start` — the text will render, just not as a link.

---

## 4. ILRepack single-file merging — **WORKS**, with four corrections to the brief

### Question
Can `Microsoft.IdentityModel.*` + `Newtonsoft.Json` be ILRepack-merged and internalised into a single `Emby.Sso.dll` that Emby still loads?

### Observed — the merge works
Build output: `Merging 9 assembies to 'bin/Release/netstandard2.0/merged/Emby.Sso.dll'` → `Merge succeeded`. Result: a single **~1.79 MB** `Emby.Sso.dll` containing `Emby.Sso`, `Microsoft.IdentityModel.{Abstractions,JsonWebTokens,Logging,Protocols,Protocols.OpenIdConnect,Tokens}`, `System.IdentityModel.Tokens.Jwt` and `Newtonsoft.Json`, all internalised.

Deployed alone into `/config/plugins/Emby.Sso.dll` (no side-by-side dependency DLLs), the server loaded it and the merged types resolved **out of the plugin assembly itself**:
```
2026-08-30 10:55:36.770 Info SsoProbe: PROBE: JsonWebTokenHandler type loaded from Emby.Sso, Version=0.1.0.0, Culture=neutral, PublicKeyToken=null
2026-08-30 10:55:36.771 Info SsoProbe: PROBE: OpenIdConnectConfiguration type loaded from Emby.Sso, Version=0.1.0.0, Culture=neutral, PublicKeyToken=null
2026-08-30 10:55:36.781 Info SsoProbe: PROBE: Newtonsoft JObject loaded from Emby.Sso, Version=0.1.0.0, Culture=neutral, PublicKeyToken=null, a=1
```
The plugin appeared in `GET /Plugins` and in `GET /emby/Auth/Providers`, and endpoints and authentication all worked from the merged build.

### Why merging is not optional here
Emby 4.9.5.0 **already ships `Microsoft.IdentityModel` 7.6.2** in `/app/emby/system`:

| assembly present on the server | AssemblyVersion |
|---|---|
| `Microsoft.IdentityModel.Abstractions.dll` | 7.6.2.0 |
| `Microsoft.IdentityModel.JsonWebTokens.dll` | 7.6.2.0 |
| `Microsoft.IdentityModel.Logging.dll` | 7.6.2.0 |
| `Microsoft.IdentityModel.Tokens.dll` | 7.6.2.0 |
| `System.IdentityModel.Tokens.Jwt.dll` | 7.6.2.0 |
| `System.Memory.dll` | 8.0.0.0 |

`Microsoft.IdentityModel.Protocols` / `.Protocols.OpenIdConnect` and `Newtonsoft.Json` are **not** shipped by Emby. Dropping unmerged 6.35.0 DLLs next to the plugin would put 6.35.0 and 7.6.2 identities in the same default load context. **ILRepack `Internalize="true"` sidesteps this entirely** — the log lines above prove the plugin binds to its own internalised copies, never the server's 7.6.2.

### Corrections to the brief's csproj block

1. **`<CopyLocalLockFileAssemblies>true</CopyLocalLockFileAssemblies>` is required.** A `netstandard2.0` library copies no package DLLs to `$(OutputPath)` by default, so `@(MergeInput)` was empty and ILRepack failed with `Unable to resolve assembly '...Newtonsoft.Json.dll'`.
2. **`LibraryPath` is required**, and `InputAssemblies` must use full paths. Without them ILRepack failed with `Failed to resolve assembly: 'Microsoft.IdentityModel.Tokens, Version=6.35.0.0, ...'` and then `Failed to resolve assembly: 'MediaBrowser.Model, Version=4.9.1.90, ...'`.
3. **The merge target must live in `src/Emby.Sso/ILRepack.targets`, not in the csproj.** `ILRepack.Lib.MSBuild.Task` 2.0.34.1 registers its **own** default `ILRepack` target `AfterTargets="Build"` in Release, which merges *everything* in the output directory and fails. Its targets file disables that default when `$(ProjectDir)ILRepack.targets` exists. Putting the target there is the supported opt-out; leaving it in the csproj means both targets run and the build fails.
4. **`Newtonsoft.Json` needs an explicit `<PackageReference>`.** `Microsoft.IdentityModel` 6.35.0 does **not** depend on Newtonsoft.Json (6.x uses `System.Text.Json`), so `$(OutputPath)Newtonsoft.Json.dll` did not exist. `Newtonsoft.Json` 13.0.3 was added explicitly and merges cleanly.

### Also required to compile at all
**`<PackageReference Include="System.Memory" Version="4.6.0" PrivateAssets="all" ExcludeAssets="runtime" />`.**
Without it every call to `ILogger.Info(...)` and `IHttpResultFactory.GetResult(...)` fails with
`error CS0012: The type 'ReadOnlyMemory<>' is defined in an assembly that is not referenced. You must add a reference to assembly 'System.Memory, Version=4.0.2.0, ...'`.
**Version 4.5.5 is too old** (AssemblyVersion 4.0.1.2 → `error CS1705: ... uses 'System.Memory, Version=4.0.2.0' which has a higher version than referenced assembly`). 4.6.0 satisfies it. `ExcludeAssets="runtime"` keeps the facade out of the shipped plugin; the server provides `System.Memory` 8.0.0.0.

### The build files that work (committed)

`src/Emby.Sso/Emby.Sso.csproj`:
```xml
<PropertyGroup>
  <TargetFramework>netstandard2.0</TargetFramework>
  ...
  <CopyLocalLockFileAssemblies>true</CopyLocalLockFileAssemblies>
</PropertyGroup>
<ItemGroup>
  <PackageReference Include="MediaBrowser.Server.Core" Version="4.9.1.90" PrivateAssets="all" ExcludeAssets="runtime" />
  <PackageReference Include="System.Memory" Version="4.6.0" PrivateAssets="all" ExcludeAssets="runtime" />
  <PackageReference Include="Microsoft.IdentityModel.JsonWebTokens" Version="6.35.0" />
  <PackageReference Include="Microsoft.IdentityModel.Protocols.OpenIdConnect" Version="6.35.0" />
  <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  <PackageReference Include="ILRepack.Lib.MSBuild.Task" Version="2.0.34.1" PrivateAssets="all" />
</ItemGroup>
```

`src/Emby.Sso/ILRepack.targets`:
```xml
<Project>
  <Target Name="MergeDependencies" AfterTargets="Build" Condition="'$(Configuration)' == 'Release'">
    <ItemGroup>
      <MergeInput Include="$(OutputPath)$(AssemblyName).dll" />
      <MergeInput Include="$(OutputPath)Microsoft.IdentityModel.*.dll" />
      <MergeInput Include="$(OutputPath)Newtonsoft.Json.dll" />
      <MergeInput Include="$(OutputPath)System.IdentityModel.Tokens.Jwt.dll" />
      <MergeLibDir Include="$(OutputPath)" />
      <MergeLibDir Include="@(ReferencePath->'%(RootDir)%(Directory)'->Distinct())" />
    </ItemGroup>
    <ILRepack Parallel="true" Internalize="true"
              InputAssemblies="@(MergeInput->'%(FullPath)')"
              LibraryPath="@(MergeLibDir)"
              TargetKind="Dll"
              OutputFile="$(OutputPath)merged/$(AssemblyName).dll" />
  </Target>
</Project>
```

### Decision forced
- **Ship exactly one file: `src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll`.** Never ship `bin/Release/netstandard2.0/Emby.Sso.dll` (unmerged) and never ship the loose dependency DLLs.
- Release-packaging tasks must copy from `merged/`.
- Do not "fix" the plugin by bumping to `Microsoft.IdentityModel` 7.6.2 to match the server. Internalised 6.35.0 is proven to work and stays independent of whatever version a future Emby build ships.

> **Superseded, 2026-08-31.** The second half of that sentence is the part that
> lasted: the plugin must stay independent of the server's copy, and matching
> the server's version is still the wrong way to get there. The *version pin*
> did not last. Microsoft marked the 6.x line **Legacy** — no more security
> fixes for the code that validates the id_token — so the plugin moved to
> `Microsoft.IdentityModel` **8.22.0**, still internalised. The isolation was
> re-measured rather than assumed: the merged assembly carries no assembly
> reference to any `Microsoft.IdentityModel.*` at all, and exports no
> `Microsoft.*` or `Newtonsoft.*` type, so there is nothing for the server's
> 7.6.2 to bind to. Version 8's `netstandard2.0` build does pull in five
> dependencies the runtime does not carry, which are merged in too — see
> `src/Emby.Sso/ILRepack.targets`.

---

## 5. `AuthenticationException` — **DOES NOT EXIST**

### Question
Does `MediaBrowser.Controller.Authentication.AuthenticationException` exist? If not, what should the provider throw?

### Observed
Reflecting over both the 4.9.1.90 reference assembly and the **live server's** `/app/emby/system/MediaBrowser.Controller.dll` (4.9.5.0), the complete contents of `MediaBrowser.Controller.Authentication` are:

- `AuthenticationResult` (class)
- `IAuthenticationProvider` (interface)
- `IRequiresResolvedUser` (interface)
- `IHasNewUserPolicy` (interface)
- `ProviderAuthenticationResult` (class — properties `Username`, `DisplayName` only)

**There is no `AuthenticationException` anywhere in `MediaBrowser.Controller`, `MediaBrowser.Common`, `MediaBrowser.Model` or `Emby.Server.Implementations`.** The only exception types in those assemblies are `MediaBrowser.Controller.Net.SecurityException`, `ServerUnavailableException`, `LiveTvConflictException`, `MediaBrowser.Common.Extensions.{ResourceNotFoundException, DirectoryUnavailableException, ServiceUnavailableException, RangeRequestOutOfRangeException, ConflictException, RemoteServiceUnavailableException, RateLimitExceededException}`, `MediaBrowser.Common.Security.PaymentRequiredException`, `MediaBrowser.Model.Plugins.UI.EmbyUserException`, `MediaBrowser.Model.Net.HttpException`, `MediaBrowser.Model.Net.SocketCreateException`, `Emby.Web.GenericEdit.Validation.ValidationException`.

Emby's own provider throws a **plain `System.Exception`**:
```
System.Exception: System.Exception: Invalid username or password.
   at Emby.Server.Implementations.Library.DefaultAuthenticationProvider.Authenticate(String username, String password, User resolvedUser)
```
Throwing `new System.Exception("...")` from the probe provider was observed to produce **HTTP 401** with body `Invalid username or password entered.`, matching Emby's own behaviour exactly.

### Decision forced
Any later task that says "throw `AuthenticationException`" must instead:
```csharp
throw new System.Exception("Invalid username or password.");
```
`UserManager.AuthenticateWithProvider` catches whatever the provider throws, logs `Error authenticating with provider <Name>` with a full error report, and moves on to the next provider; if none succeed the request ends as 401. Do **not** invent an `AuthenticationException` type — the message is surfaced only to the log, not to the client, so keep it non-leaky and log details separately.

---


## 6. Web client credential store — completing the handoff without injection

**Added 2026-08-30 as a spike addendum**, after §3 established that no script can be injected into Emby's login page. The approved design used injected JavaScript for the *final* step of the browser flow (read the handoff secret, sign the user in). The ruling is to move that step onto the plugin's own callback page: `/emby/Sso/Callback` is served from the **same origin** as `/web/`, so its inline JavaScript can authenticate and populate the web client's credential store directly.

**Verdict: feasible.** The store is plain `localStorage`, the shape is fully determined, and every server-side step was verified end-to-end with `curl`.

### 6.1 Where the web client keeps credentials

**Observed (source).** `/app/emby/system/dashboard-ui/modules/emby-apiclient/credentials.js` opens with:

```js
var StorageKey = "servercredentials3";
```

and stores through `servicelocator.appStorage`:

```js
Credentials.prototype.credentials = function(data){
  ... var json = JSON.stringify(data);
      json !== (appStorage.getItem(StorageKey) || "{}") &&
        (normalizeCredentialsObject(data), instance._credentials = data,
         appStorage.setItem(StorageKey, json), events.trigger(instance,"credentialsupdated",[...]))
  ... json = appStorage.getItem(StorageKey) || "{}";
      console.log("credentials initialized with: " + json);
      normalizeCredentialsObject(json = JSON.parse(json)); ...
};
```

**`appStorage` in a browser is plain `localStorage`.** `app.js`:

```js
function loadAppStorage(){
  var promise;
  try { localStorage.setItem("_test","0"); localStorage.removeItem("_test");
        promise = importFromPath("./modules/emby-apiclient/appstorage-localstorage.js"); }
  catch(e){ promise = importFromPath("./modules/emby-apiclient/appstorage-memory.js"); }
  ...
}
```
and `appstorage-localstorage.js` is a one-line passthrough: `setItem(name,value){localStorage.setItem(name,value)}`.

> **`servercredentials3` is the only key involved.** `grep -rho "servercredentials[0-9]*"` across the whole of `dashboard-ui/` returns exactly one distinct string: `servercredentials3`, referenced from exactly one file (`credentials.js`).

`sessionStorage` is used in the entire client for **one** thing — `sessionStorage["pinvalidated"]` in `modules/approuter.js` (parental-PIN gating). **No cookies at all**: `grep -rlo "document.cookie"` over `modules/`, `app.js` and `apploader.js` returns nothing. So `localStorage` is the whole story.

### 6.2 The exact stored shape

> ### ⚠️ Evidence boundary for everything in §6.2 — read before implementing
> **The credential format below is read from the shipped 4.9.5.0 client JavaScript. It was NOT observed in a browser** — no browser, headless or otherwise, was available in the probe environment, so no `localStorage` write was ever executed and no DOM behaviour was witnessed. Full statement of what *is* observed vs read: **§6.8**.
>
> The source is unambiguous and I do not hedge the claims — but the boundary travels with the data, so:
>
> **First acceptance test for Task 12/13, before building on this table:** complete an SSO sign-in through `/emby/Sso/Callback`, then confirm the browser lands on the **home screen** at `/web/index.html` and **not** the login screen. If it lands on the login screen, the format below is where to look first (most likely suspects, in order: the token written to `Servers[].AccessToken` instead of `Servers[].Users[]`, then an `ManualAddress` mismatch — §6.4).

The value is `JSON.stringify({ Servers: [ ... ] })` (plus optional `ConnectUserId` / `ConnectAccessToken` for Emby Connect, which we do not touch).

**The access token does NOT live at the server level. It lives in a per-user `Users[]` array.** This is the single most important detail, and it is easy to get wrong. `connectionmanager.js`:

```js
function updateUserAuthenticationInfoOnServer(server,userId,accessToken){
  if(accessToken){
    server.UserId = userId;
    server.AccessToken = null; delete server.AccessToken;      // <-- server-level token is DELETED
    for(var users=(server.Users||[]).slice(0),i=0,length=users.length;i<length;i++){
      var user=users[i];
      if(user.UserId===userId) return void(user.AccessToken=accessToken);
    }
    users.push({UserId:userId,AccessToken:accessToken});
    server.Users = users;
  } else removeUserFromServer(server,userId);
}

function getUserAuthInfoFromServer(server,userId){
  if(server.Users) for(var users=(server.Users||[]).slice(0),i=0,l=users.length;i<l;i++){
    var user=users[i]; if(user.UserId===userId) return user; }
  return null;
}
function getLastUserAuthInfoFromServer(server){
  return server.UserId ? getUserAuthInfoFromServer(server,server.UserId) : null;
}
```

I checked **every** occurrence of `.AccessToken` in `connectionmanager.js`: the only places `server.AccessToken` appears are `addOrUpdateServer` (merge bookkeeping) and the three functions that `delete` it. **Nothing ever reads `server.AccessToken`.** All reads go through `Users[]`.

The canonical writer is `onAuthenticated`, which the client runs after its own interactive login:

```js
function onAuthenticated(apiClient,result){
  var options={}, credentials=_credentials.default.credentials();
  var servers=credentials.Servers.filter(function(s){return s.Id===result.ServerId});
  var server=servers.length?servers[0]:apiClient.serverInfo();
  server.DateLastAccessed = Date.now();
  server.Id = result.ServerId;
  updateUserAuthenticationInfoOnServer(server, result.User.Id, result.AccessToken);
  _credentials.default.addOrUpdateServer(credentials.Servers,server) && _credentials.default.credentials(credentials);
  ...
}
```

**So the object our page must produce is exactly what `onAuthenticated` produces.** Concrete, real example — built from a live `AuthenticateByName` response and a live `GET /emby/System/Info` on this server (token since revoked):

```json
{
  "Servers": [
    {
      "Id": "c5bc6e91458540caa295c4efdda1a58a",
      "Name": "KC Bios",
      "ManualAddress": "http://10.10.140.5:8090",
      "ManualAddressOnly": true,
      "IsLocalServer": true,
      "LastConnectionMode": 2,
      "DateLastAccessed": 1788123456789,
      "UserId": "5c2bf06fe9434e5ebb333ebe53a33445",
      "Users": [
        { "UserId": "5c2bf06fe9434e5ebb333ebe53a33445",
          "AccessToken": "bf40735059274247a4f2df38247a58f6" }
      ]
    }
  ]
}
```

Literal `localStorage` value (one line, no whitespace — `JSON.stringify` output):

```
{"Servers":[{"Id":"c5bc6e91458540caa295c4efdda1a58a","Name":"KC Bios","ManualAddress":"http://10.10.140.5:8090","ManualAddressOnly":true,"IsLocalServer":true,"LastConnectionMode":2,"DateLastAccessed":1788123456789,"UserId":"5c2bf06fe9434e5ebb333ebe53a33445","Users":[{"UserId":"5c2bf06fe9434e5ebb333ebe53a33445","AccessToken":"bf40735059274247a4f2df38247a58f6"}]}]}
```

Field by field — **read from client source, not browser-observed (§6.8); verify with the acceptance test above**:

| Field | Required? | Where it comes from | Notes |
|---|---|---|---|
| `Id` | **yes** | auth response `.ServerId` (or `GET /emby/System/Info/Public` → `.Id`) | keys the ApiClient map |
| `UserId` | **yes** | auth response `.User.Id` | `getLastUserAuthInfoFromServer` uses it to index `Users` |
| `Users[].UserId` / `Users[].AccessToken` | **yes** | auth response `.User.Id` / `.AccessToken` | **this is where the token must go** |
| `ManualAddress` | **yes** | the origin the client will compute (see §6.4) | must match, case-insensitively |
| `ManualAddressOnly` | **yes in practice** | literal `true` | see §6.4 — without it the client may try the server's advertised, unreachable addresses |
| `LastConnectionMode` | recommended | literal `2` (`ConnectionMode_Manual`; Local=0, Remote=1) | `getApiClientFromServerInfo` sets it from `ManualAddress` if null, but be explicit |
| `IsLocalServer` | recommended | literal `true` | lets `_getOrAddApiClient` reuse the singleton ApiClient |
| `DateLastAccessed` | **yes** | `Date.now()` | servers are sorted by this descending; a stale value loses to a competing entry |
| `Name` | optional | `GET /emby/System/Info` → `.ServerName` | cosmetic; overwritten by `updateServerInfo` on connect |
| `AccessToken` at server level | **no — omit it** | — | nothing reads it; the client deletes it |
| `Type` | no | — | set at runtime by `setServerProperties(server){server.Type="Server"}` |
| `LocalAddress` / `RemoteAddress` | no | — | filled in by `updateServerInfo` after a successful connect |

### 6.3 What the client does with it on startup

**Observed (source).** `autoLogin` defaults to `"lastuser"` (`modules/common/appsettings.js`: `return this.get("autoLogin")||"lastuser"`), which routes to `getLastUserAuthInfoFromServer(server)`.

`connect()` → `getAvailableServers()` (saved servers, sorted `DateLastAccessed` descending) → `connectToServer(first)` → `afterConnectValidated(...)`:

```js
var userAuthInfo = (options.userId ? getUserAuthInfoFromServer(server, options.userId)
                                   : /* autoLogin==="lastuser" */ getLastUserAuthInfoFromServer(server)) || {};
if (verifyLocalAuthentication && userAuthInfo.UserId && userAuthInfo.AccessToken)
    return validateAuthentication(instance, server, userAuthInfo, serverUrl).then(...);
...
result.State = userAuthInfo.UserId && userAuthInfo.AccessToken
               && "none" !== autoLogin && "showlogin" !== autoLogin ? "SignedIn" : "ServerSignIn";
```

and the validation step is:

```js
function validateAuthentication(instance,server,userAuthInfo,serverUrl){
  return ajax({type:"GET",
               url: instance.getEmbyServerUrl(serverUrl,"System/Info",{api_key:userAuthInfo.AccessToken}),
               dataType:"json"})
    .then(function(systemInfo){ updateServerInfo(server,systemInfo); return systemInfo; },
          function(){ removeUserFromServer(server,userId); return Promise.resolve(); });
}
```

So: **a stored token that does not answer `GET /System/Info?api_key=<token>` with a 2xx is discarded and the user lands on the login screen.** That is the exact call I verified in §6.6.

### 6.4 The address-matching trap (real failure mode — design around it)

`app.js` bootstraps the singleton ApiClient like this (deminified):

```js
if (!appHost.supports("multiserver")) {
  connectionManager.enableServerAddressValidation = false;
  var accessToken = null, userId = null;
  if (window.location.search) {
    var q = new URLSearchParams(window.location.search);
    accessToken = q.get("accessToken"); userId = q.get("userId");
    if (!(accessToken && userId && q.get("e") === "1")) userId = accessToken = null;
  }
  connectionManager.validateServerIds = false;
  var href = window.location.href.toLowerCase();
  var i = href.lastIndexOf("/web");
  var serverAddress = i !== -1 ? href.substring(0, i)
      : location.protocol + "//" + location.hostname + (location.port ? ":" + location.port : "");
  var apiClient = connectionManager.getApiClientFromServerInfo(
      { ManualAddress: serverAddress, ManualAddressOnly: true, IsLocalServer: true,
        AccessToken: accessToken, UserId: userId }, serverAddress);
  if (accessToken && userId) window.location = "index.html";
  apiClient.enableAutomaticNetworking = false;
}
```

and `getApiClientFromServerInfo` merges that object into the stored list:

```js
ConnectionManager.prototype.getApiClientFromServerInfo = function(server, serverUrlToMatch){
  server.DateLastAccessed = Date.now();
  if (server.LastConnectionMode == null && server.ManualAddress) server.LastConnectionMode = ConnectionMode_Manual;
  var credentials = _credentials.default.credentials();
  if (_credentials.default.addOrUpdateServer(credentials.Servers, server, serverUrlToMatch))
      _credentials.default.credentials(credentials);          // persists to localStorage
  ...
};
```

`addOrUpdateServer` matches by `Id` **first**, and the object above has **no `Id`**, so it falls back to matching `serverUrlToMatch` case-insensitively against the stored entry's `ManualAddress` / `LocalAddress` / `RemoteAddress`. If nothing matches it does `list.push(server)` — **a second, credential-less entry with `DateLastAccessed = Date.now()`**, which then sorts *first* and wins, and the user sees the login screen even though our credentials are sitting right there.

> **Therefore: our stored `ManualAddress` must equal the string `app.js` computes.** Do not use `location.origin` blindly. Because our callback page's URL contains no `/web`, it hits the second branch; but a reverse-proxy sub-path (`https://media.example.com/emby/web/index.html`) makes `app.js` compute `https://media.example.com/emby` while `location.origin` would give `https://media.example.com`. Derive the address by stripping our own known route off our own URL:
>
> ```js
> // page is served at <base>/emby/Sso/Callback
> var base = location.href.toLowerCase().split("?")[0].split("#")[0]
>                    .replace(/\/emby\/sso\/callback\/?$/, "");
> ```
>
> Matching is case-insensitive (`stringEqualsIgnoreCase`), and `app.js` lowercases in the `/web` branch, so writing a lowercased address is safe and consistent.

**`ManualAddressOnly: true` also matters.** On this server `GET /emby/System/Info` reports (observed):

```
LocalAddress : "http://172.30.1.7:8096"      <- the container's internal address
WanAddress   : "http://213.197.12.36:8096"
```

Neither is reachable as `http://10.10.140.5:8090`. `updateServerInfo` copies those into `server.LocalAddress` / `server.RemoteAddress` after a successful connect, and `connectToServer` races **all** the addresses it knows unless `ManualAddressOnly` is set. Set it.

### 6.5 The `?accessToken=&userId=&e=1` query-string entry point — **do not rely on it**

`app.js` (quoted above) accepts `accessToken`, `userId` and `e=1` on the web app's query string and, if all three are present, feeds them into `getApiClientFromServerInfo` and then redirects to `index.html`. That looks like a purpose-built handoff hook and would be much simpler than writing `localStorage` ourselves.

**Reading the code, it does not appear to work in 4.9.5.0's browser client.** The values are placed at the *server level* (`AccessToken`, `UserId` on the server object), `addOrUpdateServer` stores them there, and — per §6.2 — **nothing ever reads `server.AccessToken`**. Both `_getOrAddApiClient` and `afterConnectValidated` obtain the token via `getLastUserAuthInfoFromServer(server)`, which requires a `Users[]` entry that this path never creates. On the follow-up load of `index.html` the query string is gone, so nothing repairs it.

**Honesty:** this is a code-reading conclusion, not an observation — no browser was available. It is possible some path I did not find populates `Users[]`. Treat the query-string hook as an *optimisation to test later*, not as the mechanism. The `localStorage` write in §6.6 is provably the shape the client itself produces and does not depend on this.

### 6.6 `POST /emby/Users/AuthenticateByName` — observed live

**The client-identity headers are mandatory.** Without them (observed):

```
POST /emby/Users/AuthenticateByName   (Content-Type: application/json only)
→ HTTP/1.1 400
   Value cannot be null. (Parameter 'appName')
```

Three forms all return **200** (all observed):

1. Single combined header (what most tooling uses):
   ```
   X-Emby-Authorization: MediaBrowser Client="Emby Web", Device="SSO Handoff", DeviceId="<id>", Version="4.9.5.0"
   ```
2. Discrete headers — **recommended for our page, simplest to build**:
   ```
   X-Emby-Client: Emby Web
   X-Emby-Device-Name: <browser name>
   X-Emby-Device-Id: <stable per-browser id>
   X-Emby-Client-Version: 4.9.5.0
   ```
3. The same four as **query-string parameters**. This is in fact what the 4.9.5.0 web client itself does — `apiclient.js`:
   ```js
   ApiClient.prototype.setAuthorizationInfoIntoRequest = function(request, includeAccessToken){
     var authValues = {};
     if (this._appName)    authValues["X-Emby-Client"]         = this._appName;
     if (this._deviceName) authValues["X-Emby-Device-Name"]    = this._deviceName;
     if (this._deviceId)   authValues["X-Emby-Device-Id"]      = this._deviceId;
     if (this._appVersion) authValues["X-Emby-Client-Version"] = this._appVersion;
     if (includeAccessToken !== false && this.accessToken()) authValues["X-Emby-Token"] = this.accessToken();
     if (this.getCurrentLocale()) authValues["X-Emby-Language"] = this.getCurrentLocale();
     var qs = new URLSearchParams(authValues).toString();
     if (qs) request.url += (request.url.includes("?") ? "&" : "?") + qs;
   };
   ```

Request body: `{"Username":"<name>","Pw":"<password>"}` with `Content-Type: application/json`.

**Response (observed, 200, `Content-Type: application/json; charset=utf-8`, 2844 bytes).** Top-level keys are exactly:

```
["User", "SessionInfo", "AccessToken", "ServerId"]
```

with, for the probe account:

```
AccessToken     : "bf40735059274247a4f2df38247a58f6"     (32 lowercase hex)
ServerId        : "c5bc6e91458540caa295c4efdda1a58a"
User.Id         : "5c2bf06fe9434e5ebb333ebe53a33445"
User.Name       : "claude"
User.ServerId   : "c5bc6e91458540caa295c4efdda1a58a"
User keys       : Name, ServerId, Prefix, DateCreated, Id, HasPassword, HasConfiguredPassword,
                  LastLoginDate, LastActivityDate, Configuration, Policy
SessionInfo keys: PlayState, AdditionalUsers, RemoteEndPoint, Protocol, PlayableMediaTypes,
                  PlaylistIndex, PlaylistLength, Id, ServerId, UserId, UserName, Client,
                  LastActivityDate, DeviceName, InternalDeviceId, DeviceId, ApplicationVersion,
                  SupportedCommands, SupportsRemoteControl
```

**Everything the credential store needs is in this one response** — `AccessToken`, `ServerId`, `User.Id`. `SessionInfo` is not used by the store. `Name` (nice-to-have) comes from `GET /emby/System/Info` → `.ServerName`, or `GET /emby/System/Info/Public` → `.ServerName` if you want an anonymous call.

### 6.7 Decision forced — the completion page's sequence

**Decision:** the browser flow's final step is served by the plugin itself. `/emby/Sso/Callback` returns an HTML page whose inline script authenticates against `/emby/Users/AuthenticateByName` with the one-time handoff secret as the password, merges the result into `localStorage["servercredentials3"]` (token into `Users[]`, per §6.2), and then redirects to `/web/index.html`. No injection into any Emby-owned page is required, and no `sessionStorage` or cookie is involved. Task 12 implements this page; Task 13 documents the lock-out consequences from §1l.

**Acceptance test that closes the §6.8 evidence gap:** open `/emby/Sso/Callback` in a real browser and confirm it lands on the home screen, not the login screen. Do this first, before building anything else on §6.2.

Our `/emby/Sso/Callback` handler validates the OIDC code, resolves the Emby user, mints a one-time handoff secret, and returns an HTML page (per §2g: `Request.ResponseContentType = "text/html"` first). That page's inline script does:

```js
(function () {
  var USERNAME = "…";        // server-rendered
  var HANDOFF  = "…";        // server-rendered one-time secret; used as the password
  var SERVER_ID = "…";       // server-rendered from IServerApplicationHost.SystemId — saves a round trip

  // 1. the address the web client will compute for itself
  var base = location.href.toLowerCase().split("?")[0].split("#")[0]
                     .replace(/\/emby\/sso\/callback\/?$/, "");

  // 2. a stable per-browser device id, so repeat sign-ins reuse one device row
  var deviceId = localStorage.getItem("embysso-deviceid");
  if (!deviceId) {
    deviceId = (crypto.randomUUID && crypto.randomUUID()) ||
               (Date.now().toString(16) + Math.random().toString(16).slice(2));
    localStorage.setItem("embysso-deviceid", deviceId);
  }

  // 3. authenticate — the plugin's IAuthenticationProvider validates HANDOFF and burns it
  fetch(base + "/emby/Users/AuthenticateByName", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Emby-Client": "Emby Web",
      "X-Emby-Device-Name": "Browser",
      "X-Emby-Device-Id": deviceId,
      "X-Emby-Client-Version": "4.9.5.0"
    },
    body: JSON.stringify({ Username: USERNAME, Pw: HANDOFF })
  })
  .then(function (r) { if (!r.ok) throw new Error("auth failed: " + r.status); return r.json(); })
  .then(function (result) {

    // 4. MERGE into the existing store — never blind-overwrite (other servers/users may be present)
    var creds;
    try { creds = JSON.parse(localStorage.getItem("servercredentials3") || "{}"); } catch (e) { creds = {}; }
    if (!creds.Servers) creds.Servers = [];

    var entry = null;
    for (var i = 0; i < creds.Servers.length; i++) {
      var s = creds.Servers[i];
      if (s.Id === result.ServerId ||
          (s.ManualAddress || "").toLowerCase() === base) { entry = s; break; }
    }
    if (!entry) { entry = {}; creds.Servers.push(entry); }

    entry.Id                = result.ServerId;
    entry.ManualAddress     = base;
    entry.ManualAddressOnly = true;
    entry.IsLocalServer     = true;
    entry.LastConnectionMode= 2;                 // ConnectionMode_Manual
    entry.DateLastAccessed  = Date.now();
    entry.UserId            = result.User.Id;

    // the token goes in Users[] — NOT entry.AccessToken
    delete entry.AccessToken;
    if (!entry.Users) entry.Users = [];
    var found = false;
    for (var j = 0; j < entry.Users.length; j++) {
      if (entry.Users[j].UserId === result.User.Id) { entry.Users[j].AccessToken = result.AccessToken; found = true; break; }
    }
    if (!found) entry.Users.push({ UserId: result.User.Id, AccessToken: result.AccessToken });

    localStorage.setItem("servercredentials3", JSON.stringify(creds));

    // 5. hand over to the web client
    location.replace(base + "/web/index.html");
  })
  .catch(function (err) { /* render a visible failure with a link back to /emby/Sso/Start */ });
})();
```

Notes:
- **No `sessionStorage` and no cookie are needed.** (§6.1)
- Because the plugin's `IAuthenticationProvider` is what validates `HANDOFF`, the password field carries the one-time secret; nothing in the browser ever sees the OIDC tokens.
- `SERVER_ID` is rendered for convenience only — `result.ServerId` from the auth response is authoritative and is what the code above uses.
- Rendering `USERNAME`/`HANDOFF` into the page: JSON-encode and HTML-escape them. The username originates from the IdP.
- If `location.protocol` is `https:` the whole flow is same-origin and unaffected; over plain HTTP the token is exposed on the wire exactly as it already is for the normal login form.

### 6.8 End-to-end verification with `curl` — what is observed vs read

**Observed** (run against the live server; token has since been revoked):

| Step | Call | Result |
|---|---|---|
| auth, no identity headers | `POST /emby/Users/AuthenticateByName` | **400** `Value cannot be null. (Parameter 'appName')` |
| auth, `X-Emby-Authorization` | same + combined header | **200**, full body above |
| auth, discrete `X-Emby-*` headers | same + 4 headers | **200** |
| **exactly the client's startup check** | `GET /emby/System/Info?api_key=<token>` | **200**, `Id=c5bc6e91458540caa295c4efdda1a58a`, `ServerName=KC Bios`, `Version=4.9.5.0`, `LocalAddress=http://172.30.1.7:8096`, `WanAddress=http://213.197.12.36:8096` |
| authenticated API call | `GET /emby/Users/{id}` with `X-Emby-Token` | **200** |
| authenticated API call | `GET /emby/Users/{id}/Views` with `X-Emby-Token` | **200** |
| authenticated API call | `GET /emby/Sessions?api_key=<token>` | **200** |
| negative control | `GET /emby/System/Info?api_key=000…0` | **401** |
| after logout | same call with the revoked token | **401** |

So: a token minted by `AuthenticateByName` from a non-browser client satisfies precisely the check the web client performs on startup, and works for ordinary authenticated requests. **Every server-side link in the chain is observed.**

**Read from source, not observed:** the `localStorage` write and the client's reaction to it. No browser (headless or otherwise) was available in the probe environment, so nothing at DOM level was executed. What is *read* is unambiguous — the key name, the `JSON.stringify` round-trip, the `Users[]` indirection, the `autoLogin` default, and the `System/Info?api_key=` validation. **A single browser check would upgrade this to fully observed, and Task 12/13 should do it as their first acceptance test:** open `/emby/Sso/Callback`, then confirm `/web/index.html` lands on the home screen rather than the login screen.

### 6.9 How stable is this?

| Signal | Assessment |
|---|---|
| **Is the key versioned?** | Yes — `servercredentials3`. The trailing digit is the format version. Emby has bumped it before (1 → 2 → 3), and there is **no migration code** in the 4.9.5.0 bundle: a bump silently abandons the old key and users re-log-in. |
| **Blast radius of a bump** | Low and self-healing. If Emby ships `servercredentials4`, our page writes a key nothing reads, `/web/index.html` shows the login screen, and the user is inconvenienced — not locked out or corrupted. |
| **Likelihood of change** | Low per-release, non-zero across major versions. The shape (`Servers[].Users[].AccessToken`) has been stable across the Emby 4.x line and is shared with the mobile/TV clients, so it is not a casual internal detail. |
| **Is anything else fragile?** | Two things, both called out above: the **address match** (§6.4) and the assumption that `autoLogin` is `"lastuser"`. A user who has explicitly set auto-login to `none`/`showlogin` will get the login screen no matter what we store — correctly so. |
| **Recommended mitigation** | Put the key name and the entry shape in **one** constant/builder in Task 12, not scattered. Add a plugin config toggle for the key name if that is cheap. Make the callback page verify its own work: after writing, `GET {base}/emby/System/Info?api_key=<token>`; if that is not 200, show an explicit failure instead of bouncing the user to a login screen with no explanation. |

**Bottom line: the completion page is feasible and is a better mechanism than the injection it replaces**, because it depends only on same-origin `localStorage` plus a public, stable HTTP API — no hook Emby has to agree to offer.

---

## Quick reference for later tasks

| Thing | Answer |
|---|---|
| Provider interfaces | `IAuthenticationProvider, IRequiresResolvedUser` (`MediaBrowser.Controller.Authentication`) |
| Overload Emby calls | `Authenticate(string username, string password, User resolvedUser)` |
| `resolvedUser` | non-null for existing user; **null** for unknown username (all providers tried; success auto-creates the user) |
| Provider id string | full CLR type name, e.g. `Emby.Sso.Auth.SsoAuthenticationProvider` |
| Set provider on a user | `POST /emby/Users/{id}/Policy` with full policy JSON + `AuthenticationProviderId` |
| List providers | `GET /emby/Auth/Providers` (authenticated) |
| Dashboard selector | `.fldSelectLoginProvider`, visible only when >1 provider **and** the user is not an administrator |
| Reject a login | `throw new System.Exception("Invalid username or password.")` → 401 |
| User with **no** provider assigned | every enabled provider is tried (Default first), and the winner is **stamped** onto `Policy.AuthenticationProviderId` (§1j–1k) |
| Once stamped | only that provider is consulted — an SSO-stamped user **cannot** use their Emby password (§1l). Keep a Default-provider break-glass admin |
| Endpoint URL | `http://<emby>/emby/Sso/<Route>` (bare `/Sso/<Route>` also works) |
| Anonymous endpoint | `[MediaBrowser.Controller.Net.Unauthenticated]` on the request DTO |
| Result factory | `MediaBrowser.Controller.Net.IHttpResultFactory`, **constructor-injected** (property injection via `IHasResultFactory` is broken) |
| `IRequest` | property injection via `MediaBrowser.Model.Services.IRequiresRequest` works |
| 302 redirect | `resultFactory.GetRedirectResult(url)` |
| HTML body | `Request.ResponseContentType = "text/html";` then `resultFactory.GetResult(Request, html.AsSpan(), "text/html", null)` |
| Login-page script injection | **impossible** — bookmarkable `/emby/Sso/Start` is the only entry point |
| Completing sign-in without injection | the plugin's own `/emby/Sso/Callback` page writes the web client's credential store (§6) |
| Credential store *(read from client source, not browser-observed — §6.8)* | `localStorage["servercredentials3"]` — plain `localStorage` in a browser; the only key involved |
| Stored value *(read from source — §6.8)* | `JSON.stringify({Servers:[{...}]})` |
| **Where the token goes** *(read from source — §6.8)* | `Servers[].Users[] = [{UserId, AccessToken}]` — **never** `Servers[].AccessToken` (the client deletes that and nothing reads it) |
| Other required entry fields *(read from source — §6.8)* | `Id`, `UserId`, `ManualAddress`, `ManualAddressOnly:true`, `IsLocalServer:true`, `LastConnectionMode:2`, `DateLastAccessed` |
| `ManualAddress` must equal | the address `app.js` computes: `location.href.toLowerCase()` truncated at `lastIndexOf("/web")`, else `protocol//hostname[:port]`. Mismatch ⇒ a second credential-less entry wins and the login screen appears (§6.4) |
| Auth call | `POST /emby/Users/AuthenticateByName`, body `{"Username","Pw"}`, **client-identity headers mandatory** (`X-Emby-Client`, `X-Emby-Device-Name`, `X-Emby-Device-Id`, `X-Emby-Client-Version`) — without them `400 Value cannot be null. (Parameter 'appName')` |
| Auth response | `{User, SessionInfo, AccessToken, ServerId}` — `AccessToken`, `ServerId`, `User.Id` are all the store needs |
| Client's startup token check | `GET /emby/System/Info?api_key=<token>`; non-2xx ⇒ token discarded, login screen |
| `autoLogin` default | `"lastuser"` ⇒ `getLastUserAuthInfoFromServer` ⇒ needs `UserId` + matching `Users[]` entry |
| sessionStorage / cookies | not used for auth (`sessionStorage["pinvalidated"]` only; no cookies anywhere) |
| `?accessToken=&userId=&e=1` on `/web/` | exists in `app.js` but stores the token where nothing reads it — **do not rely on it** (§6.5) |
| Redirect after writing the store | `location.replace(base + "/web/index.html")` |
| **First acceptance test for the credential format** | complete a sign-in via `/emby/Sso/Callback` in a real browser and confirm it lands on the **home screen**, not the login screen. Nothing in §6.2 was browser-verified (§6.8) — do this before building on it |
| Shipping artifact | `src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll` (single file, deps internalised) |
| `AuthenticationException` | does not exist — use `System.Exception` |

---

## Server state after the spike

Everything changed on `10.10.140.5` was reverted and the reversion verified after a final `docker restart emby`. This covers both the original spike and the 2026-08-30 addendum (§6), which installed the probe plugin twice more:

| Changed | Restored to | Verified |
|---|---|---|
| `/config/plugins/Emby.Sso.dll` installed | deleted | `ls` shows no `*Sso*`; `GET /Plugins` returns 19 plugins, no "Authentik SSO" |
| `claude`.`Policy.AuthenticationProviderId` set to `Emby.Sso.Auth.ProbeProvider` | **key removed entirely** (its original state — the key was absent, not `Default`) | `GET /emby/Users/{id}` shows no `AuthenticationProviderId`; on-disk `policy.xml` contains no `<AuthenticationProviderId>` element |
| branding `LoginDisclaimer` + `CustomCss` set | `{}` | `GET /emby/System/Configuration/branding` → `{}`; `GET /emby/Branding/Css` → 0 bytes |
| user `nosuchuser-probe` auto-created by the probe | deleted (`DELETE /emby/Users/{id}`), plus its empty leftover `config/users/<id>` directory removed | `GET /Users` lists only `claude` and `embyadmin` |
| probe devices `sso-probe-001`, `sso-probe-002`, `sso-probe-restore-check` | deleted | `GET /emby/Devices` lists only the pre-existing `Emby Web`/`Chrome` and `Emby for iOS` entries |
| access tokens minted by probe logins | revoked (`POST /emby/Sessions/Logout`) | `GET /emby/Sessions` shows only the server's own session |

`GET /System/Info/Public` → **200** (`4.9.5.0`, `KC Bios`). `POST /emby/Users/AuthenticateByName` as `claude` / `claude123` → **200**.
**`embyadmin` was never modified.**

**Addendum note on `Policy.AuthenticationProviderId`.** Per §1j, Emby **stamps** this field on every successful login. That means the "absent" baseline is not a stable state: the very act of verifying that `claude` can still sign in re-writes it to `Emby.Server.Implementations.Library.DefaultAuthenticationProvider`. The restore sequence was therefore ordered deliberately — sign-in check **first**, then clear the key — so the server was left in the exact state it was found (`grep -c AuthenticationProviderId .../policy.xml` → **0**). The user's next real sign-in will re-stamp `Default`, which is what would have happened anyway on their next login regardless of this spike.

**One residual cosmetic change, disclosed:** the final "can `claude` still sign in" check reused the existing browser device id `e152764f-…`, so that device row's `LastUserName` now reads `claude` instead of `embyadmin`, and `DateLastActivity`/`IpAddress` reflect the probe. The token that check created was revoked. `embyadmin`'s own credential on that device was not touched and deleting the device row (which would have reset the label) was deliberately avoided because it would have signed the user's browser out.


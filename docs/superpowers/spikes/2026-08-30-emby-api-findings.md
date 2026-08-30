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
| Endpoint URL | `http://<emby>/emby/Sso/<Route>` (bare `/Sso/<Route>` also works) |
| Anonymous endpoint | `[MediaBrowser.Controller.Net.Unauthenticated]` on the request DTO |
| Result factory | `MediaBrowser.Controller.Net.IHttpResultFactory`, **constructor-injected** (property injection via `IHasResultFactory` is broken) |
| `IRequest` | property injection via `MediaBrowser.Model.Services.IRequiresRequest` works |
| 302 redirect | `resultFactory.GetRedirectResult(url)` |
| HTML body | `Request.ResponseContentType = "text/html";` then `resultFactory.GetResult(Request, html.AsSpan(), "text/html", null)` |
| Login-page script injection | **impossible** — bookmarkable `/emby/Sso/Start` is the only entry point |
| Shipping artifact | `src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll` (single file, deps internalised) |
| `AuthenticationException` | does not exist — use `System.Exception` |

---

## Server state after the spike

Everything changed on `10.10.140.5` was reverted and the reversion verified after a final `docker restart emby`:

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

**One residual cosmetic change, disclosed:** the final "can `claude` still sign in" check reused the existing browser device id `e152764f-…`, so that device row's `LastUserName` now reads `claude` instead of `embyadmin`, and `DateLastActivity`/`IpAddress` reflect the probe. The token that check created was revoked. `embyadmin`'s own credential on that device was not touched and deleting the device row (which would have reset the label) was deliberately avoided because it would have signed the user's browser out.

# Emby OIDC SSO Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an Emby server plugin that authenticates users against Authentik over OpenID Connect, in the browser by redirect and in native apps by direct grant.

**Architecture:** A single `netstandard2.0` assembly. Security-critical protocol logic (PKCE, token validation, one-time secrets, credential decisions) lives in classes that reference no Emby types and are unit tested against a fake identity provider. A thin Emby-facing shell implements `IAuthenticationProvider`, `IRequiresResolvedUser` and `IService` endpoints. The browser flow ends by handing the web client a one-time secret which the plugin's own authentication provider accepts, so Emby issues the session through its normal login path.

**Tech Stack:** C#, netstandard2.0, `MediaBrowser.Server.Core` 4.9.x reference assemblies, `Microsoft.IdentityModel.*` 6.35.0 for JWT and OIDC metadata (merged and internalized with ILRepack), xUnit for tests.

**Spec:** `docs/superpowers/specs/2026-08-30-emby-oidc-sso-design.md`

## Global Constraints

- Target framework: `netstandard2.0`. Emby plugins do not load `net8.0` assemblies.
- Emby reference assemblies: NuGet package `MediaBrowser.Server.Core`, version `4.9.1.90`.
- The shipped plugin is **one file**, `Emby.Sso.dll`. All third-party dependencies are merged and internalized by ILRepack so they cannot conflict with assemblies Emby has already loaded.
- Classes under `src/Emby.Sso/Protocol/` MUST NOT reference any `MediaBrowser.*` type. This is what makes them testable without a server; a reviewer should reject any task that breaks it.
- The client secret, access tokens, ID tokens, passwords and handoff secrets are NEVER written to a log, an exception message, or an HTTP response body.
- All random values used as secrets come from `System.Security.Cryptography.RandomNumberGenerator`, never `System.Random`.
- Secret comparisons use the fixed-time comparison helper from Task 4, never `==` or `string.Equals`.
- Plugin display name: `Authentik SSO`. Plugin GUID is fixed at Task 3 and never changes.
- Every task ends with a commit. Test commands are run from the repository root.

## Deliberate deviation from the spec

The spec's architecture table has `PendingLoginStore` holding a return URL
alongside the nonce and PKCE verifier. This plan drops it. Nothing in the flow
needs a caller-supplied destination — sign-in always ends at the Emby web
client — and accepting one would create exactly the open-redirect surface the
spec's security section forbids. `PendingLogin` therefore carries state, nonce,
verifier, challenge and expiry only.

## Prerequisite knowledge

If you have not worked on an Emby plugin before, read these before Task 1:

- How to build a Server Plugin: https://github.com/MediaBrowser/Emby/wiki/How-to-build-a-Server-Plugin
- Creating API endpoints: https://dev.emby.media/doc/plugins/dev/Creating-Api-Endpoints.html
- Plugin API reference: https://dev.emby.media/reference/pluginapi/

The Emby interfaces this plugin implements, confirmed from the plugin API reference:

```csharp
namespace MediaBrowser.Controller.Authentication
{
    public interface IAuthenticationProvider
    {
        string Name { get; }
        bool IsEnabled { get; }
        Task<ProviderAuthenticationResult> Authenticate(string username, string password);
        Task ChangePassword(User user, string newPassword);
        Task<bool> HasPassword(User user);
    }

    public interface IRequiresResolvedUser
    {
        Task<ProviderAuthenticationResult> Authenticate(string username, string password, User resolvedUser);
    }

    public sealed class ProviderAuthenticationResult
    {
        public string Username { get; set; }
        public string DisplayName { get; set; }
    }
}
```

Emby assigns an authentication provider **per user**. An administrator must set each Emby user's authentication provider to `Authentik SSO` in that user's profile. The plugin never creates users.

## File structure

```
Emby.Sso.sln
src/Emby.Sso/
  Emby.Sso.csproj
  Plugin.cs                                 BasePlugin<PluginConfiguration>, IHasWebPages
  Configuration/PluginConfiguration.cs      settings model
  Configuration/configPage.html             embedded dashboard page
  Protocol/                                 NO MediaBrowser types below this line
    SecureRandom.cs                         CSPRNG tokens, PKCE verifier and challenge
    FixedTime.cs                            fixed-time byte comparison
    PendingLogin.cs                         in-flight browser login record
    PendingLoginStore.cs                    state -> nonce/verifier, single use, TTL
    HandoffSecretStore.cs                   one-time secret -> username, single use, TTL
    OidcOptions.cs                          protocol configuration, no Emby types
    OidcIdentity.cs                         subject, username, display name
    OidcClient.cs                           discovery, auth URL, code exchange, direct grant
    UsernameMatcher.cs                      claim value -> canonical Emby username
    SsoCredentialValidator.cs               handoff-or-direct-grant decision
    SsoErrors.cs                            user-safe error reasons
  Api/
    SsoService.cs                           IService: /Sso/Start, /Sso/Callback, /Sso/Script.js
    SsoRequests.cs                          request DTOs with Route attributes
    ErrorPage.cs                            plain HTML failure page
    LoginScript.cs                          injected JavaScript, served as text/javascript
  Auth/
    SsoAuthenticationProvider.cs            IAuthenticationProvider + IRequiresResolvedUser
  SsoRuntime.cs                             shared stores and the configured OIDC client
tests/Emby.Sso.Tests/
  Emby.Sso.Tests.csproj
  FakeIdentityProvider.cs                   RSA key, JWKS, signed tokens, stub HTTP handler
  TestClock.cs                              controllable time source
  PendingLoginStoreTests.cs
  HandoffSecretStoreTests.cs
  SecureRandomTests.cs
  OidcClientDiscoveryTests.cs
  OidcClientTokenTests.cs
  OidcClientDirectGrantTests.cs
  UsernameMatcherTests.cs
  SsoCredentialValidatorTests.cs
docs/superpowers/spikes/2026-08-30-emby-api-findings.md
.gitlab-ci.yml
README.md
```

---

### Task 1: Toolchain and a plugin that loads

**Files:**
- Create: `Emby.Sso.sln`
- Create: `src/Emby.Sso/Emby.Sso.csproj`
- Create: `src/Emby.Sso/Plugin.cs`
- Create: `src/Emby.Sso/Configuration/PluginConfiguration.cs`
- Create: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: `Emby.Sso.Plugin` with `public static Plugin Instance { get; private set; }` and `public PluginConfiguration Configuration { get; }` (inherited from `BasePlugin<T>`); `Emby.Sso.Configuration.PluginConfiguration` with the properties defined below.

- [ ] **Step 1: Install the .NET SDK**

```bash
curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
bash /tmp/dotnet-install.sh --channel 8.0 --install-dir "$HOME/.dotnet"
echo 'export PATH="$HOME/.dotnet:$PATH"' >> ~/.bashrc
export PATH="$HOME/.dotnet:$PATH"
dotnet --version
```

Expected: a version number prints. The .NET 8 SDK builds `netstandard2.0` targets; the target framework of the plugin is unaffected by the SDK version.

- [ ] **Step 2: Create the .gitignore**

```
bin/
obj/
*.user
.dotnet/
artifacts/
```

- [ ] **Step 3: Create the solution and project**

```bash
cd /home/coder/git/emby-sso
dotnet new sln -n Emby.Sso
mkdir -p src/Emby.Sso/Configuration
```

Write `src/Emby.Sso/Emby.Sso.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>netstandard2.0</TargetFramework>
    <AssemblyName>Emby.Sso</AssemblyName>
    <RootNamespace>Emby.Sso</RootNamespace>
    <LangVersion>latest</LangVersion>
    <GenerateAssemblyInfo>true</GenerateAssemblyInfo>
    <Version>0.1.0</Version>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="MediaBrowser.Server.Core" Version="4.9.1.90" PrivateAssets="all" ExcludeAssets="runtime" />
  </ItemGroup>

</Project>
```

`ExcludeAssets="runtime"` matters: the Emby assemblies are provided by the server at run time and must not be copied next to the plugin.

```bash
dotnet sln add src/Emby.Sso/Emby.Sso.csproj
```

- [ ] **Step 4: Write the configuration model**

`src/Emby.Sso/Configuration/PluginConfiguration.cs`:

```csharp
using MediaBrowser.Model.Plugins;

namespace Emby.Sso.Configuration
{
    public class PluginConfiguration : BasePluginConfiguration
    {
        public string IssuerUrl { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string Scopes { get; set; } = "openid profile email";
        public string EmbyPublicBaseUrl { get; set; } = string.Empty;
        public string UsernameClaim { get; set; } = "preferred_username";
        public bool EnableDirectGrant { get; set; } = false;
        public bool EnableButtonInjection { get; set; } = true;
        public bool AllowInsecureHttp { get; set; } = false;

        public bool IsConfigured =>
            !string.IsNullOrWhiteSpace(IssuerUrl) &&
            !string.IsNullOrWhiteSpace(ClientId) &&
            !string.IsNullOrWhiteSpace(EmbyPublicBaseUrl);
    }
}
```

- [ ] **Step 5: Write the plugin class**

Generate a GUID once and use it forever: `python3 -c "import uuid; print(uuid.uuid4())"`. Substitute it below.

`src/Emby.Sso/Plugin.cs`:

```csharp
using System;
using Emby.Sso.Configuration;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Serialization;

namespace Emby.Sso
{
    public class Plugin : BasePlugin<PluginConfiguration>
    {
        public static Plugin Instance { get; private set; }

        public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
            : base(applicationPaths, xmlSerializer)
        {
            Instance = this;
        }

        public override Guid Id => new Guid("PASTE-YOUR-GENERATED-GUID-HERE");

        public override string Name => "Authentik SSO";

        public override string Description =>
            "Sign in to Emby with an OpenID Connect provider such as Authentik.";
    }
}
```

- [ ] **Step 6: Build**

Run: `dotnet build -c Release`
Expected: build succeeds and `src/Emby.Sso/bin/Release/netstandard2.0/Emby.Sso.dll` exists. If `MediaBrowser.Server.Core` 4.9.1.90 cannot be restored, run `dotnet package search MediaBrowser.Server.Core --exact-match --prerelease` to find the current version, use it, and record the change in the commit message.

- [ ] **Step 7: Install into the test Emby server and confirm it loads**

Copy `Emby.Sso.dll` into the Emby server's `plugins` directory and restart Emby. Open Dashboard, then Plugins.
Expected: **Authentik SSO** appears in the installed plugin list. If it does not, check the Emby server log for a plugin load error; a `TargetFramework` or missing-dependency mistake shows up here.

- [ ] **Step 8: Commit**

```bash
git add .gitignore Emby.Sso.sln src/
git commit -m "feat: scaffold Emby SSO plugin that loads in the server"
```

---

### Task 2: Spike — confirm the four unknowns

This task writes throwaway code. Its deliverable is a findings document. Do not build features here.

**Files:**
- Create: `docs/superpowers/spikes/2026-08-30-emby-api-findings.md`
- Temporarily modify: `src/Emby.Sso/Plugin.cs` and scratch files, all reverted at the end except the findings document and any csproj change the spike proves necessary.

**Interfaces:**
- Consumes: `Emby.Sso.Plugin` from Task 1.
- Produces: `docs/superpowers/spikes/2026-08-30-emby-api-findings.md`, which Tasks 11 through 13 read for the confirmed route prefix, the correct redirect mechanism, the endpoint authentication attribute, and whether script injection is available.

- [ ] **Step 1: Probe whether Emby calls a third-party authentication provider**

Add a temporary file `src/Emby.Sso/Auth/ProbeProvider.cs`:

```csharp
using System.Threading.Tasks;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Model.Logging;

namespace Emby.Sso.Auth
{
    public class ProbeProvider : IAuthenticationProvider, IRequiresResolvedUser
    {
        private readonly ILogger _logger;

        public ProbeProvider(ILogManager logManager)
        {
            _logger = logManager.GetLogger("SsoProbe");
        }

        public string Name => "Authentik SSO";

        public bool IsEnabled => true;

        public Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        {
            _logger.Info("PROBE: two-argument Authenticate called for {0}", username);
            return Task.FromResult(new ProviderAuthenticationResult { Username = username });
        }

        public Task<ProviderAuthenticationResult> Authenticate(string username, string password, User resolvedUser)
        {
            _logger.Info("PROBE: resolved-user Authenticate called, resolvedUser is null: {0}", resolvedUser == null);
            return Task.FromResult(new ProviderAuthenticationResult { Username = username });
        }

        public Task ChangePassword(User user, string newPassword) => Task.FromResult(true);

        public Task<bool> HasPassword(User user) => Task.FromResult(true);
    }
}
```

Build, install, restart Emby. In the Emby dashboard open a test user's profile and look for an authentication provider selector.

Record in the findings document:
- Does `Authentik SSO` appear as a selectable authentication provider for a user? **This is the make-or-break answer.**
- After selecting it and logging in as that user with any password, which of the two `Authenticate` overloads is called, and is `resolvedUser` null?
- What happens when logging in with a username that does not exist in Emby: is the provider called at all?

If the provider does not appear, **stop and report back**. The design's browser handoff and native flow both depend on this, and the spec says the design returns for revision rather than proceeding.

- [ ] **Step 2: Probe the endpoint route prefix and the redirect mechanism**

Add a temporary file `src/Emby.Sso/Api/ProbeService.cs`:

```csharp
using MediaBrowser.Model.Services;

namespace Emby.Sso.Api
{
    [Route("/Sso/Probe", "GET")]
    public class SsoProbe : IReturnVoid
    {
    }

    public class ProbeService : IService, IHasResultFactory
    {
        public IHttpResultFactory ResultFactory { get; set; }
        public IRequest Request { get; set; }

        public object Get(SsoProbe request)
        {
            return ResultFactory.GetResult(Request, "probe ok", "text/plain");
        }
    }
}
```

Build, install, restart. Try both `http://<emby>:8096/emby/Sso/Probe` and `http://<emby>:8096/Sso/Probe`.

Record: which URL works, whether the endpoint is reachable without being logged in, and if it requires authentication, what attribute controls that. Then inspect `IHttpResultFactory` in the plugin API reference at https://dev.emby.media/reference/pluginapi/MediaBrowser.Model.Services.IHttpResultFactory.html and record the exact way to return a 302 redirect and the exact way to return an HTML body. If no redirect helper exists, record the fallback: return an HTML page whose body is `<script>location.replace(...)</script>`.

- [ ] **Step 3: Probe script injection on the login page**

In the Emby dashboard, find the branding or custom CSS/HTML setting. Enter a marker such as `<script>console.log('sso-probe')</script>` plus a plain `<b>marker</b>`, save, and load the login page in a browser with the developer console open.

Record: is the plain HTML rendered, is the script executed, is the script stripped, and what is the exact name and location of the setting. If scripts are stripped, record that the injected button is unavailable and the bookmarkable URL is the only entry point.

- [ ] **Step 4: Probe ILRepack merging**

Add `Microsoft.IdentityModel.JsonWebTokens` 6.35.0 and `Microsoft.IdentityModel.Protocols.OpenIdConnect` 6.35.0 to the plugin csproj, plus `ILRepack.Lib.MSBuild.Task` 2.0.34.1, and merge the dependencies internalized into `Emby.Sso.dll`:

```xml
  <ItemGroup>
    <PackageReference Include="Microsoft.IdentityModel.JsonWebTokens" Version="6.35.0" />
    <PackageReference Include="Microsoft.IdentityModel.Protocols.OpenIdConnect" Version="6.35.0" />
    <PackageReference Include="ILRepack.Lib.MSBuild.Task" Version="2.0.34.1" PrivateAssets="all" />
  </ItemGroup>

  <Target Name="MergeDependencies" AfterTargets="Build" Condition="'$(Configuration)' == 'Release'">
    <ItemGroup>
      <MergeInput Include="$(OutputPath)$(AssemblyName).dll" />
      <MergeInput Include="$(OutputPath)Microsoft.IdentityModel.*.dll" />
      <MergeInput Include="$(OutputPath)Newtonsoft.Json.dll" />
      <MergeInput Include="$(OutputPath)System.IdentityModel.Tokens.Jwt.dll" />
    </ItemGroup>
    <ILRepack
      Parallel="true"
      Internalize="true"
      InputAssemblies="@(MergeInput)"
      TargetKind="Dll"
      OutputFile="$(OutputPath)merged/$(AssemblyName).dll" />
  </Target>
```

Build in Release, install `bin/Release/netstandard2.0/merged/Emby.Sso.dll`, restart Emby.

Record: does the merged single-file plugin still load and does the probe provider still appear? If merging fails, record the fallback decision — ship the dependency DLLs alongside the plugin DLL and note whether Emby loads them cleanly.

- [ ] **Step 5: Write the findings document**

Create `docs/superpowers/spikes/2026-08-30-emby-api-findings.md` with one section per probe, each stating the question, the observed result, and the decision it forces. Include exact URLs, exact setting names, and exact API signatures observed. Later tasks depend on this being specific rather than impressionistic.

- [ ] **Step 6: Remove the probe code**

```bash
git rm -f --ignore-unmatch src/Emby.Sso/Auth/ProbeProvider.cs src/Emby.Sso/Api/ProbeService.cs
rm -f src/Emby.Sso/Auth/ProbeProvider.cs src/Emby.Sso/Api/ProbeService.cs
```

Keep the csproj changes from Step 4 if merging worked. Run `dotnet build -c Release` and confirm it still succeeds.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "docs: record Emby plugin API spike findings"
```

---

### Task 3: Secure random and PKCE

**Files:**
- Create: `src/Emby.Sso/Protocol/SecureRandom.cs`
- Create: `tests/Emby.Sso.Tests/Emby.Sso.Tests.csproj`
- Test: `tests/Emby.Sso.Tests/SecureRandomTests.cs`

**Interfaces:**
- Consumes: nothing.
- Produces: `Emby.Sso.Protocol.SecureRandom` with `public static string CreateToken(int byteLength)`, `public static string CreateCodeVerifier()`, `public static string CreateCodeChallenge(string verifier)`. All return base64url strings without padding.

- [ ] **Step 1: Create the test project**

```bash
cd /home/coder/git/emby-sso
mkdir -p tests/Emby.Sso.Tests
```

`tests/Emby.Sso.Tests/Emby.Sso.Tests.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <LangVersion>latest</LangVersion>
    <IsPackable>false</IsPackable>
    <Nullable>disable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.11.1" />
    <PackageReference Include="xunit" Version="2.9.2" />
    <PackageReference Include="xunit.runner.visualstudio" Version="2.8.2" />
  </ItemGroup>

  <ItemGroup>
    <Compile Include="../../src/Emby.Sso/Protocol/**/*.cs" LinkBase="Protocol" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.IdentityModel.JsonWebTokens" Version="6.35.0" />
    <PackageReference Include="Microsoft.IdentityModel.Protocols.OpenIdConnect" Version="6.35.0" />
  </ItemGroup>

</Project>
```

The test project compiles the `Protocol` sources directly rather than referencing the plugin project. This is deliberate: the plugin targets `netstandard2.0` against Emby reference assemblies that cannot load in a test host, while the `Protocol` folder is guaranteed free of Emby types. If a later task accidentally puts a `MediaBrowser` reference in `Protocol/`, this project stops compiling — the constraint enforces itself.

```bash
dotnet sln add tests/Emby.Sso.Tests/Emby.Sso.Tests.csproj
```

- [ ] **Step 2: Write the failing test**

`tests/Emby.Sso.Tests/SecureRandomTests.cs`:

```csharp
using System;
using System.Linq;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class SecureRandomTests
    {
        [Fact]
        public void CreateToken_produces_url_safe_unpadded_output()
        {
            var token = SecureRandom.CreateToken(32);

            Assert.DoesNotContain('+', token);
            Assert.DoesNotContain('/', token);
            Assert.DoesNotContain('=', token);
            Assert.True(token.Length >= 43, "32 bytes of base64url is at least 43 characters");
        }

        [Fact]
        public void CreateToken_does_not_repeat()
        {
            var tokens = Enumerable.Range(0, 100).Select(_ => SecureRandom.CreateToken(32)).ToList();

            Assert.Equal(tokens.Count, tokens.Distinct().Count());
        }

        [Fact]
        public void CreateCodeChallenge_matches_rfc7636_test_vector()
        {
            // RFC 7636 Appendix B.
            const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

            var challenge = SecureRandom.CreateCodeChallenge(verifier);

            Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
        }

        [Fact]
        public void CreateCodeVerifier_is_within_rfc7636_length_limits()
        {
            var verifier = SecureRandom.CreateCodeVerifier();

            Assert.InRange(verifier.Length, 43, 128);
        }
    }
}
```

- [ ] **Step 3: Run the test and verify it fails**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: compile error, `SecureRandom` does not exist.

- [ ] **Step 4: Implement**

`src/Emby.Sso/Protocol/SecureRandom.cs`:

```csharp
using System;
using System.Security.Cryptography;
using System.Text;

namespace Emby.Sso.Protocol
{
    public static class SecureRandom
    {
        public static string CreateToken(int byteLength)
        {
            if (byteLength <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(byteLength));
            }

            var bytes = new byte[byteLength];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            return Base64Url(bytes);
        }

        public static string CreateCodeVerifier()
        {
            return CreateToken(32);
        }

        public static string CreateCodeChallenge(string verifier)
        {
            if (string.IsNullOrEmpty(verifier))
            {
                throw new ArgumentException("verifier is required", nameof(verifier));
            }

            using (var sha = SHA256.Create())
            {
                return Base64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));
            }
        }

        private static string Base64Url(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add tests/ src/Emby.Sso/Protocol/SecureRandom.cs
git commit -m "feat: add CSPRNG token and PKCE challenge generation"
```

---

### Task 4: Fixed-time comparison and the handoff secret store

**Files:**
- Create: `src/Emby.Sso/Protocol/FixedTime.cs`
- Create: `src/Emby.Sso/Protocol/HandoffSecretStore.cs`
- Create: `tests/Emby.Sso.Tests/TestClock.cs`
- Test: `tests/Emby.Sso.Tests/HandoffSecretStoreTests.cs`

**Interfaces:**
- Consumes: `SecureRandom.CreateToken(int)` from Task 3.
- Produces:
  - `Emby.Sso.Protocol.FixedTime` with `public static bool Equals(string a, string b)`.
  - `Emby.Sso.Protocol.HandoffSecretStore` with constructor `HandoffSecretStore(Func<DateTimeOffset> clock, TimeSpan ttl)`, `public string Issue(string username)`, `public bool TryConsume(string username, string secret)`.

- [ ] **Step 1: Write the failing test**

`tests/Emby.Sso.Tests/TestClock.cs`:

```csharp
using System;

namespace Emby.Sso.Tests
{
    public sealed class TestClock
    {
        public DateTimeOffset Now { get; set; } = new DateTimeOffset(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

        public Func<DateTimeOffset> Func => () => Now;

        public void Advance(TimeSpan by) => Now = Now.Add(by);
    }
}
```

`tests/Emby.Sso.Tests/HandoffSecretStoreTests.cs`:

```csharp
using System;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class HandoffSecretStoreTests
    {
        private readonly TestClock _clock = new TestClock();

        private HandoffSecretStore CreateStore() =>
            new HandoffSecretStore(_clock.Func, TimeSpan.FromSeconds(30));

        [Fact]
        public void A_freshly_issued_secret_is_accepted()
        {
            var store = CreateStore();
            var secret = store.Issue("alice");

            Assert.True(store.TryConsume("alice", secret));
        }

        [Fact]
        public void A_secret_cannot_be_used_twice()
        {
            var store = CreateStore();
            var secret = store.Issue("alice");

            Assert.True(store.TryConsume("alice", secret));
            Assert.False(store.TryConsume("alice", secret));
        }

        [Fact]
        public void A_secret_expires_after_the_ttl()
        {
            var store = CreateStore();
            var secret = store.Issue("alice");

            _clock.Advance(TimeSpan.FromSeconds(31));

            Assert.False(store.TryConsume("alice", secret));
        }

        [Fact]
        public void A_secret_is_bound_to_one_username()
        {
            var store = CreateStore();
            var secret = store.Issue("alice");

            Assert.False(store.TryConsume("bob", secret));
            Assert.True(store.TryConsume("alice", secret));
        }

        [Fact]
        public void Username_matching_is_case_insensitive()
        {
            var store = CreateStore();
            var secret = store.Issue("Alice");

            Assert.True(store.TryConsume("alice", secret));
        }

        [Fact]
        public void A_wrong_secret_is_rejected()
        {
            var store = CreateStore();
            store.Issue("alice");

            Assert.False(store.TryConsume("alice", "not-the-secret"));
        }

        [Fact]
        public void An_empty_secret_is_rejected()
        {
            var store = CreateStore();
            store.Issue("alice");

            Assert.False(store.TryConsume("alice", string.Empty));
            Assert.False(store.TryConsume("alice", null));
        }

        [Fact]
        public void Issuing_a_second_secret_invalidates_the_first()
        {
            var store = CreateStore();
            var first = store.Issue("alice");
            var second = store.Issue("alice");

            Assert.False(store.TryConsume("alice", first));
            Assert.True(store.TryConsume("alice", second));
        }
    }
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: compile error, `HandoffSecretStore` does not exist.

- [ ] **Step 3: Implement the fixed-time comparison**

`src/Emby.Sso/Protocol/FixedTime.cs`:

```csharp
using System.Text;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Comparison whose duration does not depend on where two values first differ.
    /// netstandard2.0 has no CryptographicOperations.FixedTimeEquals.
    /// </summary>
    public static class FixedTime
    {
        public static bool Equals(string a, string b)
        {
            if (a == null || b == null)
            {
                return false;
            }

            var left = Encoding.UTF8.GetBytes(a);
            var right = Encoding.UTF8.GetBytes(b);

            var difference = left.Length ^ right.Length;
            var length = left.Length < right.Length ? left.Length : right.Length;

            for (var i = 0; i < length; i++)
            {
                difference |= left[i] ^ right[i];
            }

            return difference == 0;
        }
    }
}
```

- [ ] **Step 4: Implement the store**

`src/Emby.Sso/Protocol/HandoffSecretStore.cs`:

```csharp
using System;
using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Holds the single-use secrets that carry a completed browser login into
    /// Emby's ordinary login form. One live secret per user at a time.
    /// </summary>
    public sealed class HandoffSecretStore
    {
        private readonly Dictionary<string, Entry> _entries =
            new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);

        private readonly object _lock = new object();
        private readonly Func<DateTimeOffset> _clock;
        private readonly TimeSpan _ttl;

        public HandoffSecretStore(Func<DateTimeOffset> clock, TimeSpan ttl)
        {
            _clock = clock ?? throw new ArgumentNullException(nameof(clock));
            _ttl = ttl;
        }

        public string Issue(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("username is required", nameof(username));
            }

            var secret = SecureRandom.CreateToken(32);

            lock (_lock)
            {
                RemoveExpired();
                _entries[username] = new Entry(secret, _clock().Add(_ttl));
            }

            return secret;
        }

        public bool TryConsume(string username, string secret)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(secret))
            {
                return false;
            }

            lock (_lock)
            {
                RemoveExpired();

                if (!_entries.TryGetValue(username, out var entry))
                {
                    return false;
                }

                if (!FixedTime.Equals(entry.Secret, secret))
                {
                    return false;
                }

                _entries.Remove(username);
                return true;
            }
        }

        private void RemoveExpired()
        {
            var now = _clock();
            var stale = new List<string>();

            foreach (var pair in _entries)
            {
                if (pair.Value.ExpiresAt <= now)
                {
                    stale.Add(pair.Key);
                }
            }

            foreach (var key in stale)
            {
                _entries.Remove(key);
            }
        }

        private sealed class Entry
        {
            public Entry(string secret, DateTimeOffset expiresAt)
            {
                Secret = secret;
                ExpiresAt = expiresAt;
            }

            public string Secret { get; }

            public DateTimeOffset ExpiresAt { get; }
        }
    }
}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: 12 passed.

- [ ] **Step 6: Commit**

```bash
git add src/Emby.Sso/Protocol/FixedTime.cs src/Emby.Sso/Protocol/HandoffSecretStore.cs tests/
git commit -m "feat: add single-use handoff secret store with fixed-time comparison"
```

---

### Task 5: Pending login store

**Files:**
- Create: `src/Emby.Sso/Protocol/PendingLogin.cs`
- Create: `src/Emby.Sso/Protocol/PendingLoginStore.cs`
- Test: `tests/Emby.Sso.Tests/PendingLoginStoreTests.cs`

**Interfaces:**
- Consumes: `SecureRandom` from Task 3, `TestClock` from Task 4.
- Produces:
  - `Emby.Sso.Protocol.PendingLogin` with read-only properties `State`, `Nonce`, `CodeVerifier`, `CodeChallenge`, `ExpiresAt`.
  - `Emby.Sso.Protocol.PendingLoginStore` with constructor `PendingLoginStore(Func<DateTimeOffset> clock, TimeSpan ttl, int maxEntries = 256)`, `public PendingLogin Create()`, `public PendingLogin Consume(string state)` returning null when unknown, expired or already used.

- [ ] **Step 1: Write the failing test**

`tests/Emby.Sso.Tests/PendingLoginStoreTests.cs`:

```csharp
using System;
using System.Linq;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class PendingLoginStoreTests
    {
        private readonly TestClock _clock = new TestClock();

        private PendingLoginStore CreateStore(int maxEntries = 256) =>
            new PendingLoginStore(_clock.Func, TimeSpan.FromMinutes(5), maxEntries);

        [Fact]
        public void Create_produces_distinct_state_nonce_and_verifier()
        {
            var store = CreateStore();
            var login = store.Create();

            Assert.False(string.IsNullOrWhiteSpace(login.State));
            Assert.False(string.IsNullOrWhiteSpace(login.Nonce));
            Assert.False(string.IsNullOrWhiteSpace(login.CodeVerifier));
            Assert.NotEqual(login.State, login.Nonce);
            Assert.NotEqual(login.State, login.CodeVerifier);
        }

        [Fact]
        public void Create_derives_the_challenge_from_the_verifier()
        {
            var store = CreateStore();
            var login = store.Create();

            Assert.Equal(SecureRandom.CreateCodeChallenge(login.CodeVerifier), login.CodeChallenge);
        }

        [Fact]
        public void Consume_returns_the_matching_login()
        {
            var store = CreateStore();
            var created = store.Create();

            var consumed = store.Consume(created.State);

            Assert.NotNull(consumed);
            Assert.Equal(created.Nonce, consumed.Nonce);
            Assert.Equal(created.CodeVerifier, consumed.CodeVerifier);
        }

        [Fact]
        public void Consume_rejects_a_replayed_state()
        {
            var store = CreateStore();
            var created = store.Create();

            Assert.NotNull(store.Consume(created.State));
            Assert.Null(store.Consume(created.State));
        }

        [Fact]
        public void Consume_rejects_an_unknown_state()
        {
            var store = CreateStore();
            store.Create();

            Assert.Null(store.Consume("never-issued"));
        }

        [Fact]
        public void Consume_rejects_null_and_empty_state()
        {
            var store = CreateStore();

            Assert.Null(store.Consume(null));
            Assert.Null(store.Consume(string.Empty));
        }

        [Fact]
        public void Consume_rejects_an_expired_state()
        {
            var store = CreateStore();
            var created = store.Create();

            _clock.Advance(TimeSpan.FromMinutes(6));

            Assert.Null(store.Consume(created.State));
        }

        [Fact]
        public void The_store_evicts_the_oldest_entries_past_its_limit()
        {
            var store = CreateStore(maxEntries: 3);
            var first = store.Create();
            store.Create();
            store.Create();
            store.Create();

            Assert.Null(store.Consume(first.State));
        }
    }
}
```

The eviction test matters because `/Sso/Start` is reachable without authentication; without a bound, an unauthenticated caller could grow the dictionary without limit.

- [ ] **Step 2: Run the tests and verify they fail**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: compile error, `PendingLoginStore` does not exist.

- [ ] **Step 3: Implement the record**

`src/Emby.Sso/Protocol/PendingLogin.cs`:

```csharp
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
```

- [ ] **Step 4: Implement the store**

`src/Emby.Sso/Protocol/PendingLoginStore.cs`:

```csharp
using System;
using System.Collections.Generic;
using System.Linq;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Holds browser logins between the redirect to the identity provider and
    /// the callback. Entries are single-use and bounded, because the endpoint
    /// that creates them is reachable without authentication.
    /// </summary>
    public sealed class PendingLoginStore
    {
        private readonly Dictionary<string, PendingLogin> _entries = new Dictionary<string, PendingLogin>(StringComparer.Ordinal);
        private readonly List<string> _insertionOrder = new List<string>();
        private readonly object _lock = new object();
        private readonly Func<DateTimeOffset> _clock;
        private readonly TimeSpan _ttl;
        private readonly int _maxEntries;

        public PendingLoginStore(Func<DateTimeOffset> clock, TimeSpan ttl, int maxEntries = 256)
        {
            _clock = clock ?? throw new ArgumentNullException(nameof(clock));
            _ttl = ttl;
            _maxEntries = maxEntries > 0 ? maxEntries : throw new ArgumentOutOfRangeException(nameof(maxEntries));
        }

        public PendingLogin Create()
        {
            var login = new PendingLogin(
                SecureRandom.CreateToken(32),
                SecureRandom.CreateToken(32),
                SecureRandom.CreateCodeVerifier(),
                _clock().Add(_ttl));

            lock (_lock)
            {
                RemoveExpired();

                while (_insertionOrder.Count >= _maxEntries)
                {
                    var oldest = _insertionOrder[0];
                    _insertionOrder.RemoveAt(0);
                    _entries.Remove(oldest);
                }

                _entries[login.State] = login;
                _insertionOrder.Add(login.State);
            }

            return login;
        }

        public PendingLogin Consume(string state)
        {
            if (string.IsNullOrEmpty(state))
            {
                return null;
            }

            lock (_lock)
            {
                RemoveExpired();

                if (!_entries.TryGetValue(state, out var login))
                {
                    return null;
                }

                _entries.Remove(state);
                _insertionOrder.Remove(state);
                return login;
            }
        }

        private void RemoveExpired()
        {
            var now = _clock();
            var stale = _entries.Where(pair => pair.Value.ExpiresAt <= now).Select(pair => pair.Key).ToList();

            foreach (var key in stale)
            {
                _entries.Remove(key);
                _insertionOrder.Remove(key);
            }
        }
    }
}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: 20 passed.

- [ ] **Step 6: Commit**

```bash
git add src/Emby.Sso/Protocol/PendingLogin.cs src/Emby.Sso/Protocol/PendingLoginStore.cs tests/
git commit -m "feat: add bounded single-use pending login store"
```

---

### Task 6: Fake identity provider, OIDC discovery and the authorization URL

**Files:**
- Create: `src/Emby.Sso/Protocol/OidcOptions.cs`
- Create: `src/Emby.Sso/Protocol/OidcIdentity.cs`
- Create: `src/Emby.Sso/Protocol/OidcClient.cs`
- Create: `tests/Emby.Sso.Tests/FakeIdentityProvider.cs`
- Test: `tests/Emby.Sso.Tests/OidcClientDiscoveryTests.cs`
- Modify: `src/Emby.Sso/Emby.Sso.csproj` (add `Newtonsoft.Json`), `tests/Emby.Sso.Tests/Emby.Sso.Tests.csproj` (add `Newtonsoft.Json`)

**Interfaces:**
- Consumes: `PendingLogin` from Task 5.
- Produces:
  - `Emby.Sso.Protocol.OidcOptions` with settable properties `IssuerUrl`, `ClientId`, `ClientSecret`, `Scopes`, `RedirectUri`, `UsernameClaim`.
  - `Emby.Sso.Protocol.OidcIdentity` with read-only `Subject`, `Username`, `DisplayName`.
  - `Emby.Sso.Protocol.OidcClient` with constructor `OidcClient(HttpClient http, OidcOptions options)` and method `public Task<string> BuildAuthorizationUrlAsync(PendingLogin login, CancellationToken ct)`. Tasks 7 and 8 add `ExchangeCodeAsync` and `DirectGrantAsync` to this same class.
  - `Emby.Sso.Tests.FakeIdentityProvider`, an `HttpMessageHandler` serving discovery, JWKS and token endpoints, with `CreateIdToken(...)` for minting signed tokens.

- [ ] **Step 1: Add the JSON dependency to both projects**

In `src/Emby.Sso/Emby.Sso.csproj` and `tests/Emby.Sso.Tests/Emby.Sso.Tests.csproj`, add to the existing `PackageReference` item group:

```xml
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
```

The plugin project already merges `Newtonsoft.Json.dll` via the ILRepack target from Task 2.

- [ ] **Step 2: Write the fake identity provider**

`tests/Emby.Sso.Tests/FakeIdentityProvider.cs`:

```csharp
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// An in-process OpenID Connect provider: real RSA keys, real signatures,
    /// no network. Tests drive it to produce the tokens they want to reject.
    /// </summary>
    public sealed class FakeIdentityProvider : HttpMessageHandler
    {
        public const string Issuer = "https://idp.test/application/o/emby/";
        public const string ClientId = "emby-client";
        public const string ClientSecret = "emby-secret";
        public const string KeyId = "test-key-1";

        private readonly RSA _rsa = RSA.Create(2048);

        /// <summary>Body returned by the token endpoint. Set by each test.</summary>
        public string TokenResponseJson { get; set; }

        public HttpStatusCode TokenResponseStatus { get; set; } = HttpStatusCode.OK;

        /// <summary>The form fields of the most recent token request.</summary>
        public Dictionary<string, string> LastTokenRequestForm { get; private set; }

        public AuthenticationHeaderValueSnapshot LastTokenRequestAuthorization { get; private set; }

        public int DiscoveryRequestCount { get; private set; }

        public string CreateIdToken(
            string subject = "sub-1",
            string username = "alice",
            string displayName = "Alice Example",
            string nonce = null,
            string issuer = Issuer,
            string audience = ClientId,
            DateTime? expires = null,
            DateTime? notBefore = null,
            IDictionary<string, object> extraClaims = null)
        {
            var claims = new Dictionary<string, object> { ["sub"] = subject };

            // Omitted rather than set to null, so that tests can produce a token
            // that genuinely lacks the claim.
            if (username != null)
            {
                claims["preferred_username"] = username;
            }

            if (displayName != null)
            {
                claims["name"] = displayName;
            }

            if (nonce != null)
            {
                claims["nonce"] = nonce;
            }

            if (extraClaims != null)
            {
                foreach (var pair in extraClaims)
                {
                    claims[pair.Key] = pair.Value;
                }
            }

            var key = new RsaSecurityKey(_rsa) { KeyId = KeyId };
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                Claims = claims,
                NotBefore = notBefore ?? DateTime.UtcNow.AddMinutes(-1),
                Expires = expires ?? DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            };

            return new JsonWebTokenHandler().CreateToken(descriptor);
        }

        public string CreateTokenResponse(string idToken)
        {
            return new JObject
            {
                ["access_token"] = "access-token-value",
                ["token_type"] = "Bearer",
                ["expires_in"] = 300,
                ["id_token"] = idToken,
            }.ToString();
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri.AbsoluteUri;

            if (path.EndsWith(".well-known/openid-configuration", StringComparison.Ordinal))
            {
                DiscoveryRequestCount++;
                return Json(HttpStatusCode.OK, DiscoveryDocument());
            }

            if (path.EndsWith("/jwks/", StringComparison.Ordinal))
            {
                return Json(HttpStatusCode.OK, JwksDocument());
            }

            if (path.EndsWith("/token/", StringComparison.Ordinal))
            {
                var body = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
                LastTokenRequestForm = ParseForm(body);
                LastTokenRequestAuthorization = request.Headers.Authorization == null
                    ? null
                    : new AuthenticationHeaderValueSnapshot(
                        request.Headers.Authorization.Scheme,
                        request.Headers.Authorization.Parameter);

                return Json(TokenResponseStatus, TokenResponseJson ?? "{}");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static Dictionary<string, string> ParseForm(string body)
        {
            var form = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var pair in body.Split('&'))
            {
                if (pair.Length == 0)
                {
                    continue;
                }

                var parts = pair.Split(new[] { '=' }, 2);
                form[Uri.UnescapeDataString(parts[0])] =
                    parts.Length > 1 ? Uri.UnescapeDataString(parts[1].Replace("+", "%20")) : string.Empty;
            }

            return form;
        }

        private static string DiscoveryDocument()
        {
            return new JObject
            {
                ["issuer"] = Issuer,
                ["authorization_endpoint"] = Issuer + "authorize/",
                ["token_endpoint"] = Issuer + "token/",
                ["jwks_uri"] = Issuer + "jwks/",
                ["userinfo_endpoint"] = Issuer + "userinfo/",
                ["response_types_supported"] = new JArray("code"),
                ["subject_types_supported"] = new JArray("public"),
                ["id_token_signing_alg_values_supported"] = new JArray("RS256"),
            }.ToString();
        }

        private string JwksDocument()
        {
            var parameters = _rsa.ExportParameters(false);

            return new JObject
            {
                ["keys"] = new JArray(new JObject
                {
                    ["kty"] = "RSA",
                    ["use"] = "sig",
                    ["alg"] = "RS256",
                    ["kid"] = KeyId,
                    ["n"] = Base64UrlEncoder.Encode(parameters.Modulus),
                    ["e"] = Base64UrlEncoder.Encode(parameters.Exponent),
                }),
            }.ToString();
        }

        private static HttpResponseMessage Json(HttpStatusCode status, string body)
        {
            return new HttpResponseMessage(status)
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
            };
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _rsa.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    public sealed class AuthenticationHeaderValueSnapshot
    {
        public AuthenticationHeaderValueSnapshot(string scheme, string parameter)
        {
            Scheme = scheme;
            Parameter = parameter;
        }

        public string Scheme { get; }

        public string Parameter { get; }
    }
}
```

- [ ] **Step 3: Write the failing discovery test**

`tests/Emby.Sso.Tests/OidcClientDiscoveryTests.cs`:

```csharp
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class OidcClientDiscoveryTests
    {
        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();

        private OidcClient CreateClient()
        {
            var options = new OidcOptions
            {
                IssuerUrl = FakeIdentityProvider.Issuer,
                ClientId = FakeIdentityProvider.ClientId,
                ClientSecret = FakeIdentityProvider.ClientSecret,
                Scopes = "openid profile email",
                RedirectUri = "https://emby.test/emby/Sso/Callback",
                UsernameClaim = "preferred_username",
            };

            return new OidcClient(new HttpClient(_idp), options);
        }

        [Fact]
        public async Task The_authorization_url_carries_every_required_parameter()
        {
            var store = new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
            var login = store.Create();

            var url = await CreateClient().BuildAuthorizationUrlAsync(login, CancellationToken.None);

            var uri = new Uri(url);
            var query = HttpUtility.ParseQueryString(uri.Query);

            Assert.Equal(FakeIdentityProvider.Issuer + "authorize/", uri.GetLeftPart(UriPartial.Path));
            Assert.Equal("code", query["response_type"]);
            Assert.Equal(FakeIdentityProvider.ClientId, query["client_id"]);
            Assert.Equal("https://emby.test/emby/Sso/Callback", query["redirect_uri"]);
            Assert.Equal("openid profile email", query["scope"]);
            Assert.Equal(login.State, query["state"]);
            Assert.Equal(login.Nonce, query["nonce"]);
            Assert.Equal(login.CodeChallenge, query["code_challenge"]);
            Assert.Equal("S256", query["code_challenge_method"]);
        }

        [Fact]
        public async Task The_authorization_url_never_contains_the_code_verifier_or_client_secret()
        {
            var store = new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
            var login = store.Create();

            var url = await CreateClient().BuildAuthorizationUrlAsync(login, CancellationToken.None);

            Assert.DoesNotContain(login.CodeVerifier, url, StringComparison.Ordinal);
            Assert.DoesNotContain(FakeIdentityProvider.ClientSecret, url, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Discovery_is_fetched_once_and_reused()
        {
            var client = CreateClient();
            var store = new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

            await client.BuildAuthorizationUrlAsync(store.Create(), CancellationToken.None);
            await client.BuildAuthorizationUrlAsync(store.Create(), CancellationToken.None);
            await client.BuildAuthorizationUrlAsync(store.Create(), CancellationToken.None);

            Assert.Equal(1, _idp.DiscoveryRequestCount);
        }
    }
}
```

- [ ] **Step 4: Run the tests and verify they fail**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: compile error, `OidcClient` and `OidcOptions` do not exist.

- [ ] **Step 5: Implement the options and identity types**

`src/Emby.Sso/Protocol/OidcOptions.cs`:

```csharp
namespace Emby.Sso.Protocol
{
    public sealed class OidcOptions
    {
        public string IssuerUrl { get; set; } = string.Empty;

        public string ClientId { get; set; } = string.Empty;

        public string ClientSecret { get; set; } = string.Empty;

        public string Scopes { get; set; } = "openid profile email";

        public string RedirectUri { get; set; } = string.Empty;

        public string UsernameClaim { get; set; } = "preferred_username";

        public string MetadataAddress => IssuerUrl.TrimEnd('/') + "/.well-known/openid-configuration";
    }
}
```

`src/Emby.Sso/Protocol/OidcIdentity.cs`:

```csharp
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
```

- [ ] **Step 6: Implement discovery and the authorization URL**

`src/Emby.Sso/Protocol/OidcClient.cs`:

```csharp
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Talks OpenID Connect to the identity provider. Knows nothing about Emby.
    /// Metadata and signing keys are cached and refreshed by ConfigurationManager,
    /// which also backs off when the provider is unreachable.
    /// </summary>
    public sealed partial class OidcClient
    {
        private readonly HttpClient _http;
        private readonly OidcOptions _options;
        private readonly ConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

        public OidcClient(HttpClient http, OidcOptions options)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _options = options ?? throw new ArgumentNullException(nameof(options));

            _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                _options.MetadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(http) { RequireHttps = _options.MetadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase) });
        }

        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancellationToken)
        {
            return _configurationManager.GetConfigurationAsync(cancellationToken);
        }

        public async Task<string> BuildAuthorizationUrlAsync(PendingLogin login, CancellationToken cancellationToken)
        {
            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            var configuration = await GetConfigurationAsync(cancellationToken).ConfigureAwait(false);

            var parameters = new Dictionary<string, string>
            {
                ["response_type"] = "code",
                ["client_id"] = _options.ClientId,
                ["redirect_uri"] = _options.RedirectUri,
                ["scope"] = _options.Scopes,
                ["state"] = login.State,
                ["nonce"] = login.Nonce,
                ["code_challenge"] = login.CodeChallenge,
                ["code_challenge_method"] = "S256",
            };

            var query = new List<string>();
            foreach (var pair in parameters)
            {
                query.Add(Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value));
            }

            var separator = configuration.AuthorizationEndpoint.IndexOf('?') >= 0 ? "&" : "?";
            return configuration.AuthorizationEndpoint + separator + string.Join("&", query);
        }
    }
}
```

The class is `partial` because Tasks 7 and 8 add the token-handling half in the same file; keep both halves in `OidcClient.cs` unless the file exceeds roughly 250 lines, in which case split the token half into `OidcClient.Tokens.cs`.

- [ ] **Step 7: Run the tests and verify they pass**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: 23 passed.

- [ ] **Step 8: Commit**

```bash
git add src/ tests/
git commit -m "feat: add OIDC discovery and PKCE authorization URL construction"
```

---

### Task 7: Code exchange and ID token validation

This is the security core of the plugin. The negative tests are the point of the task; do not weaken them to make an implementation pass.

**Files:**
- Modify: `src/Emby.Sso/Protocol/OidcClient.cs`
- Create: `src/Emby.Sso/Protocol/SsoErrors.cs`
- Test: `tests/Emby.Sso.Tests/OidcClientTokenTests.cs`

**Interfaces:**
- Consumes: `OidcClient`, `OidcOptions`, `OidcIdentity` from Task 6; `PendingLogin` from Task 5.
- Produces:
  - `Emby.Sso.Protocol.SsoException`, a `System.Exception` subclass with `public string UserSafeReason { get; }`.
  - `Emby.Sso.Protocol.SsoErrors` with the constants `InvalidToken`, `ProviderRejected`, `ProviderUnreachable`, `UnknownUser`, `SessionExpired`, `DirectGrantDisabled`, `NotConfigured` — all short strings safe to show a user.
  - `OidcClient.ExchangeCodeAsync(string code, PendingLogin login, CancellationToken ct)` returning `Task<OidcIdentity>` and throwing `SsoException` on any failure.

- [ ] **Step 1: Write the failing tests**

`tests/Emby.Sso.Tests/OidcClientTokenTests.cs`:

```csharp
using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class OidcClientTokenTests
    {
        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();
        private readonly PendingLoginStore _logins =
            new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

        private OidcClient CreateClient()
        {
            var options = new OidcOptions
            {
                IssuerUrl = FakeIdentityProvider.Issuer,
                ClientId = FakeIdentityProvider.ClientId,
                ClientSecret = FakeIdentityProvider.ClientSecret,
                Scopes = "openid profile email",
                RedirectUri = "https://emby.test/emby/Sso/Callback",
                UsernameClaim = "preferred_username",
            };

            return new OidcClient(new HttpClient(_idp), options);
        }

        [Fact]
        public async Task A_valid_code_exchange_yields_the_identity()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(username: "alice", displayName: "Alice Example", nonce: login.Nonce));

            var identity = await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.Equal("alice", identity.Username);
            Assert.Equal("Alice Example", identity.DisplayName);
            Assert.Equal("sub-1", identity.Subject);
        }

        [Fact]
        public async Task The_token_request_sends_the_pkce_verifier_and_authenticates_the_client()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(nonce: login.Nonce));

            await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

            Assert.Equal("authorization_code", _idp.LastTokenRequestForm["grant_type"]);
            Assert.Equal("the-code", _idp.LastTokenRequestForm["code"]);
            Assert.Equal(login.CodeVerifier, _idp.LastTokenRequestForm["code_verifier"]);
            Assert.Equal("https://emby.test/emby/Sso/Callback", _idp.LastTokenRequestForm["redirect_uri"]);

            Assert.Equal("Basic", _idp.LastTokenRequestAuthorization.Scheme);
            var decoded = Encoding.UTF8.GetString(
                Convert.FromBase64String(_idp.LastTokenRequestAuthorization.Parameter));
            Assert.Equal(
                FakeIdentityProvider.ClientId + ":" + FakeIdentityProvider.ClientSecret,
                decoded);

            Assert.False(_idp.LastTokenRequestForm.ContainsKey("client_secret"));
        }

        [Fact]
        public async Task A_token_signed_by_the_wrong_key_is_rejected()
        {
            var otherIdp = new FakeIdentityProvider();
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(otherIdp.CreateIdToken(nonce: login.Nonce));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task An_expired_token_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(
                nonce: login.Nonce,
                notBefore: DateTime.UtcNow.AddHours(-2),
                expires: DateTime.UtcNow.AddHours(-1)));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_for_a_different_audience_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: login.Nonce, audience: "some-other-client"));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_from_a_different_issuer_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: login.Nonce, issuer: "https://evil.test/"));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_with_the_wrong_nonce_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(nonce: "a-different-nonce"));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_with_no_nonce_at_all_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(nonce: null));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_token_missing_the_username_claim_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(
                _idp.CreateIdToken(username: null, nonce: login.Nonce));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task A_rejected_code_surfaces_as_a_provider_rejection()
        {
            var login = _logins.Create();
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.ProviderRejected, error.UserSafeReason);
        }

        [Fact]
        public async Task A_response_without_an_id_token_is_rejected()
        {
            var login = _logins.Create();
            _idp.TokenResponseJson = "{\"access_token\":\"a\",\"token_type\":\"Bearer\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task Failures_never_leak_the_client_secret_or_the_token()
        {
            var login = _logins.Create();
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None));

            var text = error.ToString();
            Assert.DoesNotContain(FakeIdentityProvider.ClientSecret, text, StringComparison.Ordinal);
            Assert.DoesNotContain(login.CodeVerifier, text, StringComparison.Ordinal);
        }
    }
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: compile error, `SsoException`, `SsoErrors` and `ExchangeCodeAsync` do not exist.

- [ ] **Step 3: Implement the error types**

`src/Emby.Sso/Protocol/SsoErrors.cs`:

```csharp
using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Short reasons that are safe to show a user. Anything more specific goes
    /// to the server log, never to the browser.
    /// </summary>
    public static class SsoErrors
    {
        public const string NotConfigured = "Single sign-on is not configured on this server.";
        public const string ProviderUnreachable = "The sign-in provider could not be reached.";
        public const string ProviderRejected = "The sign-in provider rejected this sign-in.";
        public const string InvalidToken = "The sign-in response could not be verified.";
        public const string SessionExpired = "This sign-in attempt expired. Please try again.";
        public const string UnknownUser = "This account is not set up on this server.";
        public const string DirectGrantDisabled = "Password sign-in is disabled for this account.";
    }

    /// <summary>
    /// Carries a user-safe reason alongside the diagnostic detail. The message
    /// of the inner exception is for the log; UserSafeReason is for the browser.
    /// </summary>
    public sealed class SsoException : Exception
    {
        public SsoException(string userSafeReason, string logDetail, Exception inner = null)
            : base(logDetail, inner)
        {
            UserSafeReason = userSafeReason;
        }

        public string UserSafeReason { get; }
    }
}
```

- [ ] **Step 4: Implement the exchange and validation**

Add to `src/Emby.Sso/Protocol/OidcClient.cs`, inside the same `partial class OidcClient`:

```csharp
        public async Task<OidcIdentity> ExchangeCodeAsync(string code, PendingLogin login, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(code))
            {
                throw new SsoException(SsoErrors.ProviderRejected, "authorization code missing from callback");
            }

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = _options.RedirectUri,
                ["code_verifier"] = login.CodeVerifier,
            };

            var idToken = await PostTokenRequestAsync(form, cancellationToken).ConfigureAwait(false);
            return ValidateIdToken(idToken, login.Nonce, await GetConfigurationAsync(cancellationToken).ConfigureAwait(false));
        }

        private async Task<string> PostTokenRequestAsync(Dictionary<string, string> form, CancellationToken cancellationToken)
        {
            var configuration = await GetConfigurationAsync(cancellationToken).ConfigureAwait(false);

            using (var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint))
            {
                request.Content = new FormUrlEncodedContent(form);

                if (string.IsNullOrEmpty(_options.ClientSecret))
                {
                    // Public client: identify without authenticating.
                    form["client_id"] = _options.ClientId;
                    request.Content = new FormUrlEncodedContent(form);
                }
                else
                {
                    var credentials = Convert.ToBase64String(
                        System.Text.Encoding.UTF8.GetBytes(_options.ClientId + ":" + _options.ClientSecret));
                    request.Headers.Authorization =
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);
                }

                HttpResponseMessage response;
                try
                {
                    response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    throw new SsoException(SsoErrors.ProviderUnreachable, "token endpoint request failed", ex);
                }

                using (response)
                {
                    var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                    if (!response.IsSuccessStatusCode)
                    {
                        // Only the OAuth error code is logged; the body may contain more.
                        throw new SsoException(
                            SsoErrors.ProviderRejected,
                            "token endpoint returned " + (int)response.StatusCode + " " + ReadErrorCode(body));
                    }

                    var idToken = ReadStringField(body, "id_token");

                    if (string.IsNullOrEmpty(idToken))
                    {
                        throw new SsoException(SsoErrors.InvalidToken, "token response contained no id_token");
                    }

                    return idToken;
                }
            }
        }

        private OidcIdentity ValidateIdToken(string idToken, string expectedNonce, OpenIdConnectConfiguration configuration)
        {
            var parameters = new TokenValidationParameters
            {
                ValidIssuer = configuration.Issuer,
                ValidAudience = _options.ClientId,
                IssuerSigningKeys = configuration.SigningKeys,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ClockSkew = TimeSpan.FromMinutes(2),
            };

            var result = new JsonWebTokenHandler().ValidateToken(idToken, parameters);

            if (!result.IsValid)
            {
                throw new SsoException(
                    SsoErrors.InvalidToken,
                    "id_token validation failed: " + (result.Exception?.GetType().Name ?? "unknown"),
                    result.Exception);
            }

            var token = (JsonWebToken)result.SecurityToken;

            if (expectedNonce != null)
            {
                token.TryGetClaim("nonce", out var nonceClaim);

                if (nonceClaim == null || !FixedTime.Equals(expectedNonce, nonceClaim.Value))
                {
                    throw new SsoException(SsoErrors.InvalidToken, "id_token nonce did not match the pending login");
                }
            }

            var username = ReadClaim(token, _options.UsernameClaim);

            if (string.IsNullOrWhiteSpace(username))
            {
                throw new SsoException(
                    SsoErrors.InvalidToken,
                    "id_token did not contain the configured username claim '" + _options.UsernameClaim + "'");
            }

            return new OidcIdentity(ReadClaim(token, "sub"), username.Trim(), ReadClaim(token, "name") ?? username.Trim());
        }

        private static string ReadClaim(JsonWebToken token, string name)
        {
            return token.TryGetClaim(name, out var claim) ? claim.Value : null;
        }

        private static string ReadStringField(string json, string field)
        {
            try
            {
                return (string)Newtonsoft.Json.Linq.JObject.Parse(json)[field];
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static string ReadErrorCode(string json)
        {
            return ReadStringField(json, "error") ?? "unknown_error";
        }
```

Add these `using` directives at the top of the file:

```csharp
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: 35 passed. If `A_token_with_no_nonce_at_all_is_rejected` fails, check that `expectedNonce` is non-null on the code-exchange path; the nonce is optional only for the direct grant added in Task 8.

- [ ] **Step 6: Commit**

```bash
git add src/ tests/
git commit -m "feat: exchange authorization codes and fully validate ID tokens"
```

---

### Task 8: Direct grant for native clients

**Files:**
- Modify: `src/Emby.Sso/Protocol/OidcClient.cs`
- Test: `tests/Emby.Sso.Tests/OidcClientDirectGrantTests.cs`

**Interfaces:**
- Consumes: everything from Task 7.
- Produces: `OidcClient.DirectGrantAsync(string username, string password, CancellationToken ct)` returning `Task<OidcIdentity>` and throwing `SsoException` on failure.

- [ ] **Step 1: Write the failing tests**

`tests/Emby.Sso.Tests/OidcClientDirectGrantTests.cs`:

```csharp
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class OidcClientDirectGrantTests
    {
        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();

        private OidcClient CreateClient()
        {
            var options = new OidcOptions
            {
                IssuerUrl = FakeIdentityProvider.Issuer,
                ClientId = FakeIdentityProvider.ClientId,
                ClientSecret = FakeIdentityProvider.ClientSecret,
                Scopes = "openid profile email",
                RedirectUri = "https://emby.test/emby/Sso/Callback",
                UsernameClaim = "preferred_username",
            };

            return new OidcClient(new HttpClient(_idp), options);
        }

        [Fact]
        public async Task Correct_credentials_yield_the_identity()
        {
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "alice"));

            var identity = await CreateClient().DirectGrantAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal("alice", identity.Username);
        }

        [Fact]
        public async Task The_request_uses_the_password_grant_and_carries_the_credentials()
        {
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "alice"));

            await CreateClient().DirectGrantAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal("password", _idp.LastTokenRequestForm["grant_type"]);
            Assert.Equal("alice", _idp.LastTokenRequestForm["username"]);
            Assert.Equal("correct horse", _idp.LastTokenRequestForm["password"]);
            Assert.Equal("openid profile email", _idp.LastTokenRequestForm["scope"]);
        }

        [Fact]
        public async Task Wrong_credentials_surface_as_a_provider_rejection()
        {
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().DirectGrantAsync("alice", "wrong", CancellationToken.None));

            Assert.Equal(SsoErrors.ProviderRejected, error.UserSafeReason);
        }

        [Fact]
        public async Task An_empty_password_is_rejected_without_contacting_the_provider()
        {
            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().DirectGrantAsync("alice", string.Empty, CancellationToken.None));

            Assert.Equal(SsoErrors.ProviderRejected, error.UserSafeReason);
            Assert.Null(_idp.LastTokenRequestForm);
        }

        [Fact]
        public async Task A_direct_grant_token_is_still_fully_validated()
        {
            var otherIdp = new FakeIdentityProvider();
            _idp.TokenResponseJson = _idp.CreateTokenResponse(otherIdp.CreateIdToken(username: "alice"));

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().DirectGrantAsync("alice", "correct horse", CancellationToken.None));

            Assert.Equal(SsoErrors.InvalidToken, error.UserSafeReason);
        }

        [Fact]
        public async Task Failures_never_leak_the_password()
        {
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var error = await Assert.ThrowsAsync<SsoException>(
                () => CreateClient().DirectGrantAsync("alice", "hunter2", CancellationToken.None));

            Assert.DoesNotContain("hunter2", error.ToString(), StringComparison.Ordinal);
        }
    }
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: compile error, `DirectGrantAsync` does not exist.

- [ ] **Step 3: Implement**

Add to the `partial class OidcClient`:

```csharp
        /// <summary>
        /// Resource owner password credentials. Used only by native clients that
        /// cannot perform a browser redirect. Cannot satisfy multi-factor
        /// authentication, and is disabled unless an administrator enables it.
        /// </summary>
        public async Task<OidcIdentity> DirectGrantAsync(string username, string password, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                throw new SsoException(SsoErrors.ProviderRejected, "direct grant attempted with an empty credential");
            }

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = username,
                ["password"] = password,
                ["scope"] = _options.Scopes,
            };

            var idToken = await PostTokenRequestAsync(form, cancellationToken).ConfigureAwait(false);

            // No nonce: there was no authorization request to bind one to.
            return ValidateIdToken(idToken, null, await GetConfigurationAsync(cancellationToken).ConfigureAwait(false));
        }
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: 41 passed.

- [ ] **Step 5: Commit**

```bash
git add src/ tests/
git commit -m "feat: add OIDC direct grant for native clients"
```

---

### Task 9: Username matching and the credential decision

This is the logic Emby's authentication provider delegates to. Keeping it here, free of Emby types, is what makes the login rules testable.

**Files:**
- Create: `src/Emby.Sso/Protocol/UsernameMatcher.cs`
- Create: `src/Emby.Sso/Protocol/SsoCredentialValidator.cs`
- Test: `tests/Emby.Sso.Tests/UsernameMatcherTests.cs`
- Test: `tests/Emby.Sso.Tests/SsoCredentialValidatorTests.cs`

**Interfaces:**
- Consumes: `HandoffSecretStore` (Task 4), `OidcClient` and `OidcIdentity` (Tasks 6-8), `SsoException` and `SsoErrors` (Task 7).
- Produces:
  - `Emby.Sso.Protocol.UsernameMatcher` with `public static bool Matches(string claimValue, string embyUsername)`.
  - `Emby.Sso.Protocol.SsoCredentialOutcome`, an enum with `Rejected`, `HandoffAccepted`, `DirectGrantAccepted`.
  - `Emby.Sso.Protocol.SsoCredentialResult` with `Outcome`, `DisplayName`, `Reason`, and factory methods `Handoff(string displayName)`, `DirectGrant(string displayName)`, `Reject(string reason)`.
  - `Emby.Sso.Protocol.SsoCredentialValidator` with constructor `SsoCredentialValidator(HandoffSecretStore handoff, Func<OidcClient> clientFactory, Func<bool> directGrantEnabled)` and `public Task<SsoCredentialResult> ValidateAsync(string embyUsername, string password, CancellationToken ct)`.

- [ ] **Step 1: Write the failing username matcher test**

`tests/Emby.Sso.Tests/UsernameMatcherTests.cs`:

```csharp
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class UsernameMatcherTests
    {
        [Theory]
        [InlineData("alice", "alice")]
        [InlineData("Alice", "alice")]
        [InlineData("alice", "ALICE")]
        [InlineData("  alice  ", "alice")]
        public void Equivalent_names_match(string claim, string emby)
        {
            Assert.True(UsernameMatcher.Matches(claim, emby));
        }

        [Theory]
        [InlineData("alice", "bob")]
        [InlineData("alice", "alice2")]
        [InlineData("alicia", "alice")]
        [InlineData(null, "alice")]
        [InlineData("alice", null)]
        [InlineData("", "alice")]
        [InlineData("   ", "alice")]
        public void Different_or_missing_names_do_not_match(string claim, string emby)
        {
            Assert.False(UsernameMatcher.Matches(claim, emby));
        }
    }
}
```

- [ ] **Step 2: Write the failing validator test**

`tests/Emby.Sso.Tests/SsoCredentialValidatorTests.cs`:

```csharp
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class SsoCredentialValidatorTests
    {
        private readonly FakeIdentityProvider _idp = new FakeIdentityProvider();
        private readonly HandoffSecretStore _handoff =
            new HandoffSecretStore(() => DateTimeOffset.UtcNow, TimeSpan.FromSeconds(30));

        private bool _directGrantEnabled = true;
        private bool _configured = true;

        private OidcClient Client()
        {
            if (!_configured)
            {
                return null;
            }

            return new OidcClient(new HttpClient(_idp), new OidcOptions
            {
                IssuerUrl = FakeIdentityProvider.Issuer,
                ClientId = FakeIdentityProvider.ClientId,
                ClientSecret = FakeIdentityProvider.ClientSecret,
                Scopes = "openid profile email",
                RedirectUri = "https://emby.test/emby/Sso/Callback",
                UsernameClaim = "preferred_username",
            });
        }

        private SsoCredentialValidator CreateValidator() =>
            new SsoCredentialValidator(_handoff, Client, () => _directGrantEnabled);

        [Fact]
        public async Task A_valid_handoff_secret_is_accepted_without_contacting_the_provider()
        {
            var secret = _handoff.Issue("alice");

            var result = await CreateValidator().ValidateAsync("alice", secret, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.HandoffAccepted, result.Outcome);
            Assert.Null(_idp.LastTokenRequestForm);
        }

        [Fact]
        public async Task A_handoff_secret_works_only_once()
        {
            var secret = _handoff.Issue("alice");
            var validator = CreateValidator();

            await validator.ValidateAsync("alice", secret, CancellationToken.None);
            _directGrantEnabled = false;

            var second = await validator.ValidateAsync("alice", secret, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, second.Outcome);
        }

        [Fact]
        public async Task A_real_password_is_checked_by_direct_grant()
        {
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "alice"));

            var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.DirectGrantAccepted, result.Outcome);
            Assert.Equal("password", _idp.LastTokenRequestForm["grant_type"]);
        }

        [Fact]
        public async Task A_password_is_rejected_when_direct_grant_is_disabled()
        {
            _directGrantEnabled = false;

            var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Equal(SsoErrors.DirectGrantDisabled, result.Reason);
            Assert.Null(_idp.LastTokenRequestForm);
        }

        [Fact]
        public async Task A_handoff_secret_is_accepted_even_when_direct_grant_is_disabled()
        {
            _directGrantEnabled = false;
            var secret = _handoff.Issue("alice");

            var result = await CreateValidator().ValidateAsync("alice", secret, CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.HandoffAccepted, result.Outcome);
        }

        [Fact]
        public async Task Wrong_credentials_are_rejected()
        {
            _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
            _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

            var result = await CreateValidator().ValidateAsync("alice", "wrong", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Equal(SsoErrors.ProviderRejected, result.Reason);
        }

        [Fact]
        public async Task A_provider_identity_for_a_different_user_is_rejected()
        {
            // The provider authenticated someone, but not the account being signed into.
            _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(username: "mallory"));

            var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Equal(SsoErrors.UnknownUser, result.Reason);
        }

        [Fact]
        public async Task An_unconfigured_plugin_rejects_everything()
        {
            _configured = false;

            var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

            Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
            Assert.Equal(SsoErrors.NotConfigured, result.Reason);
        }

        [Fact]
        public async Task An_empty_username_or_password_is_rejected()
        {
            var validator = CreateValidator();

            Assert.Equal(SsoCredentialOutcome.Rejected, (await validator.ValidateAsync(null, "x", CancellationToken.None)).Outcome);
            Assert.Equal(SsoCredentialOutcome.Rejected, (await validator.ValidateAsync("alice", null, CancellationToken.None)).Outcome);
            Assert.Equal(SsoCredentialOutcome.Rejected, (await validator.ValidateAsync("alice", "", CancellationToken.None)).Outcome);
        }
    }
}
```

- [ ] **Step 3: Run the tests and verify they fail**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: compile error, `UsernameMatcher` and `SsoCredentialValidator` do not exist.

- [ ] **Step 4: Implement the matcher**

`src/Emby.Sso/Protocol/UsernameMatcher.cs`:

```csharp
using System;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Decides whether a claim value names a given Emby user. Ordinal
    /// case-insensitive after trimming: no culture-sensitive comparison, because
    /// culture-dependent casing rules have produced authentication bypasses.
    /// </summary>
    public static class UsernameMatcher
    {
        public static bool Matches(string claimValue, string embyUsername)
        {
            if (string.IsNullOrWhiteSpace(claimValue) || string.IsNullOrWhiteSpace(embyUsername))
            {
                return false;
            }

            return string.Equals(claimValue.Trim(), embyUsername.Trim(), StringComparison.OrdinalIgnoreCase);
        }
    }
}
```

- [ ] **Step 5: Implement the validator**

`src/Emby.Sso/Protocol/SsoCredentialValidator.cs`:

```csharp
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Emby.Sso.Protocol
{
    public enum SsoCredentialOutcome
    {
        Rejected = 0,
        HandoffAccepted = 1,
        DirectGrantAccepted = 2,
    }

    public sealed class SsoCredentialResult
    {
        private SsoCredentialResult(SsoCredentialOutcome outcome, string displayName, string reason)
        {
            Outcome = outcome;
            DisplayName = displayName;
            Reason = reason;
        }

        public SsoCredentialOutcome Outcome { get; }

        public string DisplayName { get; }

        public string Reason { get; }

        public static SsoCredentialResult Handoff(string displayName) =>
            new SsoCredentialResult(SsoCredentialOutcome.HandoffAccepted, displayName, null);

        public static SsoCredentialResult DirectGrant(string displayName) =>
            new SsoCredentialResult(SsoCredentialOutcome.DirectGrantAccepted, displayName, null);

        public static SsoCredentialResult Reject(string reason) =>
            new SsoCredentialResult(SsoCredentialOutcome.Rejected, null, reason);
    }

    /// <summary>
    /// The single decision an Emby sign-in funnels into: is this password a live
    /// browser handoff secret, or a real password the identity provider should
    /// check? Emby resolves the user first, so the account is known to exist.
    /// </summary>
    public sealed class SsoCredentialValidator
    {
        private readonly HandoffSecretStore _handoff;
        private readonly Func<OidcClient> _clientFactory;
        private readonly Func<bool> _directGrantEnabled;

        public SsoCredentialValidator(
            HandoffSecretStore handoff,
            Func<OidcClient> clientFactory,
            Func<bool> directGrantEnabled)
        {
            _handoff = handoff ?? throw new ArgumentNullException(nameof(handoff));
            _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
            _directGrantEnabled = directGrantEnabled ?? throw new ArgumentNullException(nameof(directGrantEnabled));
        }

        public async Task<SsoCredentialResult> ValidateAsync(string embyUsername, string password, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(embyUsername) || string.IsNullOrEmpty(password))
            {
                return SsoCredentialResult.Reject(SsoErrors.ProviderRejected);
            }

            if (_handoff.TryConsume(embyUsername, password))
            {
                return SsoCredentialResult.Handoff(embyUsername);
            }

            var client = _clientFactory();

            if (client == null)
            {
                return SsoCredentialResult.Reject(SsoErrors.NotConfigured);
            }

            if (!_directGrantEnabled())
            {
                return SsoCredentialResult.Reject(SsoErrors.DirectGrantDisabled);
            }

            OidcIdentity identity;

            try
            {
                identity = await client.DirectGrantAsync(embyUsername, password, cancellationToken).ConfigureAwait(false);
            }
            catch (SsoException ex)
            {
                return SsoCredentialResult.Reject(ex.UserSafeReason);
            }

            if (!UsernameMatcher.Matches(identity.Username, embyUsername))
            {
                return SsoCredentialResult.Reject(SsoErrors.UnknownUser);
            }

            return SsoCredentialResult.DirectGrant(identity.DisplayName);
        }
    }
}
```

Note the ordering: the unconfigured check precedes the direct-grant check, so a server with no issuer configured reports `NotConfigured` rather than `DirectGrantDisabled`. The test `An_unconfigured_plugin_rejects_everything` asserts exactly that, with direct grant left enabled.

- [ ] **Step 6: Run the tests and verify they pass**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: 61 passed.

- [ ] **Step 7: Commit**

```bash
git add src/ tests/
git commit -m "feat: add username matching and the SSO credential decision"
```

---

### Task 10: Wire the protocol layer into Emby and implement the authentication provider

From here on, code touches Emby types and is verified against the test server rather than by unit tests. Keep these classes thin; anything containing a decision belongs in `Protocol/`.

**Files:**
- Create: `src/Emby.Sso/SsoRuntime.cs`
- Create: `src/Emby.Sso/Auth/SsoAuthenticationProvider.cs`
- Modify: `docs/superpowers/spikes/2026-08-30-emby-api-findings.md` (only if this task discovers something new)

**Interfaces:**
- Consumes: `PendingLoginStore`, `HandoffSecretStore`, `OidcClient`, `OidcOptions`, `SsoCredentialValidator`, `SsoErrors` from Tasks 4-9; `Plugin.Instance.Configuration` from Task 1.
- Produces:
  - `Emby.Sso.SsoRuntime`, a static class exposing `PendingLogins`, `HandoffSecrets`, `Validator`, `Configuration`, `GetClient()` returning null when unconfigured, and `RedirectUri()`. Task 12 uses all of these.
  - `Emby.Sso.Auth.SsoAuthenticationProvider` implementing `IAuthenticationProvider` and `IRequiresResolvedUser`.

- [ ] **Step 1: Implement the runtime**

`src/Emby.Sso/SsoRuntime.cs`:

```csharp
using System;
using System.Net.Http;
using Emby.Sso.Configuration;
using Emby.Sso.Protocol;

namespace Emby.Sso
{
    /// <summary>
    /// The process-wide state the plugin needs. Emby constructs authentication
    /// providers and API services independently, so the stores they must share
    /// live here.
    /// </summary>
    public static class SsoRuntime
    {
        private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        private static readonly object ClientLock = new object();

        private static OidcClient _client;
        private static string _clientKey;

        public static PendingLoginStore PendingLogins { get; } =
            new PendingLoginStore(() => DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

        public static HandoffSecretStore HandoffSecrets { get; } =
            new HandoffSecretStore(() => DateTimeOffset.UtcNow, TimeSpan.FromSeconds(30));

        public static SsoCredentialValidator Validator { get; } =
            new SsoCredentialValidator(
                HandoffSecrets,
                GetClient,
                () => Configuration?.EnableDirectGrant == true);

        public static PluginConfiguration Configuration => Plugin.Instance?.Configuration;

        /// <summary>The callback URL registered with the identity provider.</summary>
        public static string RedirectUri()
        {
            var configuration = Configuration;

            return configuration == null
                ? null
                : configuration.EmbyPublicBaseUrl.TrimEnd('/') + "/emby/Sso/Callback";
        }

        /// <summary>Returns null when the plugin has not been configured.</summary>
        public static OidcClient GetClient()
        {
            var configuration = Configuration;

            if (configuration == null || !configuration.IsConfigured)
            {
                return null;
            }

            // Rebuild whenever a setting that shapes the client changes.
            var key = string.Join("|",
                configuration.IssuerUrl,
                configuration.ClientId,
                configuration.ClientSecret,
                configuration.Scopes,
                configuration.UsernameClaim,
                configuration.EmbyPublicBaseUrl);

            lock (ClientLock)
            {
                if (_client != null && string.Equals(_clientKey, key, StringComparison.Ordinal))
                {
                    return _client;
                }

                _client = new OidcClient(Http, new OidcOptions
                {
                    IssuerUrl = configuration.IssuerUrl,
                    ClientId = configuration.ClientId,
                    ClientSecret = configuration.ClientSecret,
                    Scopes = configuration.Scopes,
                    RedirectUri = RedirectUri(),
                    UsernameClaim = configuration.UsernameClaim,
                });
                _clientKey = key;

                return _client;
            }
        }
    }
}
```

If the spike found that plugin endpoints are served under a prefix other than `/emby`, correct `RedirectUri()` to match and say so in the commit message.

- [ ] **Step 2: Implement the authentication provider**

`src/Emby.Sso/Auth/SsoAuthenticationProvider.cs`:

```csharp
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Model.Logging;

namespace Emby.Sso.Auth
{
    /// <summary>
    /// The single point Emby calls for both sign-in paths. A password is either
    /// a live browser handoff secret or a real password for the identity
    /// provider to check; SsoCredentialValidator decides which.
    /// </summary>
    public class SsoAuthenticationProvider : IAuthenticationProvider, IRequiresResolvedUser
    {
        private readonly ILogger _logger;

        public SsoAuthenticationProvider(ILogManager logManager)
        {
            _logger = logManager.GetLogger("AuthentikSso");
        }

        public string Name => "Authentik SSO";

        public bool IsEnabled => SsoRuntime.Configuration?.IsConfigured == true;

        public Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        {
            // Emby calls the resolved-user overload for this provider. Reaching
            // here means no user could be resolved, and this plugin never
            // creates users.
            _logger.Info("Rejecting sign-in for an unresolved user");
            throw new AuthenticationException(SsoErrors.UnknownUser);
        }

        public async Task<ProviderAuthenticationResult> Authenticate(string username, string password, User resolvedUser)
        {
            if (resolvedUser == null)
            {
                _logger.Info("Rejecting sign-in: no matching Emby user");
                throw new AuthenticationException(SsoErrors.UnknownUser);
            }

            var result = await SsoRuntime.Validator
                .ValidateAsync(resolvedUser.Name, password, CancellationToken.None)
                .ConfigureAwait(false);

            if (result.Outcome == SsoCredentialOutcome.Rejected)
            {
                _logger.Info("Rejected sign-in for {0}: {1}", resolvedUser.Name, result.Reason);
                throw new AuthenticationException(result.Reason);
            }

            _logger.Info("Accepted {0} sign-in for {1}", result.Outcome, resolvedUser.Name);

            return new ProviderAuthenticationResult
            {
                Username = resolvedUser.Name,
                DisplayName = result.DisplayName,
            };
        }

        public Task ChangePassword(User user, string newPassword)
        {
            // Passwords live in the identity provider. Accepting a change here
            // would create a local credential that bypasses it.
            throw new AuthenticationException("Passwords for this account are managed by the sign-in provider.");
        }

        public Task<bool> HasPassword(User user)
        {
            return Task.FromResult(true);
        }
    }
}
```

If `AuthenticationException` does not exist in `MediaBrowser.Controller.Authentication`, look up the exception type the built-in providers throw in the plugin API reference, use that, and record it in the spike document. A plain `System.Exception` works as a fallback but produces a worse client-side message.

- [ ] **Step 3: Build and re-run the unit tests**

Run: `dotnet build -c Release`
Expected: succeeds.

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: 61 passed. This also confirms nothing under `Protocol/` acquired an Emby reference, since the test project compiles those sources without Emby assemblies.

- [ ] **Step 4: Verify on the test server**

Install the merged DLL and restart Emby. In a test user's profile, set the authentication provider to **Authentik SSO**. The plugin cannot be configured yet, so confirm only that:
- the provider appears in the selector, and
- signing in as that user fails with a message rather than a server error, and the Emby log records `Rejected sign-in ... Single sign-on is not configured on this server.`

- [ ] **Step 5: Commit**

```bash
git add src/
git commit -m "feat: add the Emby authentication provider backed by the SSO validator"
```

---

### Task 11: Configuration page

**Files:**
- Modify: `src/Emby.Sso/Plugin.cs` (implement `IHasWebPages`)
- Modify: `src/Emby.Sso/Emby.Sso.csproj` (embed the HTML page)
- Create: `src/Emby.Sso/Configuration/configPage.html`

**Interfaces:**
- Consumes: `PluginConfiguration` from Task 1.
- Produces: a dashboard page that reads and writes every `PluginConfiguration` property and displays the redirect URI to paste into Authentik.

- [ ] **Step 1: Embed the page in the assembly**

Add to `src/Emby.Sso/Emby.Sso.csproj`:

```xml
  <ItemGroup>
    <EmbeddedResource Include="Configuration\configPage.html" />
  </ItemGroup>
```

- [ ] **Step 2: Implement IHasWebPages**

In `src/Emby.Sso/Plugin.cs` add `using System.Collections.Generic;` and `using MediaBrowser.Model.Plugins;`, change the declaration to `public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages`, and add this method:

```csharp
        public IEnumerable<PluginPageInfo> GetPages()
        {
            return new[]
            {
                new PluginPageInfo
                {
                    Name = "AuthentikSso",
                    EmbeddedResourcePath = GetType().Namespace + ".Configuration.configPage.html",
                },
            };
        }
```

The embedded resource path is the assembly default namespace plus the folder path. If the page fails to load, list the embedded resource names with `dotnet tool install -g ilspycmd` and `ilspycmd -r Emby.Sso.dll --list-resources`, or simply `strings Emby.Sso.dll | grep configPage`, and correct the string.

- [ ] **Step 3: Write the configuration page**

`src/Emby.Sso/Configuration/configPage.html`:

```html
<div id="authentikSsoConfigPage" data-role="page" class="page type-interior pluginConfigurationPage">
  <div data-role="content">
    <div class="content-primary">
      <form id="authentikSsoConfigForm">

        <div class="inputContainer">
          <label for="issuerUrl">Issuer URL</label>
          <input is="emby-input" type="url" id="issuerUrl" required />
          <div class="fieldDescription">
            The OpenID Connect issuer, for example
            https://auth.example.com/application/o/emby/ . Every other endpoint
            is read from its discovery document.
          </div>
        </div>

        <div class="inputContainer">
          <label for="clientId">Client ID</label>
          <input is="emby-input" type="text" id="clientId" required />
        </div>

        <div class="inputContainer">
          <label for="clientSecret">Client secret</label>
          <input is="emby-input" type="password" id="clientSecret" />
          <div class="fieldDescription">Leave empty for a public client.</div>
        </div>

        <div class="inputContainer">
          <label for="scopes">Scopes</label>
          <input is="emby-input" type="text" id="scopes" />
        </div>

        <div class="inputContainer">
          <label for="embyPublicBaseUrl">Emby public base URL</label>
          <input is="emby-input" type="url" id="embyPublicBaseUrl" required />
          <div class="fieldDescription">
            The address users reach this server on, for example
            https://emby.example.com . Used to build the redirect URI.
          </div>
        </div>

        <div class="inputContainer">
          <label for="usernameClaim">Username claim</label>
          <input is="emby-input" type="text" id="usernameClaim" />
          <div class="fieldDescription">
            The claim matched against the Emby username. Users are never created
            automatically: the Emby account must already exist, and its
            authentication provider must be set to Authentik SSO.
          </div>
        </div>

        <div class="checkboxContainer">
          <label>
            <input is="emby-checkbox" type="checkbox" id="enableDirectGrant" />
            <span>Allow native apps to sign in with a password</span>
          </label>
          <div class="fieldDescription">
            Lets phone and TV apps sign in by sending the password to the
            provider directly. This path cannot perform multi-factor
            authentication, and needs a direct-grant authentication flow bound to
            the provider in Authentik.
          </div>
        </div>

        <div class="checkboxContainer">
          <label>
            <input is="emby-checkbox" type="checkbox" id="enableButtonInjection" />
            <span>Show a sign-in button on the login page</span>
          </label>
        </div>

        <div class="checkboxContainer">
          <label>
            <input is="emby-checkbox" type="checkbox" id="allowInsecureHttp" />
            <span>Allow plain HTTP (testing only)</span>
          </label>
        </div>

        <br />

        <div class="inputContainer">
          <label>Redirect URI to configure in Authentik</label>
          <p id="redirectUri" style="user-select: all; font-family: monospace;"></p>
        </div>

        <div class="inputContainer">
          <label>Sign-in URL for users to bookmark</label>
          <p id="startUrl" style="user-select: all; font-family: monospace;"></p>
        </div>

        <div>
          <button is="emby-button" type="submit" class="raised button-submit block">
            <span>Save</span>
          </button>
        </div>

      </form>
    </div>
  </div>

  <script type="text/javascript">
    (function () {
      var pluginId = 'PASTE-YOUR-GENERATED-GUID-HERE';

      function showUrls(page, baseUrl) {
        var base = (baseUrl || '').replace(/[\/]+$/, '');
        page.querySelector('#redirectUri').textContent = base + '/emby/Sso/Callback';
        page.querySelector('#startUrl').textContent = base + '/emby/Sso/Start';
      }

      function load(page, config) {
        page.querySelector('#issuerUrl').value = config.IssuerUrl || '';
        page.querySelector('#clientId').value = config.ClientId || '';
        page.querySelector('#clientSecret').value = config.ClientSecret || '';
        page.querySelector('#scopes').value = config.Scopes || 'openid profile email';
        page.querySelector('#embyPublicBaseUrl').value = config.EmbyPublicBaseUrl || '';
        page.querySelector('#usernameClaim').value = config.UsernameClaim || 'preferred_username';
        page.querySelector('#enableDirectGrant').checked = config.EnableDirectGrant === true;
        page.querySelector('#enableButtonInjection').checked = config.EnableButtonInjection === true;
        page.querySelector('#allowInsecureHttp').checked = config.AllowInsecureHttp === true;
        showUrls(page, config.EmbyPublicBaseUrl);
      }

      document.querySelector('#authentikSsoConfigPage').addEventListener('pageshow', function () {
        var page = this;
        Dashboard.showLoadingMsg();
        ApiClient.getPluginConfiguration(pluginId).then(function (config) {
          load(page, config);
          Dashboard.hideLoadingMsg();
        });
      });

      document.querySelector('#authentikSsoConfigForm').addEventListener('submit', function (event) {
        event.preventDefault();
        var page = document.querySelector('#authentikSsoConfigPage');
        Dashboard.showLoadingMsg();

        ApiClient.getPluginConfiguration(pluginId).then(function (config) {
          config.IssuerUrl = page.querySelector('#issuerUrl').value.trim();
          config.ClientId = page.querySelector('#clientId').value.trim();
          config.ClientSecret = page.querySelector('#clientSecret').value;
          config.Scopes = page.querySelector('#scopes').value.trim();
          config.EmbyPublicBaseUrl = page.querySelector('#embyPublicBaseUrl').value.trim();
          config.UsernameClaim = page.querySelector('#usernameClaim').value.trim();
          config.EnableDirectGrant = page.querySelector('#enableDirectGrant').checked;
          config.EnableButtonInjection = page.querySelector('#enableButtonInjection').checked;
          config.AllowInsecureHttp = page.querySelector('#allowInsecureHttp').checked;

          ApiClient.updatePluginConfiguration(pluginId, config).then(function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            showUrls(page, config.EmbyPublicBaseUrl);
          });
        });

        return false;
      });
    })();
  </script>
</div>
```

Replace `PASTE-YOUR-GENERATED-GUID-HERE` with the GUID from `Plugin.cs`.

- [ ] **Step 4: Verify on the test server**

Build, install, restart. Open Dashboard, then Plugins, then Authentik SSO.
Expected: the page loads; saving persists across a server restart; the redirect URI shown ends in `/emby/Sso/Callback`. Reopen the page to confirm values were stored.

- [ ] **Step 5: Commit**

```bash
git add src/
git commit -m "feat: add the plugin configuration page"
```

---

### Task 12: The SSO endpoints

**Files:**
- Create: `src/Emby.Sso/Api/SsoRequests.cs`
- Create: `src/Emby.Sso/Api/ErrorPage.cs`
- Create: `src/Emby.Sso/Api/SsoService.cs`

**Interfaces:**
- Consumes: `SsoRuntime` (Task 10), `SsoErrors` and `SsoException` (Task 7), `OidcClient` (Tasks 6-8), `IUserManager.GetUserByName(string)` from Emby.
- Produces: the HTTP endpoints `GET /emby/Sso/Start` and `GET /emby/Sso/Callback`. Task 13 adds `GET /emby/Sso/Script.js` to the same service class.

- [ ] **Step 1: Write the request DTOs**

`src/Emby.Sso/Api/SsoRequests.cs`:

```csharp
using MediaBrowser.Model.Services;

namespace Emby.Sso.Api
{
    [Route("/Sso/Start", "GET")]
    public class SsoStart : IReturnVoid
    {
    }

    [Route("/Sso/Callback", "GET")]
    public class SsoCallback : IReturnVoid
    {
        public string Code { get; set; }

        public string State { get; set; }

        public string Error { get; set; }
    }
}
```

If the spike found that plugin endpoints require an attribute to be reachable without a session, these DTOs need it; a login endpoint that demands a login is useless. Apply whatever the spike recorded.

- [ ] **Step 2: Write the error page**

`src/Emby.Sso/Api/ErrorPage.cs`:

```csharp
using System.Net;

namespace Emby.Sso.Api
{
    /// <summary>
    /// The only thing a failed sign-in shows the browser. Detail goes to the log.
    /// </summary>
    public static class ErrorPage
    {
        public static string Render(string userSafeReason, string loginUrl)
        {
            var reason = WebUtility.HtmlEncode(userSafeReason ?? "Sign-in failed.");
            var href = WebUtility.HtmlEncode(loginUrl ?? "/");

            return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + "<title>Sign-in failed</title><style>"
                + "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;"
                + "background:#101010;color:#eee;display:flex;min-height:100vh;margin:0;"
                + "align-items:center;justify-content:center;text-align:center}"
                + "main{max-width:32rem;padding:2rem}h1{font-size:1.25rem;font-weight:600}"
                + "p{color:#bbb;line-height:1.5}a{color:#9cf}</style></head><body><main>"
                + "<h1>Sign-in failed</h1><p>" + reason + "</p>"
                + "<p><a href=\"" + href + "\">Back to sign in</a></p>"
                + "</main></body></html>";
        }

        /// <summary>
        /// A page that sends the browser onward. Used instead of a 302 so that
        /// the URL fragment carrying the handoff secret survives the hop.
        /// </summary>
        public static string RenderRedirect(string url)
        {
            var json = Newtonsoft.Json.JsonConvert.ToString(url ?? "/");

            return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<title>Signing in</title></head><body>"
                + "<script>location.replace(" + json + ");</script>"
                + "</body></html>";
        }
    }
}
```

`JsonConvert.ToString` produces a correctly quoted and escaped JavaScript string literal, which is what keeps a hostile URL from breaking out of the script context.

- [ ] **Step 3: Write the service**

`src/Emby.Sso/Api/SsoService.cs`:

```csharp
using System;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Logging;
using MediaBrowser.Model.Services;

namespace Emby.Sso.Api
{
    public class SsoService : IService, IHasResultFactory
    {
        private readonly ILogger _logger;
        private readonly IUserManager _userManager;

        public SsoService(ILogManager logManager, IUserManager userManager)
        {
            _logger = logManager.GetLogger("AuthentikSso");
            _userManager = userManager;
        }

        public IHttpResultFactory ResultFactory { get; set; }

        public IRequest Request { get; set; }

        public async Task<object> Get(SsoStart request)
        {
            var configuration = SsoRuntime.Configuration;

            if (configuration == null || !configuration.IsConfigured)
            {
                return Error(SsoErrors.NotConfigured, "sign-in started while the plugin was not configured");
            }

            if (!configuration.EmbyPublicBaseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                && !configuration.AllowInsecureHttp)
            {
                return Error(
                    SsoErrors.NotConfigured,
                    "refusing to start sign-in: the public base URL is not HTTPS and insecure HTTP is not allowed");
            }

            try
            {
                var login = SsoRuntime.PendingLogins.Create();
                var url = await SsoRuntime.GetClient()
                    .BuildAuthorizationUrlAsync(login, CancellationToken.None)
                    .ConfigureAwait(false);

                return Html(ErrorPage.RenderRedirect(url));
            }
            catch (Exception ex)
            {
                return Error(SsoErrors.ProviderUnreachable, "could not build the authorization URL: " + ex.Message);
            }
        }

        public async Task<object> Get(SsoCallback request)
        {
            if (!string.IsNullOrEmpty(request.Error))
            {
                // request.Error is provider-supplied; log it, never render it.
                return Error(SsoErrors.ProviderRejected, "provider returned error=" + request.Error);
            }

            var login = SsoRuntime.PendingLogins.Consume(request.State);

            if (login == null)
            {
                return Error(SsoErrors.SessionExpired, "callback carried an unknown, expired or replayed state");
            }

            var client = SsoRuntime.GetClient();

            if (client == null)
            {
                return Error(SsoErrors.NotConfigured, "callback arrived while the plugin was not configured");
            }

            OidcIdentity identity;

            try
            {
                identity = await client.ExchangeCodeAsync(request.Code, login, CancellationToken.None).ConfigureAwait(false);
            }
            catch (SsoException ex)
            {
                _logger.Error("SSO callback failed: {0}", ex.Message);
                return Error(ex.UserSafeReason, null);
            }

            var user = _userManager.GetUserByName(identity.Username);

            if (user == null || !UsernameMatcher.Matches(identity.Username, user.Name))
            {
                _logger.Info("Rejected sign-in: no Emby user named '{0}'", identity.Username);
                return Error(SsoErrors.UnknownUser, null);
            }

            var secret = SsoRuntime.HandoffSecrets.Issue(user.Name);
            _logger.Info("Issued a sign-in handoff for {0}", user.Name);

            var target = LoginUrl(user.Name, secret);
            return Html(ErrorPage.RenderRedirect(target));
        }

        private string LoginUrl(string username, string secret)
        {
            var baseUrl = SsoRuntime.Configuration.EmbyPublicBaseUrl.TrimEnd('/');

            // Everything after '#' is a fragment, so the secret is never sent to
            // a server and never appears in an access log or a proxy log.
            return baseUrl + "/web/index.html#!/login.html?sso_user="
                + Uri.EscapeDataString(username) + "&sso_secret=" + Uri.EscapeDataString(secret);
        }

        private object Error(string userSafeReason, string logDetail)
        {
            if (!string.IsNullOrEmpty(logDetail))
            {
                _logger.Error("SSO: {0}", logDetail);
            }

            var baseUrl = SsoRuntime.Configuration?.EmbyPublicBaseUrl?.TrimEnd('/') ?? string.Empty;
            return Html(ErrorPage.Render(userSafeReason, baseUrl + "/web/index.html"));
        }

        private object Html(string body)
        {
            return ResultFactory.GetResult(Request, body, "text/html; charset=utf-8");
        }
    }
}
```

The login page path `/web/index.html#!/login.html` is the value to confirm against the running server. Open the Emby login page in a browser and copy the address bar; if it differs, correct `LoginUrl` and note the real value in the spike document.

- [ ] **Step 4: Verify on the test server**

Build, install, restart. Configure the plugin against Authentik with the redirect URI the configuration page displays, and in Authentik create an OAuth2/OpenID provider whose redirect URI matches exactly.

Check each of these:
- `GET /emby/Sso/Start` with the plugin unconfigured renders the "not configured" error page, not a stack trace.
- With it configured, `/emby/Sso/Start` lands on the Authentik login screen.
- Completing sign-in as a user who exists in Emby lands on the Emby login page with `sso_user` and `sso_secret` in the fragment. Nothing happens yet; Task 13 adds the script that consumes them.
- Completing sign-in as an Authentik user with no Emby account renders the "not set up on this server" page, and the log names the username.
- Loading `/emby/Sso/Callback?state=garbage` renders the expired-attempt page.
- Confirm the Emby access log contains no `sso_secret`.

- [ ] **Step 5: Commit**

```bash
git add src/
git commit -m "feat: add the SSO start and callback endpoints"
```

---

### Task 13: The login page script

**Files:**
- Create: `src/Emby.Sso/Api/LoginScript.cs`
- Modify: `src/Emby.Sso/Api/SsoRequests.cs` (add the script route)
- Modify: `src/Emby.Sso/Api/SsoService.cs` (serve the script)
- Modify: `README.md` (created in Task 14; if it does not exist yet, leave the note for Task 14)

**Interfaces:**
- Consumes: `SsoRuntime.Configuration` (Task 10), the endpoints from Task 12.
- Produces: `GET /emby/Sso/Script.js`, which both completes a handoff and renders the sign-in button.

- [ ] **Step 1: Add the route**

Append to `src/Emby.Sso/Api/SsoRequests.cs`:

```csharp
    [Route("/Sso/Script.js", "GET")]
    public class SsoScript : IReturnVoid
    {
    }
```

- [ ] **Step 2: Write the script**

`src/Emby.Sso/Api/LoginScript.cs`:

```csharp
namespace Emby.Sso.Api
{
    /// <summary>
    /// Served to the Emby web client. Two jobs: finish a handoff when the page
    /// is loaded with sso_user and sso_secret in the fragment, and offer a
    /// sign-in button otherwise.
    /// </summary>
    public static class LoginScript
    {
        public static string Render(bool showButton)
        {
            var button = showButton ? "true" : "false";

            return @"
(function () {
  var SHOW_BUTTON = " + button + @";
  var START_URL = '/emby/Sso/Start';

  function readHandoff() {
    var hash = window.location.hash || '';
    var q = hash.indexOf('?');
    if (q < 0) { return null; }

    var params = new URLSearchParams(hash.substring(q + 1));
    var user = params.get('sso_user');
    var secret = params.get('sso_secret');
    if (!user || !secret) { return null; }

    // Remove the secret from the address bar before doing anything else.
    params.delete('sso_user');
    params.delete('sso_secret');
    var rest = params.toString();
    var cleaned = hash.substring(0, q) + (rest ? '?' + rest : '');
    history.replaceState(null, '', window.location.pathname + window.location.search + cleaned);

    return { user: user, secret: secret };
  }

  function finishSignIn(handoff) {
    if (typeof ApiClient === 'undefined' || !ApiClient.authenticateUserByName) {
      console.error('[sso] ApiClient is unavailable; cannot complete sign-in');
      return;
    }

    ApiClient.authenticateUserByName(handoff.user, handoff.secret).then(function () {
      if (typeof Dashboard !== 'undefined' && Dashboard.navigate) {
        Dashboard.navigate('home.html');
      } else {
        window.location.replace('/web/index.html#!/home.html');
      }
    }, function (error) {
      console.error('[sso] sign-in was rejected', error);
    });
  }

  function addButton() {
    if (!SHOW_BUTTON || document.getElementById('ssoSignInButton')) { return; }

    var form = document.querySelector('form');
    if (!form) { return; }

    var button = document.createElement('button');
    button.id = 'ssoSignInButton';
    button.type = 'button';
    button.className = 'raised block';
    button.style.marginTop = '1em';
    button.textContent = 'Sign in with Authentik';
    button.addEventListener('click', function () { window.location.href = START_URL; });
    form.appendChild(button);
  }

  function tick() {
    var handoff = readHandoff();
    if (handoff) {
      finishSignIn(handoff);
      return;
    }
    addButton();
  }

  // The web client is a single-page app: the login view can appear long after
  // this script loads, so watch for it rather than running once.
  document.addEventListener('DOMContentLoaded', tick);
  window.addEventListener('hashchange', tick);
  setInterval(tick, 750);
  tick();
})();
";
        }
    }
}
```

- [ ] **Step 3: Serve it**

Add to `SsoService`:

```csharp
        public object Get(SsoScript request)
        {
            var showButton = SsoRuntime.Configuration?.EnableButtonInjection == true;
            return ResultFactory.GetResult(Request, LoginScript.Render(showButton), "application/javascript; charset=utf-8");
        }
```

- [ ] **Step 4: Verify the handoff end to end**

Build, install, restart. Load the Emby login page with the developer console open and paste this to load the script manually:

```javascript
var s = document.createElement('script'); s.src = '/emby/Sso/Script.js'; document.head.appendChild(s);
```

Then run the full browser flow from `/emby/Sso/Start`.
Expected: after Authentik, the browser returns to the Emby login page and is signed in without typing anything. If `ApiClient.authenticateUserByName` is unavailable or named differently in this Emby web version, find the real function in the console (`Object.keys(ApiClient).filter(k => /auth/i.test(k))`), correct `finishSignIn`, and record the finding in the spike document.

Also confirm:
- The address bar no longer contains `sso_secret` after sign-in.
- Reloading the page after sign-in does not attempt a second sign-in.
- Replaying the callback URL by pasting it again fails, because the state was consumed.

- [ ] **Step 5: Install the script permanently**

Using whatever the spike found in Step 3 of Task 2:
- If the branding hook executes scripts, paste `<script src="/emby/Sso/Script.js"></script>` into it and confirm the button appears on a fresh load of the login page.
- If scripts are stripped, record that in the README instead, and confirm the bookmarkable `/emby/Sso/Start` URL completes a sign-in on its own. The handoff still works because the script is loaded by whatever means the administrator chooses; without it, users start at `/emby/Sso/Start` and the flow needs the script only for the final step, so in this case document that the administrator must add the script tag through a reverse proxy body-rewrite or accept that only the button is lost.

Record the outcome in the README section written in Task 14.

- [ ] **Step 6: Commit**

```bash
git add src/
git commit -m "feat: serve the login page script that completes the SSO handoff"
```

---

### Task 14: Packaging, CI and documentation

**Files:**
- Create: `.gitlab-ci.yml`
- Modify: `README.md`

**Interfaces:**
- Consumes: the build from Task 1 and the ILRepack target from Task 2.
- Produces: a CI job publishing `Emby.Sso.dll` as an artifact, and a README covering Authentik setup, Emby setup and the per-user provider assignment.

- [ ] **Step 1: Write the CI configuration**

`.gitlab-ci.yml`:

```yaml
stages:
  - test
  - build

default:
  image: mcr.microsoft.com/dotnet/sdk:8.0

test:
  stage: test
  script:
    - dotnet test tests/Emby.Sso.Tests --logger "console;verbosity=normal"

build:
  stage: build
  script:
    - dotnet build -c Release
  artifacts:
    name: "emby-sso-$CI_COMMIT_SHORT_SHA"
    paths:
      - src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll
    expire_in: 30 days
```

If Task 2 concluded that ILRepack could not be used, change the artifact path to `src/Emby.Sso/bin/Release/netstandard2.0/` and list every DLL that must be installed.

- [ ] **Step 2: Write the README**

Replace `README.md` with a document covering:

- What the plugin does, and the explicit statement that it never creates users.
- **Authentik setup:** create an OAuth2/OpenID provider; redirect URI is the value shown on the plugin configuration page; note that enabling native-app sign-in additionally requires an authentication flow bound to the provider for the direct grant.
- **Emby setup:** install the DLL into the `plugins` folder, restart, configure the plugin page, then — stated prominently, because nothing works without it — **set each user's authentication provider to Authentik SSO in that user's Emby profile**.
- **Signing in:** the bookmarkable URL `https://<emby>/emby/Sso/Start`, and how the login page button is installed, reflecting what Task 13 Step 5 actually established on this server.
- **Native apps:** what the direct grant does, that it cannot do multi-factor authentication, and that it is off by default.
- **Troubleshooting:** where the plugin logs, and what each user-visible message means.
- **Building from source:** `dotnet build -c Release`, and where the merged DLL lands.

- [ ] **Step 3: Verify the pipeline configuration parses**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal && dotnet build -c Release`
Expected: both succeed locally, which is what the two CI jobs run. Push the branch and confirm the pipeline is green.

- [ ] **Step 4: Commit**

```bash
git add .gitlab-ci.yml README.md
git commit -m "docs: add setup documentation and CI pipeline"
```

---

### Task 15: End-to-end verification

No new code. This task proves the finished plugin behaves as the spec says, including the cases that are easy to get wrong and impossible to catch in unit tests.

**Files:**
- Create: `docs/superpowers/verification/2026-08-30-emby-oidc-sso-verification.md`

**Interfaces:**
- Consumes: everything.
- Produces: a record of what was tested and what was observed.

- [ ] **Step 1: Verify the browser flow**

Against the test Emby and a real Authentik:
- A user who exists in Emby, has the Authentik SSO provider assigned, and authenticates at Authentik is signed in without typing an Emby password.
- Multi-factor authentication configured in Authentik is enforced during that sign-in.
- A user who authenticates at Authentik but has no Emby account sees the "not set up on this server" page, and no Emby user is created.

- [ ] **Step 2: Verify the native flow**

- With direct grant disabled, a native client sign-in for an SSO user fails.
- With it enabled, the same sign-in succeeds using the Authentik password.
- A wrong password fails.
- Changing the password in Authentik immediately changes which password works in the native app.

- [ ] **Step 3: Verify the security properties**

- Replaying a completed callback URL fails.
- Replaying a handoff secret fails: capture one from the fragment, complete the sign-in, then attempt an Emby login with that secret as the password.
- Waiting more than 30 seconds before completing a handoff fails.
- Neither the Emby log nor the reverse proxy access log contains a `sso_secret`, a client secret, or a password. Grep for the actual values.
- A user whose Emby account is disabled cannot sign in through SSO.

- [ ] **Step 4: Verify configuration robustness**

- An unreachable issuer produces an error page and a log entry rather than a hang, and does not produce a request storm.
- Restarting Emby does not invalidate configuration, and does invalidate outstanding handoff secrets, which are in memory by design.

- [ ] **Step 5: Record the results**

Write the verification document with one line per check, the observed result, and any deviation from the spec. Anything that failed becomes an issue or a follow-up task rather than a silent omission.

- [ ] **Step 6: Commit**

```bash
git add docs/
git commit -m "docs: record end-to-end verification results"
```

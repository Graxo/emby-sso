# Group-Gated Account Provisioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an Authentik identity holding a designated group sign in to Emby, creating its account from a template user if it does not exist, and refusing anyone who lacks the group.

**Architecture:** The gate decision is a pure function in `Protocol/`, tested without a server, consistent with every other decision in this plugin. `OidcIdentity` gains the groups read from the token; `SsoCredentialResult` carries the verified identity so callers can apply the gate. A thin `UserProvisioner` in the Emby shell clones a template user. The browser callback provisions before minting a handoff secret; the authentication provider's null-user branch — currently an unconditional throw and the plugin's dominant security property — gains one narrowly guarded opening.

**Tech Stack:** C#, netstandard2.0, `MediaBrowser.Server.Core` 4.9.1.90, `Microsoft.IdentityModel.*` 6.35.0 merged by ILRepack, xUnit.

**Spec:** `docs/superpowers/specs/2026-08-30-group-gated-provisioning-design.md`

## Global Constraints

- Target framework `netstandard2.0`. `dotnet build -c Release` must end at 0 warnings with the ILRepack merge succeeding.
- The .NET SDK is not on the default PATH: `export PATH="$HOME/.dotnet:$PATH"` in every shell invocation.
- Classes under `src/Emby.Sso/Protocol/` MUST NOT reference any `MediaBrowser.*` type. The test project compiles `Protocol/**` without Emby assemblies, which enforces this mechanically.
- The test suite is at **113 tests** and must stay green. Report the number you observe; never adjust anything to hit a predicted count.
- A created account is **never** an administrator, whatever the template says. Enforced in code, not left to the operator.
- `UserData` is never cloned.
- No credential — client secret, token, password, handoff secret — may reach a log, a URL, or a rendered page.
- Group values are untrusted input: matched, never rendered, never logged in full.
- Group matching is ordinal and case-insensitive after trimming, matching `UsernameMatcher`'s rule and for the same reason.
- Every task ends with a commit. Commands run from the repository root.

## Existing interfaces this plan builds on

```csharp
// Protocol/OidcIdentity.cs — gains Groups in Task 2
public sealed class OidcIdentity {
    public OidcIdentity(string subject, string username, string displayName);
    public string Subject { get; } public string Username { get; } public string DisplayName { get; }
}

// Protocol/SsoCredentialValidator.cs — gains Identity in Task 4
public sealed class SsoCredentialResult {
    public SsoCredentialOutcome Outcome { get; }   // Rejected | HandoffAccepted | DirectGrantAccepted
    public string DisplayName { get; } public string Reason { get; }
    public static SsoCredentialResult Handoff(string displayName);
    public static SsoCredentialResult DirectGrant(string displayName);
    public static SsoCredentialResult Reject(string reason);
}

// Protocol/SsoErrors.cs — eight constants today: NotConfigured, ProviderUnreachable,
// ProviderRejected, InvalidToken, SessionExpired, UnknownUser, DirectGrantDisabled, EmptyCredential

// Protocol/OidcClient.cs
private static string ReadClaim(JsonWebToken token, string name);   // single-valued
// ValidateIdToken ends with:
//   return new OidcIdentity(ReadClaim(token, "sub"), username.Trim(), ReadClaim(token, "name") ?? username.Trim());

// Auth/SsoAuthenticationProvider.cs — the null-user branch, currently an unconditional throw
// Api/SsoService.cs:199-209 — GetUserByName, refuse with UnknownUser, then HandoffSecrets.Issue
```

## File structure

```
src/Emby.Sso/Protocol/OidcIdentity.cs          modify — add Groups
src/Emby.Sso/Protocol/OidcClient.cs            modify — read the groups claim
src/Emby.Sso/Protocol/GroupGate.cs             create — the pure gate decision
src/Emby.Sso/Protocol/SsoErrors.cs             modify — three new reasons
src/Emby.Sso/Protocol/SsoCredentialValidator.cs modify — carry the identity
src/Emby.Sso/Configuration/PluginConfiguration.cs modify — four new settings
src/Emby.Sso/Configuration/configPage.html     modify — four new fields
src/Emby.Sso/Configuration/configPage.js       modify — load/save them
src/Emby.Sso/Auth/UserProvisioner.cs           create — clone the template
src/Emby.Sso/Auth/SsoAuthenticationProvider.cs modify — the guarded opening
src/Emby.Sso/Api/SsoService.cs                 modify — provision in the callback
src/Emby.Sso/SsoRuntime.cs                     modify — expose gate options
tests/Emby.Sso.Tests/GroupGateTests.cs         create
tests/Emby.Sso.Tests/FakeIdentityProvider.cs   modify — mint groups claims
tests/Emby.Sso.Tests/OidcClientTokenTests.cs   modify — groups parsing
tests/Emby.Sso.Tests/SsoCredentialValidatorTests.cs modify — identity on results
README.md                                      modify
docs/superpowers/spikes/2026-08-30-provisioning-mechanics.md create (Task 1)
```

---

### Task 1: Spike — who wins when a provider creates the account itself?

Throwaway code. The deliverable is the findings document. **This gates Task 8 only**; Tasks 2–7 and 9 do not depend on it.

**Files:**
- Create: `docs/superpowers/spikes/2026-08-30-provisioning-mechanics.md`
- Temporarily modify: `src/Emby.Sso/Auth/SsoAuthenticationProvider.cs` (reverted before commit)

**Interfaces:**
- Consumes: nothing.
- Produces: the findings document, which Task 8 reads to decide its approach.

**The question.** The earlier spike established that Emby **auto-creates an account when an authentication provider returns success for an unknown username**, using default policy. Task 8 needs the account to exist with the *template's* policy instead. So: if the provider calls `IUserManager.CreateUser` itself and then returns success, does Emby adopt that account, create a second one, or fail?

- [ ] **Step 1: Build a probe provider**

Temporarily replace the body of the `resolvedUser == null` branch in `Authenticate(string, string, User)` with a probe that, when `username` starts with `probe-`:
1. logs that it was reached with a null resolved user,
2. calls `_userManager.CreateUser(username, templateUser, new[] { UserCopyOptions.UserPolicy, UserCopyOptions.UserConfiguration })` where `templateUser` is fetched by `GetUserByName` from a name you hardcode for the probe,
3. logs the created user's id and `Policy.EnabledFolders`,
4. returns `new ProviderAuthenticationResult { Username = username }`.

`IUserManager` must be injected into the provider for this; the constructor currently takes only `ILogManager`. Add the parameter — Task 8 needs it permanently anyway.

- [ ] **Step 2: Observe against the live server**

Server details: Emby 4.9.5.0 at `http://10.10.140.5:8090`, API key `bf4c830bf6b044e4b79c10bcf8ba9677` as header `X-Emby-Token`. `ssh graxo@10.10.140.5` (key authorised, `BatchMode=yes`, passwordless `sudo`). Plugins dir `/docker-data/compose/dl-cluster/configs/emby/plugins/`, logs at `/docker-data/compose/dl-cluster/configs/emby/logs/`. Restart with `sudo docker restart emby`, then poll `/System/Info/Public` until 200. **Restart freely** — the user has confirmed any playback is their own testing. **Never modify the `embyadmin` account.**

Create a template user with restricted libraries first (via `POST /emby/Users/New` then `POST /emby/Users/{id}/Policy` with `EnableAllFolders: false` and one entry in `EnabledFolders`). Then attempt a sign-in as `probe-alpha`, a username that does not exist, and record:

- Does exactly one account named `probe-alpha` exist afterwards, or two, or none?
- What are its `Policy.EnabledFolders` and `EnableAllFolders` — the template's, or Emby's defaults?
- What is its `Policy.AuthenticationProviderId`?
- Does the sign-in succeed, and does the client receive a usable token?
- If Emby's own creation wins, is there an observable ordering — does our account exist first and get replaced, or is ours ignored?

- [ ] **Step 3: Probe the fallback**

Whatever Step 2 shows, also determine whether `IUserManager.UpdateUserPolicy(long userId, UserPolicy policy)` applied immediately after a successful return produces the intended policy — that is the fallback if Emby's creation wins.

- [ ] **Step 4: Write the findings**

Create `docs/superpowers/spikes/2026-08-30-provisioning-mechanics.md`: the question, exactly what was observed with quoted log lines and API responses, and the decision forced for Task 8. State plainly which of these three the evidence supports:

1. The provider may create the account and Emby adopts it — Task 8 provisions directly.
2. Emby's creation wins — Task 8 returns success, then immediately applies the template policy, and the findings must say how long the account exists with default access.
3. Neither works reliably — Task 8 withdraws native provisioning; a new user must sign in through a browser first. **This partly reverses a decision the user made, so it stops and reports rather than proceeding.**

- [ ] **Step 5: Revert the probe and restore the server**

Revert `SsoAuthenticationProvider.cs` to its committed state except for the `IUserManager` constructor parameter, which stays. Delete every `probe-*` account and the template user you created, remove the probe DLL, restart, and verify: `/System/Info/Public` returns 200, `claude` / `claude123` still signs in, `embyadmin` untouched. Verify rather than assume.

- [ ] **Step 6: Commit**

```bash
git add docs/superpowers/spikes/2026-08-30-provisioning-mechanics.md src/Emby.Sso/Auth/SsoAuthenticationProvider.cs
git commit -m "docs: record Emby provisioning mechanics spike findings"
```

---

### Task 2: Read groups from the token

**Files:**
- Modify: `src/Emby.Sso/Protocol/OidcIdentity.cs`
- Modify: `src/Emby.Sso/Protocol/OidcClient.cs`
- Modify: `tests/Emby.Sso.Tests/FakeIdentityProvider.cs`
- Test: `tests/Emby.Sso.Tests/OidcClientTokenTests.cs`

**Interfaces:**
- Consumes: `OidcClient.ValidateIdToken`, `FakeIdentityProvider.CreateIdToken`.
- Produces: `OidcIdentity.Groups` as `IReadOnlyList<string>`, never null — an empty list when the claim is absent — and `OidcIdentity.HasGroupsClaim` as `bool`, distinguishing "claim absent" from "claim present but empty". `OidcOptions.GroupsClaim` (string, default `"groups"`).

The distinction matters: an absent claim usually means a misconfigured Authentik provider, and the spec requires a different log reason for it.

- [ ] **Step 1: Let the fake provider mint groups**

In `FakeIdentityProvider.CreateIdToken`, add an optional parameter `string[] groups = null` and, when it is non-null, add `claims["groups"] = groups;`. A `string[]` claim value produces a multi-valued claim, which is how a real provider emits group membership. Passing an empty array must produce a present-but-empty claim, so do not treat empty as null.

- [ ] **Step 2: Write the failing tests**

Add to `OidcClientTokenTests.cs`:

```csharp
[Fact]
public async Task Groups_are_read_from_the_token()
{
    var login = _logins.Create();
    _idp.TokenResponseJson = _idp.CreateTokenResponse(
        _idp.CreateIdToken(nonce: login.Nonce, groups: new[] { "emby-users", "staff" }));

    var identity = await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

    Assert.True(identity.HasGroupsClaim);
    Assert.Equal(new[] { "emby-users", "staff" }, identity.Groups);
}

[Fact]
public async Task An_absent_groups_claim_is_distinguishable_from_an_empty_one()
{
    var login = _logins.Create();
    _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(nonce: login.Nonce));

    var identity = await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

    Assert.False(identity.HasGroupsClaim);
    Assert.Empty(identity.Groups);
}

[Fact]
public async Task An_empty_groups_claim_is_present_but_empty()
{
    var login = _logins.Create();
    _idp.TokenResponseJson = _idp.CreateTokenResponse(
        _idp.CreateIdToken(nonce: login.Nonce, groups: new string[0]));

    var identity = await CreateClient().ExchangeCodeAsync("the-code", login, CancellationToken.None);

    Assert.Empty(identity.Groups);
}

[Fact]
public async Task The_groups_claim_name_is_configurable()
{
    var login = _logins.Create();
    _idp.TokenResponseJson = _idp.CreateTokenResponse(_idp.CreateIdToken(
        nonce: login.Nonce,
        extraClaims: new Dictionary<string, object> { ["roles"] = new[] { "emby-users" } }));

    var client = CreateClient(options => options.GroupsClaim = "roles");
    var identity = await client.ExchangeCodeAsync("the-code", login, CancellationToken.None);

    Assert.Equal(new[] { "emby-users" }, identity.Groups);
}
```

The last test needs a `CreateClient(Action<OidcOptions>)` overload in the test class; add one that applies the action to the options before constructing the client, and leave the existing no-argument overload delegating to it.

- [ ] **Step 3: Run and verify they fail**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: compile errors — `Groups`, `HasGroupsClaim` and `GroupsClaim` do not exist.

- [ ] **Step 4: Extend `OidcIdentity`**

```csharp
using System.Collections.Generic;

namespace Emby.Sso.Protocol
{
    public sealed class OidcIdentity
    {
        public OidcIdentity(string subject, string username, string displayName,
            IReadOnlyList<string> groups, bool hasGroupsClaim)
        {
            Subject = subject;
            Username = username;
            DisplayName = displayName;
            Groups = groups ?? new string[0];
            HasGroupsClaim = hasGroupsClaim;
        }

        public string Subject { get; }

        public string Username { get; }

        public string DisplayName { get; }

        /// <summary>Never null. Empty when the claim was absent or carried no values.</summary>
        public IReadOnlyList<string> Groups { get; }

        /// <summary>
        /// Whether the token carried the groups claim at all. An absent claim
        /// usually means the provider was not configured to emit groups, which
        /// is a different operator problem from a user simply lacking a group.
        /// </summary>
        public bool HasGroupsClaim { get; }
    }
}
```

- [ ] **Step 5: Read the claim in `OidcClient`**

Add `GroupsClaim` to `OidcOptions`:

```csharp
public string GroupsClaim { get; set; } = "groups";
```

Add a multi-valued reader beside `ReadClaim`, and use it where the identity is constructed:

```csharp
        private static IReadOnlyList<string> ReadClaims(JsonWebToken token, string name)
        {
            var values = new List<string>();

            foreach (var claim in token.Claims)
            {
                if (string.Equals(claim.Type, name, StringComparison.Ordinal))
                {
                    values.Add(claim.Value);
                }
            }

            return values;
        }
```

Then replace the `return new OidcIdentity(...)` line in `ValidateIdToken` with:

```csharp
            var groups = ReadClaims(token, _options.GroupsClaim);

            return new OidcIdentity(
                ReadClaim(token, "sub"),
                username.Trim(),
                ReadClaim(token, "name") ?? username.Trim(),
                groups,
                token.Claims.Any(c => string.Equals(c.Type, _options.GroupsClaim, StringComparison.Ordinal)));
```

Add `using System.Linq;` if it is not already present. A JSON array claim is flattened by IdentityModel into one claim per element sharing the same type, which is why `ReadClaims` collects rather than taking the first.

- [ ] **Step 6: Run and verify they pass**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: all pass, four more than before.

- [ ] **Step 7: Commit**

```bash
git add src/Emby.Sso/Protocol/ tests/
git commit -m "feat: read group membership from the ID token"
```

---

### Task 3: The gate decision

**Files:**
- Create: `src/Emby.Sso/Protocol/GroupGate.cs`
- Modify: `src/Emby.Sso/Protocol/SsoErrors.cs`
- Test: `tests/Emby.Sso.Tests/GroupGateTests.cs`

**Interfaces:**
- Consumes: `OidcIdentity` from Task 2.
- Produces: `GroupGateOutcome` (`Allowed`, `GroupsClaimMissing`, `GroupNotHeld`, `NotConfigured`) and `GroupGate.Evaluate(OidcIdentity identity, string requiredGroup)` returning it. New `SsoErrors` constants `GroupsClaimMissing` and `GroupNotHeld`.

- [ ] **Step 1: Write the failing tests**

`tests/Emby.Sso.Tests/GroupGateTests.cs`:

```csharp
using System.Collections.Generic;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    public class GroupGateTests
    {
        private static OidcIdentity Identity(IReadOnlyList<string> groups, bool hasClaim = true) =>
            new OidcIdentity("sub-1", "alice", "Alice", groups, hasClaim);

        [Fact]
        public void A_held_group_is_allowed()
        {
            Assert.Equal(GroupGateOutcome.Allowed,
                GroupGate.Evaluate(Identity(new[] { "emby-users" }), "emby-users"));
        }

        [Theory]
        [InlineData("EMBY-USERS")]
        [InlineData("  emby-users  ")]
        public void Group_matching_is_ordinal_case_insensitive_and_trimmed(string held)
        {
            Assert.Equal(GroupGateOutcome.Allowed,
                GroupGate.Evaluate(Identity(new[] { held }), "emby-users"));
        }

        [Fact]
        public void The_group_is_found_among_several()
        {
            Assert.Equal(GroupGateOutcome.Allowed,
                GroupGate.Evaluate(Identity(new[] { "staff", "emby-users", "other" }), "emby-users"));
        }

        [Fact]
        public void A_missing_group_is_refused()
        {
            Assert.Equal(GroupGateOutcome.GroupNotHeld,
                GroupGate.Evaluate(Identity(new[] { "staff" }), "emby-users"));
        }

        [Fact]
        public void An_empty_group_list_is_refused_as_not_held()
        {
            Assert.Equal(GroupGateOutcome.GroupNotHeld,
                GroupGate.Evaluate(Identity(new string[0]), "emby-users"));
        }

        [Fact]
        public void An_absent_claim_is_reported_separately_from_a_missing_group()
        {
            Assert.Equal(GroupGateOutcome.GroupsClaimMissing,
                GroupGate.Evaluate(Identity(new string[0], hasClaim: false), "emby-users"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void An_unconfigured_required_group_refuses(string required)
        {
            Assert.Equal(GroupGateOutcome.NotConfigured,
                GroupGate.Evaluate(Identity(new[] { "emby-users" }), required));
        }

        [Fact]
        public void A_null_identity_refuses()
        {
            Assert.Equal(GroupGateOutcome.NotConfigured, GroupGate.Evaluate(null, "emby-users"));
        }
    }
}
```

Note what the empty-list and absent-claim tests pin: an identity that *has* the claim but holds no groups is `GroupNotHeld`, while one lacking the claim entirely is `GroupsClaimMissing`. Collapsing these would tell an operator with a misconfigured provider that their users lack a group they actually hold.

- [ ] **Step 2: Run and verify they fail**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: compile error — `GroupGate` does not exist.

- [ ] **Step 3: Implement**

`src/Emby.Sso/Protocol/GroupGate.cs`:

```csharp
using System;

namespace Emby.Sso.Protocol
{
    public enum GroupGateOutcome
    {
        /// <summary>The gate is unusable: no required group is configured, or there is no identity.</summary>
        NotConfigured = 0,

        /// <summary>The token carried no groups claim at all — usually a misconfigured provider.</summary>
        GroupsClaimMissing = 1,

        /// <summary>The identity is real and the claim was present, but the group is not among them.</summary>
        GroupNotHeld = 2,

        Allowed = 3,
    }

    /// <summary>
    /// Decides whether a verified identity holds the group an operator requires.
    /// Knows nothing about Emby and performs no verification of its own — the
    /// caller must already have validated the identity.
    /// </summary>
    public static class GroupGate
    {
        public static GroupGateOutcome Evaluate(OidcIdentity identity, string requiredGroup)
        {
            if (identity == null || string.IsNullOrWhiteSpace(requiredGroup))
            {
                return GroupGateOutcome.NotConfigured;
            }

            if (!identity.HasGroupsClaim)
            {
                return GroupGateOutcome.GroupsClaimMissing;
            }

            var wanted = requiredGroup.Trim();

            foreach (var group in identity.Groups)
            {
                if (group != null &&
                    string.Equals(group.Trim(), wanted, StringComparison.OrdinalIgnoreCase))
                {
                    return GroupGateOutcome.Allowed;
                }
            }

            return GroupGateOutcome.GroupNotHeld;
        }
    }
}
```

- [ ] **Step 4: Add the error reasons**

In `SsoErrors`, beside the existing constants:

```csharp
        public const string GroupsClaimMissing = "This account is not set up on this server.";
        public const string GroupNotHeld = "This account is not set up on this server.";
```

Both deliberately show the user the same sentence as `UnknownUser`. The spec requires the log to distinguish them and the browser not to: telling a stranger "you exist but lack a group" leaks membership.

- [ ] **Step 5: Run and verify they pass**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: all pass, ten more than after Task 2 (five facts plus five theory cases).

- [ ] **Step 6: Commit**

```bash
git add src/Emby.Sso/Protocol/ tests/
git commit -m "feat: add the group gate decision"
```

---

### Task 4: Carry the identity out of the validator

**Files:**
- Modify: `src/Emby.Sso/Protocol/SsoCredentialValidator.cs`
- Test: `tests/Emby.Sso.Tests/SsoCredentialValidatorTests.cs`

**Interfaces:**
- Consumes: `OidcIdentity` (Task 2).
- Produces: `SsoCredentialResult.Identity` (`OidcIdentity`, null on rejection and on the handoff path); `SsoCredentialResult.DirectGrant(OidcIdentity identity)` replacing the string overload.

The provider needs the verified identity to apply the gate, and today the validator discards everything but the display name.

- [ ] **Step 1: Write the failing tests**

Add to `SsoCredentialValidatorTests.cs`:

```csharp
[Fact]
public async Task A_direct_grant_result_carries_the_verified_identity()
{
    _idp.TokenResponseJson = _idp.CreateTokenResponse(
        _idp.CreateIdToken(username: "alice", groups: new[] { "emby-users" }));

    var result = await CreateValidator().ValidateAsync("alice", "correct horse", CancellationToken.None);

    Assert.Equal(SsoCredentialOutcome.DirectGrantAccepted, result.Outcome);
    Assert.NotNull(result.Identity);
    Assert.Equal("alice", result.Identity.Username);
    Assert.Equal(new[] { "emby-users" }, result.Identity.Groups);
}

[Fact]
public async Task A_rejection_carries_no_identity()
{
    _idp.TokenResponseStatus = HttpStatusCode.BadRequest;
    _idp.TokenResponseJson = "{\"error\":\"invalid_grant\"}";

    var result = await CreateValidator().ValidateAsync("alice", "wrong", CancellationToken.None);

    Assert.Equal(SsoCredentialOutcome.Rejected, result.Outcome);
    Assert.Null(result.Identity);
}

[Fact]
public async Task A_handoff_result_carries_no_identity()
{
    var secret = _handoff.Issue("alice");

    var result = await CreateValidator().ValidateAsync("alice", secret, CancellationToken.None);

    Assert.Equal(SsoCredentialOutcome.HandoffAccepted, result.Outcome);
    Assert.Null(result.Identity);
}
```

The last is not pedantry: a handoff secret proves the browser already completed a flow in which the gate was applied, so there is no identity here and the caller must not expect one. Making that explicit stops a later reader assuming `Identity` is always populated on success.

- [ ] **Step 2: Run and verify they fail**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: compile error — `Identity` does not exist.

- [ ] **Step 3: Implement**

In `SsoCredentialResult`, add the property, extend the private constructor, and change the `DirectGrant` factory:

```csharp
        private SsoCredentialResult(SsoCredentialOutcome outcome, string displayName, string reason, OidcIdentity identity)
        {
            Outcome = outcome;
            DisplayName = displayName;
            Reason = reason;
            Identity = identity;
        }

        /// <summary>
        /// The verified identity, on the direct-grant path only. Null on rejection,
        /// and null for a handoff secret — that path proves the browser flow already
        /// ran and applied the gate, so no identity is carried here.
        /// </summary>
        public OidcIdentity Identity { get; }

        public static SsoCredentialResult Handoff(string displayName) =>
            new SsoCredentialResult(SsoCredentialOutcome.HandoffAccepted, displayName, null, null);

        public static SsoCredentialResult DirectGrant(OidcIdentity identity) =>
            new SsoCredentialResult(SsoCredentialOutcome.DirectGrantAccepted, identity.DisplayName, null, identity);

        public static SsoCredentialResult Reject(string reason) =>
            new SsoCredentialResult(SsoCredentialOutcome.Rejected, null, reason, null);
```

Update the one call site in `ValidateAsync` from `SsoCredentialResult.DirectGrant(identity.DisplayName)` to `SsoCredentialResult.DirectGrant(identity)`.

- [ ] **Step 4: Run and verify they pass**

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: all pass, three more than after Task 3.

- [ ] **Step 5: Commit**

```bash
git add src/Emby.Sso/Protocol/ tests/
git commit -m "feat: carry the verified identity out of the credential validator"
```

---

### Task 5: Configuration

**Files:**
- Modify: `src/Emby.Sso/Configuration/PluginConfiguration.cs`
- Modify: `src/Emby.Sso/Configuration/configPage.html`
- Modify: `src/Emby.Sso/Configuration/configPage.js`
- Modify: `src/Emby.Sso/SsoRuntime.cs`

**Interfaces:**
- Produces: `PluginConfiguration.EnableAutoCreate` (bool, default false), `RequiredGroup` (string, default empty), `TemplateUserName` (string, default empty), `GroupsClaim` (string, default `"groups"`); `SsoRuntime.GetClient()` passing `GroupsClaim` into `OidcOptions` and including it plus `RequiredGroup` in the client cache key.

There are no unit tests for configuration or the dashboard page — the test project compiles `Protocol/**` only. Verification is a clean build plus the live check in Task 9.

- [ ] **Step 1: Add the properties**

```csharp
        public bool EnableAutoCreate { get; set; } = false;
        public string RequiredGroup { get; set; } = string.Empty;
        public string TemplateUserName { get; set; } = string.Empty;
        public string GroupsClaim { get; set; } = "groups";
```

Leave `IsConfigured` unchanged — provisioning settings must not affect whether sign-in works at all.

- [ ] **Step 2: Add the fields to the page**

Follow the existing markup exactly — the page uses Emby's `emby-scroller` / `data-controller` pattern and **no script tag survives**, so the JavaScript lives in `configPage.js`. Add, in the same `inputContainer` / `checkboxContainer` style as the fields already there:

- a text input `requiredGroup`, described as the Authentik group a user must hold to sign in, and noting that leaving it empty blocks all group-gated sign-in
- a text input `groupsClaim`, defaulting to `groups`, described as the claim the group list is read from, and noting Authentik must be configured to emit it — on the direct-grant flow too, if native sign-in is enabled
- a text input `templateUserName`, described as the existing Emby user whose libraries and permissions new accounts are cloned from, and stating plainly that **new accounts are never administrators regardless of the template**
- a checkbox `enableAutoCreate`, described as creating an Emby account automatically for a group holder who does not have one, and warning that this is the setting that lets the plugin create users at all

- [ ] **Step 3: Load and save them**

In `configPage.js`, add each to the load function and the submit handler, matching the existing pattern exactly, including the `.catch(handleError)` behaviour already present on both chains.

- [ ] **Step 4: Pass the claim name to the client**

In `SsoRuntime.GetClient()`, set `GroupsClaim = configuration.GroupsClaim` on the constructed `OidcOptions`, and add `configuration.GroupsClaim` and `configuration.RequiredGroup` to the `_clientKey` tuple so changing either rebuilds the client.

- [ ] **Step 5: Build and test**

Run: `dotnet build -c Release` — expect 0 warnings and the merge to succeed.
Run: `dotnet test tests/Emby.Sso.Tests -v minimal` — expect the same count as after Task 4.

- [ ] **Step 6: Commit**

```bash
git add src/Emby.Sso/
git commit -m "feat: add group and provisioning settings"
```

---

### Task 6: The provisioner

**Files:**
- Create: `src/Emby.Sso/Auth/UserProvisioner.cs`

**Interfaces:**
- Consumes: `IUserManager`, `PluginConfiguration`.
- Produces: `UserProvisioner(IUserManager userManager, ILogger logger)` with `Task<User> ProvisionAsync(string username, string templateUserName)`, returning the created user, or throwing `SsoException(SsoErrors.NotConfigured, ...)` when the template is missing.

Emby-facing, so no unit tests; the guarantees below are verified live in Task 9.

- [ ] **Step 1: Implement**

```csharp
using System;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Logging;

namespace Emby.Sso.Auth
{
    /// <summary>
    /// Creates an Emby account by cloning a template user. The caller is
    /// responsible for having verified the identity and applied the group gate
    /// BEFORE calling this — nothing here re-checks either.
    /// </summary>
    public sealed class UserProvisioner
    {
        private readonly IUserManager _userManager;
        private readonly ILogger _logger;

        public UserProvisioner(IUserManager userManager, ILogger logger)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<User> ProvisionAsync(string username, string templateUserName)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new SsoException(SsoErrors.UnknownUser, "provisioning attempted with an empty username");
            }

            if (string.IsNullOrWhiteSpace(templateUserName))
            {
                throw new SsoException(SsoErrors.NotConfigured, "no template user is configured");
            }

            var template = _userManager.GetUserByName(templateUserName);

            if (template == null)
            {
                throw new SsoException(
                    SsoErrors.NotConfigured,
                    "the configured template user does not exist: '" + templateUserName + "'");
            }

            // UserData is deliberately excluded: watch history belongs to the
            // template's owner, not to every account cloned from it.
            var created = await _userManager.CreateUser(
                username,
                template,
                new[] { UserCopyOptions.UserPolicy, UserCopyOptions.UserConfiguration })
                .ConfigureAwait(false);

            var policy = created.Policy;

            // Enforced here rather than trusted to the operator's choice of
            // template: a template that happens to be an administrator would
            // otherwise make every group holder an Emby administrator.
            policy.IsAdministrator = false;

            // Stamp this provider at creation so the account is never offered
            // to any other provider on a later sign-in.
            policy.AuthenticationProviderId = typeof(SsoAuthenticationProvider).FullName;

            _userManager.UpdateUserPolicy(created.InternalId, policy);

            _logger.Info("Provisioned Emby account {0} from template {1}", created.Name, templateUserName);

            return created;
        }
    }
}
```

If `created.InternalId` is not the correct property for `UpdateUserPolicy`'s `long userId` parameter, check `User` in the plugin API reference at https://dev.emby.media/reference/pluginapi/ and use whichever member carries the numeric id. Report what you used.

- [ ] **Step 2: Build**

Run: `dotnet build -c Release`
Expected: 0 warnings, merge succeeds.

Run: `dotnet test tests/Emby.Sso.Tests -v minimal`
Expected: unchanged count — this task adds no tests, and says so in its report rather than implying coverage.

- [ ] **Step 3: Commit**

```bash
git add src/Emby.Sso/Auth/UserProvisioner.cs
git commit -m "feat: add the template-cloning user provisioner"
```

---

### Task 7: Gate and provision on the browser path

**Files:**
- Modify: `src/Emby.Sso/Api/SsoService.cs`

**Interfaces:**
- Consumes: `GroupGate` (Task 3), `UserProvisioner` (Task 6), `PluginConfiguration` (Task 5).
- Produces: a callback that applies the gate to every sign-in and provisions when the account is absent.

- [ ] **Step 1: Apply the gate to every callback**

The callback currently does `GetUserByName`, refuses with `UnknownUser` if absent, then issues a handoff secret. Restructure to:

1. Evaluate `GroupGate.Evaluate(identity, configuration.RequiredGroup)` **first**, before looking the user up, and refuse on anything but `Allowed`. Map each outcome to its own log detail — `GroupsClaimMissing` must say the token carried no groups claim and name the configured claim, since that is an operator misconfiguration, not a user problem — and to the corresponding `SsoErrors` constant, all of which show the same sentence to the browser.
2. Then `GetUserByName`.
3. If the user exists, continue exactly as today.
4. If the user does not exist: refuse with `UnknownUser` unless `configuration.EnableAutoCreate` is true; otherwise call `UserProvisioner.ProvisionAsync(identity.Username, configuration.TemplateUserName)` and continue with the returned user.
5. Mint the handoff secret on the resulting user's `Name`, as today.

Wrap the provisioning call so an `SsoException` from it renders an error page like any other failure.

Order matters and is the point of this step: the gate runs before the user lookup, so a non-holder never causes an account to be created and never learns whether the account existed.

- [ ] **Step 2: Construct the provisioner**

`SsoService` already takes `ILogManager` and `IUserManager` in its constructor. Build a `UserProvisioner` from them rather than adding a constructor parameter, so Emby's DI is unaffected.

- [ ] **Step 3: Build and test**

Run: `dotnet build -c Release` — 0 warnings, merge succeeds.
Run: `dotnet test tests/Emby.Sso.Tests -v minimal` — unchanged count.

- [ ] **Step 4: Commit**

```bash
git add src/Emby.Sso/Api/SsoService.cs
git commit -m "feat: gate and provision on the browser sign-in path"
```

---

### Task 8: Gate and provision on the native path

**Read `docs/superpowers/spikes/2026-08-30-provisioning-mechanics.md` before starting.** It decides this task's approach, and if it reported outcome 3 — that neither mechanism works reliably — **stop and report** rather than implementing; that outcome reverses a decision the user made and is theirs to rule on.

**Files:**
- Modify: `src/Emby.Sso/Auth/SsoAuthenticationProvider.cs`

**Interfaces:**
- Consumes: `GroupGate` (Task 3), `SsoCredentialResult.Identity` (Task 4), `UserProvisioner` (Task 6).
- Produces: a provider whose null-user branch opens only under the full gate.

- [ ] **Step 1: Apply the gate to existing accounts**

In the `resolvedUser != null` path, after the validator returns an accepting outcome, apply the gate — but **only when `result.Identity` is non-null**. A handoff result carries no identity because the browser flow already applied the gate; re-checking there would be impossible, not merely redundant. A direct-grant result carries the identity and is gated here. Refuse with the gate's reason.

- [ ] **Step 2: Open the null-user branch, narrowly**

Replace the unconditional throw with a branch that throws unless **all** of the following hold, in this order:

1. `SsoRuntime.Configuration?.EnableAutoCreate == true` — otherwise throw `SsoErrors.UnknownUser`
2. the configured `TemplateUserName` is non-empty — otherwise throw `SsoErrors.NotConfigured`
3. `SsoRuntime.Configuration?.EnableDirectGrant == true` — otherwise throw `SsoErrors.DirectGrantDisabled`; this branch is only ever reached by a native sign-in
4. the validator, called with the **supplied** `username` since there is no resolved user, returns `DirectGrantAccepted` — otherwise throw its reason
5. `result.Identity` is non-null and `UsernameMatcher.Matches(result.Identity.Username, username)` — otherwise throw `SsoErrors.UnknownUser`
6. `GroupGate.Evaluate(result.Identity, SsoRuntime.Configuration.RequiredGroup)` returns `Allowed` — otherwise throw the gate's reason

Only then provision and return success. Keep the existing comment's warning at the top of the branch, amended to say that the opening exists and what guards it — a future reader must not remove a guard believing the branch is still unconditional.

Follow whichever mechanism the spike established: provision then return, or return then apply the template policy immediately.

- [ ] **Step 3: Inject `IUserManager`**

The constructor gained `IUserManager` during the spike (Task 1, Step 5 keeps it). Build the `UserProvisioner` from it and the logger.

- [ ] **Step 4: Build and test**

Run: `dotnet build -c Release` — 0 warnings, merge succeeds.
Run: `dotnet test tests/Emby.Sso.Tests -v minimal` — unchanged count.

- [ ] **Step 5: Commit**

```bash
git add src/Emby.Sso/Auth/SsoAuthenticationProvider.cs
git commit -m "feat: gate and provision on the native sign-in path"
```

---

### Task 9: Documentation and live verification

**Files:**
- Modify: `README.md`
- Create: `docs/superpowers/verification/2026-08-30-group-provisioning-verification.md`

- [ ] **Step 1: Document the feature**

Add a README section covering: the four new settings; that Authentik must be configured to emit the groups claim, **on the direct-grant flow too** if native sign-in is enabled, and that an absent claim refuses every sign-in by design; that the template user's libraries and permissions become every created account's, and that created accounts are never administrators whatever the template says; that losing the group in Authentik blocks sign-in immediately for existing accounts; and that library access is never re-applied after creation, so manual adjustments survive.

State the interaction with the existing stamping warning: an account created by this plugin is stamped to it at birth and therefore cannot use an Emby password afterwards.

- [ ] **Step 2: Verify against the live server**

Server and restart details as in Task 1. This needs a working Authentik configuration; if none is available, record every check as NOT VERIFIED and say why rather than inferring results.

Verify, recording each: a group holder with no Emby account signs in through the browser and the account is created with the template's libraries, not an administrator, and stamped to this provider; a non-holder is refused and **no account is created**; an existing account whose identity has lost the group is refused; a token with no groups claim is refused and the log names the claim; with `EnableAutoCreate` off, an unknown group holder is refused and nothing is created; with a template name that does not exist, the failure is a clear error page and a log line naming the template; and the same creation and refusal cases on the native path.

- [ ] **Step 3: Restore what you created**

Delete every account the verification created, and the template user if you made one for the purpose. Verify `embyadmin` is untouched and `claude` still signs in.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/superpowers/verification/
git commit -m "docs: document group-gated provisioning and record verification"
```

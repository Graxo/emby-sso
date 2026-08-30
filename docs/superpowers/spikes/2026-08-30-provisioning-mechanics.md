# Emby provisioning mechanics — findings

**Date:** 2026-08-30
**Probed against:** Emby Server **4.9.5.0** (.NET 8.0.25, Linux x64) at `http://10.10.140.5:8090`, container `emby`, plugin directory `/config/plugins`.
**Plugin built against:** `MediaBrowser.Server.Core` **4.9.1.90**, `netstandard2.0`.
**Method:** two throwaway builds of `Emby.Sso.dll`, each carrying a probe `SsoAuthenticationProvider`, were installed into `/config/plugins`, the container restarted, and behaviour observed through `POST /emby/Users/AuthenticateByName`, `GET /emby/Users` and `/config/logs/embyserver.txt`. In addition, `Emby.Server.Implementations.dll` was copied **out of the running container** and decompiled, so the observations below are paired with the server's own code.

Everything marked **Observed** was seen directly on the running server. **Source** means it was read out of the decompiled `Emby.Server.Implementations.dll` taken from this exact server. **Inference** means neither — it is reasoning, and says what would confirm it.

All probe code and all server-side changes have been reverted; see "Server state" at the end. **The plugin is not installed on the server any more.**

---

## The question

Task 8 must create an Emby account for an identity that holds a designated Authentik group, and that account must get its libraries from a **template user's** policy — not Emby's defaults, which grant access to every library.

The earlier spike (`2026-08-30-emby-api-findings.md` §1f) established that Emby **auto-creates the account itself** when an authentication provider returns success for a username that does not resolve. So: if the provider calls `IUserManager.CreateUser` itself and then returns success, does Emby adopt that account, create a second one, or fail?

---

## The answer in one sentence

**A provider-created account survives, but the sign-in that created it fails outright**, because Emby unconditionally creates the account a second time and its `CreateUser` throws on the duplicate name — and the mechanism that actually works is neither of the two the brief anticipated: **`MediaBrowser.Controller.Authentication.IHasNewUserPolicy` lets the provider supply the policy Emby uses at creation time**, so the account is created once, by Emby, with the template's policy, and never exists with default access at all.

---

## 1. What Emby does, from its own code

**Source.** `Emby.Server.Implementations.Library.UserManager.AuthenticateUser`, decompiled from the running server's binary. The unknown-username branch, verbatim from the decompiler:

```csharp
User user = GetUserByName(username, cancellationToken);
...
else                                            // user == null
{
    Tuple<IAuthenticationProvider, bool, ProviderAuthenticationResult> tuple2 =
        await AuthenticateLocalUser(username, password, null, cancellationToken)...;
    authenticationProvider = tuple2.Item1;
    success = tuple2.Item2;
    ProviderAuthenticationResult item = tuple2.Item3;
    if (success && authenticationProvider != null && !(authenticationProvider is DefaultAuthenticationProvider))
    {
        IHasNewUserPolicy val = (IHasNewUserPolicy)(object)((authenticationProvider is IHasNewUserPolicy) ? authenticationProvider : null);
        UserPolicy userPolicy = (UserPolicy)((val != null) ? ((object)val.GetNewUserPolicy()) : ((object)new UserPolicy()));
        user = await CreateUser(item.Username ?? username, userPolicy)...;
    }
}
if (success && user != null && authenticationProvider != null)
{
    string authenticationProviderId = GetAuthenticationProviderId(authenticationProvider);
    if (!string.Equals(authenticationProviderId, user.Policy.AuthenticationProviderId, StringComparison.OrdinalIgnoreCase))
    {
        user.Policy.AuthenticationProviderId = authenticationProviderId;
        UpdateUserPolicy(user, user.Policy, fireEvent: true);
    }
}
```

Four things follow, and every one of them was then confirmed on the live server:

1. `user` is resolved **once**, before any provider runs, and is never re-read. An account the provider creates during `Authenticate` is invisible to this method.
2. Emby therefore always calls its own `CreateUser` for an unknown username when a **non-Default** provider succeeded — there is no "adopt the existing account" path.
3. `IHasNewUserPolicy.GetNewUserPolicy()` is the **supported** hook for the policy of that account. Without it Emby uses `new UserPolicy()`.
4. After creation Emby writes the policy **again** to stamp `AuthenticationProviderId`. That second write is what a "return success, then fix the policy" strategy has to race.

And `CreateUser` refuses a duplicate name (**Source**):

```csharp
if (GetUserByName(name) != null)
{
    throw new ArgumentException(string.Format(..., "A user with the name '{0}' already exists.", name));
}
```

Nothing between `CreateUser` and `Emby.Api.UserService.Post` catches that exception.

---

## 2. The probe

Two builds of `SsoAuthenticationProvider` with `IsEnabled => true` and constructor `(ILogManager, IUserManager)`. The `resolvedUser == null` branch dispatched on the username prefix:

| Prefix | Behaviour |
|---|---|
| `probe-plain-` | return `ProviderAuthenticationResult` and nothing else — the §1f baseline |
| `probe-create-` | `_userManager.CreateUser(username, template, new[]{ UserCopyOptions.UserPolicy, UserCopyOptions.UserConfiguration })`, then return success |
| `probe-after-` | return success; a background task polls for the account and calls `UpdateUserPolicy` the instant it appears |
| `probe-delay-` | as above, but waits 1500 ms after the account appears |
| `probe-policy-` | return success and nothing else; **build 2 implements `IHasNewUserPolicy`** and returns a clone of the template's policy |

Build 2 also implements `IHasNewUserPolicy`; `GetNewUserPolicy()` returns the template clone only for `probe-policy-*` and `new UserPolicy()` otherwise, so the baseline stayed observable.

**Template user.** `template_user` already existed on the server when this spike began (created 2026-08-30T14:32:56Z, by the operator, not by this spike). Its policy:

```
EnableAllFolders : false
EnabledFolders   : ["0f9f8082a8c1492bbb5668f59112fd62",   # Movies
                    "11395a5984f341f7ad6f61152d7a222c"]   # TV shows
IsAdministrator  : false
IsHidden         : true      IsHiddenRemotely : true      IsHiddenFromUnusedDevices : true
EnableLiveTvAccess : false   EnableLiveTvManagement : false
EnablePublicSharing : false  AllowCameraUpload : false
AuthenticationProviderId : "Emby.Server.Implementations.Library.DefaultAuthenticationProvider"
```

The server has three libraries: Movies (`0f9f8082…`), TV shows (`11395a59…`), Collections (`b2294c97…`). The template grants the first two. The decisive difference between "template" and "default" is `EnableAllFolders: false` + an explicit list versus `EnableAllFolders: true` + an empty list.

---

## 3. Baseline — return success and nothing else (`probe-plain-one`)

**Observed.** `POST /emby/Users/AuthenticateByName` with `{"Username":"probe-plain-one","Pw":"probepw"}` → **HTTP 200** with a usable `AccessToken`. Log:

```
2026-08-30 16:38:48.988 Error DefaultAuthenticationProvider: Invalid username or password. No user named probe-plain-one exists
2026-08-30 16:38:48.990 Info AuthentikSso: PROBE: reached null-resolvedUser branch for probe-plain-one
2026-08-30 16:38:48.990 Info AuthentikSso: PROBE-PLAIN: returning success without creating anything
2026-08-30 16:38:48.990 Info AuthentikSso: PROBE: returning ProviderAuthenticationResult for probe-plain-one
2026-08-30 16:38:49.047 Info UserManager: Authentication request for probe-plain-one has succeeded.
2026-08-30 16:38:49.048 Info SessionManager: Creating new access token for user 6 probe-plain-one
```

Resulting account, from the auth response body:

```json
"EnabledFolders":[], "EnableAllFolders":true,
"AuthenticationProviderId":"Emby.Sso.Auth.SsoAuthenticationProvider",
"IsAdministrator":false, "IsHidden":false, "EnableLiveTvAccess":true, "EnablePublicSharing":true
```

This reconfirms §1f and fixes the thing to beat: **an account with access to every library**.

---

## 4. Provider creates the account, then returns success (`probe-create-alpha`)

**Observed.** The sign-in **fails**.

```
HTTP 400
A user with the name 'probe-create-alpha' already exists.
```

Log, in order:

```
2026-08-30 16:38:55.508 Info AuthentikSso: PROBE: reached null-resolvedUser branch for probe-create-alpha
2026-08-30 16:38:55.529 Info AuthentikSso: PROBE-CREATE: CreateUser returned name=probe-create-alpha id=83af873b-dc84-4e50-ad45-df904be35ae3 internalId=7 EnableAllFolders=False EnabledFolders=[0f9f8082a8c1492bbb5668f59112fd62,11395a5984f341f7ad6f61152d7a222c] providerId=Emby.Server.Implementations.Library.DefaultAuthenticationProvider IsAdministrator=False
2026-08-30 16:38:55.529 Info AuthentikSso: PROBE: returning ProviderAuthenticationResult for probe-create-alpha
2026-08-30 16:38:55.530 Error UserService-0HNO6KH9O4MMQ:00000001: Error processing request
	System.ArgumentException: System.ArgumentException: A user with the name 'probe-create-alpha' already exists.
	   at Emby.Server.Implementations.Library.UserManager.CreateUser(String name, UserPolicy userPolicy, UserConfiguration userConfiguration, Int64 copySettingsFromUserId, Int64 copyUserDataFromUserId)
	   at Emby.Server.Implementations.Library.UserManager.AuthenticateUser(String username, String password, Boolean isUserSession, CancellationToken cancellationToken)
	   at Emby.Server.Implementations.Session.SessionManager.AuthenticateNewSessionInternal(AuthenticationRequest request, Boolean enforcePassword, CancellationToken cancellationToken)
	   at Emby.Api.UserService.Post(AuthenticateUserByName request)
2026-08-30 16:38:55.531 Info UserService-...: http/1.1 Response 400 ... Content-Length=57
```

Answering the brief's questions directly:

- **How many accounts afterwards?** Exactly **one**, ours. Emby's own creation never completed.
- **Its policy?** The **template's**: `EnableAllFolders=false`, `EnabledFolders=[Movies, TV shows]`. A field-by-field diff of the created account against `template_user` differed in **nothing** except `AuthenticationProviderId`.
- **Its `AuthenticationProviderId`?** `Emby.Server.Implementations.Library.DefaultAuthenticationProvider` — **inherited from the template**, because `UserCopyOptions.UserPolicy` copies that field too. Emby's stamping code never ran; it is downstream of the throw.
- **Does the sign-in succeed / is there a token?** **No.** HTTP 400, no token, no session.
- **Ordering — is ours replaced or ignored?** Neither. Ours exists first and Emby's creation *fails* on it. There is no adoption and no replacement.

**The account is then unreachable through SSO.** Because it carries the template's `AuthenticationProviderId` (Default), Emby offers it only to the Default provider on the next attempt. **Observed** — a second sign-in as `probe-create-alpha`:

```
HTTP 401
Invalid username or password. Please try again.
```
```
2026-08-30 16:42:51.168 Info UserManager: Authentication request for probe-create-alpha has been denied.
```

No `AuthentikSso:` line appears at all — the plugin was never consulted. After `POST /emby/Users/{id}/Policy` set `AuthenticationProviderId` to `Emby.Sso.Auth.SsoAuthenticationProvider` (**204**), the next sign-in returned **HTTP 200** and the restricted policy was still intact. So a provisioner that overwrites `AuthenticationProviderId` (as the planned `UserProvisioner` does) fixes the second attempt — but **not the first**, which fails regardless.

`probe-create-beta` reproduced the identical 400 on build 2.

---

## 5. `IHasNewUserPolicy` — the provider supplies the policy Emby creates with (`probe-policy-*`)

**This is the mechanism Task 8 should use, and the strength of the evidence for it differs by claim. Read §5.1 before quoting a run count.**

### 5.1 Where the guarantee actually comes from

The security property — *the account never exists with default access* — rests **primarily on the architectural guarantee in the decompiled construction order quoted in §1 (Source)**, not on a run count. Emby's unknown-username branch reads:

```csharp
UserPolicy userPolicy = (UserPolicy)((val != null) ? ((object)val.GetNewUserPolicy()) : ((object)new UserPolicy()));
user = await CreateUser(item.Username ?? username, userPolicy)...;
```

The policy is a **constructor argument to the account's creation**, not something written to an already-created account. `CreateUser` instantiates the user, adds it to the list and calls `UpdateUserPolicy(val, userPolicy, fireEvent: false)` **before it returns**, all inside `_userListLock` (**Source**, §1). There is therefore no code path in which a default policy is written and then overwritten, and so **no window to race** — which is a categorically stronger guarantee than any number of successful runs, and is independent of how many runs were logged.

The live runs below serve a narrower purpose: confirming that no unexpected quirk of the 4.9.5.0 build breaks that structure in practice — that the hook is reached at all, that the policy object survives Emby's serialisation intact, and that the stamping write in §1's second block really does become a no-op. They are corroboration, not the foundation.

### 5.2 The runs

**Observed. 6 runs (`probe-policy-one` … `probe-policy-six`), all HTTP 200 with a usable `AccessToken`, all ending with the template's restricted policy.** The per-run evidence is **not** uniform, and is set out in §5.3 — it is weaker than §6's fully-logged race table, and should not be read as equivalent to it.

```
2026-08-30 16:42:10.775 Info AuthentikSso: PROBE2: reached null-resolvedUser branch for probe-policy-two
2026-08-30 16:42:10.775 Info AuthentikSso: PROBE2: returning success without creating anything
2026-08-30 16:42:10.775 Info AuthentikSso: PROBE2: returning ProviderAuthenticationResult for probe-policy-two
2026-08-30 16:42:10.775 Info AuthentikSso: PROBE2: GetNewUserPolicy() called, pending probe username = probe-policy-two
2026-08-30 16:42:10.775 Info AuthentikSso: PROBE2: GetNewUserPolicy returning template policy EnableAllFolders=False EnabledFolders=[0f9f8082a8c1492bbb5668f59112fd62,11395a5984f341f7ad6f61152d7a222c] providerId=Emby.Sso.Auth.SsoAuthenticationProvider
```

The account in the auth response body:

```
AccessToken present: True
EnableAllFolders False
EnabledFolders ['0f9f8082a8c1492bbb5668f59112fd62', '11395a5984f341f7ad6f61152d7a222c']
ProviderId Emby.Sso.Auth.SsoAuthenticationProvider
IsAdministrator False
IsHidden True   IsHiddenRemotely True
EnableLiveTvAccess False
EnablePublicSharing False
```

A field-by-field diff of `probe-policy-one`'s policy against `template_user`'s differed in **exactly one field**, `AuthenticationProviderId` — and only because the probe deliberately set it to the SSO provider id.

### 5.3 Exactly what evidence exists per run

| Run | Server log lines | Account state |
|---|---|---|
| `probe-policy-one` | **full excerpt, quoted below** | field-by-field policy diff against `template_user` (one field differs) + account listing |
| `probe-policy-two` | **full excerpt, quoted above** | full auth-response body quoted above |
| `probe-policy-three` | **not captured individually** | account listing only |
| `probe-policy-four` | **not captured individually** | account listing only |
| `probe-policy-five` | **not captured individually** | account listing only |
| `probe-policy-six` | **not captured individually** | configuration comparison in §7 (`allFolders=False`) |

The other fully-logged run, `probe-policy-one` (chronologically the first) — note the 127 ms spent inside `GetNewUserPolicy()`, the first call to `GetUserByName` for the template on a freshly restarted server:

```
2026-08-30 16:42:01.174 Info AuthentikSso: PROBE2: reached null-resolvedUser branch for probe-policy-one
2026-08-30 16:42:01.175 Info AuthentikSso: PROBE2: returning success without creating anything
2026-08-30 16:42:01.175 Info AuthentikSso: PROBE2: returning ProviderAuthenticationResult for probe-policy-one
2026-08-30 16:42:01.175 Info AuthentikSso: PROBE2: GetNewUserPolicy() called, pending probe username = probe-policy-one
2026-08-30 16:42:01.302 Info AuthentikSso: PROBE2: GetNewUserPolicy returning template policy EnableAllFolders=False EnabledFolders=[0f9f8082a8c1492bbb5668f59112fd62,11395a5984f341f7ad6f61152d7a222c] providerId=Emby.Sso.Auth.SsoAuthenticationProvider
```

"Account listing" means these lines, rendered from `GET /emby/Users` by the spike's helper script — the field values are verbatim from the API, the layout is the script's, and the raw JSON body was not saved:

```
probe-policy-five  id=ecfdf16a3245492f855e0a43c7a0da4a allFolders=False folders=['0f9f8082a8c1492bbb5668f59112fd62', '11395a5984f341f7ad6f61152d7a222c'] provider=Emby.Sso.Auth.SsoAuthenticationProvider admin=False
probe-policy-four  id=8b0f826a867b4ff18dab5af56e50cac3 allFolders=False folders=['0f9f8082a8c1492bbb5668f59112fd62', '11395a5984f341f7ad6f61152d7a222c'] provider=Emby.Sso.Auth.SsoAuthenticationProvider admin=False
probe-policy-one   id=4a56c9a7196444f8aeb263076139f38b allFolders=False folders=['0f9f8082a8c1492bbb5668f59112fd62', '11395a5984f341f7ad6f61152d7a222c'] provider=Emby.Sso.Auth.SsoAuthenticationProvider admin=False
probe-policy-three id=a2bdfa6314cf481791af5ef8ae9b255b allFolders=False folders=['0f9f8082a8c1492bbb5668f59112fd62', '11395a5984f341f7ad6f61152d7a222c'] provider=Emby.Sso.Auth.SsoAuthenticationProvider admin=False
probe-policy-two   id=7ef2dad348004331b986a6a94bf99275 allFolders=False folders=['0f9f8082a8c1492bbb5668f59112fd62', '11395a5984f341f7ad6f61152d7a222c'] provider=Emby.Sso.Auth.SsoAuthenticationProvider admin=False
```

So: **`-three`, `-four`, `-five` and `-six` have outcome evidence but no individual log evidence.** Their `GetNewUserPolicy()` log lines were presumably written — the log window that was read simply did not cover them — but they were never captured, so they are not quoted, and none are reconstructed here. This does not weaken the conclusion — §5.1 is what carries it — but a reader comparing "6 runs" with §6's "7 runs" should know the two are not documented to the same standard.

### 5.4 Why the conclusion holds

Two properties matter here and both are important for Task 8:

- **The account never exists with default access, not even for a microsecond.** **Source** (§1, §5.1): the policy is passed *into* `CreateUser`, which writes it before the account is visible or the method returns. This is the architectural guarantee; the runs confirm it, they do not establish it.
- **Because the returned policy already carries the right `AuthenticationProviderId`, Emby's post-creation stamping write does not fire at all** (`!string.Equals(...)` is false — **Source**, §1). There is no second write to race. **Observed** corroboration: unlike every `probe-after-*` run, no probe-policy account's policy was ever seen to change after creation.

`GetNewUserPolicy()` is called **after** `Authenticate` returns and **before** `CreateUser`. **Observed** in every run whose log lines were captured — `probe-policy-one`, `probe-policy-two`, all five `probe-after-*` runs, both `probe-delay-*` runs and `probe-create-beta`, where it was called moments before Emby's `CreateUser` threw — and **Source** in §1, which is why it holds for the runs that were not captured too.

---

## 6. The brief's fallback — return success, then apply the policy (`probe-after-*`, `probe-delay-*`)

This is the mechanism the brief anticipated for outcome 2. **It is unreliable.**

**Observed.** Applying `UpdateUserPolicy` the instant the account appears — a background task polling every 5 ms, which found the account 0.25–1.2 ms after `Authenticate` returned and wrote roughly 3–6 ms in — **lost the race with Emby's own stamping write in 6 of 7 runs.**

| Run | `UpdateUserPolicy` at | Read-back straight after our write | Final `EnableAllFolders` |
|---|---|---|---|
| `probe-after-one` | +2.6 ms | `EnableAllFolders=False` (ours) | **true** — lost |
| `probe-after-two` | +5.8 ms | `EnableAllFolders=False` | false — won |
| `probe-after-three` | +5.6 ms | `EnableAllFolders=True` | **true** — lost |
| `probe-after-four` | +3.9 ms | `EnableAllFolders=False` | **true** — lost |
| `probe-after-five` | +3.7 ms | `EnableAllFolders=True` | **true** — lost |
| `probe-after-six` | +3.5 ms | `EnableAllFolders=True` | **true** — lost |
| `probe-after-seven` | +3.6 ms | `EnableAllFolders=True` | **true** — lost |

The read-back column is the giveaway: in four runs the value we had *just written* was already gone when we read it back a few microseconds later. Verbatim, one losing run:

```
2026-08-30 16:42:51.004 Info AuthentikSso: PROBE2-AFTER: starting background applier for probe-after-three, settle=0 ms
2026-08-30 16:42:51.005 Info AuthentikSso: PROBE2-AFTER: probe-after-three appeared after 0.3492 ms with EnableAllFolders=True EnabledFolders=[] providerId=(null)
2026-08-30 16:42:51.010 Info AuthentikSso: PROBE2-AFTER: UpdateUserPolicy applied at +5.6246 ms; in-memory now EnableAllFolders=True EnabledFolders=[] providerId=Emby.Sso.Auth.SsoAuthenticationProvider
```

**Inference (well supported by §1's source):** the loser is Emby's stamping block. It reads `user.Policy.AuthenticationProviderId` (empty on a fresh account), decides to write, mutates the *default* policy object, and then serialises it — and `UpdateUserPolicy(User, UserPolicy, bool)` ends with `user.Policy = userPolicy`, replacing whatever we had installed. Only the file write is inside `lock (_policySyncLock)`; the decision is not. What would confirm it beyond doubt is instrumenting Emby itself, which was not attempted.

**Waiting works, at a price.** With a 1500 ms settle after the account appears, 3 of 3 runs (`probe-delay-one` … `probe-delay-three`) ended with the template's policy:

```
2026-08-30 16:43:23.130 Info AuthentikSso: PROBE2-AFTER: UpdateUserPolicy applied at +1500.0344 ms; in-memory now EnableAllFolders=False EnabledFolders=[...] providerId=Emby.Sso.Auth.SsoAuthenticationProvider
```

But that is exactly the window the brief asked to be quantified: **the account exists with `EnableAllFolders: true` for the entire settle period.** That much is **Observed** — the policy field's value was read at that point in every run.

**Inference** — that the client can *use* that access during the window. The token is minted by `SessionManager` immediately after `AuthenticateUser` returns (`Creating new access token for user 6 probe-plain-one`, §3), and the probe's fix ran fire-and-forget after the response had already been written, so the token necessarily exists before any post-return fix can land. **No API call was made with an issued token during a settle window to demonstrate the access practically** — the claim rests on the policy field's value, not on an exercised request. What would confirm it is a `GET /emby/Users/{id}/Items` with the new account's token, issued inside the settle window, returning items from a library the template excludes.

Either way there is no delay short enough to be safe and long enough to be reliable; ~4 ms already loses, and any duration that wins is a duration during which the new account's policy grants every library. This mechanism should not be used.

---

## 7. What `IHasNewUserPolicy` does **not** carry: the user configuration

**Observed.** `template_user`'s configuration was temporarily marked (`DisplayMissingEpisodes: true`, `ResumeRewindSeconds: 42`, `SubtitleMode: "Default"`) and two accounts were provisioned, then the template's configuration was restored exactly (verified field-by-field, diff empty):

```
template:            {'DisplayMissingEpisodes': True,  'ResumeRewindSeconds': 42, 'SubtitleMode': 'Default'}
probe-policy-six:    {'DisplayMissingEpisodes': False, 'ResumeRewindSeconds': 0,  'SubtitleMode': 'Smart'}    allFolders=False
probe-create-beta:   {'DisplayMissingEpisodes': True,  'ResumeRewindSeconds': 42, 'SubtitleMode': 'Default'}  allFolders=False
```

So:

- `CreateUser(name, template, [UserPolicy, UserConfiguration])` copies **policy and configuration**.
- `IHasNewUserPolicy` controls **policy only**. The configuration is Emby's default, because Emby calls `CreateUser(name, userPolicy)`, which is `CreateUser(name, userPolicy, new UserConfiguration(), 0L, 0L)` (**Source**) — the trailing zeros also mean the template's *user settings* (home-screen layout and the like) are not copied either.

Configuration is display preference, not access. **Inference:** a post-return `IUserManager.UpdateConfiguration(created.InternalId, clonedTemplateConfiguration)` is safe to add if the operator's template configuration matters, because nothing in `AuthenticateUser` after `CreateUser` touches the configuration — only the policy, `LastLoginDate` and the invalid-login counter. This was **not** tested; testing it would mean one more probe build that applies the configuration after returning and checking it survives.

---

## 8. `IUserManager` on the provider's constructor

**Observed.** Emby's DI resolves it with no circular-dependency problem, even though `UserManager` is what owns the provider list:

```
2026-08-30 16:38:15.753 Info AuthentikSso: PROBE: SsoAuthenticationProvider constructed, userManager null: False
```

The constructor parameter is kept in the committed code.

---

## 9. Which outcome — and what it forces for Task 8

The brief offered three. The evidence supports **outcome 2 — Emby's creation wins** — but with a decisive amendment that makes it strictly better than the brief assumed:

> **2. Emby's creation wins** — Task 8 returns success, then immediately applies the template policy, and the findings must say how long the account exists with default access.

Emby's creation does win: outcome 1 is dead (§4 — the provider's own `CreateUser` makes the sign-in fail with HTTP 400 and leaves an account that cannot sign in through SSO), and outcome 3 is wrong (a working mechanism exists, so nothing the operator decided is reversed).

But **Task 8 must not implement outcome 2 the way the brief describes it.** "Return success, then immediately apply the template policy" was measured and it loses the race 6 times in 7 (§6); the only variant that wins leaves the account open to every library for the whole settle period, with the client already holding a token. Instead:

> **Task 8 implements `MediaBrowser.Controller.Authentication.IHasNewUserPolicy` on `SsoAuthenticationProvider` and returns the template's policy from `GetNewUserPolicy()`.** Emby creates the account — once — with that policy. There is **no** window of default access: the answer to "how long does the account exist with default access" is **zero**.

That "zero" is a structural claim, not a statistical one. It follows from the decompiled construction order in §1 — the policy is a constructor argument to `CreateUser`, so no default policy is ever written and later replaced — and six live runs confirmed nothing in the 4.9.5.0 build breaks that. §5.1 sets out the reasoning and §5.3 says exactly which of those runs carry individual evidence.

The gate in Task 8 Step 2 is unaffected: `GetNewUserPolicy()` is only reached when `Authenticate` has already returned success, so every guard still runs first, and a rejected identity still never causes an account to exist.

### What Task 8 must get right

1. **Correlating `GetNewUserPolicy()` with the sign-in.** It takes no arguments. Observed call order within one request is: `Authenticate(...)` returns → `GetNewUserPolicy()` → `CreateUser`. An `AsyncLocal` set inside `Authenticate` will **not** work — values set in a callee do not flow back to the caller's continuation — so the provider needs a small piece of shared state written at the end of the provisioning branch and consumed by `GetNewUserPolicy()`. The probe used one `static volatile string`, which is fine for a probe and **not** fine for shipping: two concurrent unknown-username sign-ins could cross, and a slot can go stale if `GetNewUserPolicy()` is never called (it is skipped when the account turns out to exist after all). Give the slot the username, a timestamp and a short expiry, and have `GetNewUserPolicy()` clear it. Concurrency here was **not** exercised — every probe run was serial.
2. **Never return `null`** from `GetNewUserPolicy()`. **Inference from source:** Emby passes it straight to `CreateUser`, which dereferences `userPolicy.IsAdministrator`, so `null` would throw inside `AuthenticateUser`. Not tested. When there is nothing to provision, return `new UserPolicy()` — Emby's own default and what it would have used anyway.
3. **Clone the template's policy.** Emby stores the object you hand back; returning `template.Policy` itself would alias the template user's live policy object. The probe round-tripped it through JSON.
4. **Force `IsAdministrator = false`** on the clone, as the planned `UserProvisioner` already does. `CreateUser` calls `SetDefaultAdministratorOptions(userPolicy)` when the flag is set (**Source**).
5. **Set `AuthenticationProviderId` to `typeof(SsoAuthenticationProvider).FullName` on the returned policy.** Two reasons: the template almost certainly carries `…DefaultAuthenticationProvider` and copying that would make the account SSO-unreachable (§4); and pre-setting it makes Emby's stamping write a no-op, so there is no second policy write at all.
6. **The account is created by Emby, not by the plugin.** Task 8's null-user branch returns a `ProviderAuthenticationResult` and does **not** call `UserProvisioner.ProvisionAsync`. `Username` on that result is the name Emby creates (`item.Username ?? username`) — set it deliberately.
7. **The user configuration is not inherited on this path** (§7). Decide whether that matters; if it does, apply it after returning, which is not racy.
8. **The browser path (Tasks 6 and 7) is unaffected.** `UserProvisioner.CreateUser(name, template, [UserPolicy, UserConfiguration])` was observed to work exactly as designed — one account, template policy *and* template configuration (§4, §7). Its problem is only that it cannot be called from inside `AuthenticateUser`. The `/emby/Sso/Callback` handler runs outside that flow and can call it freely.

---

## 10. Quick reference

| Thing | Answer |
|---|---|
| Provider calls `IUserManager.CreateUser` then returns success | Sign-in fails **HTTP 400** `A user with the name 'X' already exists.`; the account exists with the template's policy but no token is issued |
| Does Emby adopt a provider-created account? | **No.** `user` is resolved once, before any provider runs, and never re-read |
| Two accounts? | **No** — Emby's `CreateUser` throws on the duplicate name; exactly one account exists |
| Policy hook | `MediaBrowser.Controller.Authentication.IHasNewUserPolicy` → `UserPolicy GetNewUserPolicy()` |
| When is it called | after `Authenticate` returns success, before `CreateUser`, only when the username did not resolve and the winning provider is not `DefaultAuthenticationProvider` |
| Does it work | **Yes.** No default-access window — that rests on the **decompiled construction order** (the policy is a constructor argument to `CreateUser`, so no default policy is ever written then overwritten), *confirmed* by 6 live runs, all HTTP 200 with the template's policy. Run-level evidence is uneven — see §5.3 |
| Does it carry the configuration | **No** — policy only; `CreateUser(name, policy)` uses `new UserConfiguration()` and copies no user settings |
| Return success then `UpdateUserPolicy` | **Unreliable** — lost the race in 6 of 7 fully-logged runs at ~4 ms; wins with a ~1.5 s settle, during which the account's policy grants every library (token use during the window is an inference, §6) |
| Default auto-created policy | `EnableAllFolders: true`, `EnabledFolders: []` — access to everything |
| `AuthenticationProviderId` on a template clone | copied from the template; leave it and the account can never sign in through SSO |
| `IUserManager` constructor injection into a provider | **works** on 4.9.5.0 |
| `CreateUser` username rules | letters, digits, `-`, `_`, `'`, `.` — `probe-alpha` style names are valid |

---

## Server state after the spike

| Changed | Restored to | Verified |
|---|---|---|
| `/config/plugins/Emby.Sso.dll` replaced with two probe builds | **deleted** — no SSO plugin is installed | `ls` shows no `*Sso*` in the plugins dir; `GET /emby/Plugins` returns 20 plugins, none named Authentik SSO; `GET /emby/Auth/Providers` returns `[{"Name":"Default","Id":"Emby.Server.Implementations.Library.DefaultAuthenticationProvider"}]` only |
| 19 `probe-*` accounts created during the probe | all deleted, plus their leftover `config/users/<id>` directories | `GET /emby/Users` lists exactly `claude`, `embyadmin`, `graxo`, `template_user`; `ls config/users/` shows exactly those four ids |
| `template_user` configuration temporarily marked (§7) | restored field-by-field from a saved copy | re-fetched `Configuration` compares **equal** to the saved original, diff empty |
| `probe-create-alpha`'s `AuthenticationProviderId` set to the SSO provider (§4) | account deleted entirely | — |
| probe device `sso-spike-001` / `spike-cli` | deleted twice (it reappeared on the final verification login) | `GET /emby/Devices` lists only the pre-existing `Emby Web`, `Emby for iOS` and `VerificationScript` rows |
| access tokens minted by probe logins | probe accounts deleted; the token from the final `claude` verification login was revoked via `POST /emby/Sessions/Logout` | `GET /emby/Sessions` shows no probe session |

`GET /System/Info/Public` → **200**. `POST /emby/Users/AuthenticateByName` as `claude` / `claude123` → **200**.

**`embyadmin` was never modified** — its `policy.xml` mtime is `2026-08-30 10:09:43`, hours before this spike began.

**Not touched, and disclosed rather than changed:**

- `template_user` (created 14:32:56Z) and `graxo` (created 14:34:22Z) are the operator's own accounts and both predate the first probe (14:38). They were left in place; `template_user` was used as the spike's template and its configuration was restored exactly.
- `/config/plugins/configurations/Emby.Sso.xml` remains on the server. It is the operator's plugin configuration, last written at 16:24 local — before this spike — and it holds a real issuer URL and client secret. The DLL it belongs to has been removed as instructed; the settings file was **not** deleted, because destroying the operator's configuration was not asked for. Note that this secret was configured against the pre-security-fix build; whether to rotate it is the operator's call.

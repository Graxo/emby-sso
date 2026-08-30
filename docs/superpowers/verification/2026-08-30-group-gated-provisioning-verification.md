# Group-gated provisioning — verification record

**Date:** 2026-08-30
**Feature:** group-gated sign-in and OIDC account auto-provisioning (plan
`docs/superpowers/plans/2026-08-30-group-gated-provisioning.md`, design
`docs/superpowers/specs/2026-08-30-group-gated-provisioning-design.md`).
**Build under test:** working tree at the head of `main` for this feature.
`dotnet build -c Release` → **0 warnings, 0 errors**, ILRepack merge OK;
`dotnet test` → **203 passed, 0 failed** (measured, this session).
**Target:** **none.** No Emby server has this build installed and no Authentik
provider is configured for it. Nothing in this document was observed on a
running system unless it says so explicitly.

The earlier live pass — `2026-08-30-emby-oidc-sso-verification.md`, run against
Emby 4.9.5.0 at `10.10.140.5` — covers a **previous build**, before this
feature existed. Its results (install, plugin listing, config page render and
save, error-page behaviour, log hygiene) are evidence about the plugin shell,
not about anything below.

## How to read this document

Three labels are used throughout, and they are not interchangeable:

- **MEASURED** — something was executed and its result observed: a test run, a
  mutation applied and the suite re-run, a harness driven against the shipped
  source.
- **SOURCE** — read out of a binary. Emby's own behaviour here comes from
  decompiling the running 4.9.5.0 assemblies or reflecting over the 4.9.1.90
  reference assemblies. It establishes what Emby's code says; that the composed
  system behaves that way at runtime is a further step, and that step is
  inference.
- **INFERENCE** — reasoning, however strong. Not observed.

**The single most important thing about this feature's status: it has never run
inside Emby.** Every decision it makes is under automated test; every reaction
Emby has to those decisions is SOURCE or INFERENCE.

---

## What is VERIFIED, and how

### 1. The decisions — 203 automated tests (MEASURED)

`dotnet test` → 203 passed, 0 failed. The suite compiles
`src/Emby.Sso/Protocol/**/*.cs` and nothing else, which is exactly the set of
types that make decisions:

| Under test | What is pinned |
|---|---|
| `GroupGate` | claim absent vs present-but-empty vs group not held vs held; ordinal case-insensitive matching after trimming; `NotConfigured = 0` so a default-initialised value refuses; an unset/blank required group refuses |
| `ProvisioningPreconditions` | the whole ordered chain — auto-create, template configured, direct grant, plain-HTTP exclusion, required group, throttle — and that every configuration refusal is decided *above* the throttle read and *above* the credential forward |
| `ProvisioningThrottle` | 10 per username, 100 global, 15-minute window from the first counted failure; failures only; success clears the username's bucket but deliberately not the global one; an unreachable provider is not counted; the map's bound; the refusal string is the ordinary one |
| `PendingPolicies` | unanimity, single-consumption, expiry, refuse-rather-than-evict at capacity, including under real concurrent threads |
| `OidcClient` id-token validation | signature required, algorithm pinned, issuer/audience/lifetime/nonce validated, base64url payload decoding |
| `UsernameMatcher`, `PendingLoginStore`, handoff store, cookie binding | trimming, single-use state, expiry, browser binding |

### 2. That those tests are not vacuous — mutation testing (MEASURED)

Two independent rounds, each mutation applied to the shipped source in a
throwaway `git worktree` and reverted immediately.

- Final review (`final-review.md`, at 177 tests): **22 mutations, 19 killed, 3
  survived.** All three survivors were in `OidcClient`'s token validation —
  `RequireSignedTokens = false`, deleting `ValidAlgorithms`, and
  `AllowedRsaAlgorithms` returning an empty list — i.e. the token the group
  claim is read out of was correct but untested.
- Final fix wave (`final-fix-report.md`, at 203 tests): those three are now
  **killed** by seven new tests (2, 3, 1 and 3 failures respectively), and the
  new guards were mutation-checked as well: moving the required-group check
  below the throttle read fails 1 test, deleting it fails 5, deleting the
  plain-HTTP precondition fails 1, deleting the token-endpoint HTTPS check
  fails 2.

The ordering mutation is the one worth remembering: it is the exact shape of
the defect (F1) that survived eight prior task reviews because the guard order
existed only as a comment.

### 3. Emby's own mechanics — decompilation (SOURCE)

Recorded in `docs/superpowers/spikes/2026-08-30-provisioning-mechanics.md` and
re-checked during the final review:

| Established | Where from | Weight |
|---|---|---|
| Emby recovers the `IHasNewUserPolicy` hook from the very provider object that authenticated (`authenticationProvider is IHasNewUserPolicy`), so arm and claim always land on the same instance | decompiled 4.9.5.0 | SOURCE |
| `CreateUser` is downstream of `GetNewUserPolicy`, so no account exists when the policy is refused | decompiled 4.9.5.0 | SOURCE |
| `IUserManager.AddParts(IEnumerable<IAuthenticationProvider>, …)` is a one-shot registration of *instances*, not a factory | reflected, MediaBrowser.Controller 4.9.1.90 | SOURCE |
| `UserConfiguration.ProfilePin` defaults to `null` and `EnableLocalPassword` to `false` — exactly the values `TemplateClone.CloneConfiguration` forces, so the browser/native configuration difference carries no access | decompiled 4.9.1.90 | SOURCE |
| An `IAuthenticationProvider` is handed a username, a password and (on the `IRequiresResolvedUser` overload) the resolved user — no request, no headers, no client address, so per-source throttling is impossible in-plugin | reflected 4.9.1.90 | SOURCE |
| Emby reports a generic 401 for any throw out of `Authenticate` | spike | SOURCE |

### 4. Structural facts about the shipped code (MEASURED by reading + tests)

- Both paths build the new account's policy through the same
  `TemplateClone.ClonePolicy`, so `IsAdministrator = false` and
  `AuthenticationProviderId` cannot drift between them; the policy is a
  constructor argument to `CreateUser`, so there is no window in which the
  account exists with the template's rights.
- The three membership refusals are character-identical constants
  (`SsoErrors.UnknownUser`, `GroupsClaimMissing`, `GroupNotHeld`), as is the
  throttle's.
- Neither path reaches a user lookup or account creation without a verified
  identity holding the required group; the final review traced every route and
  found no bypass.
- `_throttle` is `static`, so the brake does not depend on Emby holding one
  provider instance.

---

## What is UNVERIFIED, and why

Gathered from `final-review.md`, `final-fix-report.md` and the earlier waves
rather than re-derived. None of it can be settled without a live server.

| # | Unverified | Why it matters | Current basis |
|---|---|---|---|
| U1 | That the `GetNewUserPolicy` throw leaves **no account behind** | It is the native path's last guard; if Emby created the account first, a refusal would leave a half-made user | SOURCE (`CreateUser` is downstream of the hook) + INFERENCE that the running server composes them that way |
| U2 | What a client actually **sees** when `GetNewUserPolicy` throws | Determines whether the refusal is a status-code oracle. Most likely HTTP 400 with the message in the body, by analogy with spike §4 — unlike `Authenticate`'s generic 401 | INFERENCE |
| U3 | Whether `UpdateConfiguration` after `CreateUser` **applies and survives** (browser path display preferences) | A silent failure is cosmetic only, but nobody has seen it work | INFERENCE; the call is best-effort and cannot fail the sign-in |
| U4 | The **live effect of every new refusal**: an unset required group on the native path, the plain-HTTP/direct-grant exclusion, the `/Sso/Start` refusal, the throttle's refusal | These are the refusals an operator will actually meet on upgrade day | INFERENCE from the fact that they use the same `throw` / `Error()` exits as refusals the earlier live pass did observe |
| U5 | The **throttle inside Emby**: that its counters persist across requests as intended, and how fast real Emby clients retry (the review's "100 refusals arrive quickly" claim) | Sets how bad the upgrade-day lockout actually is | INFERENCE; Emby client retry behaviour was never measured and cannot be here |
| U6 | Whether Emby holds **exactly one** provider instance | If not, per-instance state would be wrong. Mitigated rather than answered: `_throttle` is now static, and `PendingPolicies` is recovered from the authenticating instance and fails closed on a miss | SOURCE (`AddParts` takes instances) + INFERENCE (whether Emby materialises or re-enumerates that sequence is not visible in the reference assemblies) |
| U7 | Whether the three previously-surviving id-token mutants were **exploitable** against IdentityModel 6.35.0 | The new tests prove the guards are load-bearing, not that removing them yields a working forgery | Open; a coverage finding, not an exploit finding |
| U8 | That both paths produce the **same account shape** on a real server | Verified by construction (shared `TemplateClone`), never compared live | INFERENCE |
| U9 | The browser handoff's **`localStorage` write** | Carried over from the earlier live pass — no browser was available then either | INFERENCE |
| U10 | That the **config page still renders and saves** after this task's text edits | The page is fragile: Emby 4.9 strips script tags and requires the `emby-scroller` + `data-controller` AMD structure | INFERENCE: the edits changed text inside existing elements only, added and removed no element or attribute, and did not touch `configPage.js` — but the render was user-confirmed for the previous text, not this one |

Also unverified, and structural rather than a question: the test project
compiles `Protocol/` only, so `Auth/`, `Api/`, `SsoRuntime` and `Plugin` have
**zero** automated coverage. Named in `final-fix-report.md` as untested by
construction: `SsoRuntime.DirectGrantPermitted()`, the
`Settings(configuration)` mapping, `RefuseByPrecondition`'s log arms, the
existing-account branch's early required-group refusal, and `/Sso/Start`'s new
refusal.

---

## Live verification checklist

To run when an Authentik provider and a plugin install are available. Ordered
so that a failure early does not waste the rest: phases A and B need no
identity provider at all, and each later phase assumes the previous one passed.

**Before starting.** Take a backup of Emby's data directory. Keep one
administrator account on the **default** provider as break-glass — several
checks below deliberately lock SSO users out. Create two Authentik test users,
one in the required group and one not in it, and an Emby *template* user with
the library access new accounts should get (an ordinary account, not an admin,
except where check C4 asks otherwise).

### Phase A — install and configuration (no Authentik needed)

| # | Step | Expected |
|---|---|---|
| A1 | Copy the merged `Emby.Sso.dll` into `plugins/`, restart, open Dashboard → Plugins | **Authentik SSO** is listed; the config page renders as a full view, not an overlay (reload the dashboard once if Emby served a cached page) |
| A2 | Fill in every field including *Required group*, *Groups claim*, *Template user*, *Automatically create accounts*; save; reload the page | All four persist and repopulate. Closes U10 |
| A3 | Read the page's help text for *Required group* and *Allow plain HTTP* | Matches this build's behaviour (the lockout; that plain HTTP disables native sign-in) |

### Phase B — the refusals that need no identity provider

Do these **before** anything is expected to work; B1 is the upgrade-day
lockout and is the cheapest thing here to get wrong.

| # | Step | Expected |
|---|---|---|
| B1 | Clear *Required group*, save, then `curl` `/emby/Sso/Start` | HTTP 200 error page reading *"Single sign-on is not configured on this server."*, **no redirect to Authentik**, and the log line `SSO: refusing to start sign-in: no required group is configured, so the callback could only refuse`. Partly closes U4 |
| B2 | With *Required group* still empty, sign in from a native client as an **existing** SSO user | Refused (Emby's generic 401). Log: `Rejecting sign-in for <user> without contacting the provider: no required group is configured`. Authentik's logs show **no** authentication attempt — the credential must not have left Emby. Closes the existing-account half of U4 |
| B3 | Restore *Required group*. Tick *Allow plain HTTP* while native sign-in is on; try a native sign-in | Refused with *"Password sign-in is disabled for this account."*; log names plain HTTP and says to turn one of the two off. Untick *Allow plain HTTP* before continuing |
| B4 | Set *Automatically create accounts* on with *Template user* empty; native sign-in as an unknown username | Refused; log `auto-create is on but no template user is configured`; Authentik shows no attempt. Restore the template afterwards |

### Phase C — the happy paths

| # | Step | Expected |
|---|---|---|
| C1 | Existing Emby user, in the required group, browser flow from `/emby/Sso/Start` | Lands on the Emby home screen. Log: gate allowed, sign-in accepted |
| C2 | Same user, native client (direct grant), with the groups claim emitted on that flow | Signs in. If it fails here but C1 passed, Authentik is not emitting the claim on the direct-grant flow — check that first |
| C3 | **Browser provisioning**: Authentik user in the group with *no* Emby account, browser flow | An Emby account is created and the browser lands signed in. Compare the new account's policy against the template in Dashboard → Users: same libraries and permissions, `IsAdministrator` false, provider `Emby.Sso.Auth.SsoAuthenticationProvider`. Check the display preferences copied (closes U3) |
| C4 | **Admin template**: temporarily point *Template user* at an administrator, provision another new user | The created account is **not** an administrator — check the policy immediately, and again after a server restart. Restore the ordinary template afterwards |
| C5 | **Native provisioning**: a third group-holding Authentik user with no Emby account, from a native client | Account created; log `Accepted DirectGrantAccepted sign-in for unknown user '<name>'; Emby will create the account from template '<template>'`. Closes the working half of U1 |
| C6 | Compare the C3 and C5 accounts field by field (policy JSON via `GET /emby/Users/{id}`, and the user configuration) | Policies identical apart from name/id. Configuration may differ in display preferences only; `ProfilePin` null and `EnableLocalPassword` false on both. Closes U8 |
| C7 | Confirm the template's own profile PIN, if it had one, is **not** on either new account | Absent on both |

### Phase D — the negative cases

| # | Step | Expected |
|---|---|---|
| D1 | **Group not held**: Authentik user outside the required group, browser flow | *"This account is not set up on this server."*; log `required group not held`; **no Emby account created** — confirm in Dashboard → Users |
| D2 | Same user, native client | Generic 401; same log reason; no account |
| D3 | **Groups claim absent**: remove the scope mapping so the token carries no groups claim; sign in as a group holder | Same user-facing sentence as D1 (it must not differ); log `the token carried no '<claim>' claim`. Restore the mapping |
| D4 | **Groups claim present but empty**: emit `groups: []` | Refused, and the log distinguishes it from D3 |
| D5 | **Lost group on a second sign-in**: take the C3 user out of the required group in Authentik, then sign in again | Refused, although the account still exists. Any session token minted before the removal keeps working until it is revoked or expires — check that too, and confirm it matches what the README says |
| D6 | **Unset required group with an existing SSO account**: clear the field again and repeat C1 | Refused. This is the full lockout; restore the setting and confirm C1 works again |
| D7 | **A refused sign-in leaves nothing behind**: after D1–D4, list users and check for a partially created account | None. Together with C5 this closes U1; the log for a refused `GetNewUserPolicy` should read `GetNewUserPolicy: no unambiguous pending provisioning; refusing to create the account` |
| D8 | Note what the **native client itself displays** in D2 and D7 (status code and body, e.g. via a proxy or the client's own error) | Records U2 — expected 401 for a refusal inside `Authenticate` and possibly 400 for a `GetNewUserPolicy` refusal |

### Phase E — the throttle

Run last: it deliberately closes the provisioning branch for up to fifteen
minutes, and phases C and D are cheaper to repeat than to wait out.

| # | Step | Expected |
|---|---|---|
| E1 | 10 native sign-in attempts for one unknown username with a wrong password, then an 11th | The 11th is refused **without any attempt appearing in Authentik's logs**; Emby's log says `the provisioning throttle is closed`; the user-facing sentence is unchanged from D1's |
| E2 | Immediately try a *correct* password for a **different** unknown username | Still allowed — one username's budget is its own, until the global bucket fills |
| E3 | Within the same window, drive failures across many distinct usernames past 100 total, then try a legitimate new user | Refused; provisioning is shut globally. Confirm it reopens by itself roughly fifteen minutes after the first counted failure, with no restart |
| E4 | Before the window expires, fail once with a username then succeed with the right password | The success clears that username's bucket. Closes the operational half of U5 |
| E5 | Stop Authentik (or point the issuer at an unreachable host), attempt several native provisioning sign-ins, restore Authentik, then provision legitimately | The unreachable attempts are **not** counted: provisioning works immediately after recovery |
| E6 | Note how many attempts a real native client generates on its own after one refusal | Records the retry rate U5 leaves open |

### Phase F — restoration

Reverse everything the checks changed: remove the test accounts created in C3,
C4 and C5; restore *Template user*, *Required group*, *Allow plain HTTP* and
the auto-create switch to their intended values; put the Authentik test users
back in (or out of) the required group; re-check that the break-glass
administrator still signs in with its local password; and confirm one ordinary
SSO user can still sign in. Record any account whose
`Policy.AuthenticationProviderId` this pass stamped.

---

## Summary

| Area | Status |
|---|---|
| Decision logic (gate, preconditions, throttle, token validation) | **VERIFIED** by 203 tests, mutation-confirmed |
| Guard order on the provisioning branch | **VERIFIED** by test since the final fix wave |
| Emby's provisioning mechanics (`IHasNewUserPolicy`, `CreateUser`, `AddParts`, `UserConfiguration` defaults) | **SOURCE** — decompiled, not observed at runtime |
| Every end-to-end effect inside a running Emby | **UNVERIFIED** — U1–U10 above |
| Operator-facing documentation | Updated this task (README, config page, design doc); the config page's render after the edit is U10 |

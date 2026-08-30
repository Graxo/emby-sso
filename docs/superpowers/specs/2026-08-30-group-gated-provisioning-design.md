# Group-Gated Account Provisioning — Design

Date: 2026-08-30
Status: Approved for planning
Supersedes: the "Provisioning" decision in `2026-08-30-emby-oidc-sso-design.md`

## Purpose

Let an Authentik user who holds a designated group sign in to Emby without an
account having been created for them by hand, and give that new account a
predefined shape and set of libraries.

## What this changes

The original design chose **never auto-create**, and cut a group gate as
unnecessary on the reasoning that, with creation disabled, the Emby user list
was itself the access control list. Both decisions are reversed here. The
plugin's dominant security property becomes conditional rather than absolute:
an account is created only when every condition in "The gate" below holds.

This is a deliberate widening of the plugin's authority. The guard that
previously made auto-creation impossible now has a documented opening, and the
implementation must treat that opening as the most security-sensitive code in
the project.

## Decisions

| Decision | Choice | Reason |
|---|---|---|
| Group model | One gate group, one library set | One rule, one outcome. Auditable, and it avoids a second access-control system alongside Emby's own. |
| Library source | The template user's policy | The admin already picks libraries in Emby's UI; configuring them again in plugin settings would be two sources of truth for one thing. |
| New-account shape | Clone a template Emby user | The operator controls the shape where such things are naturally expressed, rather than through plugin settings that mirror Emby's own. |
| Group re-check | Every sign-in, both paths, existing accounts included | Revocation in Authentik must actually revoke. A gate checked only at creation makes removal silently ineffective. |
| Library re-apply | Never after creation | Manual per-user adjustments in Emby must survive. Re-applying on every sign-in would silently overwrite them. |
| Creation paths | Both browser and native | The operator wants a new user to be able to start on a TV, accepting that creation can then occur behind a path without MFA. |
| Missing groups claim | Refuse, with a distinct reason | The likely cause is a misconfigured Authentik provider. Treating an absent claim as "no groups" would silently deny everyone with a message pointing nowhere. |

## The gate

An account is created only when ALL of the following hold. Any failure refuses
the sign-in and creates nothing.

1. Auto-provisioning is enabled in plugin configuration.
2. A template user is configured, and that user currently exists.
3. The identity was positively verified — a validated ID token from a code
   exchange, or a successful direct grant.
4. The username claim matches the account name being signed into, by the
   existing ordinal case-insensitive rule.
5. The groups claim is present in the token.
6. The required group is among the identity's groups.

For an account that already exists, conditions 3, 5 and 6 still apply on every
sign-in. Conditions 1 and 2 do not — disabling provisioning or removing the
template must not lock out accounts that already exist.

> **Precision noted 2026-08-30 (final review, F7).** "Every sign-in" means every
> sign-in that carries an identity. The browser flow applies conditions 3, 5 and
> 6 in the callback and then hands `SsoAuthenticationProvider` a short-lived
> handoff secret which carries no identity, so the provider does not re-evaluate
> the gate for that one call — it cannot, and re-checking would be impossible
> rather than redundant. Separately, the gate acts at sign-in only: an Emby
> access token minted before the user lost the group keeps working until it is
> revoked.

## Configuration

Four new properties:

- **Enable automatic account creation** — off by default. Turning it on is the
  act that opens the guard.
- **Required group** — the group an identity must hold. No default; empty
  refuses **every** SSO sign-in, existing accounts included, whatever the enable
  flag says.

  > **Corrected 2026-08-30 by ratified decision R10.** This paragraph originally
  > read "empty means provisioning cannot proceed, whatever the enable flag
  > says", scoping the refusal to auto-creation only. Tasks 7 and 8 shipped the
  > stronger rule (`GroupGateOutcome.NotConfigured` → `SsoErrors.NotConfigured`
  > on both paths), the choice was put to the user, and the user ratified the
  > shipped behaviour: an unset required group refuses everyone. The design text
  > was the wrong one and is corrected here rather than the code being changed.
  > See `.superpowers/sdd/2026-08-30-group-gated-provisioning/progress.md`,
  > "Ratified decision — 2026-08-30: unset RequiredGroup refuses everyone".

- **Template user** — an existing Emby user whose policy is cloned. No default.

  > **Drift noted 2026-08-30 (final review, F6).** This originally said "policy
  > and configuration are cloned". Only the browser path clones the template's
  > `UserConfiguration`; the native path's account is created by Emby itself and
  > gets Emby's default `UserConfiguration`. The difference is display
  > preference only — the two authentication-bearing fields, `ProfilePin` and
  > `EnableLocalPassword`, are `null`/`false` in Emby's default and are forced to
  > exactly those values by `TemplateClone.CloneConfiguration`, measured against
  > decompiled `MediaBrowser.Model.Configuration.UserConfiguration` 4.9.1.90.
  > Not fixed in code; recorded so a reader does not mistake it for a defect.
- **Groups claim** — the claim to read groups from, defaulting to `groups`.

## Components

Following the existing boundary: every decision lives in `Protocol/` and
references no `MediaBrowser.*` type; the Emby shell stays thin.

| Component | Responsibility | Layer |
|---|---|---|
| `OidcIdentity` | Gains `Groups` (string array), populated from the configured claim | Protocol (existing, extended) |
| `OidcClient` | Reads the groups claim during ID token validation, on both the code-exchange and direct-grant paths | Protocol (existing, extended) |
| `GroupGate` | Given an identity's groups and the required group, decides whether the gate opens. Distinguishes "claim absent" from "group not held" | Protocol (new) |
| `SsoCredentialResult` | Gains the verified identity so the caller can apply the gate. Rejection outcomes carry no identity | Protocol (existing, extended) |
| `UserProvisioner` | Creates the Emby account from the template and stamps this plugin as its authentication provider | Emby shell (new) |
| `SsoService` callback | On an unknown user: applies the gate, provisions, then mints the handoff secret | API (existing, extended) |
| `SsoAuthenticationProvider` | On a null resolved user: opens only under the full gate; otherwise throws as it does today | Emby shell (existing, extended) |

Group matching is ordinal and case-insensitive after trimming, consistent with
username matching and for the same reason.

## Flow

**Browser.** The callback resolves the username claim to an Emby user. If none
exists, it applies the gate and provisions before minting the handoff secret.
The account therefore exists by the time Emby calls the authentication
provider, and the provider's null-user branch is not involved on this path.

**Native.** Emby calls the provider with a null resolved user. The provider runs
the direct grant, and on success applies the gate. Only then does it provision
and return success.

**Every sign-in.** After credentials are verified and before success is
returned, the gate's group conditions are re-applied. An account whose identity
no longer holds the group is refused.

## The open mechanical question

The spike established that Emby **auto-creates an account when an
authentication provider returns success for an unknown username**, using
default policy. It is not yet known whether a provider may create the account
itself during that call and have Emby adopt it, or whether Emby's own creation
takes precedence — in which case the account would exist with default policy
rather than the template's, and the template's library restriction would not
apply.

This is the difference between an account restricted to the intended libraries
and one with Emby's defaults, so it must be settled before the native path is
built. **Phase 0 of implementation is a spike** against the live server:
provision from inside the provider call, observe which account survives and
with what policy, and record the mechanism. If Emby's creation wins and cannot
be pre-empted, the fallback is to apply the template policy immediately after
Emby's creation and to document the brief window in which the account exists
with default access — or, if that window is unacceptable, to withdraw native
provisioning and require a first browser sign-in.

## Security requirements

- Provisioning is unreachable unless explicitly enabled, and the enable flag is
  off by default.
- No path may provision on an unverified credential. Every provisioning call
  site must be reachable only after a validated ID token or a successful direct
  grant.
- A created account is never an administrator, whatever the template says. This
  is enforced in code, not left to the operator's choice of template.
- The created account is stamped with this plugin's authentication provider at
  creation, so it is never offered to other providers.
- `UserData` is never cloned.
- Group values are treated as untrusted input: they are matched, never rendered
  and never logged in full.
- The refusal reasons for "claim absent" and "group not held" are distinct in
  the log and identical in the browser, so an operator can diagnose a
  misconfigured provider without the difference being visible to a user.

## Error handling

Each gate failure has its own log detail and a user-safe reason: provisioning
disabled, no template configured, template missing, groups claim absent, group
not held. The browser sees a generic refusal; the log carries the specific one.

## Testing

`GroupGate` and the extended `OidcIdentity` and `SsoCredentialResult` are pure
and unit tested against the existing fake identity provider, which gains the
ability to mint tokens with, without, and with an empty groups claim. The
negative cases carry the weight: claim absent, group not held, empty group
list, group present but identity unverified, and provisioning disabled.

`UserProvisioner` and the two extended call sites touch Emby types and are
verified against the live server, as the rest of the shell was: an account
created for a group holder with the template's libraries and not administrator;
a non-holder refused with nothing created; an existing account refused after
the group is removed in Authentik.

## Out of scope

Mapping several groups to different library sets; re-applying library access
after creation; removing or disabling accounts when a group is lost, beyond
refusing the sign-in; and any synchronisation of display names or other profile
attributes.

# Group gating and account creation

Two things ship together here, and only one of them is optional.

- **The group gate is not optional.** Every sign-in through this plugin —
  browser or native, brand-new account or one that predates the plugin — is
  allowed only if the identity Authentik returns carries the configured
  *Groups claim* and that claim contains the *Required group*.
- **Creating accounts is optional and off by default.** With *Automatically
  create accounts for group holders* enabled and a *Template user* named, a
  group holder who has no Emby account gets one, cloned from that template.

!!! danger "With no required group configured, nobody signs in at all"

    Not "the gate is off". Every SSO sign-in is refused, existing accounts
    included. See
    [the required-group lockout](before-you-install.md#the-required-group-lockout).

!!! unverified "None of this has run on a live server"

    Everything on this page is **built and unit-tested, but has never run
    inside Emby.** How Emby *reacts* is
    [inferred from decompiled assemblies](verification-status.md#group-gating-and-automatic-account-creation),
    not observed.

## The four settings

| Setting | What it does | Unset / empty |
|---|---|---|
| [**Required group**](settings.md#required-group) | The Authentik group an identity must carry in the groups claim. Matched ordinal, case-insensitively, after trimming — the same rule usernames use. | **Refuses every SSO sign-in**, existing accounts included. Not a way to switch the gate off. |
| [**Groups claim**](settings.md#groups-claim) | The claim the group list is read out of. Defaults to `groups`. Authentik must be configured to emit it — including on the direct-grant flow, if native sign-in is enabled. | Falls back to `groups`. A token that carries no such claim at all is refused, and only the log says why. |
| [**Template user**](settings.md#template-user) | An existing Emby user whose **policy** — libraries, permissions, everything Emby calls access — is copied onto each account this plugin creates. | Automatic creation refuses; nothing is created. An existing user still signs in normally. |
| [**Automatically create accounts for group holders**](settings.md#automatically-create-accounts-for-group-holders) | Off by default. Turning it on is the act that lets the plugin call Emby's `CreateUser` at all. | No account is ever created; an unknown username is refused exactly as it was before this feature existed. |

## What a created account actually gets

**The template's policy, not Emby's defaults.**

!!! warning "This matters more than it sounds"

    A brand-new Emby user created by Emby's own defaults has access to **every
    library**. An account created by this plugin has exactly the access its
    template has, because the policy is built from the template *before* the
    account exists and handed to Emby as a constructor argument — there is no
    window in which the account exists with different rights.

So **choose the template deliberately.** Whatever that user can see, every
account provisioned from it can see. The usual answer is to create one ordinary
account with the libraries you want new people to get and nominate that as the
template.

### Deliberately not inherited, whatever the template says

- **Administrator.** An administrator template does *not* produce
  administrators. `IsAdministrator` is forced to `false` on both paths, at
  construction. There is no moment at which the new account is an admin.
- **Disabled.** `IsDisabled` is forced to `false`. The template is an ordinary,
  sign-in-able Emby account that exists only to donate a policy, so the right
  thing to do with it is to **disable it** once its library access is set — and
  that must not produce disabled new accounts.
- **The template's own login history.** `InvalidLoginAttemptCount` and
  `LockedOutDate` are reset. They are not policy intent; inheriting them would
  start an account part-way to a lockout, or locked out outright.
- **The profile PIN.** The template's `ProfilePin` is a per-person secret;
  handing every provisioned account a copy of it would be handing them each
  other's. It is cleared.
- **The obsolete local-password switch.** `EnableLocalPassword` (Emby's old
  "easy password" feature) is cleared, because the credential it pairs with is
  not copied — an account would otherwise carry an enabled local-password
  switch with nothing behind it.

The new account is stamped with this plugin as its authentication provider, so
from that point Emby consults only Authentik for it. See
[provider stamping](before-you-install.md#emby-stamps-the-provider-permanently).

### One cosmetic asymmetry, called out so it is not filed as a bug

The browser path also copies the template's **display preferences**
(`UserConfiguration` — subtitle mode, resume offsets, view order); the native
path's account is created by Emby itself and gets Emby's defaults for those.

Nothing that grants access differs between the two — the two fields in that
structure that are not preferences, `ProfilePin` and `EnableLocalPassword`, end
up identical either way. Two people provisioned on the same day may simply have
different subtitle defaults depending on which client they first signed in
from.

## Losing the group

The gate is re-evaluated on every sign-in, so removing someone from the group
in Authentik removes their Emby access — **at their next sign-in**.

!!! warning "It does not reach back and revoke a token that was already minted"

    If you need someone out *now*, disable their Emby account or delete their
    device/session in Dashboard → Devices, as well as removing the group.

## Brute-force protection

Opening the "unknown username" branch means an unauthenticated stranger can
make this server forward a guessed password to Authentik.
[Two brakes cover it, and both are required](brute-force-protection.md).

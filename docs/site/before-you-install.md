# Read this before you install

Emby's authentication pipeline behaves in ways that are easy to get wrong and
hard to undo. Two of the three things on this page cannot be reversed from the
Emby dashboard once they have happened.

!!! verified "Verified on a live server"

    Everything on this page about Emby's own behaviour was confirmed against a
    live Emby 4.9.5.0 server. It was not assumed from documentation.

---

## The required-group lockout

**Every single sign-on this build performs is gated on an Authentik group, and
until you name that group the plugin refuses everyone.**

!!! danger "Leaving *Required group* empty is not a way to switch the group check off"

    It means:

    - every existing SSO user is refused, including accounts that were signing
      in fine a minute before the upgrade — this is not limited to the new
      account-creation path;
    - a browser sign-in is refused at `https://<emby>/sso/start` itself,
      before the browser is sent to Authentik;
    - a native app sign-in is refused before the password is forwarded
      anywhere.

So, in order: **install the DLL, then immediately set *Required group* in
Dashboard → Plugins → Authentik SSO** — or set it first, if you are upgrading
in place and the field is already there. Keep at least one administrator on the
default provider as a [break-glass account](#2-keep-a-break-glass-administrator);
that is what gets you back into the dashboard to fix it.

### How to recognise it

The user-facing message is the ordinary *"Single sign-on is not configured on
this server."* — deliberately the same sentence an unconfigured plugin gives,
because a refusal must not tell a stranger which of several reasons applied.
What tells *you* is the server log, under category `AuthentikSso`:

```
SSO: refusing to start sign-in: no required group is configured, so the callback could only refuse
Rejecting sign-in for <user> without contacting the provider: no required group is configured
```

This is deliberate and was decided with the lockout understood: a server whose
operator has not said which group may sign in has not said who may sign in, and
the fail-closed answer to that is nobody.

---

## Emby stamps the provider permanently

!!! danger "The first successful sign-in decides a user's provider for good"

    The first time a user signs in successfully, Emby writes that provider's ID
    into the user's `Policy.AuthenticationProviderId` on disk. From then on,
    **only that provider is consulted** for that user. A user who signs in
    through this plugin once can no longer use their Emby password — Emby will
    not even try the default provider for them again. **The only way back is
    for an administrator to reset the field via the Emby API.**

### A user with no provider assigned is offered to every enabled provider

If an account's `AuthenticationProviderId` has never been set, Emby tries every
provider in turn (its own built-in password check first, then this plugin) and
stamps whichever one succeeds. That would make every unstamped Emby account
reachable through Authentik the moment this plugin is installed — including a
newly created administrator that has never logged in.

**This plugin therefore refuses any existing account that is not already
assigned to it**, on both sign-in paths, so that adopting an account into SSO
is always a deliberate action. The log says so:

```
the account has no authentication provider assigned, so this plugin will not adopt it
```

Note that Emby still *offers* those accounts to the plugin — it is the plugin
that says no — so this is a guard, not a reason to skip assigning providers
deliberately.

---

## Do these three things before you install the plugin

### 1. Pin every account you do not want migrated

For every Emby account you do **not** want migrated to SSO, explicitly set its
authentication provider to the default one first — **Dashboard → Users →
select the user → Login provider → Default**, or via the API (see below for
why the dashboard selector cannot be trusted for administrators).

Setting it explicitly, even to the value it already has, fixes it in place:
Emby will no longer try this plugin for that account.

### 2. Keep a break-glass administrator

**Keep at least one administrator account permanently on the default provider.**
If Authentik is ever unreachable, this is the only account that can still get
into Emby. It is also what gets you back in after the required-group lockout
above.

### 3. Know that the dashboard's provider selector lies for administrators

The dashboard's "Login provider" dropdown is only shown for
**non-administrator** accounts, and only once more than one provider is
registered.

!!! danger "For an administrator account, saving the profile tab writes back the hidden dropdown"

    Saving the profile tab in the dashboard writes back the dropdown's value
    even though it is hidden, which silently defaults to the built-in provider
    unless you set it deliberately.

To assign or fix an administrator's provider, use the API directly:

```
POST /emby/Users/{userId}/Policy
```

with the full `UserPolicy` JSON body and `"AuthenticationProviderId"` set to
either:

| Value | Meaning |
|---|---|
| `Emby.Server.Implementations.Library.DefaultAuthenticationProvider` | Emby's built-in password check |
| `Emby.Sso.Auth.SsoAuthenticationProvider` | This plugin |

None of this is a bug in the plugin — it is how Emby's own
`IAuthenticationProvider` pipeline works for every third-party provider,
including this one.

---

## Next

- [Installing and upgrading](installing.md)
- [Assigning each user's login provider](login-providers.md) — required, per
  user, and easy to miss.

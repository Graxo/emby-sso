# Assigning each user's login provider

**Nothing works until this is done, per user.** Creating a matching Authentik
account and installing the plugin is not enough by itself.

## For an ordinary user

Dashboard → Users → select the user → **Login provider** → **Authentik SSO**.

This selector only appears for **non-administrator** accounts, and only once
more than one provider is registered — that is, once this plugin is installed.

## For an administrator

!!! danger "The dashboard cannot be trusted for administrator accounts"

    The selector is hidden for administrators, and saving the profile tab
    writes back the hidden dropdown's value anyway — silently defaulting to the
    built-in provider unless you set it deliberately.

Set it through the API instead:

```
POST /emby/Users/{userId}/Policy
```

with the full `UserPolicy` JSON body and `"AuthenticationProviderId"` set to
`Emby.Sso.Auth.SsoAuthenticationProvider`.

The same call, with
`Emby.Server.Implementations.Library.DefaultAuthenticationProvider`, is how you
pin an account to Emby's own password check — and how you undo a
[provider stamp](before-you-install.md#emby-stamps-the-provider-permanently)
after the fact.

## If you skip this step

The account cannot sign in through SSO at all: the plugin refuses any account
not already assigned to it, and the user sees the ordinary *"This account is
not set up on this server."* Only the server log says which of several reasons
applied.

## Accounts the plugin creates itself

Accounts created by
[automatic account creation](groups-and-account-creation.md) are stamped with
this plugin as their authentication provider at the moment they are created, so
this step does not apply to them. It applies to every account that existed
before.

## Keep one administrator out of this

!!! danger "Keep at least one administrator permanently on the default provider"

    If Authentik is ever unreachable, or the required group is misconfigured,
    that break-glass account is the only thing that can still get into the Emby
    dashboard to fix it.

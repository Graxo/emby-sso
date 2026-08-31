# Emby OIDC SSO

Lets existing Emby users sign in with an external OpenID Connect provider — in
particular [Authentik](https://goauthentik.io/). Emby has no native OIDC
support; this plugin implements the browser authorization-code flow (with
PKCE) and, optionally, the OIDC direct-grant flow for native apps.

!!! danger "Three things to read before you install anything"

    1. **Leaving *Required group* empty refuses every user**, including ones
       who were signing in fine a minute earlier. It is not a way to switch
       the group check off. See
       [Read this before you install](before-you-install.md#the-required-group-lockout).
    2. **Emby stamps the winning provider onto a user permanently.** Once
       somebody signs in through this plugin, Emby will not try their Emby
       password again — only an API call can undo it. See
       [Provider stamping](before-you-install.md#emby-stamps-the-provider-permanently).
    3. **This is licensed software, not open source**, and a licence key
       issued for your specific server must be pasted into the configuration.
       See [Licensing](licensing.md).

**Out of the box this plugin creates no Emby users.** The Emby account must
already exist, and an administrator must explicitly point that account's
authentication provider at this plugin. There is one optional, off-by-default
path that creates an account — for a user who holds a required Authentik
group, cloned from a template user you nominate. Read
[Group gating and account creation](groups-and-account-creation.md) before you
turn it on.

## What you are probably here to do

<div class="grid cards" markdown>

- **Get it running**

    [Read this before you install](before-you-install.md) →
    [Installing and upgrading](installing.md) →
    [Setting up Authentik](authentik.md) →
    [Assigning each user's login provider](login-providers.md)

- **Understand a setting**

    [Every setting, explained](settings.md) — one section per field, with a
    stable link you can paste anywhere.

- **Let people sign in on a TV**

    [Native apps with a one-time PIN](pin-sign-in.md) keeps multi-factor
    authentication. [Native apps with a password](native-apps.md) does not.

- **Work out why somebody cannot sign in**

    [Troubleshooting](troubleshooting.md) — every sentence a user can be
    shown, what it means, and what to check.

</div>

## How it works

- **Browser sign-in.** The user opens a bookmarkable URL
  (`https://<emby>/emby/Sso/Start`). The plugin redirects to Authentik,
  Authentik authenticates the user under its own flows (including MFA and
  passkeys), and redirects back to `https://<emby>/emby/Sso/Callback`. The
  plugin validates the response, checks that the username matches an existing
  Emby user, and completes the sign-in — the browser lands directly on the
  Emby home screen with no further clicks.
- **Native apps (phone, TV).** Off by default. When enabled, a native client's
  normal username/password screen is checked against Authentik using an OIDC
  direct grant instead of Emby's local password.
- **Native apps, with a one-time PIN instead.** Also off by default, and a
  separate setting. The user completes a full browser sign-in (MFA and all) on
  a phone or laptop, is shown a short PIN, and types their username and that
  PIN into the TV app's ordinary sign-in screen.
- **No account is created unless you switch that on.** If the username from
  Authentik does not match an existing Emby user, the sign-in is rejected with
  a generic error and nothing is written to the log except the fact that it
  happened — unless automatic account creation is enabled and the identity
  holds the required group, in which case an account is created from your
  template user.
- **Every sign-in is checked against the required group**, whether the account
  is new or years old. Losing the group in Authentik loses Emby access at the
  next sign-in.

There is no button on Emby's login page, and there cannot be one —
[here is why](browser-sign-in.md#there-is-no-button-on-the-login-page).

## How this documentation talks about evidence

This project is careful about the difference between something that was
measured and something that was worked out. That distinction is kept here, in
three marks that mean exactly what they say.

!!! verified "Verified on a live server"

    Observed directly against a running Emby 4.9.5.0 server. Not assumed from
    documentation, and not inferred.

!!! inferred "Inferred from decompiled source"

    Reasoned out of Emby's own assemblies (4.9.5.0 as running, 4.9.1.90
    reference assemblies) rather than observed. It is the best answer
    available and it is still an inference.

!!! unverified "Not verified"

    Built and covered by the automated test suite, but never run in the place
    it will actually run. Treat it as a thing to check, not a thing to trust.

Whole features carry one of these marks. The complete list is on
[What has and has not been verified](verification-status.md); read it before
you decide how much of this to rely on.

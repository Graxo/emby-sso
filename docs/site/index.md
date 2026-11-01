# Emby SSO

Emby has no single sign-on of its own. This plugin adds it: your users sign in
to Emby with their [Authentik](https://goauthentik.io/) account (or another
OpenID Connect provider that behaves like Authentik), with whatever two-factor
policy you already enforce there.

- **New here?** Read [How it works](how-it-works.md), then follow
  [Setup](setup.md) from top to bottom.
- **Something is not working?** Go to [Troubleshooting](troubleshooting.md).
- **Looking up one setting?** [Settings reference](settings.md).
- **Licence, trial, activation?** [Licensing](licensing.md).

## The short version

1. Users open `https://<your-emby>/sso/start` (there is no button on Emby's
   login page, so give them this link).
2. They sign in at Authentik as usual, MFA included.
3. Authentik sends them back to Emby, the plugin checks who they are, and they
   land on the Emby home screen, signed in.

Televisions and phone apps can sign in too, either with a
[one-time PIN](pin-sign-in.md) the user gets from a browser, or (off by
default) with an Authentik app password.

## Before you start, know these three things

1. **The plugin only signs in accounts you have moved to it.** Installing it
   changes nothing for existing users. You switch each account to the plugin
   yourself (see [Setup, step 6](setup.md#6-move-accounts-to-sso)).
2. **Once an account is on SSO, its Emby password stops working.** Emby only
   asks the account's assigned login provider. Keep at least one administrator
   on Emby's own password login so you can always get into the dashboard.
3. **Nobody can sign in until you set *Required group*.** The plugin only lets
   in people who are in that Authentik group.

## What you need

- Emby Server 4.9 or newer, reachable over HTTPS.
- Authentik (or another OpenID Connect provider), reachable from the Emby
  server.
- A licence for your Emby server. A free 14-day trial is available; see
  [Licensing](licensing.md).

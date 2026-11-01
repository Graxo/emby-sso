# Emby SSO — sign in to Emby with Authentik

Emby has no single sign-on of its own. This plugin adds it: your users sign in
to Emby with their [Authentik](https://goauthentik.io/) account, with whatever
two-factor policy you already enforce there. It works with any OpenID Connect
provider that behaves like Authentik.

## What it does

- **Browser sign-in.** Users open `https://<emby>/sso/start`, sign in at
  Authentik, and land on the Emby home screen. Emby never sees their password.
- **TVs and phone apps.** Sign in with a one-time PIN obtained in a browser
  (keeps MFA), or with an Authentik app password. Both optional.
- **Group gating.** Only members of the Authentik group you choose can sign in.
- **Automatic accounts** (optional). New group members get an Emby account
  copied from a template user.
- **Safe to roll out.** Nothing changes until you move an account to SSO, and
  a problem with the plugin, Authentik or the licence never locks you out of
  your own Emby administrator account.
- **One file, updates itself.** The plugin offers new versions on its settings
  page and checks the vendor's signature before installing. It never restarts
  Emby for you.
- **Kept current with Emby.** The developer runs this plugin on their own
  server every day, so it is kept working with the latest Emby releases.

## Quick start

```bash
base=https://license.koper.cloud/v1/release
curl -fLo Emby.Sso.dll $base/download
curl -fLo Emby.Sso.dll.sha256 $base/download.sha256
sha256sum -c Emby.Sso.dll.sha256
```

Copy `Emby.Sso.dll` (only that file) into Emby's `plugins` folder and restart
Emby. Then follow [Setup](docs/site/setup.md): create the provider in
Authentik, fill in the plugin settings, activate a licence, and move accounts
to SSO.

## Documentation

| | |
|---|---|
| [Overview](docs/site/index.md) | What it is and what you need |
| [How it works](docs/site/how-it-works.md) | The sign-in flows, the checks, login providers, the licence |
| [Setup](docs/site/setup.md) | Step by step, from install to first sign-in |
| [Troubleshooting](docs/site/troubleshooting.md) | Every error message, and what the log tells you |
| [One-time PIN sign-in](docs/site/pin-sign-in.md) | Signing in on a TV, with instructions to send your users |
| [Settings reference](docs/site/settings.md) | Every field on the settings page |
| [Licensing](docs/site/licensing.md) | Trial, buying, activating, the daily check |
| [Building from source](docs/site/building.md) | For developers |

## Licensing

**This is paid software, not open source.** The source is published so you can
read what runs on your server; you may not redistribute it or run it without a
licence. See [`LICENSE`](LICENSE).

A licence is issued for one Emby server and checked offline on that server.
Buy one from the plugin's settings page (**Buy a licence**), then paste the
redemption code you receive and press **Activate**.

### A trial licence

There is a proper way to try the plugin, and it is free: request a **trial
licence** in the client portal at <https://portal.koper.cloud>. A trial licence
is valid for **14 days**.

Please do take one before buying, especially if you are not certain your
provider is set up the way this plugin expects.

### If a licence is missing or expired

New SSO sign-ins and automatic account creation are refused, and nothing else.
People already signed in stay signed in, and Emby's own accounts are untouched.

### What the plugin sends the vendor

When you activate: your redemption code and server id. Once a day, from a
scheduled task you can switch off: your server id, a fingerprint of the licence
and the plugin version. Nothing about your users, libraries or viewing, ever.

## Help

See [Troubleshooting](docs/site/troubleshooting.md), or email
<support@koper.cloud> with the message you saw and the `AuthentikSso` lines from
the server log. Never include your redemption code.

---

The licence check is a signed key verified on your own machine. A .NET assembly
can be decompiled and the check removed; this is not DRM, and the enforceable
part is [`LICENSE`](LICENSE).

Developed and tested against Emby Server 4.9.5.0.

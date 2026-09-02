# Emby SSO — sign in to Emby with Authentik

Emby has no support for single sign-on. This plugin adds it, so the people who
use your server sign in with the account they already have.

One password for everything they use, managed in one place, with whatever
two-factor policy you already enforce.

Built for [Authentik](https://goauthentik.io/), and works with any OpenID
Connect provider that behaves like it.

---

## Features

**Signing in**

- **Browser sign-in.** Users open one bookmarkable link and come back signed
  in. The modern, secure flow (authorization code with PKCE) — your server
  never sees anyone's password.
- **Native apps with a password.** Optional, off by default. Lets the Emby apps
  on phones and consoles sign in through your provider.
- **Native apps with a PIN.** Sign in on a television by typing a short code
  shown on your phone — so a device with no keyboard still gets your
  two-factor policy instead of skipping it. There are
  [step-by-step instructions you can send your users](docs/site/pin-sign-in.md#instructions-to-send-your-users).

**Deciding who gets in**

- **Group gating.** Only members of the group you name may sign in. Everyone
  else is refused, and told nothing useful.
- **Automatic accounts.** Optional. A group member who has never used your
  server can get one, cloned from a template account whose libraries and
  permissions you set.
- **One account, one identity.** An Emby account is bound to the identity that
  first used it, so a renamed or recreated account elsewhere cannot quietly
  take it over.
- **Brute-force protection**, on both the sign-in and the PIN paths.

**Running it**

- **One file to install.** No dependencies, no runtime to add.
- **Updates itself, safely.** When a new version is published, the plugin
  offers a button. It checks the download against the vendor's signature
  before writing anything, and never restarts your server for you.
- **Quiet by default.** Nothing about your users, your libraries or your media
  ever leaves your server.
- **You cannot be locked out.** Your own Emby accounts keep using Emby's own
  password check, so a problem with the plugin, your provider, or your licence
  never costs you the dashboard.

---

## Installing

The whole plugin is one file. Download it and check it:

```bash
base=https://license.koper.cloud/v1/release
curl -fLo Emby.Sso.dll $base/download
curl -fLo Emby.Sso.dll.sha256 $base/download.sha256
sha256sum -c Emby.Sso.dll.sha256
```

That address always serves the current release and needs no account.

Then:

1. Put `Emby.Sso.dll` in the `plugins` folder of your Emby installation,
   replacing any earlier copy.
2. Restart Emby Server.
3. Open **Dashboard → Plugins**. **Authentik SSO** should be listed, at the
   version you just downloaded. A different number means the old file is still
   there.
4. Open it and fill in your provider's details. **Set *Required group*** — until
   you name a group, nobody is allowed to sign in through the plugin.

**Install this one file and nothing else.** It already contains everything it
needs; adding other DLLs beside it breaks it.

Next: [Setting up Authentik](docs/site/authentik.md), then
[assign each user's login provider](docs/site/login-providers.md) — that second
step is required and easy to miss.

### Nothing changes until you say so

Installing the plugin does not move anyone to SSO. It refuses any account that
has not been deliberately assigned to it, so your existing users, and your own
administrator account, carry on signing in with their Emby passwords exactly as
before. You move accounts across one at a time, when you are ready.

Two things are worth knowing once you start:

- **Emby remembers the first provider that works for an account, permanently.**
  Once someone signs in through SSO, Emby stops offering them the Emby password
  check. Moving them back needs an API call, so keep one administrator on Emby's
  own login as a break-glass account.
- **Plain HTTP and native password sign-in cannot both be on.** That is
  deliberate: this server will not put anyone's password on the wire in
  cleartext.

Both are explained in [Read this before you install](docs/site/before-you-install.md)
and [Native apps with a password](docs/site/native-apps.md).

### Updating

You should only ever do the above once. When a newer version is published, the
plugin's configuration page shows **Download and install**. It verifies the
vendor's signature and the file's checksum before it writes anything, and asks
you to restart when it suits you.

Details: [Updates and the daily check](docs/site/updates.md).

---

## Licensing

**This is paid software, not open source.** The source is published so you can
read what runs on your server; you may not redistribute it or run it without a
licence. See [`LICENSE`](LICENSE).

### What a licence is

A licence is a key issued for **one Emby server**, identified by the server id
Emby prints in its log at startup and shows on the plugin's configuration page.
It is checked on your own machine, offline.

### Buying one

From the plugin itself. Open **Dashboard → Plugins → Authentik SSO** and press
**Buy a licence** — you are taken to the shop with your server id already
filled in. Pay, and a **redemption code** arrives by email at the address on
your payment.

Paste that code into the same page and press **Activate**. The first activation
of a new code is not instant: it may answer *"your licence is being issued"*,
and pressing Activate again a few minutes later completes it. The code is not
used up by the wait.

One code covers more than one server — how many is shown on the configuration
page once you have activated. Re-activating a server you have already activated,
after a rebuild or a restore or a move, does not use up another.

### A licence for testing

There is a proper way to get one, and it is free: **ask.** Email
<support@koper.cloud> with your Emby server id and say what you want to try. You
will get a redemption code that works exactly like a bought one, for a limited
time.

Please do take one before buying, especially if you are not certain your
provider is set up the way this plugin expects.

### If a licence is missing or expired

**New single sign-ons and automatic account creation are refused, and nothing
else.** People already signed in stay signed in, your own Emby accounts are
untouched, your media is untouched, and nothing is deleted or reconfigured. You
cannot be locked out of your own server by a licensing problem — that is the
one thing the design will not do.

More: [Licensing](docs/site/licensing.md) and
[Buying and activating a licence](docs/site/activation.md).

### What the plugin tells the vendor

Almost nothing, and never anything about your users.

- **When you activate:** your redemption code and your server id, once.
- **Once a day:** your server id and a one-way fingerprint of your licence, to
  ask whether the licence is still valid and whether a new version exists. It
  is an ordinary Emby scheduled task — you can see it, run it, and **switch it
  off**. If it gets no answer, nothing changes.

That is the complete list. No usernames, no libraries, no viewing habits, no
addresses, ever.

---

## Getting help

- **[Troubleshooting](docs/site/troubleshooting.md)** — every message a user
  can be shown, and what to check for each one.
- **[What has and has not been verified](docs/site/verification-status.md)** —
  an honest list of what has been tested on a real server and what has not.
  Worth reading before you trust anything here with a server people rely on.
- **Email <support@koper.cloud>** with what the plugin told you and what the
  server log said under `AuthentikSso`. Never include your redemption code.

---

## Documentation

| | |
|---|---|
| [Start here](docs/site/index.md) | What it is and how it works |
| [Read this before you install](docs/site/before-you-install.md) | How Emby assigns accounts to a provider, and what that means |
| [Installing and upgrading](docs/site/installing.md) | Download, checksum, three steps |
| [Updates and the daily check](docs/site/updates.md) | The update button, and what is sent once a day |
| [Setting up Authentik](docs/site/authentik.md) | Provider, application, groups, scopes |
| [Assigning each user's login provider](docs/site/login-providers.md) | Required, and easy to miss |
| [Browser sign-in](docs/site/browser-sign-in.md) | The bookmarkable URL |
| [Native apps with a password](docs/site/native-apps.md) | Direct grant, and what it costs you |
| [Native apps with a one-time PIN](docs/site/pin-sign-in.md) | Two-factor, on a television |
| [Group gating and account creation](docs/site/groups-and-account-creation.md) | Who may sign in, and who gets an account |
| [One Emby account, one Authentik identity](docs/site/identity-binding.md) | How accounts are bound to people |
| [Brute-force protection](docs/site/brute-force-protection.md) | Both brakes, and why you need both |
| [Every setting, explained](docs/site/settings.md) | One section per field |
| [Licensing](docs/site/licensing.md) | What an invalid licence does and does not stop |
| [Buying and activating a licence](docs/site/activation.md) | Redemption codes, step by step |
| [Troubleshooting](docs/site/troubleshooting.md) | When something is wrong |
| [What has and has not been verified](docs/site/verification-status.md) | The honesty ledger |
| [Building from source](docs/site/building.md) | For developers |

The same pages are published to the project wiki, generated from `docs/site/`
on every push — so **edits made in the wiki are overwritten**.

---

## Building from source

You do not need to build anything to use the plugin. If you want to read it and
run its tests:

```bash
dotnet build -c Release          # produces the installable plugin
dotnet test tests/Emby.Sso.Tests # 621 tests, no Emby server or network needed
```

The build output is at
`src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll`, and reports its
version as `0.0.0-dev` so a copy you built yourself can never be mistaken for a
release.

Details: [Building from source](docs/site/building.md).

---

## Honesty about what this is

The licence check is a signed key verified on your own machine. The plugin is a
.NET assembly, and **a .NET assembly can be decompiled and the check removed.**
There is no obfuscation and none is planned. This is not DRM and is not
described as DRM anywhere here — it raises the cost of casually copying a
licence between servers, and the enforceable part is [`LICENSE`](LICENSE),
not the code.

Developed and tested against Emby Server 4.9.5.0.

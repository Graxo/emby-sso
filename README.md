# Emby OIDC SSO Plugin

Lets existing Emby users sign in with an external OpenID Connect provider —
in particular [Authentik](https://goauthentik.io/). Emby has no native OIDC
support; this plugin implements the browser authorization-code flow (with
PKCE) and, optionally, the OIDC direct-grant flow for native apps.

**Out of the box this plugin creates no Emby users.** The Emby account must
already exist, and an administrator must explicitly point that account's
authentication provider at this plugin. There is one optional, off-by-default
path that creates an account — for a user who holds a required Authentik
group, cloned from a template user you nominate.

**This is licensed software, not open source.** See `LICENSE`. A licence key
issued for your specific Emby server has to be in the plugin configuration —
pasted in, or bought and redeemed from the configuration page itself. Without
a valid one the plugin refuses new sign-ons.

## The documentation

Everything that used to be in this file lives in
[`docs/site/`](docs/site/index.md). It is published two ways from that one
source, on every push to `main`:

- **the project wiki**, which is where to look, and what the plugin's
  configuration page links to;
- **GitLab Pages**, as a searchable site with the Material theme.

Both are generated, so **edits made in the wiki are overwritten**. Change the
files in `docs/site/`. Every page is also readable here as ordinary Markdown.

| | |
|---|---|
| [Start here](docs/site/index.md) | What it is and how it works |
| [Read this before you install](docs/site/before-you-install.md) | The two things Emby does that are hard to undo |
| [Installing and upgrading](docs/site/installing.md) | Download, checksum, three steps |
| [Setting up Authentik](docs/site/authentik.md) | Provider, application, groups, scopes |
| [Assigning each user's login provider](docs/site/login-providers.md) | Required, and easy to miss |
| [Browser sign-in](docs/site/browser-sign-in.md) | The bookmarkable URL, and why there is no login-page button |
| [Native apps with a password](docs/site/native-apps.md) | Direct grant, and what it costs you |
| [Native apps with a one-time PIN](docs/site/pin-sign-in.md) | Keeps multi-factor authentication on a television |
| [Group gating and account creation](docs/site/groups-and-account-creation.md) | Who may sign in, and who gets an account |
| [One Emby account, one Authentik identity](docs/site/identity-binding.md) | Subject binding, trust on first use |
| [Brute-force protection](docs/site/brute-force-protection.md) | Both brakes, and why you need both |
| [Every setting, explained](docs/site/settings.md) | One section per field on the configuration page |
| [Licensing](docs/site/licensing.md) | What an invalid licence does and does not stop |
| [Buying and activating a licence](docs/site/activation.md) | Redemption codes, and the one call this plugin makes |
| [Troubleshooting](docs/site/troubleshooting.md) | Every message a user can be shown, and what to check |
| [What has and has not been verified](docs/site/verification-status.md) | The honesty ledger — read it |
| [Building from source](docs/site/building.md) | Build, test, and cut a release |
| [Signing licences offline](docs/site/offline-signing.md) | Vendor only — the key is not on the server |
| [Rotating and revoking a signing key](docs/site/key-rotation.md) | Vendor only — how a leak is survived |

---

# Read this before you install anything

Three things below can lock people out of a working server, and one of them
can lock out every user at once. They are kept here in full, rather than
behind a link, because a repository is readable when a documentation site may
not be.

## 1. Leaving *Required group* empty refuses everyone

Every single sign-on this build performs is gated on an Authentik group, and
**until you name that group the plugin refuses everyone.** Leaving *Required
group* empty does not mean "the group check is off". It means:

- every existing SSO user is refused, including accounts that were signing in
  fine a minute before the upgrade — this is not limited to the new
  account-creation path;
- a browser sign-in is refused at `https://<emby>/sso/start` itself,
  before the browser is sent to Authentik;
- a native app sign-in is refused before the password is forwarded anywhere.

So, in order: **install the DLL, then immediately set *Required group* in
Dashboard → Plugins → Authentik SSO** — or set it first, if you are upgrading
in place and the field is already there. Keep at least one administrator on
the default provider as a break-glass account (see the next section); that is
what gets you back into the dashboard to fix it.

**How to recognise it.** The user-facing message is the ordinary *"Single
sign-on is not configured on this server."* — deliberately the same sentence
an unconfigured plugin gives, because a refusal must not tell a stranger which
of several reasons applied. What tells *you* is the server log, under category
`AuthentikSso`:

```
SSO: refusing to start sign-in: no required group is configured, so the callback could only refuse
Rejecting sign-in for <user> without contacting the provider: no required group is configured
```

This is deliberate and was decided with the lockout understood: a server whose
operator has not said which group may sign in has not said who may sign in,
and the fail-closed answer to that is nobody.

## 2. Emby stamps the provider onto a user, permanently

Emby's authentication pipeline behaves in ways that are easy to get wrong
and hard to undo. This was confirmed against a live Emby 4.9.5.0 server, not
assumed from documentation:

- **Emby stamps the provider that wins onto the user, permanently.** The
  first time a user signs in successfully, Emby writes that provider's ID
  into the user's `Policy.AuthenticationProviderId` on disk. From then on,
  **only that provider is consulted** for that user. A user who signs in
  through this plugin once can no longer use their Emby password — Emby
  will not even try the default provider for them again. The only way back
  is for an administrator to reset the field via the Emby API.
- **A user with no provider assigned is offered to every enabled provider.**
  If an account's `AuthenticationProviderId` has never been set, Emby tries
  every provider in turn (its own built-in password check first, then this
  plugin) and stamps whichever one succeeds. That would make every unstamped
  Emby account reachable through Authentik the moment this plugin is
  installed — including a newly created administrator that has never logged
  in. **This plugin therefore refuses any existing account that is not
  already assigned to it**, on both sign-in paths, so that adopting an
  account into SSO is always a deliberate action. The log says so:
  `the account has no authentication provider assigned, so this plugin will
  not adopt it`. Note that Emby still *offers* those accounts to the plugin —
  it is the plugin that says no — so this is a guard, not a reason to skip
  assigning providers deliberately.

**Consequences — do this before you install the plugin:**

1. For every Emby account you do **not** want migrated to SSO, explicitly
   set its authentication provider to the default one first (**Dashboard →
   Users → select the user → Login provider → Default**, or via the API —
   see below for why the dashboard selector doesn't work for
   administrators). Setting it explicitly, even to the value it already
   has, fixes it in place: Emby will no longer try this plugin for that
   account.
2. **Keep at least one administrator account permanently on the default
   provider as a break-glass account.** If Authentik is ever unreachable,
   this is the only account that can still get into Emby.
3. The dashboard's "Login provider" dropdown is only shown for
   **non-administrator** accounts, and only once more than one provider is
   registered. For an administrator account, saving the profile tab in the
   dashboard writes back the dropdown's value even though it's hidden,
   which silently defaults to the built-in provider unless you set it
   deliberately. To assign or fix an administrator's provider, use the API
   directly:

   ```
   POST /emby/Users/{userId}/Policy
   ```

   with the full `UserPolicy` JSON body and
   `"AuthenticationProviderId"` set to either
   `Emby.Server.Implementations.Library.DefaultAuthenticationProvider`
   (built-in password) or `Emby.Sso.Auth.SsoAuthenticationProvider` (this
   plugin).

None of this is a bug in the plugin — it is how Emby's own
`IAuthenticationProvider` pipeline works for every third-party provider,
including this one.

## 3. *Allow plain HTTP (testing only)* switches native sign-in off

Ticking *Allow plain HTTP* and *Allow native apps to sign in with a password*
at the same time is refused: native password sign-in is disabled for as long as
plain HTTP is allowed, and the log says so. This is deliberate, and the
asymmetry between the two paths is the point:

- the **browser** flow's insecure mode risks token substitution, but the user's
  password goes from their own browser to Authentik and this server never sees
  it — so the escape hatch is still honoured there;
- a **direct grant** hands this process every native client's real password and
  re-transmits it. There is no setting combination in which this server will
  put a password on the wire in cleartext.

If you want native sign-in in a lab, give the lab HTTPS. (The plugin also
refuses a token endpoint that is not HTTPS, whichever path is in use, even when
the issuer itself was HTTPS.)

---

## Licensing, in brief

The plugin checks a signed licence key issued for one Emby server, named by
the `ServerId` Emby writes to its log at startup. **The check is entirely
offline**: nothing is contacted when a licence is verified, and a server with
no internet access validates its licence exactly as well as one with it. The
one thing that does use the network is activation — a single call made when an
administrator presses **Activate** on the configuration page, on no sign-in
path whatsoever, and never again.

**An invalid or missing licence refuses new single sign-ons and automatic
account creation, and nothing else.** People already signed in stay signed in;
your own Emby accounts are authenticated by Emby's own provider, so **you
cannot be locked out of your media server by a licensing problem**; nothing is
disabled, deleted or reconfigured.

A licence cannot be revoked — the check is offline, so there is nowhere a
revocation could come from. An expiry date is the only lever. (Retiring a *signing key*
stops every licence it ever signed, all at once; that is the remedy for a leaked
key, not a way to deal with one customer. See
[Rotating and revoking a signing key](docs/site/key-rotation.md).)

**The first activation of a code is not instant.** It answers *"your licence is
being issued"*, and pressing **Activate** again a few minutes later returns the
licence; the code is not spent by the wait. That is because the vendor's licence
service does not hold the key that signs licences — a key that mints a licence
for any Emby server, forever, has no business on a host that answers requests
from the internet. A person signs what has been paid for on a machine that is
kept offline. See [Signing licences offline](docs/site/offline-signing.md).

The licence is an RS256 JWT signed with a private key that never leaves the
vendor. But the plugin ships as a .NET assembly, and **a .NET assembly can be
decompiled and the check removed**; there is no obfuscation here and none is
planned. This raises the cost of casual copying between servers. It is not DRM
and it is not described as DRM anywhere in this repository. The enforceable
part is `LICENSE`, not the code.

Full detail: [Licensing](docs/site/licensing.md) and
[Buying and activating a licence](docs/site/activation.md).

---

## Installing

The shipped artifact is a **single file**, `Emby.Sso.dll`. The current release
and its SHA256 checksum are served by the licence service, at a fixed address
that needs no account and no token:

```
base=https://license.koper.cloud/v1/release
curl -fLO $base/download
curl -fLO $base/download.sha256
mv download Emby.Sso.dll
sha256sum -c download.sha256
```

**Check the checksum before you copy anything onto a server.**

After the first install this is rarely needed: an up-to-date plugin offers its
own **Download and install** button once the vendor publishes a newer build,
and checks that download against the vendor's signature before writing it.

Then:

1. Copy `Emby.Sso.dll` into Emby's `plugins` directory (for example
   `/config/plugins` in the linuxserver.io Docker image), replacing any
   earlier copy.
2. Restart Emby Server.
3. Confirm it loaded: Dashboard → Plugins should list **Authentik SSO**, at
   the version you downloaded. If the number is not the one you just
   installed, the old DLL is still in place and Emby is still running it.

**Install exactly one DLL, and it must be the merged one.** The build produces
`Emby.Sso.dll` by merging (ILRepack) the plugin with its dependencies and
internalizing their types, because Emby ships its own, different copy of
`Microsoft.IdentityModel`. Dropping unmerged dependency DLLs next to the
plugin puts two incompatible assembly identities in one load context and fails
at runtime.

Upgrading is the same three steps — but set *Required group* first, above.

Detail, including what a fresh install must do immediately afterwards:
[Installing and upgrading](docs/site/installing.md).

---

## Building from source

Requires the .NET SDK (matching `netstandard2.0`/`net8.0` tooling).

```
dotnet build -c Release
```

produces the merged, installable plugin at:

```
src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll
```

A build with no version given reports `0.0.0-dev`, deliberately: a DLL you
built yourself should never look like a release in Emby's plugin list. Pass
`-p:Version=1.4.0` to build one that names itself, which is all CI does, with
the version taken from the tag.

```
dotnet test tests/Emby.Sso.Tests
```

runs the protocol test suite — 565 tests, no Emby server or network required.
It compiles the plugin's `Protocol/` layer only, so every decision is under
test while the Emby-facing shell that calls them (`Auth/`, `Api/`) is not,
because those types reference `MediaBrowser.*` and need a running server.
That boundary is why so much of
[What has and has not been verified](docs/site/verification-status.md) is
about how Emby reacts rather than about what the plugin decides.

Releases are made by pushing a tag and nothing else:
[Building from source](docs/site/building.md#cutting-a-release).

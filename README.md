# Emby OIDC SSO Plugin

Lets existing Emby users sign in with an external OpenID Connect provider —
in particular [Authentik](https://goauthentik.io/). Emby has no native OIDC
support; this plugin implements the browser authorization-code flow (with
PKCE) and, optionally, the OIDC direct-grant flow for native apps.

**Out of the box this plugin creates no Emby users.** The Emby account must
already exist, and an administrator must explicitly point that account's
authentication provider at this plugin. There is one optional, off-by-default
path that creates an account — for a user who holds a required Authentik
group, cloned from a template user you nominate. See **Group-gated automatic
account creation** below before you turn it on.

Read the whole of this document — especially the next two sections — before
you install anything.

---

## Upgrading an existing install: set the required group FIRST

Every single sign-on this build performs is gated on an Authentik group, and
**until you name that group the plugin refuses everyone.** Leaving *Required
group* empty does not mean "the group check is off". It means:

- every existing SSO user is refused, including accounts that were signing in
  fine a minute before the upgrade — this is not limited to the new
  account-creation path;
- a browser sign-in is refused at `https://<emby>/emby/Sso/Start` itself,
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

---

## Read this before you install

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

---

## How it works

- **Browser sign-in.** The user opens a bookmarkable URL
  (`https://<emby>/emby/Sso/Start`). The plugin redirects to Authentik,
  Authentik authenticates the user under its own flows (including MFA and
  passkeys), and redirects back to `https://<emby>/emby/Sso/Callback`. The
  plugin validates the response, checks that the username matches an
  existing Emby user, and completes the sign-in — the browser lands
  directly on the Emby home screen with no further clicks.
- **Native apps (phone, TV).** Off by default. When enabled, a native
  client's normal username/password screen is checked against Authentik
  using an OIDC direct grant instead of Emby's local password.
- **No account is created unless you switch that on.** If the username from
  Authentik does not match an existing Emby user, the sign-in is rejected with
  a generic error and nothing is written to the log except the fact that it
  happened — unless automatic account creation is enabled and the identity
  holds the required group, in which case an account is created from your
  template user. See **Group-gated automatic account creation**.
- **Every sign-in is checked against the required group**, whether the account
  is new or years old. Losing the group in Authentik loses Emby access at the
  next sign-in.

There is no button on Emby's login page, and there cannot be one — see
the next section.

**A browser that signs in through SSO gets its own device row.** The
completion page authenticates as an ordinary API client identified as
`Emby Web` with its own generated device ID (stored in that browser's
`localStorage`, separate from the web client's own device ID for the same
browser), so Dashboard → Devices ends up showing **two** "Emby Web" rows for
one browser: the one the web client itself registers on ordinary interactive
login, and this plugin's. They look like duplicates but are not — each
backs a live session. **Do not delete either one as a cleanup step**: deleting
the row this plugin's completion page created revokes the access token it
minted, which signs that browser out of its current SSO session immediately.

**The pages the plugin serves are locked down as hard as they can be.** Every
response it produces — the completion page, the error page, and the redirect to
Authentik, on failure paths as well as successful ones — carries
`X-Frame-Options: DENY`, `Content-Security-Policy` with `frame-ancestors
'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
`Cache-Control: no-store`. The completion page is the one that matters: it holds
a live one-time handoff secret and posts it to Emby's own authentication
endpoint, so it must never be framable or cached. Its policy starts at
`default-src 'none'` and adds back only what the page uses — its own inline
script and style, named by a fresh per-response nonce, and `connect-src 'self'`
— so `unsafe-inline` appears nowhere and an injected script would not run even
if one ever got in. If you put a reverse proxy in front of Emby, do not strip or
weaken these headers.

---

## Starting a sign-in: there is no button on the login page

Emby's web login page renders the "login disclaimer" setting as plain text
(`element.textContent`, not HTML) and loads custom CSS as an external
stylesheet (`<link rel="stylesheet">`), so neither field can execute a
script or render a clickable button. This was confirmed by reading the
shipped Emby 4.9.5.0 client and testing that the server passes both fields
through completely unsanitized to the client — the client itself is what
strips any markup.

So: **users start a sign-in from a bookmarkable URL**, not a button:

```
https://<your-emby-server>/emby/Sso/Start
```

The plugin's configuration page (Dashboard → Plugins → Authentik SSO)
displays this exact URL for your server under "Sign-in URL for users to
bookmark". A convenient way to surface it is to paste that URL as **plain
text** into Emby's own login disclaimer field (Dashboard → Settings →
General → "Login disclaimer") — it will render as visible instructions on
the login screen, just not as a clickable link.

The configuration page has a checkbox labelled "Reserve a sign-in button on
the login page" (`EnableButtonInjection`). It is reserved for a future
release and currently does nothing — leave it as you find it.

---

## Setting up Authentik

1. Create an **OAuth2/OpenID provider** in Authentik.
2. Set its **redirect URI** to exactly the value shown on the plugin's
   configuration page under "Redirect URI to configure in Authentik"
   (`https://<your-emby-server>/emby/Sso/Callback`). It must match exactly
   — scheme, host, and path.
3. Note the **client ID**, and the **client secret** if you configure a
   confidential client (leave the plugin's client secret field empty for a
   public client).
4. The plugin authenticates to the token endpoint using **HTTP Basic**
   (client ID and secret, each percent-encoded per RFC 6749 §2.3.1, then
   base64-encoded in the `Authorization` header) whenever a client secret
   is configured. Make sure the Authentik provider's client authentication
   method is compatible with that.
5. If you plan to enable **native app sign-in** (see below), also create a
   **direct-grant (Resource Owner Password) authentication flow** in
   Authentik and bind it to this provider. Without it, native sign-in will
   fail even with the checkbox enabled.
6. Bind an application to the provider, using scopes that include at least
   `openid`. The plugin defaults to `openid profile email`.
7. **Emit the group list in the ID token.** This plugin allows a sign-in only
   if the token carries the configured groups claim (`groups` by default) and
   that claim contains the required group, so Authentik must be configured to
   include it — in Authentik this is normally a scope mapping bound to the
   provider. If you enable native sign-in, make sure the claim is emitted on
   the **direct-grant** flow too: a token that reaches this plugin without the
   claim is refused, and the user is told only "this account is not set up on
   this server".
8. **Configure Authentik's own failed-login / reputation policy.** This is
   required, not optional — see "Brute-force protection: you need both brakes"
   below.

---

## Installing the plugin

The shipped artifact is a **single file**, `Emby.Sso.dll`. Every release is a
git tag, and the release page carries that one DLL and a SHA256 checksum for
it:

```
https://git.koper.cloud/Graxo/emby-sso/-/releases
```

The same two files have a stable, version-addressed download URL, so an
upgrade is one substitution away:

```
base=https://git.koper.cloud/api/v4/projects/Graxo%2Femby-sso/packages/generic/emby-sso/1.4.0
curl -fLO $base/Emby.Sso.dll
curl -fLO $base/Emby.Sso.dll.sha256
sha256sum -c Emby.Sso.dll.sha256
```

**Check the checksum before you copy anything onto a server.** It is also the
only way to tell two builds of the same version apart if you have been
building locally.

Building from source produces the same file, at
`src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll` — see **Building
from source** below.

Do not install any other DLL from the build output. This file is
deliberately produced by merging (ILRepack) the plugin together with its
dependencies — `Microsoft.IdentityModel.*`, `System.IdentityModel.Tokens.Jwt`
and `Newtonsoft.Json` — and internalizing their types inside `Emby.Sso.dll`
itself. This is not a packaging convenience; it is required. Emby Server
already ships its own copy of `Microsoft.IdentityModel` (version 7.6.2 as
of Emby 4.9.5.0), a different version than the one this plugin builds
against (6.35.0). Dropping unmerged dependency DLLs next to the plugin
would put two incompatible assembly identities in the same load context
and fail at runtime. The merged build was verified on a live Emby 4.9.5.0
server: the merged types resolve out of `Emby.Sso.dll` itself, never
colliding with the server's own copies.

To install:

1. Copy `Emby.Sso.dll` into Emby's `plugins` directory (for example
   `/config/plugins` in the linuxserver.io Docker image), replacing any
   earlier copy.
2. Restart Emby Server.
3. Confirm it loaded: Dashboard → Plugins should list **Authentik SSO**, at
   the version you downloaded. The version shown is the release tag — a
   release built from `v1.4.0` reports `1.4.0`, and a build you made yourself
   reports `0.0.0`. If the number is not the one you just installed, the old
   DLL is still in place and Emby is still running it.

Upgrading is the same three steps, but read **Upgrading an existing install:
set the required group FIRST** at the top of this document before you restart.

---

## Configuring the plugin

Open Dashboard → Plugins → **Authentik SSO** and fill in:

| Field | Notes |
|---|---|
| Issuer URL | e.g. `https://auth.example.com/application/o/emby/`. Every other OIDC endpoint is read from its discovery document. |
| Client ID | from Authentik. |
| Client secret | leave empty for a public client. |
| Scopes | defaults to `openid profile email`. |
| Emby public base URL | the address users reach this server on, e.g. `https://emby.example.com`. Used to build the redirect URI and the post-login redirect. Required — Emby cannot infer this reliably behind a reverse proxy. |
| Username claim | defaults to `preferred_username`, matched case-insensitively against the Emby username. |
| Allow native apps to sign in with a password | off by default — see "Native app sign-in" below. |
| Reserve a sign-in button on the login page | reserved for future use; currently does nothing. |
| Allow plain HTTP | testing only. The browser flow refuses to start over plain HTTP unless this is set — and setting it **disables native password sign-in entirely**, see below. |
| Allow an identity provider on a private or loopback address | off by default. The plugin resolves the identity provider's address before connecting and refuses loopback, private (RFC1918) and CGNAT ranges, so a hostile or mistyped issuer URL cannot make this server fetch from its own network. Tick this if your identity provider genuinely lives on a private address — a self-hosted Authentik at `https://10.0.0.5` or `https://authentik.lan` is a normal setup, not an attack. It is deliberately **separate** from "Allow plain HTTP": an identity provider on a private address with a valid certificate should not have to permit cleartext to be reachable. **Upgrade note:** an existing install whose identity provider resolves to a private address stops working until this is ticked; the log names the address and the rule that refused it. |
| Required group | **the Authentik group a user must hold to sign in.** No default, and leaving it empty refuses every SSO sign-in — read "Upgrading an existing install" above. |
| Groups claim | which claim the group list is read from; defaults to `groups`. Authentik must actually emit it, on the direct-grant flow too if native sign-in is on. |
| Template user | the existing Emby user a newly created account is cloned from. Only used when automatic account creation is on. |
| Automatically create accounts for group holders | off by default. The setting that lets this plugin create Emby users at all. |

After saving, the page displays the exact **redirect URI** to put in
Authentik and the **sign-in URL** to give your users — both computed from
the public base URL you just entered.

---

## Assign each user's authentication provider — required, and easy to miss

**Nothing works until this is done, per user.** Creating a matching
Authentik account and installing the plugin is not enough by itself:

- Dashboard → Users → select the user → **Login provider** → **Authentik
  SSO**. This selector only appears for non-administrator accounts, and
  only once more than one provider is registered (i.e., once this plugin
  is installed).
- For **administrator** accounts, the selector is hidden in the dashboard
  and must be set through the API — see "Read this before you install"
  above for the exact call and the reason the dashboard can't be trusted
  for admins.
- If you skip this step the account cannot sign in through SSO at all: the
  plugin refuses any account not already assigned to it, and the user sees
  the ordinary "This account is not set up on this server."
- Accounts the plugin **creates itself** (see "Group-gated sign-in and
  automatic account creation") are stamped with this plugin as their
  authentication provider at the moment they are created, so this step does
  not apply to them. It applies to every account that existed before.

---

## Each account is bound to one Authentik identity

A username is a display handle: identity providers let people change
`preferred_username`, and reassign a freed-up name to somebody else. The
claim OpenID Connect guarantees is stable and unique for a person is `sub`,
so that is what this plugin actually binds an Emby account to.

- **On an account's first successful SSO sign-in**, the plugin records
  "this Authentik `sub` owns this Emby account" in
  `<Emby data path>/emby-sso/subject-bindings.json`. It is kept there and
  not in the plugin's configuration, because saving the settings page
  rewrites that file wholesale and would destroy the bindings.
- **Afterwards** a different `sub` presenting the same account name is
  refused, and so is a known `sub` presenting a different account name. The
  user sees the usual generic refusal; the server log says which it was and
  that an operator has to decide.
- **The trust-on-first-use window is real.** Until an account has signed in
  once under this build, there is nothing to compare against — whoever signs
  in first establishes the binding. The group gate and the refusal to adopt
  unassigned accounts (above) narrow that window; they do not remove it.
- **If the store cannot be read or written, sign-in fails** rather than
  falling back to matching on the username alone. An unparseable file
  refuses everything until the server is restarted and is never overwritten,
  so it can still be inspected.
- **Renaming an Emby account cuts both ways — edit the store in the same
  maintenance window as the rename.** The store is keyed by account *name*, so
  a rename does not move the row, and two things happen at once:
  - the person who owned the account **is refused**: their `sub` is still
    recorded against the old name, so presenting the new one is "this identity
    belongs to a different account";
  - the account under its **new** name has no row at all, so as far as the
    store is concerned it has never signed in — it is back in the
    trust-on-first-use window, and the next `sub` to present that name adopts
    it, along with its watch history, its policy and its library access.

  What still stands in the way is the group gate and the refusal to adopt an
  account that is not already assigned to this plugin — so claiming a renamed
  account takes an Authentik principal that **holds the required group** and
  can present the new name as its username claim. That is an in-group insider
  and a narrow window, not a stranger off the internet. It is still a window:
  stop Emby, edit that account's `account` field in
  `subject-bindings.json` (or delete just that entry), and restart, as part of
  the same rename — not afterwards. The same applies if you deliberately want
  to hand an account to a different Authentik user. Deleting the whole file
  reopens the trust-on-first-use window for every account at once.
- **The server log names an adoption.** When an identity claims an Emby account
  that already existed and had no binding — the renamed-account case above, and
  every account's first SSO sign-in after this build is installed — the log
  says so at **Error**, naming the account. It is not a failure; it is the one
  moment a silent trust-on-first-use claim is worth reading. An account this
  plugin creates itself does not produce that line.
- **If you rename the Emby account but not the Authentik user** (and automatic
  account creation is on), the next sign-in matches nothing under the old name
  and provisions a **brand-new empty account** under it, leaving the renamed
  one behind. Rename on both sides, in the same window.

Relatedly, **the username claim must be immutable and unique in Authentik.**
`preferred_username` is the default and the right answer. If you configure
`email`, the plugin refuses any token that does not assert
`email_verified` — but the underlying problem stays: many providers let a
user change their own address.

---

## Native app sign-in (direct grant)

**Off by default.** When enabled, native clients (phone apps, TV apps —
anything that only ever sends a raw username and password to Emby, never
a browser redirect) are authenticated by sending that password directly to
Authentik's token endpoint as an OIDC direct grant (Resource Owner
Password Credentials).

Trade-offs to weigh before turning this on:

- **It cannot perform multi-factor authentication.** Any MFA policy
  Authentik enforces on its interactive login flow does not apply to a
  direct grant — the credentials are checked once, synchronously, with no
  redirect and no second factor.
- It requires **a direct-grant authentication flow bound to the provider**
  in Authentik (see "Setting up Authentik" above); without that, enabling
  the checkbox has no effect and sign-in will fail.
- The OAuth 2.1 draft deprecates this grant type generally, for the same
  reason: it requires the client to handle the user's raw password.

Enable it only if you need TV/phone app access badly enough to accept the
loss of MFA on that path. Browser sign-in never uses this grant and is
unaffected either way.

**It is switched off entirely while "Allow plain HTTP (testing only)" is on** —
see "Group-gated sign-in and automatic account creation" below.

---

## Group-gated sign-in and automatic account creation

Two things ship together here, and only one of them is optional.

- **The group gate is not optional.** Every sign-in through this plugin —
  browser or native, brand-new account or one that predates the plugin — is
  allowed only if the identity Authentik returns carries the configured
  *Groups claim* and that claim contains the *Required group*. With no required
  group configured, nobody signs in at all (see "Upgrading an existing
  install" above).
- **Creating accounts is optional and off by default.** With *Automatically
  create accounts for group holders* enabled and a *Template user* named, a
  group holder who has no Emby account gets one, cloned from that template.

### The four settings

| Setting | What it does | Unset / empty |
|---|---|---|
| **Required group** | The Authentik group an identity must carry in the groups claim. Matched ordinal, case-insensitively, after trimming — the same rule usernames use. | **Refuses every SSO sign-in**, existing accounts included. Not a way to switch the gate off. |
| **Groups claim** | The claim the group list is read out of. Defaults to `groups`. Authentik must be configured to emit it — including on the direct-grant flow, if native sign-in is enabled. | Falls back to `groups`. A token that carries no such claim at all is refused, and only the log says why. |
| **Template user** | An existing Emby user whose **policy** — libraries, permissions, everything Emby calls access — is copied onto each account this plugin creates. | Automatic creation refuses; nothing is created. An existing user still signs in normally. |
| **Automatically create accounts for group holders** | Off by default. Turning it on is the act that lets the plugin call Emby's `CreateUser` at all. | No account is ever created; an unknown username is refused exactly as it was before this feature existed. |

### What a created account actually gets

**The template's policy, not Emby's defaults.** This matters more than it
sounds: a brand-new Emby user created by Emby's own defaults has access to
every library. An account created by this plugin has exactly the access its
template has, because the policy is built from the template *before* the
account exists and handed to Emby as a constructor argument — there is no
window in which the account exists with different rights.

So **choose the template deliberately.** Whatever that user can see, every
account provisioned from it can see. The usual answer is to create one
ordinary account with the libraries you want new people to get and nominate
that as the template.

Some things are deliberately **not** inherited, whatever the template says:

- **Administrator.** An administrator template does *not* produce
  administrators. `IsAdministrator` is forced to `false` on both paths, at
  construction. There is no moment at which the new account is an admin.
- **Disabled.** `IsDisabled` is forced to `false`. The template is an
  ordinary, sign-in-able Emby account that exists only to donate a policy, so
  the right thing to do with it is to **disable it** once its library access
  is set — and that must not produce disabled new accounts.
- **The template's own login history.** `InvalidLoginAttemptCount` and
  `LockedOutDate` are reset. They are not policy intent; inheriting them
  would start an account part-way to a lockout, or locked out outright.
- **The profile PIN.** The template's `ProfilePin` is a per-person secret;
  handing every provisioned account a copy of it would be handing them each
  other's. It is cleared.
- **The obsolete local-password switch.** `EnableLocalPassword` (Emby's old
  "easy password" feature) is cleared, because the credential it pairs with is
  not copied — an account would otherwise carry an enabled local-password
  switch with nothing behind it.

The new account is stamped with this plugin as its authentication provider, so
from that point Emby consults only Authentik for it (see "Emby stamps the
provider that wins onto the user, permanently" above).

One cosmetic asymmetry, called out so it is not filed as a bug: the browser
path also copies the template's **display preferences** (`UserConfiguration` —
subtitle mode, resume offsets, view order); the native path's account is
created by Emby itself and gets Emby's defaults for those. Nothing that grants
access differs between the two — the two fields in that structure that are not
preferences, `ProfilePin` and `EnableLocalPassword`, end up identical either
way. Two people provisioned on the same day may simply have different subtitle
defaults depending on which client they first signed in from.

### Losing the group

The gate is re-evaluated on every sign-in, so removing someone from the group
in Authentik removes their Emby access — **at their next sign-in**. It does not
reach back and revoke an Emby access token that was already minted. If you need
someone out *now*, disable their Emby account or delete their device/session in
Dashboard → Devices as well as removing the group.

### Brute-force protection: you need both brakes

Opening the "unknown username" branch means an unauthenticated stranger can
make this server forward a guessed password to Authentik. Emby's own lockout
(`InvalidLoginAttemptCount`) lives on a user policy and therefore cannot help
here — the whole point of this branch is that no such user exists yet. Two
brakes cover it, and **both are required**:

1. **The plugin's own throttle**, automatic and not configurable. It applies to
   the native provisioning branch only — the browser flow never hands this
   server a password to relay, so there is nothing there to brute-force.
   - **A sign-in is refused only because of failures recorded against that same
     username**, inside a **15-minute** window measured from that username's
     first counted failure. Nothing anybody else does can refuse it. A stranger
     spraying invented usernames cannot stop a first-time user who has their
     password right — that is a guarantee with a test behind it, not a hope;
   - the allowance is **10 failures per username**, dropping to **3 per
     username** while more than 100 failures have been counted across all
     usernames in the window (a "surge"). The surge tightens what any one name
     can push at Authentik; it never closes the branch;
   - **failures only**, and a success clears that username's own bucket, so a
     new user who mistypes their password a few times is not locked out by
     their own typos;
   - a refusal by the throttle is **character-identical** to the ordinary
     "this account is not set up on this server" — it must not tell an attacker
     that a name was worth counting. Only the server log says a limit was hit;
   - an attempt that failed because **Authentik could not be reached** is not
     counted, so a provider outage during a mass first sign-in neither locks
     individual newcomers out of their own retries nor raises a surge;
   - configuration mistakes are not counted either — every refusal above is
     decided before anything is sent anywhere;
   - what this deliberately does **not** do is cap the total number of attempts
     the branch may forward in a window. Earlier builds did (100, then the
     branch closed for everyone), and that cap turned out to be a weapon: about
     a hundred requests carrying random usernames — **no valid credential
     needed** — shut first-time sign-in for every real user for 15 minutes,
     exactly during the mass onboarding the branch exists to serve. Any
     aggregate cap is reachable by an unauthenticated stranger, and a reached
     cap is a refusal for whoever asks next, so the cap had to go and brake 2
     below had to become non-negotiable. Per-source rate limiting belongs in
     front of Emby (reverse proxy) — the plugin cannot see a client address at
     all;
   - one consequence to know: an attacker who knows the Authentik username of
     someone **not yet onboarded** can spend that name's allowance and delay
     that one person's first sign-in by up to 15 minutes (3 attempts during a
     surge, 10 otherwise). It affects only that name and clears itself.

2. **Authentik's own failed-login / reputation policy — this is required
   configuration, not optional hardening.** Configure it on the flows this
   plugin uses, the direct-grant flow especially. The plugin's throttle only
   sees attempts that arrive through Emby; Authentik is the only side that sees
   the browser flow's password *at all*, and the only side that can rate-limit
   by source address (an Emby `IAuthenticationProvider` is handed a username
   and a password and nothing else — no request, no headers, no client IP, so
   per-source limiting is not something this plugin can do).

### "Allow plain HTTP (testing only)" switches native sign-in off

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


## Troubleshooting

The plugin logs under the category **`AuthentikSso`**, in Emby's own
server log (Dashboard → Logs, or the log file in Emby's data directory —
`embyserver.txt` on the linuxserver.io image). Diagnostic detail —
exception messages, unreachable-endpoint causes, which validation step
failed — is written there and **only** there, by design. The browser only
ever sees one of a fixed set of short, generic sentences:

| Message shown to the user | What it means | What to check |
|---|---|---|
| "Single sign-on is not configured on this server." | The plugin isn't configured (issuer URL, client ID or base URL missing); or the public base URL isn't HTTPS and plain HTTP hasn't been explicitly allowed; **or no required group is configured**, which refuses everyone; or auto-create is on with no template user; or the identity provider resolves to a private or loopback address and that has not been allowed. | Dashboard → Plugins → Authentik SSO: all required fields set, **including "Required group"**. The log distinguishes these — `no required group is configured` is the lockout described at the top of this document. If testing over HTTP, enable "Allow plain HTTP" (and note it disables native sign-in). If the log names a refused address, see "Allow an identity provider on a private or loopback address" in the settings table. |
| "The sign-in provider could not be reached." | Authentik's discovery document or token endpoint could not be fetched. | Issuer URL is correct and reachable from the Emby server itself (not just your browser); check DNS/TLS/firewall between Emby and Authentik. |
| "The sign-in provider rejected this sign-in." | Authentik returned an OAuth error on the callback, or an empty/malformed credential was submitted. | Check the Authentik provider/application logs for the same request; confirm the redirect URI matches exactly. |
| "The sign-in response could not be verified." | The ID token failed validation — bad signature, wrong issuer, wrong audience, expired, or a nonce mismatch. | Server clocks in sync (Emby and Authentik); client ID matches the token's audience; issuer URL matches the token's `iss` exactly. |
| "This sign-in attempt expired. Please try again." | The `state` value on the callback was unknown, already used, or too old (single-use, short TTL). | Usually a stale bookmark/back-button reuse — just start over from the sign-in URL. If it happens consistently, check for a reverse proxy caching or replaying the callback request. |
| "This account is not set up on this server." | Deliberately indistinguishable to the user, and now one of several things: the username claim matched no existing Emby user and automatic creation is off; the token carried no groups claim; the identity did not hold the required group; the provisioning throttle is closed for that username; **the account is not assigned to this plugin as its login provider**; or **the identity does not match the `sub` the account is bound to, or the binding store could not be read or written**. | **Only the log tells them apart** — it says which, naming the configured claim rather than any group value. Then: confirm the Emby account exists (or that auto-create and a template user are configured); confirm Authentik emits the groups claim on the flow in use, direct grant included; confirm the user is in the required group; if the log says the throttle is closed, wait out the 15-minute window. |
| "Password sign-in is disabled for this account." | A native app tried to sign in via direct grant, but either "Allow native apps to sign in with a password" is off, **or "Allow plain HTTP (testing only)" is on**, which disables native password sign-in entirely. The user-facing sentence is the same for both; the log says which. | Enable native sign-in in the plugin configuration if you want it, understanding the MFA trade-off above. If the log names plain HTTP, turn that off and serve the plugin over HTTPS — this server will not relay a password in cleartext. |
| "This sign-in could not be completed in this browser. Please try signing in again." | `/emby/Sso/Start` sets a short-lived binding cookie that must come back unchanged on `/emby/Sso/Callback`. A reverse proxy sitting in front of Emby stripped or rewrote cookies on that path, or rewrote the path so the cookie's `Path` no longer covers `/emby/Sso/Callback`. | Check the log line next to this error: it distinguishes no cookie presented at all from a cookie that was presented but did not match. Confirm the proxy forwards the `Cookie` and `Set-Cookie` headers unmodified on both `/emby/Sso/Start` and `/emby/Sso/Callback`, and that it does not rewrite either path in a way that changes the cookie's directory. |

**Note:** If the plugin's settings page renders oddly right after an update (for example, as an overlay on top of the plugin catalog instead of replacing the view), reload the Emby dashboard in your browser — Emby caches configuration pages, and the old version may still be in the browser's cache.

If a user reports being unable to sign in with their old Emby password
after using SSO once, that is expected — see "Emby stamps the provider...
permanently" above. An administrator must reset that user's
`AuthenticationProviderId` via `POST /emby/Users/{userId}/Policy`.

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
built yourself should never look like a release in Emby's plugin list. To
build one that names itself, pass the version in:

```
dotnet build -c Release -p:Version=1.4.0
```

That is all CI does — with the version taken from the tag.

Run the protocol test suite (203 tests, no Emby server or network required —
they run against a fake identity provider built from a locally generated
RSA key). Note what it does and does not cover: the suite compiles the
plugin's `Protocol/` layer only, so every decision — the group gate, the
ordered provisioning preconditions, the throttle, token validation — is under
test, while the Emby-facing shell that calls them (`Auth/`, `Api/`) is not,
because those types reference `MediaBrowser.*` and need a running server:

```
dotnet test tests/Emby.Sso.Tests
```

---

## Cutting a release

Releases are made by pushing a tag. There is nothing to build by hand and
nothing to upload.

```
git tag -a v1.4.0 -m "What changed in this release."
git push origin v1.4.0
```

The tag pipeline in `.gitlab-ci.yml` then, in order:

1. runs the test suite. Every later job hangs off it through `needs:`, so a
   tag cannot produce a release with a red suite behind it;
2. builds `-c Release` with `-p:Version=1.4.0`, derived from the tag by
   `ci/version.sh`. A tag that is not `vMAJOR.MINOR.PATCH` — optionally with a
   `-rc.1`-style suffix — fails the build instead of quietly shipping
   something;
3. checks the artifact with `ci/verify-artifact.sh` before it leaves the job.
   The file must be over a megabyte, because the merged DLL is ~1.8 MB and the
   unmerged one one directory away is ~108 KB, and it must carry
   `1.4.0+<commit>` as its assembly informational version, which shows both
   that the tag's version reached the assembly and that this file came from
   this build;
4. uploads the DLL and its `.sha256` to the project's generic package registry
   under `emby-sso/1.4.0/`, which is what gives them a permanent download URL;
5. creates the GitLab Release for the tag, linking both files as assets and
   describing it with notes generated from the tag's own message and the
   checksum.

Write the annotated tag's message for the operator who will read it on the
release page: it becomes the release notes' "What changed" section.

An untagged push runs steps 1–3 only, and versions the build
`0.0.0-dev.<short sha>`.

---

## What hasn't been verified end-to-end

The plugin's callback page (`/emby/Sso/Callback`) finishes a browser
sign-in by writing an access token directly into the Emby web client's
`localStorage` credential store (key `servercredentials3`), in the exact
shape that store's own code produces, so the browser lands on the Emby
home screen without a second login step. That shape was determined by
reading Emby 4.9.5.0's shipped client JavaScript and verified end-to-end
against a live server with `curl` — the authentication call, the token,
and the token's acceptance by Emby's API were all directly observed. **The
one thing that was not observed is the browser/`localStorage` behavior
itself** — no browser was available in the environment where this was
tested.

### Group gating and automatic account creation: not exercised on a live server

Everything in "Group-gated sign-in and automatic account creation" above is
**built and unit-tested, but has never run inside Emby.** At the time of
writing this build is installed on no server and no Authentik provider is
configured for it. What that means concretely:

- The decisions are covered by the automated suite: which identities the gate
  admits, that an unset required group refuses before any credential is
  forwarded, the order of the provisioning preconditions, the throttle's
  buckets and windows, and ID-token validation.
- How Emby *reacts* to them is reasoned from decompiling Emby's own assemblies
  (4.9.5.0 as running, 4.9.1.90 reference assemblies) rather than observed.
  That includes how an account created through the native path is finished off
  by Emby, what a native client sees when the plugin refuses, and whether a
  refused creation can leave a half-made account behind. The reasoning is
  documented and, where it is inference rather than measurement, labelled as
  such.
- The full checklist of what remains unverified, and the steps to verify it
  once an Authentik provider and a plugin install are available, is in
  `docs/superpowers/verification/2026-08-30-group-gated-provisioning-verification.md`.

Treat the first real sign-in on a new install as a test: do it with a
throwaway account that holds the group, with the server log open, before you
tell your users anything has changed.

**On first sign-in, check that you land on the Emby home screen, not the
login screen.** If you land on the login screen instead, the most likely
causes, in order, are: the plugin's public base URL not matching the
address your browser actually uses (reverse-proxy sub-paths are the usual
culprit), or a future Emby client update changing the credential store's
key or shape. Either way, sign-in through the plugin still completes on
the server side — the account is not locked out — it's only the automatic
hand-off into the already-signed-in home screen that would need a second
look.

### The release pipeline has not published a release yet

No tag has been pushed since the release jobs were written, so the download
URLs above describe what the pipeline is built to produce rather than
something already sitting on the server. What *has* been checked, locally and
outside CI: the version derivation, the merged-artifact check, and the release
notes were run as scripts against a real Release build, and the version in the
tag was confirmed to land in the merged assembly's identity by reading the
DLL's metadata back. What only a real pipeline run can confirm is GitLab's
side of it — that the runner accepts the file, that the package upload and the
Release are created, and that the asset links resolve for someone who is not
signed in. Treat the first tag as a rehearsal: push `v0.1.0`, then download
the DLL from the release page as an anonymous user and check its checksum
before telling anyone the link exists.

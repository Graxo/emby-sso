# Troubleshooting

Search this page for the exact sentence the user was shown. Each one has its
own section below.

## Where the detail is

The plugin logs under the category **`AuthentikSso`**, in Emby's own server log
— Dashboard → Logs, or the log file in Emby's data directory
(`embyserver.txt` on the linuxserver.io image).

!!! note "Diagnostic detail is written there and only there, by design"

    Exception messages, unreachable-endpoint causes, which validation step
    failed — all of it is in the log. The browser only ever sees one of a fixed
    set of short, generic sentences, because a refusal must not tell a stranger
    which of several reasons applied.

    **In almost every case below, only the log tells the causes apart.** Open it
    before you start guessing.

## The seven sentences

| What the user saw | Jump to |
|---|---|
| Single sign-on is not configured on this server. | [→](#single-sign-on-is-not-configured-on-this-server) |
| The sign-in provider could not be reached. | [→](#the-sign-in-provider-could-not-be-reached) |
| The sign-in provider rejected this sign-in. | [→](#the-sign-in-provider-rejected-this-sign-in) |
| The sign-in response could not be verified. | [→](#the-sign-in-response-could-not-be-verified) |
| This sign-in attempt expired. Please try again. | [→](#this-sign-in-attempt-expired-please-try-again) |
| This account is not set up on this server. | [→](#this-account-is-not-set-up-on-this-server) |
| Password sign-in is disabled for this account. | [→](#password-sign-in-is-disabled-for-this-account) |
| This sign-in could not be completed in this browser. Please try signing in again. | [→](#this-sign-in-could-not-be-completed-in-this-browser-please-try-signing-in-again) |

A licensing refusal is the one exception to the vagueness rule: it says it is a
licensing problem. See [Licensing](licensing.md#what-the-log-tells-you).

---

## Single sign-on is not configured on this server.

**What it means.** One of:

- the plugin is not configured — issuer URL, client ID or base URL missing;
- the public base URL is not HTTPS and plain HTTP has not been explicitly
  allowed;
- **no required group is configured**, which refuses everyone;
- auto-create is on with no template user;
- the identity provider resolves to a private or loopback address and that has
  not been allowed.

**What to check.** Dashboard → Plugins → Authentik SSO: all required fields set,
**including [Required group](settings.md#required-group)**.

!!! danger "`no required group is configured` in the log is the lockout"

    ```
    SSO: refusing to start sign-in: no required group is configured, so the callback could only refuse
    Rejecting sign-in for <user> without contacting the provider: no required group is configured
    ```

    This refuses every user, including ones who were signing in fine before an
    upgrade. See
    [the required-group lockout](before-you-install.md#the-required-group-lockout).

If you are testing over HTTP, enable
[Allow plain HTTP](settings.md#allow-plain-http-testing-only) — and note it
disables native password sign-in.

If the log names a refused address, see
[Allow an identity provider on a private or loopback address](settings.md#allow-an-identity-provider-on-a-private-or-loopback-address).

---

## The sign-in provider could not be reached.

**What it means.** Authentik's discovery document or token endpoint could not be
fetched.

**What to check.** The [issuer URL](settings.md#issuer-url) is correct and
reachable **from the Emby server itself**, not just from your browser. Check
DNS, TLS and firewall between Emby and Authentik.

!!! tip "An attempt that failed this way is not charged to the throttle"

    A provider outage during a mass first sign-in does not lock individual
    newcomers out of their own retries, and does not raise a surge. See
    [Brute-force protection](brute-force-protection.md).

---

## The sign-in provider rejected this sign-in.

**What it means.** Authentik returned an OAuth error on the callback, or an
empty/malformed credential was submitted.

**What to check.** The Authentik provider/application logs for the same request.
Confirm the [redirect URI](authentik.md#2-set-the-redirect-uri-exactly) matches
exactly — scheme, host and path.

If this is a native app: Authentik will not accept an ordinary account password
on a direct grant, only an app password token —
[read this](native-apps.md#what-authentik-accepts-as-the-password).

---

## The sign-in response could not be verified.

**What it means.** The ID token failed validation — bad signature, wrong issuer,
wrong audience, expired, or a nonce mismatch.

**What to check.**

- Server clocks in sync, on both Emby and Authentik.
- [Client ID](settings.md#client-id) matches the token's audience.
- [Issuer URL](settings.md#issuer-url) matches the token's `iss` **exactly**.

---

## This sign-in attempt expired. Please try again.

**What it means.** The `state` value on the callback was unknown, already used,
or too old. It is single-use with a short TTL.

**What to check.** Usually a stale bookmark or back-button reuse — just start
over from the sign-in URL.

If it happens consistently, check for a reverse proxy caching or replaying the
callback request.

---

## This account is not set up on this server.

Deliberately indistinguishable to the user, and it is now one of several things:

- the username claim matched no existing Emby user and automatic creation is
  off;
- the token carried no groups claim;
- the identity did not hold the required group;
- the provisioning throttle is closed for that username;
- **the account is not assigned to this plugin as its login provider**;
- **the identity does not match the `sub` the account is bound to**, or the
  binding store could not be read or written.

!!! warning "Only the log tells them apart"

    It says which — naming the *configured claim* rather than any group value.

**What to check, in order:**

1. Confirm the Emby account exists, or that
   [auto-create and a template user](groups-and-account-creation.md) are
   configured.
2. Confirm Authentik emits the groups claim **on the flow in use, direct grant
   included** — see [step 7](authentik.md#7-emit-the-group-list-in-the-id-token).
3. Confirm the user is in the [required group](settings.md#required-group).
4. Confirm the account's
   [login provider is set to this plugin](login-providers.md). This is the one
   people miss; the plugin refuses any existing account not already assigned to
   it, deliberately.
5. If the log says the throttle is closed, **wait out the 15-minute window** —
   see [Brute-force protection](brute-force-protection.md).
6. If the log talks about a binding, read
   [One Emby account, one Authentik identity](identity-binding.md). A recent
   rename of the Emby account is the usual cause.

---

## Password sign-in is disabled for this account.

**What it means.** A native app tried to sign in via direct grant, but either
[Allow native apps to sign in with a password](settings.md#allow-native-apps-to-sign-in-with-a-password)
is off, **or
[Allow plain HTTP (testing only)](settings.md#allow-plain-http-testing-only) is
on**, which disables native password sign-in entirely.

The user-facing sentence is the same for both; the log says which.

**What to check.** Enable native sign-in in the plugin configuration if you want
it, understanding
[the MFA trade-off](native-apps.md#trade-offs-to-weigh-before-turning-this-on).

If the log names plain HTTP, turn that off and serve the plugin over HTTPS —
this server will not relay a password in cleartext, in any configuration.

---

## This sign-in could not be completed in this browser. Please try signing in again.

**What it means.** `/emby/Sso/Start` sets a short-lived binding cookie that must
come back unchanged on `/emby/Sso/Callback`. A reverse proxy sitting in front of
Emby stripped or rewrote cookies on that path, or rewrote the path so the
cookie's `Path` no longer covers `/emby/Sso/Callback`.

**What to check.**

- The log line next to this error distinguishes **no cookie presented at all**
  from **a cookie that was presented but did not match**.
- Confirm the proxy forwards the `Cookie` and `Set-Cookie` headers unmodified on
  both `/emby/Sso/Start` and `/emby/Sso/Callback`.
- Confirm it does not rewrite either path in a way that changes the cookie's
  directory.

---

## Problems that are not an error message

### A user cannot sign in with their old Emby password after using SSO once

That is expected, not a fault.

!!! danger "Emby stamps the winning provider onto the user permanently"

    An administrator must reset that user's `AuthenticationProviderId` via
    `POST /emby/Users/{userId}/Policy`. See
    [provider stamping](before-you-install.md#emby-stamps-the-provider-permanently)
    for the full call.

### The settings page renders oddly right after an update

For example, as an overlay on top of the plugin catalog instead of replacing the
view.

**Reload the Emby dashboard in your browser.** Emby caches configuration pages,
and the old version may still be in the browser's cache.

If it comes up **blank**, that is a different problem — the plugin's
configuration page markup, not the feature behind it. See
[what has not been verified](verification-status.md#the-configuration-page).

### Sign-in completes but the browser lands on the login screen

The most likely causes, in order:

1. the [Emby public base URL](settings.md#emby-public-base-url) not matching the
   address your browser actually uses — reverse-proxy sub-paths are the usual
   culprit;
2. a future Emby client update changing the credential store's key or shape.

Either way, sign-in through the plugin **still completed on the server side** —
the account is not locked out. It is only the automatic hand-off into the
already-signed-in home screen that would need a second look. See
[what has not been verified there](browser-sign-in.md#what-has-not-been-observed).

### Dashboard → Devices shows two "Emby Web" rows for one browser

Expected, and **do not delete either one**. See
[the device rows](browser-sign-in.md#two-emby-web-device-rows-for-one-browser-and-you-must-not-delete-either).

### Somebody was removed from the group but can still watch

The gate is re-evaluated at the **next** sign-in; it does not revoke an access
token already minted. Disable their Emby account, or delete their device/session
in Dashboard → Devices, as well as removing the group. See
[Losing the group](groups-and-account-creation.md#losing-the-group).

### A user's PIN keeps being destroyed

Somebody who knows their username can send PIN-shaped guesses at it and destroy
each PIN as it is issued, denying **that one person** the PIN route. It affects
nobody else and no other sign-in path — browser sign-in still works. See
[what an attacker can do](pin-sign-in.md#what-an-attacker-can-do-stated-plainly).

### Everything stopped working after an upgrade, and the log names an address

An existing install whose identity provider resolves to a private or loopback
address stops working until
[that is explicitly allowed](settings.md#allow-an-identity-provider-on-a-private-or-loopback-address).
The log names the address and the rule that refused it.

# Every setting, explained

Dashboard → Plugins → **Authentik SSO**.

This page is the long-form home for the plugin's configuration. The settings
form itself should carry one line per field and a link here; everything a field
actually needs explaining lives below.

!!! tip "Deep links are stable"

    Each field has its own anchor, listed below. They are meant to be linked to
    from the configuration page and from support replies, and they will not be
    renamed without a redirect.

| Field on the form | Config id | Link here |
|---|---|---|
| Issuer URL | `issuerUrl` | [#issuer-url](#issuer-url) |
| Client ID | `clientId` | [#client-id](#client-id) |
| Client secret | `clientSecret` | [#client-secret](#client-secret) |
| Scopes | `scopes` | [#scopes](#scopes) |
| Emby public base URL | `embyPublicBaseUrl` | [#emby-public-base-url](#emby-public-base-url) |
| Username claim | `usernameClaim` | [#username-claim](#username-claim) |
| Required group | `requiredGroup` | [#required-group](#required-group) |
| Groups claim | `groupsClaim` | [#groups-claim](#groups-claim) |
| Template user | `templateUserName` | [#template-user](#template-user) |
| Automatically create accounts for group holders | `enableAutoCreate` | [#automatically-create-accounts-for-group-holders](#automatically-create-accounts-for-group-holders) |
| Allow native apps to sign in with a password | `enableDirectGrant` | [#allow-native-apps-to-sign-in-with-a-password](#allow-native-apps-to-sign-in-with-a-password) |
| Allow native apps to sign in with a one-time PIN | `enablePinSignIn` | [#allow-native-apps-to-sign-in-with-a-one-time-pin](#allow-native-apps-to-sign-in-with-a-one-time-pin) |
| Reserve a sign-in button on the login page | `enableButtonInjection` | [#reserve-a-sign-in-button-on-the-login-page](#reserve-a-sign-in-button-on-the-login-page) |
| Allow plain HTTP (testing only) | `allowInsecureHttp` | [#allow-plain-http-testing-only](#allow-plain-http-testing-only) |
| Allow an identity provider on a private or loopback address | `allowPrivateNetworkProvider` | [#allow-an-identity-provider-on-a-private-or-loopback-address](#allow-an-identity-provider-on-a-private-or-loopback-address) |
| Licence key | `licenceKey` | [#licence-key](#licence-key) |

---

## Connecting to Authentik

### Issuer URL

For example `https://auth.example.com/application/o/emby/`.

Every other OIDC endpoint — authorization, token, JWKS — is read from its
discovery document, so this is the only endpoint you configure.

Required. See [Setting up Authentik](authentik.md).

### Client ID

From the Authentik provider.

Required.

### Client secret

Leave empty for a public client.

When a secret is configured, the plugin authenticates to the token endpoint
using **HTTP Basic** — client ID and secret, each percent-encoded per RFC 6749
§2.3.1, then base64-encoded in the `Authorization` header. Make sure the
Authentik provider's client authentication method is compatible with that.

### Scopes

Defaults to `openid profile email`. Must include at least `openid`.

### Emby public base URL

The address users reach this server on, for example `https://emby.example.com`.

Used to build the redirect URI and the post-login redirect. **Required** — Emby
cannot infer this reliably behind a reverse proxy.

!!! warning "Get this wrong and a sign-in completes but lands on the login screen"

    A public base URL that does not match the address the browser actually uses
    — reverse-proxy sub-paths are the usual culprit — is the first thing to
    suspect if a user signs in and ends up back at the login page instead of the
    home screen. The sign-in itself still succeeded on the server side.

After saving, the page displays the exact **redirect URI** to put in Authentik,
the **sign-in URL** to give your users, and the **PIN URL** for users signing in
on a television, all computed from this value.

### Username claim

Defaults to `preferred_username`, matched case-insensitively against the Emby
username.

!!! warning "The username claim must be immutable and unique in your identity provider"

    `preferred_username` is the default and the right answer. If you configure
    `email`, the plugin refuses any token that does not assert `email_verified`
    — but the underlying problem stays: many providers let a user change their
    own address, and a freed-up name can be reassigned.

The account is not actually keyed on this value; it is keyed on the OIDC `sub`.
See [One Emby account, one Authentik identity](identity-binding.md).

---

## Who may sign in

### Required group

**The Authentik group a user must hold to sign in.** Matched ordinal,
case-insensitively, after trimming — the same rule usernames use.

There is **no default**.

!!! danger "Leaving this empty refuses every SSO sign-in, existing accounts included"

    It is not a way to switch the gate off. A browser sign-in is refused at
    `/emby/Sso/Start` before the browser is sent to Authentik; a native sign-in
    is refused before the password is forwarded anywhere. The user sees the
    ordinary "Single sign-on is not configured on this server."; only the log
    says why.

    Read [the required-group lockout](before-you-install.md#the-required-group-lockout)
    before you upgrade an existing install.

### Groups claim

Which claim the group list is read from. Defaults to `groups`.

**Authentik must actually emit it** — in Authentik this is normally a scope
mapping bound to the provider. If native sign-in is on, it must be emitted on
the **direct-grant flow** too.

A token that carries no such claim at all is refused, and only the log says
why — naming the configured claim rather than any group value.

### Template user

The existing Emby user a newly created account is cloned from. Only used when
[automatic account creation](#automatically-create-accounts-for-group-holders)
is on.

!!! warning "Whatever that user can see, every account provisioned from it can see"

    The template's **policy** — libraries, permissions, everything Emby calls
    access — is copied. Choose it deliberately: the usual answer is one ordinary
    account with the libraries you want new people to get, which you then
    disable.

    Administrator, disabled, login history, profile PIN and the obsolete
    local-password switch are deliberately **not** inherited. See
    [what a created account actually gets](groups-and-account-creation.md#what-a-created-account-actually-gets).

Left empty, automatic creation refuses and nothing is created. An existing user
still signs in normally.

### Automatically create accounts for group holders

**Off by default.** Turning it on is the act that lets the plugin call Emby's
`CreateUser` at all.

Off, no account is ever created; an unknown username is refused exactly as it
was before this feature existed.

On, it also opens the branch that forwards a guessed password to Authentik for
a username that does not exist yet — read
[Brute-force protection](brute-force-protection.md), whose second brake is
required configuration.

---

## Native apps

### Allow native apps to sign in with a password

**Off by default.** Authenticates a native client's username and password
against Authentik using an OIDC direct grant.

!!! warning "Authentik will not accept the user's ordinary password here"

    It routes `grant_type=password` through the same machinery as
    `client_credentials` and authenticates the user with an **app password
    token**, which each user creates for themselves under *Settings → Tokens and
    App passwords*. A real account password returns `invalid_grant`.

    A direct grant also **cannot perform multi-factor authentication** at all.

Read [Native apps with a password](native-apps.md) before enabling it.

It is switched off entirely while
[Allow plain HTTP](#allow-plain-http-testing-only) is on.

### Allow native apps to sign in with a one-time PIN

**Off by default, and not governed by the setting above.** Neither turns the
other on; you can run either, both or neither.

The user completes a full browser sign-in on a phone or laptop, is shown an
eight-character PIN, and types their Emby username and that PIN into the TV
app's ordinary sign-in screen. It works with unmodified Emby apps, and it is the
only native route that carries your MFA policy onto a television.

Turning this off stops PINs already issued from being redeemed, as well as
stopping new ones.

Read [Native apps with a one-time PIN](pin-sign-in.md).

### Reserve a sign-in button on the login page

**Reserved for a future release and currently does nothing.** Leave it as you
find it.

There cannot be a button on Emby's login page today —
[here is why](browser-sign-in.md#there-is-no-button-on-the-login-page).

---

## Network and transport

### Allow plain HTTP (testing only)

The browser flow refuses to start over plain HTTP unless this is set.

!!! danger "Setting this disables native password sign-in entirely"

    Ticking this and *Allow native apps to sign in with a password* at the same
    time is refused, and the log says so. The asymmetry is the point: the
    browser flow's password goes from the user's own browser to Authentik and
    this server never sees it; a direct grant hands this process every native
    client's real password and re-transmits it.

    **There is no setting combination in which this server will put a password
    on the wire in cleartext.**

The plugin also refuses a token endpoint that is not HTTPS, whichever path is in
use, even when the issuer itself was HTTPS.

If you want native sign-in in a lab, give the lab HTTPS.

### Allow an identity provider on a private or loopback address

**Off by default.**

The plugin resolves the identity provider's address before connecting and
refuses loopback, private (RFC1918) and CGNAT ranges, so a hostile or mistyped
issuer URL cannot make this server fetch from its own network.

Tick this if your identity provider genuinely lives on a private address — a
self-hosted Authentik at `https://10.0.0.5` or `https://authentik.lan` is a
normal setup, not an attack.

It is deliberately **separate** from *Allow plain HTTP*: an identity provider on
a private address with a valid certificate should not have to permit cleartext
to be reachable.

!!! warning "Upgrade note"

    An existing install whose identity provider resolves to a private address
    **stops working** until this is ticked. The log names the address and the
    rule that refused it.

---

## Licensing

### Licence key

The licence issued for **this** server. Paste it in whole.

Without a valid one, new sign-ons and account creation are refused. Existing
sessions keep working, your own Emby accounts are unaffected, and nothing is
disabled, deleted or reconfigured.

The check is entirely offline: nothing is sent anywhere, and a server with no
internet access validates its licence exactly as well as one with it.

Read [Licensing](licensing.md) for what an invalid licence does and does not
stop, and how to read the log lines it produces.

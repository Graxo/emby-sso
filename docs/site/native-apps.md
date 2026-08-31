# Native apps with a password (direct grant)

**Off by default.** When enabled, native clients — phone apps, TV apps,
anything that only ever sends a raw username and password to Emby, never a
browser redirect — are authenticated by sending that password directly to
Authentik's token endpoint as an OIDC direct grant (Resource Owner Password
Credentials).

!!! tip "There is another way to sign in on a television"

    [A one-time PIN](pin-sign-in.md) works with unmodified Emby apps, keeps
    multi-factor authentication, and needs nothing created in Authentik. It is a
    separate setting; neither turns the other on.

## What Authentik accepts as the password

!!! warning "Not the user's Authentik password"

    This is the single most important thing to know before enabling it, and it
    is not obvious from either project's documentation.

Authentik does not implement the Resource Owner Password Credentials grant as
its own flow. It routes `grant_type=password` through the same code path as
`client_credentials`: the user is *identified* by username and *authenticated*
by an **app password token**. Sending a real account password returns
`invalid_grant`. There is no provider setting that changes this, and no flow to
bind — an earlier version of this documentation said there was, and that was
wrong.

So each user needs a token of their own:

1. Sign in to Authentik, open **Settings → Tokens and App passwords**.
2. **Create** a token with the intent *App password*, and give it an expiry.
3. Copy the value — Authentik shows it once.

In the Emby app, the username is the Authentik username and the password is
that token. Users can do this themselves; no administrator has to issue tokens
or be involved.

Other identity providers differ. Keycloak, for one, implements this grant
against real credentials, and the plugin sends a standards-compliant request
either way — this is an Authentik behaviour, not a plugin limitation.

## Trade-offs to weigh before turning this on

- **It cannot perform multi-factor authentication.** Any MFA policy Authentik
  enforces on its interactive login flow does not apply to a direct grant — the
  credentials are checked once, synchronously, with no redirect and no second
  factor. App passwords are single-factor by design, so this is doubly true
  here.
- **It is a second, weaker credential per user.** An app password is a bearer
  secret that grants library access if it leaks, and it does not expire unless
  the user sets an expiry.
- The OAuth 2.1 draft deprecates this grant type generally, for the same
  reason: it requires the client to handle a raw credential.

Enable it only if you need TV/phone app access badly enough to accept the loss
of MFA on that path. Browser sign-in never uses this grant and is unaffected
either way.

## The groups claim must be emitted on the direct-grant flow too

A token that reaches this plugin without the configured groups claim is
refused, and the user is told only "this account is not set up on this server".
Authentik emits claims per flow; configuring the scope mapping for the
interactive flow does not configure it for the direct grant. See
[Setting up Authentik, step 7](authentik.md#7-emit-the-group-list-in-the-id-token).

## "Allow plain HTTP" switches this off entirely

Ticking *Allow plain HTTP* and *Allow native apps to sign in with a password*
at the same time is refused: native password sign-in is disabled for as long as
plain HTTP is allowed, and the log says so. The user-facing sentence is the
same as the one for the setting simply being off.

This is deliberate, and the asymmetry between the two paths is the point:

- the **browser** flow's insecure mode risks token substitution, but the user's
  password goes from their own browser to Authentik and this server never sees
  it — so the escape hatch is still honoured there;
- a **direct grant** hands this process every native client's real password and
  re-transmits it. **There is no setting combination in which this server will
  put a password on the wire in cleartext.**

If you want native sign-in in a lab, give the lab HTTPS. The plugin also
refuses a token endpoint that is not HTTPS, whichever path is in use, even when
the issuer itself was HTTPS.

## This branch is what needs both brakes

Opening this path — and specifically the "unknown username" branch of it, where
automatic account creation is on — means an unauthenticated stranger can make
this server forward a guessed password to Authentik. Read
[Brute-force protection](brute-force-protection.md); the second brake there is
required configuration, not optional hardening.

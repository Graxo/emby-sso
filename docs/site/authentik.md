# Setting up Authentik

Eight steps. Two of them (the groups claim, and Authentik's own failed-login
policy) are the ones people miss.

## 1. Create an OAuth2/OpenID provider

In Authentik, create an **OAuth2/OpenID provider**.

## 2. Set the redirect URI exactly

Set its **redirect URI** to exactly the value shown on the plugin's
configuration page under "Redirect URI to configure in Authentik":

```
https://<your-emby-server>/emby/Sso/Callback
```

**It must match exactly** — scheme, host, and path.

## 3. Note the client ID and secret

Note the **client ID**, and the **client secret** if you configure a
confidential client. Leave the plugin's
[client secret](settings.md#client-secret) field empty for a public client.

## 4. Match the client authentication method

The plugin authenticates to the token endpoint using **HTTP Basic** — client ID
and secret, each percent-encoded per RFC 6749 §2.3.1, then base64-encoded in
the `Authorization` header — whenever a client secret is configured. Make sure
the Authentik provider's client authentication method is compatible with that.

## 5. If you plan to enable native app sign-in

There is nothing to configure on the provider — but be aware of what Authentik
will accept as the password.

!!! warning "Authentik will not accept the user's ordinary password on a direct grant"

    Authentik does not implement the password grant as a flow you can bind: it
    routes `grant_type=password` through the same machinery as
    `client_credentials`, identifying the user by username and authenticating
    them with an **app password token**. A user's ordinary Authentik password
    will not work.

    Each user creates their own token under *Settings → Tokens and App
    passwords*; no administrator action is needed. See
    [Native apps with a password](native-apps.md).

## 6. Bind an application, with at least the `openid` scope

Bind an application to the provider, using scopes that include at least
`openid`. The plugin defaults to `openid profile email`.

## 7. Emit the group list in the ID token

!!! warning "This is not optional — without it, nobody signs in"

    This plugin allows a sign-in only if the token carries the configured
    [groups claim](settings.md#groups-claim) (`groups` by default) and that
    claim contains the [required group](settings.md#required-group), so
    Authentik must be configured to include it. In Authentik this is normally a
    scope mapping bound to the provider.

    If you enable native sign-in, **make sure the claim is emitted on the
    direct-grant flow too**: a token that reaches this plugin without the claim
    is refused, and the user is told only "this account is not set up on this
    server".

## 8. Configure Authentik's own failed-login / reputation policy

**This is required configuration, not optional hardening.** Configure it on the
flows this plugin uses, the direct-grant flow especially.

The plugin has a throttle of its own, but it only sees attempts that arrive
through Emby. Authentik is the only side that sees the browser flow's password
*at all*, and the only side that can rate-limit by source address. See
[Brute-force protection](brute-force-protection.md) for why both brakes are
required and what each one can and cannot do.

## The URLs the plugin gives you back

After saving the plugin's configuration, the page displays — all computed from
the public base URL you entered:

| Shown as | Value | For |
|---|---|---|
| Redirect URI to configure in Authentik | `https://<emby>/emby/Sso/Callback` | Pasting into the Authentik provider |
| Sign-in URL for users to bookmark | `https://<emby>/emby/Sso/Start` | Giving to your users |
| PIN URL for users to open on a phone or laptop | `https://<emby>/emby/Sso/Pin` | Users signing in on a television |

## Other identity providers

The plugin sends a standards-compliant request on every path, so a provider
other than Authentik may well work. The one place they differ noticeably is the
direct grant: Keycloak, for one, implements it against real credentials, where
Authentik requires an app password token. That is an Authentik behaviour, not a
plugin limitation.

Nothing here has been exercised against a non-Authentik provider.

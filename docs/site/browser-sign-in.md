# Browser sign-in

The main path, and the only one that is on by default.

The user opens a bookmarkable URL. The plugin redirects to Authentik, Authentik
authenticates the user under its own flows — including MFA and passkeys — and
redirects back to the plugin's callback. The plugin validates the response,
checks that the username matches an existing Emby user, checks the group, the
licence and the identity binding, and completes the sign-in. The browser lands
directly on the Emby home screen with no further clicks.

## There is no button on the login page

**Users start a sign-in from a bookmarkable URL, not a button:**

```
https://<your-emby-server>/sso/start
```

The plugin's configuration page (Dashboard → Plugins → Authentik SSO) displays
this exact URL for your server under "Sign-in URL for users to bookmark".

### Why there cannot be a button

!!! verified "Verified against the shipped Emby 4.9.5.0 client"

    Emby's web login page renders the "login disclaimer" setting as plain text
    (`element.textContent`, not HTML) and loads custom CSS as an external
    stylesheet (`<link rel="stylesheet">`), so neither field can execute a
    script or render a clickable button.

    This was confirmed by reading the shipped Emby 4.9.5.0 client and testing
    that the server passes both fields through completely unsanitized to the
    client — the client itself is what strips any markup.

### How to surface the URL anyway

A convenient way is to paste that URL as **plain text** into Emby's own login
disclaimer field — Dashboard → Settings → General → "Login disclaimer". It will
render as visible instructions on the login screen, just not as a clickable
link.

!!! note "The \"Reserve a sign-in button on the login page\" checkbox does nothing"

    `EnableButtonInjection` is reserved for a future release and currently has
    no effect. Leave it as you find it.

## Two "Emby Web" device rows for one browser, and you must not delete either

The completion page authenticates as an ordinary API client identified as
`Emby Web` with its own generated device ID, stored in that browser's
`localStorage` separately from the web client's own device ID for the same
browser. So Dashboard → Devices ends up showing **two** "Emby Web" rows for one
browser: the one the web client itself registers on ordinary interactive login,
and this plugin's.

!!! danger "They look like duplicates. They are not."

    Each backs a live session. **Do not delete either one as a cleanup step.**
    Deleting the row this plugin's completion page created revokes the access
    token it minted, which signs that browser out of its current SSO session
    immediately.

## The pages the plugin serves are locked down as hard as they can be

Every response the plugin produces — the completion page, the error page, and
the redirect to Authentik, on failure paths as well as successful ones —
carries:

- `X-Frame-Options: DENY`
- `Content-Security-Policy` with `frame-ancestors 'none'`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store`

The completion page is the one that matters: it holds a live one-time handoff
secret and posts it to Emby's own authentication endpoint, so it must never be
framable or cached. Its policy starts at `default-src 'none'` and adds back only
what the page uses — its own inline script and style, named by a fresh
per-response nonce, and `connect-src 'self'` — so `unsafe-inline` appears
nowhere and an injected script would not run even if one ever got in.

!!! warning "If you put a reverse proxy in front of Emby, do not strip or weaken these headers"

## Plain HTTP

The browser flow refuses to start over plain HTTP unless
[Allow plain HTTP](settings.md#allow-plain-http-testing-only) is set. That
escape hatch is honoured here — but not for the direct grant — because the
user's password goes from their own browser to Authentik and this server never
sees it. Setting it **disables native password sign-in entirely**.

## What has not been observed

!!! unverified "The browser's `localStorage` hand-off was never watched in a browser"

    The callback page finishes a browser sign-in by writing an access token
    directly into the Emby web client's `localStorage` credential store (key
    `servercredentials3`), in the exact shape that store's own code produces, so
    the browser lands on the Emby home screen without a second login step.

    That shape was determined by reading Emby 4.9.5.0's shipped client
    JavaScript and **verified end-to-end against a live server with `curl`** —
    the authentication call, the token, and the token's acceptance by Emby's API
    were all directly observed. **The one thing that was not observed is the
    browser/`localStorage` behavior itself** — no browser was available in the
    environment where this was tested.

    If a first sign-in lands on the login screen rather than the home screen,
    this is the thing to suspect second, after the public base URL. Sign-in
    still completed on the server side either way; only the hand-off failed.

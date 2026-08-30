# Emby OIDC SSO Plugin — Design

Date: 2026-08-30
Status: Approved for planning

## Purpose

Let Emby users sign in with their Authentik accounts. Emby has no native
OpenID Connect support and no third-party OIDC plugin exists; the common
workaround is Authentik's LDAP outpost with Emby's LDAP plugin. This plugin
replaces that workaround with a real OIDC integration.

## Scope

In scope:

- Browser single sign-on via OIDC authorization code flow with PKCE.
- Native-client login (Android, iOS, Roku, TV) via OIDC direct grant.
- An admin configuration page in the Emby dashboard.

Out of scope:

- Creating Emby users. Users are pre-created by the administrator.
- SAML, LDAP, or any protocol other than OIDC.
- Group-to-permission mapping. Emby's own user settings govern permissions.
- Single logout.

## Decisions

| Decision | Choice | Reason |
|---|---|---|
| Client coverage | Browser and native apps | Users must reach Emby from TV and phone apps, which only ever send a username and password. |
| Provisioning | Never auto-create | The administrator pre-creates Emby users; the Emby user list is the access control list. |
| Identity match | `preferred_username` claim, case-insensitive | Predictable, and keeps native login natural because the user types the same name in both systems. |
| Native credential check | OIDC direct grant (ROPC) | One protocol and one Authentik provider. Accepts that this path cannot do MFA. |
| Browser entry point | Bookmarkable URL, plus an injected button | The URL always works; the button is an enhancement that degrades gracefully. |
| Session handoff | One-time secret through Emby's own login form | Emby issues the session through its supported path. No internal session API and no undocumented storage format. |

A required-group gate was considered and cut. With auto-creation off, a group
check would be a second place to revoke access and a second place to forget to.

## Architecture

A single `netstandard2.0` assembly, `Emby.Sso.dll`, installed into Emby's
plugins directory. It targets the `MediaBrowser.Server.Core` reference
assemblies (4.9.x at time of writing).

The assembly separates protocol logic that knows nothing about Emby from a
thin shell that does. The protocol components carry the security-critical
logic and are unit-testable with no Emby server present.

| Component | Responsibility | Depends on |
|---|---|---|
| `OidcClient` | Discovery document with caching, authorization URL with PKCE, code exchange, ID token validation against JWKS, direct grant | HTTP only |
| `PendingLoginStore` | Maps `state` to nonce, PKCE verifier and return URL. Single-use, short TTL | Nothing |
| `HandoffSecretStore` | Maps a one-time secret to a username. Single-use, 30 second TTL, constant-time comparison | Nothing |
| `UserResolver` | Resolves the username claim to an existing Emby user; rejects unknown users | `IUserManager` |
| `SsoAuthenticationProvider` | Emby's `IAuthenticationProvider`. For a given username and password, checks the handoff store first, then falls back to direct grant | Emby, the above |
| `SsoService` | `IService` endpoints `/Sso/Start`, `/Sso/Callback`, `/Sso/Script.js` | Emby, the above |
| `Plugin`, `PluginConfiguration` | `BasePlugin<T>` and `IHasWebPages`; the admin configuration page | Emby |

`SsoAuthenticationProvider` is the single point Emby calls for both flows.
Given a username and password it first asks `HandoffSecretStore` whether the
password is a live one-time secret; if not, it treats the value as a real
password and forwards it to Authentik as a direct grant. Both paths then
resolve the user through `UserResolver`, so authorization behaves identically
whichever client the user came from.

## Browser flow

1. The user opens `/emby/Sso/Start`, by link or by the injected button.
2. The plugin generates `state`, `nonce` and a PKCE verifier, stores them in
   `PendingLoginStore`, and redirects to Authentik's authorization endpoint.
3. Authentik authenticates the user under its own flows, including MFA and
   passkeys, and redirects to `/emby/Sso/Callback`.
4. The plugin validates and consumes `state`, exchanges the code using the
   PKCE verifier, and validates the ID token: JWKS signature, `iss`, `aud`,
   `exp` and `iat` within a small clock skew, and `nonce`.
5. `UserResolver` matches the username claim against existing Emby users. If
   there is no match the flow stops with an error; no user is created.
6. The plugin mints a one-time secret bound to that username and redirects to
   Emby's login page with the username and secret in the URL fragment.
7. The injected script reads the fragment, clears it from the address bar, and
   submits Emby's ordinary login form.
8. Emby's authentication pipeline calls `SsoAuthenticationProvider`, which
   consumes the secret and approves the login. Emby issues the session.

The secret travels in a fragment, which browsers do not send to servers, so it
appears in no server log and no proxy log.

## Native flow

A native client sends a username and password to Emby as usual. Emby calls
`SsoAuthenticationProvider`. No handoff secret matches, so the plugin performs
an OIDC direct grant against Authentik's token endpoint with the supplied
credentials. On success it resolves the user exactly as the browser flow does.

This path cannot perform MFA, and the OAuth 2.1 draft deprecates the grant. It
is therefore disabled by default and labelled as such in the configuration UI.
It requires a direct-grant authentication flow bound to the OIDC provider in
Authentik.

## Configuration

Exposed on the plugin's dashboard page:

- Issuer URL, for example `https://auth.example.com/application/o/emby/`.
  Endpoints are read from the discovery document.
- Client ID and client secret.
- Scopes, defaulting to `openid profile email`.
- Emby public base URL. Required, because the redirect URI and the post-login
  redirect cannot be inferred reliably behind a reverse proxy.
- Username claim, defaulting to `preferred_username`.
- Enable native login via direct grant. Off by default.
- Enable login page button injection, with the equivalent snippet displayed
  for manual pasting into Emby's branding settings if the automatic hook is
  unavailable.

Configuration errors, such as an unreachable issuer, surface on the settings
page rather than only at login time.

## Security requirements

- PKCE S256 on every browser flow.
- `state` and `nonce` generated from a cryptographically secure RNG, each
  single-use and verified.
- Full ID token validation: JWKS signature, `iss`, `aud`, `exp` and `iat` with
  a small permitted clock skew, and `nonce`. Receiving a token from the
  expected URL is not treated as evidence of validity.
- Handoff secrets are 256 bits, single-use, expire after 30 seconds, are bound
  to one username, and are compared in constant time.
- The client secret and all tokens are excluded from logs. Failures log a
  reason, never a credential.
- The browser flow refuses plaintext HTTP unless explicitly overridden for
  local testing.
- Redirect targets are restricted to the configured Emby base URL, so the
  endpoints cannot be used as an open redirect.

## Error handling

Every failure ends at a plain error page reading "Sign-in failed" with a short
reason and a link back to the normal login page. Detail — unknown user,
expired or replayed state, unreachable discovery endpoint, rejected code — goes
to the Emby log and activity log rather than to the browser.

Discovery failures are cached with backoff so that a momentarily unreachable
Authentik does not produce a request storm.

## Testing

Test-driven, using xUnit.

The protocol components are tested against a fake identity provider built from
a locally generated RSA key, with hand-minted JWKS documents and ID tokens.
This covers the negative cases that matter: invalid signature, expired token,
wrong audience, wrong issuer, mismatched nonce, replayed state, replayed
handoff secret, and expired handoff secret. These tests require no network and
no Emby server.

The Emby-facing shell is kept thin enough to verify manually against a test
server: browser login succeeds, native login succeeds, an unknown user is
rejected, and a replayed handoff secret is rejected.

## Build and repository layout

```
src/Emby.Sso/            plugin assembly
tests/Emby.Sso.Tests/    xUnit tests
docs/superpowers/specs/  design documents
.gitlab-ci.yml           builds and publishes the DLL as an artifact
```

The .NET SDK is installed on the development machine. `dotnet build` produces
the DLL, which is copied to a test Emby server for verification.

## Risks and the opening spike

Two assumptions can only be confirmed against the real reference assemblies
and a running server. Phase 0 of implementation is a spike that settles both
before any plugin code is written.

1. **Does Emby call a third-party `IAuthenticationProvider`?** The LDAP plugin
   that implements this interface is first-party. If Emby's pipeline ignores
   external providers, both the handoff and the native flow are impossible as
   designed, and the design returns for revision rather than proceeding.
2. **Does Emby's branding hook permit script injection?** If scripts are
   stripped, the injected button is unavailable and users reach the flow
   through the bookmarkable URL. This degrades the experience without blocking
   the feature.

A third, lesser uncertainty is the exact route prefix Emby applies to plugin
`IService` endpoints; the spike confirms it.

# Troubleshooting

## Start with the log

Users only ever see a short, vague message — on purpose, so a stranger cannot
learn whether an account exists. The real reason is always in Emby's server
log:

- **Dashboard → Logs**, open the current server log, and search for
  `AuthentikSso` (or `SSO`).
- Or the `embyserver.txt` file in Emby's `logs` folder.

Reproduce the problem, then read the lines logged at that moment. Most lines
start with `SSO:` or `Rejecting sign-in` / `Rejected sign-in` and say exactly
which check failed.

## Quick checklist

Most problems are one of these:

1. **Required group** is set in the plugin, and the user is in that group in
   Authentik.
2. The user's Emby account has its **login provider set to Authentik SSO**
   ([Setup, step 6](setup.md#6-move-accounts-to-sso)).
3. The Emby username matches the user's Authentik username.
4. The **redirect URI** in Authentik is exactly the one on the plugin's
   settings page.
5. The **Emby public URL** is exactly the address users type in the browser.
6. The licence section of the settings page says **Active**.
7. If Authentik is on a private/LAN address, **Allow an identity provider on a
   private network** is ticked.

## By message

### "Single sign-on is not configured on this server."

The plugin's configuration is incomplete or refuses to run. Look for a log line
starting with `SSO: refusing to start sign-in:` or `Rejecting sign-in:`.

| Log says | Fix |
|---|---|
| `no required group is configured` | Set **Required group**. Until you do, everybody is refused. |
| `the public base URL is not HTTPS` / `the issuer URL is not HTTPS` | Use HTTPS, or tick *Allow plain HTTP* for testing. |
| `auto-create is on but no template user is configured` | Set **Template user**, or turn off automatic account creation. |
| `the configured template user '…' does not exist` | Fix the template user's name. |
| An address and the rule that refused it (loopback / private / carrier-grade NAT) | Tick **Allow an identity provider on a private network**. |

Also check that Issuer URL, Client ID and Emby public URL are filled in.

### "Single sign-on is unavailable: this server's SSO plugin licence is missing, invalid or expired."

The licence is not valid. The settings page shows why. See
[Licensing](licensing.md#when-the-licence-is-missing-expired-or-invalid).

### "The sign-in provider could not be reached."

Emby could not fetch Authentik's discovery document, keys or token endpoint.
Test **from the Emby server (or container)**, not from your own machine:

```bash
curl -v https://<authentik>/application/o/<slug>/.well-known/openid-configuration
```

Check DNS, TLS certificates (Emby must trust Authentik's certificate) and
firewalls between Emby and Authentik. Make sure the issuer URL ends with the
application slug and a `/`.

### "The sign-in provider rejected this sign-in."

Authentik returned an error. The log line `SSO: the provider returned an error
parameter: …` shows which; Authentik's own event log (**Events → Logs**) shows
more.

- `invalid_grant` on a native app: the user used their normal password. They
  need an Authentik **app password** — or use [PIN sign-in](pin-sign-in.md).
- Redirect URI errors at Authentik: the redirect URI in Authentik does not
  exactly match the one on the plugin's settings page.
- `access_denied`: the user is not allowed to use the application in Authentik
  (check the application's policy bindings).
- Client authentication errors: client ID or secret wrong, or a public client
  configured with a secret in the plugin (or the other way round).

### "The sign-in response could not be verified."

Authentik's token failed validation. Check:

- The clocks on the Emby and Authentik servers are correct.
- **Issuer URL** matches the issuer Authentik reports exactly (including the
  trailing `/`).
- **Client ID** is the one of this provider.

### "This sign-in attempt expired. Please try again."

The sign-in took too long, or the callback was opened twice (back button, an
old bookmark of the callback page). Start again from `/sso/start`. If it always
happens, check that your reverse proxy does not cache or replay requests to
`/sso/callback`.

### "This sign-in could not be completed in this browser. Please try signing in again."

The cookie set by `/sso/start` did not come back on `/sso/callback`. Usually a
reverse proxy stripping cookies or rewriting paths, or the sign-in started on
one address (e.g. `http://` or a LAN IP) and returned on another. Make sure
users start from the exact sign-in URL on the settings page, and that the
proxy passes `Cookie` / `Set-Cookie` through on `/sso/`.

### "This account is not set up on this server."

The most common message. It covers several cases; the log says which:

| Log says | Fix |
|---|---|
| `the account has no authentication provider assigned` | Set the account's login provider to Authentik SSO ([Setup, step 6](setup.md#6-move-accounts-to-sso)). |
| `no Emby user named '…'` / `no matching Emby user and auto-create is off` | Create the Emby account with the same username, or turn on automatic account creation. Check the *Username claim*. |
| `required group not held` | Add the user to the required group in Authentik. |
| `the token carried no 'groups' claim` | Authentik is not sending a `groups` claim. Check the scope mappings on the provider and that *Scopes* includes `profile`. |
| `already bound to a different Emby account` / `already bound to a different identity provider subject` | The account belongs to another Authentik user, usually after a rename. See [identity binding](how-it-works.md#one-emby-account-one-authentik-user). |
| `the provisioning throttle is closed` | Too many failed attempts for this username. Wait 15 minutes. |

### "Password sign-in is disabled for this account."

A native app tried to sign in with a password, but **Allow native apps to sign
in with a password** is off, or **Allow plain HTTP** is on (which turns it
off). Turn on the setting, or use [PIN sign-in](pin-sign-in.md) instead.

### "PIN sign-in is not enabled on this server."

Tick **Allow native apps to sign in with a one-time PIN**.

## Other problems

### The user signs in but ends up on Emby's login screen

The sign-in worked on the server, but the browser was sent to the wrong
address. **Emby public URL** must be exactly what users use, including
`https://`, the host name, the port and any sub-path.

### The user can no longer use their Emby password

Expected: once an account's login provider is Authentik SSO, Emby only asks
Authentik. To move the account back, set its provider to *Default*
([Setup, step 6](setup.md#6-move-accounts-to-sso)).

### I locked myself out of the dashboard

Sign in with an administrator that is still on Emby's own password — this is
why you keep one. A browser or app that is still signed in also keeps working.

If the lockout is caused by the plugin's configuration (for example an empty
*Required group*), stop Emby, fix the value in
`plugins/configurations/Emby.Sso.xml`, and start Emby again.

### Someone removed from the group can still watch

The group is checked at sign-in, not during a session. Disable their Emby
account or delete their device under **Dashboard → Devices**.

### Two "Emby Web" devices for one browser

Expected. The plugin's sign-in registers its own device entry next to the web
client's. Deleting either one signs that browser out.

### The settings page looks wrong or is blank after an update

Reload the dashboard in your browser (it caches plugin pages). If it stays
blank, check that only one `Emby.Sso.dll` is in the `plugins` folder and that
the version under **Dashboard → Plugins** is the one you installed.

### The plugin does not appear under Dashboard → Plugins

Check that `Emby.Sso.dll` is in the right `plugins` folder, that Emby was
restarted, and that you copied only that one file. Look for `Emby.Sso` in the
server log at startup for a load error.

### Nothing happens when I press "Download and install"

Read the message under the button and the `SSO update:` lines in the log. You
can always [update by hand](setup.md#updating).

## Asking for help

Email <support@koper.cloud> with:

- the message the user saw,
- the `AuthentikSso` lines from the log around that time,
- the plugin version and Emby version.

Never send your redemption code or client secret.

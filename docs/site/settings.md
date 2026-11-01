# Settings reference

Everything on **Dashboard → Plugins → Authentik SSO**, top to bottom. The
settings are stored in `plugins/configurations/Emby.Sso.xml`.

## Server information

### Server id

Your Emby server's id. A licence is issued for this id and works on no other
server. It is not a secret; Emby also writes it to its log at startup
(`ServerId`).

### Plugin version

The version that is running. If it does not match the file you just installed,
Emby is still running the old one: check that you replaced the file in the
right `plugins` folder and restarted.

### Update available

Only shown when a newer version has been published. **Download and install**
downloads it, checks it against the vendor's signature, and writes it into the
`plugins` folder. Restart Emby to start using it.

## Licence information

When not licensed, this section shows the problem, a **Buy a licence** link,
the **Redemption code** field and the **Activate** button. When licensed it
shows *Active* with the expiry date, the licence key, and how many activations
of your code are used. See [Licensing](licensing.md).

## URLs

Shown after you have saved the *Emby public URL*.

| Field | Use it for |
|---|---|
| Redirect URI to configure in Authentik | The provider's redirect URI in Authentik. Must match exactly. |
| Sign-in URL for users to bookmark | Give this to your users. |
| PIN URL for users to open on a phone or laptop | For [PIN sign-in](pin-sign-in.md) on TVs. |

## Settings

### Issuer URL

Your provider's issuer, for Authentik
`https://<authentik>/application/o/<slug>/`. The plugin reads every other
address it needs from `<issuer>/.well-known/openid-configuration`. Required.

### Client ID

From the provider in Authentik. Required.

### Client secret

From the provider, for a *Confidential* client. Leave empty for a *Public*
client. The secret is sent with HTTP Basic authentication.

### Scopes

Default `openid profile email`. Must include `openid`, and must include
whatever scope makes Authentik add the groups claim (`profile` by default).

### Emby public URL

The address users reach Emby on, e.g. `https://emby.example.com`, including any
sub-path. Used to build the redirect URI and to send the user back to Emby
after signing in. Required, and must be HTTPS unless *Allow plain HTTP* is
ticked.

If users sign in successfully but end up on Emby's login screen, this value
does not match the address they actually use.

### Username claim

Which token claim is matched against the Emby username (case-insensitive).
Default `preferred_username`. Use a claim that users cannot change themselves.
If you use `email`, tokens without `email_verified: true` are refused.

### Required group

The Authentik group a user must be in to sign in. Compared case-insensitively.

**There is no default, and empty refuses everyone**, including users who signed
in fine before.

### Groups claim

The token claim that holds the user's groups. Default `groups`, which is what
Authentik's default `profile` mapping produces. A token without this claim is
refused.

### Template user

The Emby user whose libraries and permissions are copied to accounts created by
*Automatically create accounts*. Administrator rights and the disabled flag are
never copied, nor is the template's profile PIN. Only used when automatic
creation is on.

### Automatically create accounts for group holders

Off by default. When on, someone in the required group who has no Emby account
gets one on their first sign-in, copied from the *Template user*. Without a
template user, such sign-ins are refused.

### Allow native apps to sign in with a password

Off by default. Lets Emby apps sign in with an Authentik **app password** (not
the user's normal password), checked against Authentik directly. No MFA on this
path. Does nothing while *Allow plain HTTP* is on.

### Allow native apps to sign in with a one-time PIN

Off by default. Lets users get a PIN from the PIN URL and type it as their
password in an Emby app. Independent of the setting above. Turning it off also
invalidates PINs already issued. See [One-time PIN sign-in](pin-sign-in.md).

### Allow plain HTTP (testing only)

Lets the browser sign-in work over `http://`. Turns off app-password sign-in
completely, because that would send passwords in cleartext. The connection to
Authentik's token endpoint must be HTTPS regardless.

### Allow an identity provider on a private network

Off by default. The plugin refuses to connect to loopback (`127.0.0.0/8`,
`::1`), private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`) and
carrier-grade NAT (`100.64/10`) addresses unless this is ticked. Tick it if
Authentik runs on your LAN. Link-local addresses (`169.254/16`) are always
refused. When something is refused, the log names the address.

## Not on the page

### Activation service address

`ActivationServiceUrl` in `Emby.Sso.xml`. Overrides the licensing service
address (`https://license.koper.cloud`). For testing only; leave empty. Must be
HTTPS. A licence returned by another service is still checked against the
vendor's key, so this cannot be used to make up a licence.

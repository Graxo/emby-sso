# How it works

## The pieces

The plugin is one file, `Emby.Sso.dll`, that you drop into Emby's `plugins`
folder. It adds three things to Emby:

| Address | What it is for |
|---|---|
| `https://<emby>/sso/start` | Starts a browser sign-in. This is the link you give your users. |
| `https://<emby>/sso/callback` | Where Authentik sends the browser back. You enter this in Authentik as the redirect URI. |
| `https://<emby>/sso/pin` | Gives a user a one-time PIN for signing in on a TV. |

It also registers itself with Emby as a **login provider** called
*Authentik SSO*, next to Emby's own password check.

## Browser sign-in

1. The user opens `/sso/start`. The plugin sets a short-lived cookie and sends
   the browser to Authentik.
2. The user signs in at Authentik, with whatever MFA, passkeys or policies you
   have configured there. Emby never sees their password.
3. Authentik sends the browser to `/sso/callback`. The plugin checks the answer
   (signature, issuer, audience, expiry, the cookie from step 1), then runs the
   [sign-in checks](#the-checks-every-sign-in-goes-through).
4. If everything passes, the plugin signs the user into Emby and the browser
   lands on the Emby home screen.

Emby's own login page cannot show a "Sign in with Authentik" button: the Emby
web client renders the login disclaimer as plain text and does not run custom
scripts there. To make the link easy to find, paste it as plain text into
**Dashboard → Settings → General → Login disclaimer**, and give it to your
users as a bookmark.

## Signing in on TVs and phone apps

Emby's native apps only have a username and a password field. The plugin
offers two ways to use those fields. Both are off by default, and they are
independent of each other.

### One-time PIN (recommended)

The user opens `/sso/pin` on their phone or laptop, signs in there exactly as
in a browser sign-in (MFA included), and gets an eight-character PIN. On the
TV they type their Emby username and the PIN as the password.

A PIN lasts five minutes, works once, and is destroyed after three wrong
entries. It works with the normal Emby apps. See
[One-time PIN sign-in](pin-sign-in.md).

### Authentik app password

The TV app sends the username and password to Emby, and the plugin checks them
against Authentik directly (an OAuth "password grant"). Two catches:

- **Authentik does not accept the user's normal password here.** It only
  accepts an *app password*, which each user creates under **Settings → Tokens
  and App passwords** in Authentik. A normal password gets `invalid_grant`.
- **There is no MFA on this path.** The app password alone is enough.

Prefer the PIN unless you have a reason not to.

## The checks every sign-in goes through

Every sign-in, on every path, has to pass all of these. If any fails, the user
sees a short, deliberately vague message and the server log says exactly which
check failed (see [Troubleshooting](troubleshooting.md)).

1. **The plugin is configured.** Issuer URL, client ID and public URL are set,
   and the addresses are HTTPS (unless you allowed plain HTTP for testing).
2. **A required group is set.** If *Required group* is empty, everybody is
   refused.
3. **The licence is valid** for this Emby server.
4. **The user is in the required group.** Authentik has to put a `groups` claim
   in the token, and the group has to be in it.
5. **The Emby account exists**, matched by username (case-insensitive). If it
   does not exist, the plugin can create it — but only if you turned on
   automatic account creation.
6. **The account is assigned to this plugin** as its login provider. Accounts
   still on Emby's own password check are never taken over.
7. **The account belongs to this Authentik user.** See
   [identity binding](#one-emby-account-one-authentik-user).

The group is checked at every sign-in, so removing someone from the group in
Authentik stops their next sign-in. It does not end sessions that are already
open; to remove someone straight away, also disable their Emby account or
delete their device under **Dashboard → Devices**.

## Login providers, and why your Emby password stops working

Every Emby account has a login provider: Emby's own password check
("Default") or a plugin such as this one. Emby asks **only** that provider when
the account signs in.

- When you set an account's login provider to *Authentik SSO*, its Emby
  password no longer works. The user signs in through Authentik.
- To move an account back, set its login provider back to *Default*.
- Accounts with no provider set at all are left alone by this plugin. It will
  not adopt an account you did not deliberately move.

Keep at least one administrator on *Default*. If Authentik is down or the
plugin is misconfigured, that account is how you get back in.

## Creating accounts automatically

Off by default. When you turn it on and name a *template user*, a person who is
in the required group but has no Emby account gets one on their first sign-in.

- The new account gets the template's libraries and permissions, nothing more.
- It is never an administrator and never disabled, whatever the template is.
  You can (and should) disable the template account itself.
- It is assigned to this plugin straight away.

## One Emby account, one Authentik user

Usernames can change and be reused, so the plugin also remembers which
Authentik user (the token's `sub`) first signed in to each Emby account. After
that, only that Authentik user can sign in to that account.

The record is kept in `<Emby data folder>/emby-sso/subject-bindings.json`.

- **Renaming an Emby account?** Stop Emby, change the account name in that
  file (or delete that one entry), and start Emby again. Otherwise the owner is
  refused under the new name.
- **Giving an account to a different Authentik user?** Delete its entry; the
  next person to sign in to it becomes the owner.
- Do not delete the whole file unless you mean to reset every account: whoever
  signs in first after that becomes the owner.

## Brute-force protection

- **App-password sign-in for unknown usernames** (only possible with automatic
  account creation on) is throttled per username: 10 failures in 15 minutes,
  or 3 when there is a burst of failures overall.
- **PINs** are destroyed after three wrong entries.
- **The plugin cannot see client IP addresses**, so it cannot rate-limit by
  source. Configure Authentik's own failed-login policy (reputation policy) on
  the flows the plugin uses — especially if you allow app-password sign-in —
  and rate-limit in your reverse proxy if you have one.

## The licence, and what talks to the internet

The licence is checked offline, on your server, at every sign-in. Without a
valid licence, **new** SSO sign-ins and account creation are refused. Nothing
else changes: open sessions keep working and Emby's own accounts are
unaffected, so a licence problem never locks you out of your server.

The plugin contacts the vendor (`license.koper.cloud`) only:

- when you press **Activate**, sending your redemption code and server id;
- once a day, from the scheduled task *Check the SSO plugin licence and for
  updates*, sending your server id, a fingerprint of the licence and the plugin
  version. It can renew your licence and tells you about new versions. You can
  turn this task off.

No usernames, libraries or viewing data are ever sent. See
[Licensing](licensing.md).

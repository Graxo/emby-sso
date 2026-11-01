# One-time PIN sign-in

Lets people sign in on a TV or console with the normal Emby app, without typing
a long password with a remote and without skipping MFA.

## How it works

1. On a phone or laptop, the user opens `https://<emby>/sso/pin` (the exact
   address is on the plugin's settings page under *PIN URL*).
2. They sign in at Authentik as usual, MFA included.
3. The page shows an eight-character PIN, such as `K7RM-3XQP`.
4. In the Emby app on the TV they enter their **Emby username**, and the
   **PIN** as the password.

The PIN:

- lasts **five minutes** and works **once**;
- only works for the account that requested it;
- is destroyed after **three wrong entries** (the user just gets a new one);
- is not case-sensitive, and the hyphen is optional;
- is kept in memory only — restarting Emby discards all open PINs.

A PIN is only issued if the user would pass every normal sign-in check (group,
licence, login provider, identity). So the account must already be on SSO, or
automatic account creation must be on.

## Turning it on

Tick **Allow native apps to sign in with a one-time PIN** on the plugin's
settings page and save. Nothing needs to change in Authentik.

## Instructions to send your users

Replace the address with your own:

```text
Download the Emby app from your app store.

1.  Open Emby and press Next.
2.  At the Emby Connect sign-in screen, press Skip.
3.  Enter the following:
        Server: https://<your-emby-server>
        Port:   (leave empty)
4.  Press Sign In Manually.
5.  Enter your username.
6.  Leave the app and open this address on your phone or laptop:
        https://<your-emby-server>/sso/pin
7.  Sign in there, and copy the PIN it shows you.
8.  Go back to the Emby app and type the PIN where it asks for a password.

Done.

The PIN lasts five minutes and works once. If it stops working, open the
same address again for a new one. Three wrong entries destroy a PIN, so
type it carefully rather than guessing.
```

Pressing **Skip** at the Emby Connect screen is where people get stuck. Emby
Connect is Emby's own online account service and has nothing to do with your
server; signing up there instead leads nowhere.

## When it does not work

| Symptom | Cause |
|---|---|
| The PIN page says *PIN sign-in is not enabled on this server.* | The setting is off. |
| The PIN page shows an error instead of a PIN | The browser sign-in itself failed — see [Troubleshooting](troubleshooting.md). The message is the same one a normal sign-in would give. |
| The TV says the username or password is wrong | The PIN expired, was already used, was typed for a different username, or was destroyed after three wrong tries. Get a new one. |
| A user's PINs keep getting destroyed | Someone is sending wrong PINs for that username. It only affects that user's PINs; browser sign-in still works. |

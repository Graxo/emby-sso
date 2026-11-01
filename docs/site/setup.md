# Setup

Follow these steps in order. Steps 1–6 are required; step 7 is optional.

Throughout, `<emby>` means the address your users use to reach Emby, for
example `emby.example.com`.

## 1. Install the plugin

Download the plugin and check it:

```bash
base=https://license.koper.cloud/v1/release
curl -fLo Emby.Sso.dll $base/download
curl -fLo Emby.Sso.dll.sha256 $base/download.sha256
sha256sum -c Emby.Sso.dll.sha256
```

1. Copy `Emby.Sso.dll` into Emby's `plugins` folder (in the Docker images this
   is `/config/plugins`). Copy only this one file; it already contains
   everything it needs, and extra DLLs next to it break it.
2. Restart Emby.
3. Open **Dashboard → Plugins**. *Authentik SSO* should be listed with the
   version you downloaded.

## 2. Create the provider in Authentik

In the Authentik admin interface:

1. **Applications → Providers → Create → OAuth2/OpenID Provider.**
    - **Client type:** *Confidential* (you will copy the client secret into
      the plugin) or *Public* (no secret).
    - **Redirect URI:** `https://<emby>/sso/callback`, mode *Strict*. It must
      match exactly — scheme, host and path. The plugin's settings page shows
      this exact value once you have saved the public URL in step 3.
    - **Scopes:** keep the defaults (`openid`, `profile`, `email`).
2. **Applications → Applications → Create**, and select the provider you just
   made. Note the application's slug; the issuer URL is
   `https://<authentik>/application/o/<slug>/`.
3. **Directory → Groups**: create a group for Emby users (for example
   `emby-users`) and add the people who should be able to sign in.
4. **Make sure the token contains the group list.** Authentik's default
   `profile` scope mapping already adds a `groups` claim. If you use your own
   scope mappings, add one that does, or nobody will get in.
5. **Set up a failed-login policy** (a *Reputation* policy) on the
   authentication flow, so that password guessing is slowed down. The plugin
   cannot see client IP addresses, so this has to happen in Authentik.

Copy the **Client ID**, the **Client secret** (if confidential) and the
**issuer URL** for the next step.

## 3. Configure the plugin

Open **Dashboard → Plugins → Authentik SSO** and fill in:

| Field | Value |
|---|---|
| Issuer URL | `https://<authentik>/application/o/<slug>/` |
| Client ID | From step 2 |
| Client secret | From step 2, or empty for a public client |
| Scopes | Leave as `openid profile email` |
| Emby public URL | `https://<emby>` — exactly what users type in their browser, including any sub-path |
| Username claim | Leave as `preferred_username` |
| Required group | The Authentik group from step 2, e.g. `emby-users` |
| Groups claim | Leave as `groups` |

If Authentik runs on a private address (`10.x`, `192.168.x`, `.lan` hosts that
resolve to one, …), also tick **Allow an identity provider on a private
network**. Without it, the plugin refuses to connect to it.

Press **Save**. The *URLs* section now shows the redirect URI, the sign-in URL
and the PIN URL for your server. Check the redirect URI matches what you
entered in Authentik.

Every field is explained in the [Settings reference](settings.md).

## 4. Activate a licence

The *Licence information* section shows your **Server id**.

- **To try it:** request a **trial licence** in the client portal at
  <https://portal.koper.cloud>. A trial licence is valid for **14 days**.
- **To buy:** press **Buy a licence**. The shop opens with your server id
  filled in, and you get a redemption code by email.

Paste the code into **Redemption code** and press **Activate**. The section
switches to *Active* and shows the expiry date.

Details and every possible message: [Licensing](licensing.md).

## 5. Test with one account

Before moving anyone real, test with a throwaway account:

1. In Emby, create a user with the same username as a test user in Authentik
   (who is in the required group).
2. Set that user's login provider to *Authentik SSO* (see step 6).
3. In a private browser window, open `https://<emby>/sso/start`.
4. You should be sent to Authentik, sign in, and land on the Emby home screen.

Keep **Dashboard → Logs** open while you do this. Everything the plugin does is
logged under `AuthentikSso`. If it fails, see
[Troubleshooting](troubleshooting.md).

## 6. Move accounts to SSO

The plugin only signs in accounts whose login provider is set to it. Do this
for each user you want on SSO.

!!! warning "Keep one administrator on Emby's own password"

    Once an account is on SSO, its Emby password stops working. Leave at least
    one administrator on the *Default* provider, so you can always reach the
    dashboard if Authentik or the plugin has a problem.

**Ordinary users:** **Dashboard → Users → (user) → Login provider → Authentik
SSO**, then save.

**Administrators:** the dashboard hides the *Login provider* field for
administrators, and saving an administrator's profile page silently resets it
to *Default*. Set it through the API instead (needs an API key from
**Dashboard → API Keys**, and `jq`):

```bash
EMBY=https://<emby>; KEY=<api key>; ID=<user id>
curl -s "$EMBY/emby/Users/$ID?api_key=$KEY" \
  | jq '.Policy | .AuthenticationProviderId = "Emby.Sso.Auth.SsoAuthenticationProvider"' \
  | curl -s -X POST -H 'Content-Type: application/json' -d @- \
      "$EMBY/emby/Users/$ID/Policy?api_key=$KEY"
```

To move an account back to its Emby password, run the same command with
`Emby.Server.Implementations.Library.DefaultAuthenticationProvider`.

The user id is in the address bar when you open the user in the dashboard.

Finally, tell your users the sign-in link, `https://<emby>/sso/start`. Putting
it as plain text in **Dashboard → Settings → General → Login disclaimer** shows
it on Emby's login page.

## 7. Optional features

### Sign-in on TVs with a one-time PIN

Tick **Allow native apps to sign in with a one-time PIN** and save. Then send
your users the [PIN instructions](pin-sign-in.md#instructions-to-send-your-users).
Nothing extra is needed in Authentik.

### Sign-in on TVs with an Authentik app password

Tick **Allow native apps to sign in with a password** and save.

- Each user creates an app password in Authentik under **Settings → Tokens and
  App passwords** and uses it as their password in the Emby app. Their normal
  Authentik password will not work.
- There is no MFA on this path.
- This cannot be combined with *Allow plain HTTP*.

### Create accounts automatically

1. Create an ordinary Emby user to act as the template, and give it the
   libraries and permissions new users should get. You can disable it
   afterwards.
2. Enter its name in **Template user**.
3. Tick **Automatically create accounts for group holders** and save.

Anyone in the required group who signs in without an Emby account now gets one,
copied from the template and already assigned to SSO.

## Updating

Once a day the plugin checks for a new version. When there is one, the plugin's
settings page shows **Update available** and a **Download and install** button.
The download is checked against the vendor's signature before anything is
written. The new version is used after you restart Emby; the plugin never
restarts Emby itself.

To update by hand instead, repeat [step 1](#1-install-the-plugin), replacing
the old file.

If the settings page looks wrong right after an update, reload the dashboard
in your browser — it caches plugin pages.

## Uninstalling

1. Move every SSO account back to the *Default* provider (step 6), or those
   users cannot sign in at all.
2. Delete `Emby.Sso.dll` from the `plugins` folder and restart Emby.
3. Optionally delete `plugins/configurations/Emby.Sso.xml` and the
   `emby-sso` folder in Emby's data folder.

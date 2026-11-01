# Licensing

This is paid software, not open source. The source is published so you can see
what runs on your server; see `LICENSE` for the terms.

A licence is issued for **one Emby server**, identified by its server id (shown
on the plugin's settings page). It is checked on your own server, offline.

## Trial licence

Request a **trial licence** in the client portal at
<https://portal.koper.cloud>. A trial licence is valid for **14 days**, and you
activate it the same way as a bought one (below).

Please take a trial before buying, especially if you are not sure your identity
provider is set up the way the plugin expects.

## Buying and activating

1. Open **Dashboard → Plugins → Authentik SSO**.
2. Press **Buy a licence**. The shop opens with your server id already filled
   in. After paying, you receive a **redemption code** by email.
3. Paste the code into **Redemption code** and press **Activate**.

The licence section then shows *Active* and the expiry date.

- One code covers a number of servers; the page shows how many are used.
- Activating the same code again on the same server (after a reinstall, a
  restore or a move) does not use up another activation.
- Treat the code like a password until it is activated. It is never written
  to the log.

### Messages after pressing Activate

| Message | What to do |
|---|---|
| Activated. The licence for this server has been saved. | Nothing. |
| Your licence has been requested and is being issued. | Not an error; your code is not used up. Press **Activate** again in a few minutes. If it still says this after a few hours, contact support. |
| That redemption code was not recognised. | Check for typos. If it is right, the purchase may not have completed, or the licence has expired. |
| That redemption code has already been activated on as many servers as it allows. | Ask support to release an activation, or buy another licence. |
| Too many activation attempts. | Wait as long as the message says and try again. |
| The licensing service could not be reached. / reported a problem of its own. | Try again later. Check that Emby can reach `https://license.koper.cloud`. |
| This plugin refused to send the activation request: … | The message names the reason, usually a network setting. |
| The licensing service returned a licence this plugin refused (…). NOTHING WAS SAVED. | Only happens if *Activation service address* was changed. Clear it. |
| The licence was issued and verified, but this server could not save it. | Make sure Emby can write to `plugins/configurations/`, then press **Activate** again (does not use another activation). |
| Anything else | The server log has the detail under `AuthentikSso`. |

## When the licence is missing, expired or invalid

**New SSO sign-ins and automatic account creation are refused. Nothing else
changes.**

- People already signed in stay signed in.
- Accounts on Emby's own password login work as normal, so you can always reach
  the dashboard.
- Nothing is deleted or reconfigured. Fix the licence and the next sign-in
  works.

The user is told: *"Single sign-on is unavailable: this server's SSO plugin
licence is missing, invalid or expired."* The settings page shows the reason
(*Not activated*, *Expired*, *Issued for a different server*, *Not valid yet –
check this server's clock*, *Not valid*), and the server log has a line like:

```
SSO refused at <path>: the plugin licence is not valid (Expired). ... This server's id is <id> ...
```

For the last 21 days before expiry the page shows *Active, expiring soon* and
the log carries a warning.

**"Issued for a different server"** means the server id changed — typically
after a reinstall without restoring Emby's data folder. Activate your code
again; if that says the code is used up, ask support to release the old
server's activation.

## The daily check

The scheduled task **Check the SSO plugin licence and for updates**
(**Dashboard → Scheduled Tasks**) runs once a day. It sends your server id, a
one-way fingerprint of the licence and the plugin version to
`license.koper.cloud`, and gets back:

- a **renewed licence**, if your licence has been extended — the plugin stores
  it automatically (log: `SSO licence renewed until <date>.`);
- a **withdrawal**, if the licence was refunded or charged back — new SSO
  sign-ins then stop, exactly as for an expired licence;
- whether a **newer plugin version** exists, which shows up on the settings
  page.

If the service cannot be reached, or its answer is not correctly signed,
nothing changes. You can turn the task off; the plugin keeps working on the
licence it has, but renewals and withdrawals will not arrive and you will not
be told about updates.

No usernames, libraries, viewing data or addresses are ever sent.

## Honest note

The licence is a signed token checked against a public key built into the
plugin. A .NET assembly can be decompiled and the check removed; there is no
obfuscation. This is not DRM — the enforceable part is `LICENSE`.

## Support

Email <support@koper.cloud> with your server id, the message you saw, and the
`AuthentikSso` lines from the server log. Never send your redemption code.

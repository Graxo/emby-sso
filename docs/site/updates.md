# Updates and the daily check

Once a day, this plugin asks the licensing service two questions: *is this
server's licence still valid*, and *is there a newer version of the plugin*.

It is a scheduled task, not a background thread. It appears in **Dashboard →
Scheduled Tasks** as *Check the SSO plugin licence and for updates*, where you
can see when it last ran, run it yourself, change when it runs, or **switch it
off**. A plugin that phones home should do it somewhere the person running the
server can watch it and stop it.

## What is sent

Two things: this server's id, and the SHA-256 of the licence it holds.

The licence itself never leaves. A fingerprint is one-way, so the service — or
anything that intercepted the request — learns nothing it could use as a
licence. Both values are ones the vendor already has, because they issued the
licence in the first place.

Nothing about your users, your libraries, your Emby version or your network is
sent, and nothing is sent on any sign-in path.

## The licence half

The answer comes back signed. Exactly one kind of answer changes anything: a
current, correctly signed statement naming **this** server and **this** licence
that says the licence has been withdrawn — for a refund, a chargeback, or a
licence issued in error.

!!! warning "It fails open, deliberately"

    No answer means nothing changes. So does an answer that is unsigned, signed
    by the wrong key, about a different server, about a different licence, or
    more than two days old.

    The vendor's service being down must never become your outage, and a hostile
    network must not be able to disable your plugin by dropping packets.

A withdrawal does exactly what an expired licence does and no more: new single
sign-ons and automatic account creation are refused. People already signed in
stay signed in, and your own Emby accounts are unaffected — see
[Licensing](licensing.md).

**Turning the task off means a withdrawal never arrives.** That is your call and
it is not fought. Running this plugin on a server with no internet access has
always been supported, and a check that cannot be declined is not a check.

## The update half

If the vendor has published a build newer than the one you are running, the
plugin's configuration page grows an **Update available** line and a **Download
and install** button.

The button is the only thing that installs anything. The daily task never
installs, never downloads, and never restarts Emby.

### What pressing it actually does

1. The vendor's statement about that release — the version, the file's SHA-256,
   and where to fetch it — is checked against a **release signing key compiled
   into your build**. This is a different key from the one that signs licences,
   held on a different machine, precisely so that breaking into the licensing
   service does not let anybody ship code to your server.
2. The file is downloaded **whole**, into memory, and hashed.
3. That hash is compared to the one the vendor signed for. **Only on a match is
   anything written to disk.** A wrong or tampered download leaves your
   installation exactly as it was.
4. The new DLL is written into Emby's plugins directory, and the page tells you
   an update is installed.

### Emby is not restarted for you

The new version starts being used at your next restart, at a moment you choose.
The page says so and keeps saying so until you have restarted.

### A newer version is never replaced by an older one

If the published release is older than or the same as what you are running, you
are offered nothing. Re-publishing an old statement — by accident, or by
somebody who has taken over the licensing service — cannot downgrade you.

## If you would rather do it by hand

Nothing here is compulsory. The current release and its checksum are downloadable
directly:

```bash
base=https://license.koper.cloud/v1/release
curl -fLo Emby.Sso.dll $base/download
curl -fLo Emby.Sso.dll.sha256 $base/download.sha256
sha256sum -c Emby.Sso.dll.sha256
```

Then copy it over the old one and restart, as in
[Installing and upgrading](installing.md).

The button is better than doing it this way, for one reason: it checks the
download against the vendor's **signature**, and a checksum published beside a
file on the same host cannot do that.

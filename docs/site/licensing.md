# Licensing

**This is licensed software, not open source.** See `LICENSE` in the source
distribution.

The plugin checks a signed licence key issued for one Emby server. Paste it into
Dashboard → Plugins → Authentik SSO → **Licence key**, or get one put there for
you by buying a code and pressing Activate — see
[Buying and activating a licence](activation.md).

A licence names your server's id — the `ServerId` Emby writes to its log at
startup — so it is valid on that server and no other.

!!! note "The check itself is entirely offline"

    Nothing is sent anywhere when a licence is checked. An Emby server with no
    internet access verifies its licence exactly as well as one with it.

    Two things do contact the licensing service, and **no sign-in path can
    reach either**: [activation](activation.md), once, when an administrator
    presses Activate; and a [daily scheduled task](updates.md) that asks whether
    the licence has been withdrawn and whether a newer release exists. A service
    that is unreachable — or shut down for good — does not affect sign-ins at
    all.

## What an invalid or missing licence actually does

It refuses **new** single sign-ons and automatic account creation. That is all.

- **People who are already signed in stay signed in.** Emby never consults this
  plugin about an access token it has already issued, so existing sessions on
  phones, TVs and browsers keep working until they are signed out.
- **Your own Emby accounts are unaffected.** A local Emby account is
  authenticated by Emby's own provider, not by this plugin, so you can always
  still reach your dashboard. **You cannot be locked out of your media server by
  a licensing problem.**
- **Nothing is disabled, deleted or reconfigured.** Fix the licence and the next
  sign-in works.

### The refusal is deliberately explicit, and it is the only one that is

The user is told there is a licensing problem rather than being given the
plugin's usual vague *"this account is not set up on this server"*.

Every other refusal in this plugin is vague on purpose, because being specific
would leak whether an account exists. This one is nobody's secret and only ever
gets fixed by whoever reads it.

## What the log tells you

The server log records the exact reason at **Error**, under category
`AuthentikSso`:

| Reason | Meaning |
|---|---|
| `Missing` | No licence key is configured. |
| `Expired` | The licence's expiry has passed. |
| `WrongServer` | The licence names a different server id than this one. |
| `BadSignature` | The signature does not verify against the embedded public key. |
| `NotYetValid` | The licence is dated in the future. |
| `Malformed` | The value is not a licence this build can parse. |

For the last three weeks before a valid licence expires it logs a **warning** —
at most one every six hours — telling you how many days are left.

!!! tip "That warning is the point of keeping existing sessions alive"

    It is what gives you time to renew without anybody being thrown out.

## Revocation, and what it can and cannot do

The licence itself is still checked **entirely offline**. Nothing is contacted
when a sign-in happens, and a server with no internet access verifies its
licence exactly as well as one with it.

Separately from that, the plugin asks the licensing service **once a day**
whether this server's licence has been withdrawn — for a refund, a chargeback,
or a licence issued in error. It appears in *Dashboard → Scheduled Tasks* as
**Check the SSO plugin licence**, where you can see when it last ran, run it
yourself, or turn it off.

!!! warning "It fails open, deliberately"

    If the licensing service cannot be reached — it is down, your server is
    offline, a firewall is in the way — **nothing changes and sign-ins carry on
    as normal.** The same is true of an answer that is unsigned, signed by the
    wrong key, about a different server, about a different licence, or older
    than two days.

    Exactly one thing stops new sign-ons: a current, correctly signed answer,
    naming this server and this licence, that says revoked.

    That asymmetry is the point. The vendor's server being down must never
    become your outage, and a hostile network must not be able to disable your
    plugin by dropping packets.

**A revocation does exactly what an expired licence does, and no more.** New
single sign-ons and automatic account creation stop. People already signed in
stay signed in, Emby's own accounts are unaffected, and nothing is disabled,
deleted or reconfigured.

**What is sent** is this server's id and a SHA-256 of the licence — both of
which the vendor already has. The licence itself never leaves your server, and a
hash cannot be turned back into one.

**Turning the task off** means revocations never arrive. That is supported: an
air-gapped server has always been a legitimate way to run this plugin.

There is one thing that acts *like* a revocation and is not one: retiring a
signing key. A licence is accepted only if one of the keys compiled into the
plugin signed it, so dropping a key from that set stops every licence it ever
signed — all of them at once, including the ones belonging to customers who did
nothing wrong. It is the remedy for a leaked key, not a way to deal with one
customer. See [Rotating and revoking a signing key](key-rotation.md).

## What this is worth, honestly

The licence is an RS256 JWT signed with a private key that never leaves the
vendor, verified against a public key compiled into the assembly. Nobody can
mint a licence without that private key, and a licence for one server does not
work on another.

!!! warning "But a .NET assembly can be decompiled and the check removed"

    The plugin ships as a .NET assembly. This project spent a day decompiling
    Emby's own binaries to build the plugin in the first place. There is no
    obfuscation here and none is planned, because obfuscation would raise the
    effort a little and change nothing about the outcome.

So this raises the cost of casual copying between servers. **It is not DRM and
it is not described as DRM anywhere in this project.** The enforceable part is
`LICENSE`, not the code.

## For the vendor

`tools/Emby.Sso.LicenceTool/` generates signing keypairs and signs licences, and
its own README covers where a private key must live. Two pages cover the rest:

- [Signing licences offline](offline-signing.md) — the round trip, and why the
  licence service does not hold a signing key at all;
- [Rotating and revoking a signing key](key-rotation.md) — how a build trusts a
  *set* of keys, and what revoking one costs.

!!! danger "A build with no public key refuses every sign-on"

    A build whose `LicencePublicKey.TrustedJwks` is empty refuses every single
    sign-on and says so in the server log — deliberately, because a build with
    no key cannot verify a licence and so cannot honestly accept one. Emby's own
    local accounts are unaffected, so this never locks an operator out of their
    own server.

## What has not been observed

!!! unverified "The licence check has never run inside Emby"

    The decision itself is under test — 21 tests covering a licence signed by
    the wrong key, one for another server, an expired one, one with no expiry,
    one dated in the future, one edited after signing, `alg: none`, an
    HMAC-signed token keyed on the embedded public key, and an algorithm the
    build does not accept. Each guard was confirmed to have a test that fails
    when that guard is removed. A licence produced by the issuing tool was
    validated end-to-end against the plugin's own checker.

    Not observed:

    - **the configuration page still rendering and saving with the Licence key
      field on it.** Emby 4.9's plugin page is fragile — it strips script tags
      and needs an exact `emby-scroller` + `data-controller` structure — so the
      field's markup is a byte-for-byte copy of an existing text field's and
      nothing structural was touched. It still has to be looked at on a real
      server.
    - **`IApplicationHost` being injectable into the plugin's constructor.**

        !!! inferred "Inferred from decompiled source"

            It is registered as a single instance in
            `ApplicationHost.RegisterResources`, which runs before `FindParts`
            builds plugins through the same container (both read off a
            decompiled 4.9.5.0 server), and plugins are constructed by
            `Container.GetInstance`, which auto-wires. If that were ever wrong
            the plugin would fail to construct and Emby would log "Error
            creating Emby.Sso.Plugin" — a loud failure, not a silent weakening.

    - **what `SystemId` looks like on your own server.** It is read from
      `IApplicationHost.SystemId`, which is the `ServerId` Emby logs at startup,
      but the value on any particular server has not been read here. **Take it
      from the log, not from a guess.**

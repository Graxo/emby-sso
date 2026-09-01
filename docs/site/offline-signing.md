# Signing licences offline

*This page is for the vendor, not for an operator installing the plugin.*

!!! info "This is the optional arrangement, not the default"

    By default the licence service signs licences itself, the moment a customer
    activates, so activation is self-service and takes one press of a button.
    That requires the private key to be mounted into the service - and therefore
    loaded by the process that answers the internet.

    Everything on this page describes the alternative: **leave the key off the
    server entirely**, and sign by hand somewhere that accepts no connections.
    It is fully supported, it is what happens whenever
    `LICENCE_SIGNING_KEY_PATH` is unset, and it is strictly safer. It is not
    instant, which is why it is not the default.

    Both use the same checks and the same file formats. Turning one into the
    other is one environment variable and one volume.

## Why it exists

The licence service used to hold the private signing key and mint a licence
during an activation. That put the one secret the whole scheme rests on — the
thing that mints a valid licence for **any** Emby server, forever, with no
revocation because the plugin verifies offline — on a host with a port open to
the internet.

Everything else in that service was a wall around that one asset: rate limits,
the admin password, webhook signature verification, container hardening. Any
single failure of any one of them lost it completely, and *silently*: a stolen
key mints licences indistinguishable from real ones, and nothing anywhere would
report it.

So the key left. The service now records what has been paid for and what terms
were agreed; a person with the key signs those terms on a machine of their
choosing; the result is uploaded back. **A total compromise of the licence
service yields the customer list and the ability to stop issuing — it does not
yield the ability to mint one licence, because there is nothing there to mint
with.**

The service refuses to start if `LICENCE_SIGNING_KEY_PATH` is still set. Not
ignores it — refuses. A key that is still mounted is still stealable whether or
not anything reads it.

## What it costs

**An activation is no longer instant.** The first time a customer redeems a
code, the service answers *"your licence is being issued"* and their plugin
tells them to press **Activate** again shortly. It waits for a person.

That is the honest price and it is not hidden from anybody: the plugin's message
says so plainly, the code is not spent by the wait, and re-pressing the button
costs nothing. Repeat activations of a server whose licence is already signed
are immediate.

## The round trip

Three steps, and the middle one is the only place the key is touched.

### 1. Download what is waiting

Sign in to `/admin`, open **Signing**. The number beside it on the navigation
bar is how many customers are waiting.

Press **Download**. You get `emby-sso-signing-requests.json`: for each waiting
licence, an opaque request id, the licensee (the code's tag — never an email
address), the Emby server id, and the exact dates the licence must carry.
Nothing else. It holds no redemption code and nothing that names a buyer.

### 2. Sign it, where the key is

**You do not need the .NET SDK on that machine.** `licencetool.sh` runs the tool
in a container; Docker is the only requirement. Inside it, `/keys` is your key
directory and `/work` is whatever directory you are standing in.

```
cd ~/Downloads
tools/Emby.Sso.LicenceTool/licencetool.sh sign \
  --requests /work/emby-sso-signing-requests.json \
  --key /keys/licence-signing-key.private.json
```

That is deliberate rather than a convenience. The key belongs on a machine that
answers no requests, and requiring that machine to also carry a development
toolchain works against it — the fewer things installed where the key lives, the
better. With the SDK already there, it is:

```
dotnet run --project tools/Emby.Sso.LicenceTool -- sign \
  --requests ~/Downloads/emby-sso-signing-requests.json \
  --key ~/emby-sso-licence/licence-signing-key.private.json
```

It writes `emby-sso-signing-requests-signed.json` beside the input, owner-only,
and appends a row per licence to the ledger beside the key so
`licencetool list` keeps working.

Every request is signed or the file is refused. A partial batch would mean
uploading something you believe is complete while some customers keep waiting,
with nothing on screen to say which.

The tool checks the key the way the service used to at startup: owner-only
permissions, private half present, never inside a git working tree.

### 3. Upload the result

Back on **Signing**, choose the signed file and press **Upload**.

Each licence is checked before it is stored:

- **the signature**, against the public keys in `LICENCE_PUBLIC_KEYS` — a file
  signed with the wrong key is caught on your screen, not on a customer's
  server;
- **the audience**, against the server id *the service recorded* — a licence
  cannot be retargeted at a different server between download and upload;
- **the expiry and issue date**, against the terms recorded at activation — a
  licence cannot be quietly extended past what was paid for;
- **the licensee**, for the same reason;
- **that the request is one this service made**, and has not already been
  answered.

Together those mean the upload has exactly one authority: to supply a signature
for terms the service already decided. Whoever is at the admin page cannot use
it to license a server nobody paid for, or to give somebody ten years for a
year's money.

Rows are checked one at a time. A bad one is named and refused; the good ones
around it are stored, because the good ones are customers waiting.

Then **delete the signed file.** Until it is uploaded it is the only copy of
those licences; afterwards it is a stack of somebody else's credentials sitting
in your downloads folder.

## Where the key should live

Anywhere that is not a server. A laptop, a machine that is off most of the time,
an encrypted volume you mount to sign a batch — the property that matters is
that nothing on the internet can reach it.

`licencetool keygen` writes it `chmod 600` and refuses to write inside a git
working tree. Back it up somewhere separate: **it is not in the service's
encrypted backup**, because it is not on that machine at all. Losing it is
unrecoverable in a way that losing the store is not — every customer would need
a new plugin build.

## Reissuing

A request that already holds a licence is refused rather than overwritten. The
customer may be using the one that is there, and replacing it would stop their
server working — re-uploading last week's file by mistake is far too easy for
that to happen silently.

If a licence really has to change, void the code and issue a new one.

## See also

- [Rotating and revoking a signing key](key-rotation.md)
- [Licensing](licensing.md) — what an invalid licence does and does not stop
- [Buying and activating a licence](activation.md)

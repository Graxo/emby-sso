# Signing and publishing a plugin update

*This page is for the vendor, not for an operator installing the plugin.*

An operator who opens the plugin's configuration page sees **Download and
install** only when their server has been offered a newer version. That offer
comes from one signed statement — a *release manifest* — that says: this
version, this file's SHA-256, at this address. Nothing else can produce that
offer, and nothing installs without one.

Making that statement is the last step of a release, and it is the only step
the build pipeline does not do.

## Where everything lives

Four things, on purpose kept apart. The point of the arrangement is the last
column: no single machine can both mint licences and ship code.

| What | Where | Holds |
| --- | --- | --- |
| **The licence service** | `https://license.koper.cloud` | The customer list, the redemption codes, and the **licence** key. Answers the internet. |
| **The licence key** | The vendor's personal machine, and a copy mounted into the service | Signs licences. Stolen, it costs sales. |
| **The release key** | A second machine, which is not the licence machine and not a server | Signs code. Stolen, it owns every customer's media server. |
| **The build pipeline** | GitLab CI | Neither key. It builds, checksums and publishes; it cannot make anything install anywhere. |

The concrete host names are in the repository's private runbook, not here.

!!! warning "The two keys are not interchangeable"

    The **licence key** signs licences and may live on the licence service. The
    **release key** signs code and must not. They are separate keypairs whose
    private files have the **same filename** and differ only by directory — so
    every release command names its directory explicitly, and the wrapper
    refuses to hand you a manifest signed by the wrong one.

## Why the pipeline does not sign

A key in a CI variable is a key held by every runner, every job, everyone who
can push a branch, and every dependency any job restores. Masking hides it from
the log; it does not hide it from the job.

A release manifest authorises code to install itself on every licensed server,
so that key stays on one machine you control. Everything up to the signature
*is* automated: the pipeline builds, stamps the version, computes the checksum,
publishes the file, and prints the exact command to sign it.

## Every release: two steps

### 1. Sign, on the release machine

Download the `Emby.Sso.dll` the pipeline published — from the GitLab release
page in a browser is fine — then:

```bash
tools/Emby.Sso.LicenceTool/release.sh 1.0.3 ~/Downloads/Emby.Sso.dll
```

That is the whole command. It fills in the address, the key directory and the
hash, and prints the manifest.

Pass the checksum from the pipeline as a third argument and it is checked
before the key is touched at all:

```bash
tools/Emby.Sso.LicenceTool/release.sh 1.0.3 ~/Downloads/Emby.Sso.dll 9f86d081...
```

Do that. It is the difference between *"this file is the build"* and *"this
file was in my downloads folder"*.

The script refuses, and throws the manifest away, if the key it just used is
not the release key the plugin trusts. That is the mistake it exists to
catch: signing with the licence key produces a manifest that verifies
everywhere except on a customer's server.

### 2. Publish, on the admin page

Sign in to `https://license.koper.cloud/admin` and open **Release**. Choose the
same `Emby.Sso.dll`, paste the manifest, press **Publish**.

Both halves go together, and the page checks them against each other: a file
that does not hash to what the manifest was signed for is refused and nothing
is stored. So is a manifest signed by the wrong key, and so is a version that
is not newer than the one already published.

That is it. There is no third step.

## Why the service hosts the file

The manifest names an address, and that address has to answer an Emby server
that has no account anywhere and sends no credential.

A package registry behind a sign-in cannot do that, and the failure is silent
in the worst way: the manifest verifies, the admin page says published, and
every customer's server reports the download unreachable. The licence service
is already the one address every plugin is configured to reach, so that is
where the file goes — `/v1/release/download`, with `/v1/release/download.sha256`
beside it for operators installing by hand.

**Serving the file grants that host nothing.** The bytes are checked against
the SHA-256 in the signed manifest by the plugin that downloads them. Somebody
who takes the licence service can stop serving the file, or serve garbage; they
cannot make an Emby server install either, because they cannot sign a manifest
for what they served.

## Once, before the first release

### Generate the release key

On the machine that will hold it, in its own directory — not the licence key's:

```bash
LICENCE_KEY_DIR="$HOME/emby-sso-release" \
  tools/Emby.Sso.LicenceTool/licencetool.sh keygen --out /keys
```

It prints the **public** JWK as one line and writes the private half to
`$HOME/emby-sso-release/licence-signing-key.private.json`. Never paste the
private half anywhere. Back that directory up the way you back up the licence
key.

### Compile the public half into the plugin

Add the printed JWK to `TrustedJwks` in
`src/Emby.Sso/Protocol/ReleasePublicKey.cs`, and put its key id in
`release.sh`'s `EXPECTED_KEY_ID`. Commit, and cut a release the normal way.

A plugin that does not carry the key cannot be offered an update by anybody,
including you. This is the same trusted-set arrangement as the licence key, so
rotation works the same way — see [Rotating and revoking a signing
key](key-rotation.md).

### Tell the licence service the public half

Set two variables in the service's environment and restart it:

```yaml
environment:
  LICENCE_PUBLIC_BASE_URL: https://license.koper.cloud
  LICENCE_RELEASE_PUBLIC_KEYS: '{"kty":"RSA","n":"...","e":"AQAB"}'
```

`LICENCE_RELEASE_PUBLIC_KEYS` is what lets the Release page check a manifest
before storing it. Without it, the page refuses everything. The service is not
trusted to decide whether a manifest is genuine — every plugin checks again,
and that check is the real one — but a manifest signed with the wrong key
should be caught on your screen rather than by every customer at once.

`LICENCE_PUBLIC_BASE_URL` is how the service knows what address to serve the
file from, and therefore what `release.sh` signs for. Without it the service
hosts nothing.

## What happens after you publish

Nothing, immediately. Publishing installs nothing and notifies nobody.

Each licensed server asks once a day, at an hour derived from its own server id
so they do not all ask at once. If the manifest names a version newer than the
one it is running, the plugin shows **Update available**. The operator presses
the button; the server downloads the file, hashes it, and compares that hash to
the signed one in constant time. Only on a match is anything written, and even
then Emby is not restarted — the page asks the operator to restart when
convenient.

A server running a *newer* version than the manifest names is offered nothing.
Re-publishing an old manifest, by accident or by somebody who has taken the
licence service, cannot downgrade anybody.

## If something is wrong

**`release.sh` says it was signed with the wrong key.** The directory it used
holds the licence key, not the release key. Nothing usable was produced. Check
`RELEASE_KEY_DIR`.

**The Release page says it has no release public key.**
`LICENCE_RELEASE_PUBLIC_KEYS` is unset or unparseable. The service keeps
serving whatever manifest was already stored and refuses new ones until it is
set.

**The Release page says the file is not the one the manifest was signed for.**
Two builds of the same name. The manifest is for the file `release.sh` hashed;
upload that one.

**The Release page says the manifest points somewhere else.** It was signed for
a different address — usually because `LICENCE_SERVICE` was set, or
`LICENCE_PUBLIC_BASE_URL` changed after signing. Sign it again.

**Nobody is offered the update.** Check, in order: that the version is genuinely
newer than what servers run; that `/v1/release` returns the manifest; and that
`/v1/release/download` answers `200` to a `curl` from somewhere that has never
authenticated to anything of yours.

**A server reports the download did not match.** Nothing was written, and that
is the design working. The file at that address is not the file that was signed
for. Publish the pair again, together.

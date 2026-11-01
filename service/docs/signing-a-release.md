# Signing and publishing a plugin update

*This page is for the vendor, not for an operator installing the plugin.*

An operator who opens the plugin's configuration page sees **Download and
install** only when their server has been offered a newer version. That offer
comes from one signed statement — a *release manifest* — that says: this
version, this file's SHA-256, at this address. Nothing else can produce that
offer, and nothing installs without one.

Making that statement is the last step of a release, and it is the only step
the build pipeline does not do: one command on the machine that holds the key.

!!! note "The licence tool is not in this repository"

    Every `tools/Emby.Sso.LicenceTool/...` command below is run in the tool's
    own checkout, on the machine that holds the key. The tool mints licences
    and signs releases, so it is not published with the plugin - it lives with
    the keys and nowhere else.

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

## Every release: one command

Push the version's tag (`v1.0.6`), then, on the release machine:

```bash
tools/Emby.Sso.LicenceTool/release.sh 1.0.6
```

That is the whole release. The script waits for the tag's pipeline to publish
the build, downloads it from the package registry, checks it against the
checksum the pipeline published, signs it with the release key, posts the pair
to the licence service's `POST /v1/release`, and reads the public download's
checksum back to confirm the service serves exactly the file it signed.

It refuses, before anything is published, if the file disagrees with the
pipeline's checksum, and it throws the manifest away if the key it used is not
the release key the plugin trusts. That is the mistake it exists to catch:
signing with the licence key produces a manifest that verifies everywhere
except on a customer's server.

**What the release machine needs**, besides the key and Docker: a GitLab token
that can only *read* the package registry - a project access token with
`read_api`, or a deploy token with `read_package_registry` - in
`~/.config/emby-sso/gitlab-token` (or `GITLAB_TOKEN`). It needs no password for
the licence service and no cluster access.

### Why publishing needs no password

`POST /v1/release` takes the same two fields the admin page's form does and
runs the same check: the manifest must verify against the release public key,
name a version newer than the one published, point at this service's download
address, and the file must hash to what it was signed for. Anything else is
refused and nothing is stored. The signature *is* the credential - nobody
without the release key can produce a pair it accepts - and a password in front
of it would add a second secret to the key machine while guarding nothing the
signature does not. It is rate-limited, capped at 32 MB, and recorded in the
admin audit.

What it cannot tell apart is a manifest you signed and meant to hold back. So
the script never leaves one lying around: it signs and publishes in one go.

### Without a token, or to publish by hand

Download `Emby.Sso.dll` from the GitLab release and pass it with the pipeline's
checksum:

```bash
tools/Emby.Sso.LicenceTool/release.sh 1.0.6 ~/Downloads/Emby.Sso.dll 9f86d081...
```

With `PUBLISH=no` the script only signs, and leaves the DLL and the manifest in
your home directory for the admin page (**Release**: choose the file, paste the
manifest, press **Publish**), which runs the same checks.

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

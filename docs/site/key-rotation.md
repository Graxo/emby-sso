# Rotating and revoking a signing key

*This page is for the vendor, not for an operator installing the plugin.*

## Why a build trusts a set, not a key

A plugin build that trusts exactly one public key cannot survive that key
leaking. The only remedy is a new keypair and a new build — which stops every
licence in the field at the same moment, including those belonging to customers
who did nothing wrong.

So a build trusts a **set**. The new key is added and shipped while the old one
is still trusted; customers move onto the new key at their own pace; the old one
is dropped in a later release. A rotation becomes a release rather than an
outage.

Each licence names the key that signed it in its `kid` header. The name is
derived from the key itself — `licencetool keygen` prints it — so nothing has to
keep a registry of which name meant which key.

## Rotating on purpose

Do this before you have to, not after.

1. **Generate the new key**, on the machine that will sign with it:

   ```
   dotnet run --project tools/Emby.Sso.LicenceTool -- keygen --out ~/emby-sso-licence-2
   ```

   It prints the public JWK and its key id.

2. **Add it** — add, do not replace — to `TrustedJwks` in
   `src/Emby.Sso/Protocol/LicencePublicKey.cs`, and to `LICENCE_PUBLIC_KEYS` on
   the licence service (a JSON array of both).

3. **Ship the plugin build.** Until customers have it, they trust only the old
   key, so nothing may be signed with the new one yet.

4. **Start signing with the new key.** Point `licencetool sign --key` at it. New
   licences carry the new `kid`; existing ones keep working, because the old key
   is still trusted.

5. **Drop the old key** in a later release, once no licence signed with it is
   still valid. `licencetool list` on the old ledger says when that is.

## Revoking, because a key has leaked

There is no revocation list and no callback — the plugin verifies offline and
never contacts anything. **A key is revoked by not being in the trusted set.**

Delete its entry from `LicencePublicKey.cs`, ship, and remove it from
`LICENCE_PUBLIC_KEYS`. Every licence it signed stops working at the moment each
server picks up the build.

That is a real cost to real customers, and it is exactly why step 1 above is
worth doing while nothing is wrong: if the new key is already trusted, a
revocation is a reissue rather than an outage.

Treat a key as leaked if it has ever been:

- on a machine that answers requests from the internet;
- readable by any account but its owner (the tool and the loader both refuse
  this, loudly);
- inside a git working tree (both refuse this too);
- pasted into a chat window, an issue, or a support thread.

## What has already been revoked

**2026-09-01.** The first signing key was retired. It had been loaded at startup
by the internet-facing licence service *and* had been pasted into a chat window,
so it had to be treated as public. It is not in `TrustedJwks` any more; nothing
it signed validates.

Every test licence issued before that date has to be replaced. A tester whose
licence stopped working on that date needs a new one — that is this, not a bug.

The key that replaced it, `173282303e3800b8`, has never been on a server. Only
`licencetool sign`, run by hand, ever loads it. See
[Signing licences offline](offline-signing.md).

## If the two sides disagree

The plugin and the service should carry the same set. When they do not, the
failure is loud and early rather than late and confusing:

- a licence signed by a key **the service** does not know is refused at upload,
  on the operator's own screen, with the key named;
- a licence signed by a key **the plugin** does not know is refused on the
  customer's server as `BadSignature`, which reads in the log as "nothing here
  was signed by a key this build trusts".

`/healthz` reports which keys the service trusts, so the two can be compared
without a shell on the box.

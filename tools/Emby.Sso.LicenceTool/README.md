# Licence tool

**This is where licences are signed.** The licence service does not hold a
signing key and cannot mint anything; it records what has been paid for and
hands it to this tool as a file. `sign` is the command that does the day-to-day
work — see [Signing licences offline](../../docs/site/offline-signing.md) for
the round trip, and [Rotating and revoking a signing
key](../../docs/site/key-rotation.md) for what a build trusting a *set* of keys
buys you.

Run this on a machine that answers no requests. That is the entire security
argument, and it is why the service refuses to start if a key is still mounted
on it.

Mints the licences `Emby.Sso` checks. **The vendor runs this. It is not shipped
to anyone.** No code in this directory reaches the plugin DLL: this project holds
no reference to `src/Emby.Sso`, nothing in the plugin references it, and ILRepack
merges only the plugin's own build output.

## Where the private key and the ledger live

**Not in this repository, and not in any repository.** The tool refuses to write
either file inside a git working tree for exactly that reason, and both
`licence-signing-key.private.json` and `licences-issued.jsonl` are in
`.gitignore` as a second line of defence.

Two files, one directory:

| File | What it is |
| --- | --- |
| `licence-signing-key.private.json` | The signing key. Everything rests on it. |
| `licences-issued.jsonl` | The ledger: one line per licence issued. Who holds what, and when it lapses. |

The ledger is not a signing key, but it is a list of who runs your plugin on
which server, and there is no way to rebuild it — the plugin never calls home,
so no server can be asked what it holds. Both files are written owner-read/write
only, and the tool says so loudly if it finds the ledger readable by anyone else.

Somewhere sensible:

- an encrypted password manager or secrets vault, as an attached file;
- or an offline, encrypted volume you back up separately.

Back it up before you issue a single licence. **If you lose it, no further
licence can ever be issued for any build that carries the matching public key** —
every customer would need a new build. If it leaks, anyone can mint licences for
your plugin, and the only remedy is a new keypair, a new release, and a reissued
licence for every customer.

## One-time setup

```
export DOTNET_ROOT=$HOME/.dotnet
dotnet run --project tools/Emby.Sso.LicenceTool -- keygen --out ~/emby-sso-licence
```

It writes the private key (owner-read/write only) and prints the public key as a
one-line JWK. Paste that line into `Jwk` in
`src/Emby.Sso/Protocol/LicencePublicKey.cs` and rebuild.

Do this **once**. Running `keygen` again into the same directory is refused;
running it into a new one gives you a key that none of your released builds
trust.

A build whose `LicencePublicKey.Jwk` is still empty refuses every single sign-on
and says so in the server log. That is deliberate: a build with no key cannot
verify a licence, so it cannot honestly accept one.

## Issuing a licence

You need the customer's Emby **server id** — the `ServerId` Emby writes to its
log at startup (`IApplicationHost.SystemId`). A licence is valid on that server
and no other.

```
dotnet run --project tools/Emby.Sso.LicenceTool -- issue \
  --key ~/emby-sso-licence/licence-signing-key.private.json \
  --server-id c5bc6e91458540caa295c4efdda1a58a \
  --licensee "Acme Media" \
  --days 365
```

The licence goes to stdout on its own — the summary goes to stderr — so
`> licence.txt` gives you just the key. It is roughly 700 characters. The
customer pastes it into **Dashboard → Plugins → Authentik SSO → Licence key**.

Every `issue` appends one line to the ledger, `licences-issued.jsonl` beside the
key, or wherever `--ledger <file>` says. The line records the licensee, the
server id, the issue and expiry times, and a SHA-256 fingerprint of the licence.

**The licence itself is not stored.** It is a live credential, and a file
holding every credential ever issued is a far worse thing to lose than a list of
names; the only thing storing them would buy is resending one to a tester who
lost theirs, and issuing them another for the same server id is one command. The
fingerprint is what ties a string somebody emails back to a row in the ledger —
`show` prints the same fingerprint.

If the ledger cannot be written, the licence is still issued and printed, with a
loud warning: losing the record of a licence is bad, and failing to issue one
because a log file is wrong is worse. **When you see that warning, write the
licensee, server id and expiry down by hand.** Nothing else knows them.

A licence must expire; `--days` has to be a positive number. There is no
revocation: the plugin checks the licence offline against the embedded public
key and never calls home, so the only way a licence stops working before its
expiry is a new keypair and a new build.

## Who holds what: `list`

```
dotnet run --project tools/Emby.Sso.LicenceTool -- list \
  --ledger ~/emby-sso-licence/licences-issued.jsonl
```

```
STATUS   EXPIRES     IN DAYS  LICENSEE                  SERVER
LAPSED   2026-06-01      -91  Lapsed Larry              9999aaaa8888bbbb7777cccc6666dddd
LAPSING  2026-09-05        4  Acme Media                c5bc6e91458540caa295c4efdda1a58a
active   2027-08-31      364  Beta Tester Bob           aaaa1111bbbb2222cccc3333dddd4444
```

Soonest expiry first, so what needs attention is at the top. `--soon <days>`
sets how far ahead counts as `LAPSING`; the default of 21 days is the window in
which the customer's own server has already started warning them in its log.

One line per holder: a reissue supersedes the earlier licence for the same
licensee and server, and the earlier ones are counted (`(+1 earlier)`) rather
than listed. `--all` lists every record instead.

A line the tool cannot parse is skipped with a warning naming the line number,
so one damaged record never hides the rest.

Nothing in `list` revokes anything, because nothing can: a lapsed holder is
fixed by issuing them a new licence, never by editing this file.

## Is this licence genuine: `show`

A tester emails "it says my licence is invalid". Ask them for the licence string
and put it through `show`:

```
dotnet run --project tools/Emby.Sso.LicenceTool -- show \
  --key ~/emby-sso-licence/licence-signing-key.private.json \
  --licence /tmp/theirs.txt \
  --server-id c5bc6e91458540caa295c4efdda1a58a
```

The licence can come from `--licence <file>` or on stdin. `--server-id` is
optional; without it the server the licence names is printed but not checked
against anything.

```
Signature   : VERIFIED against /home/you/emby-sso-licence/licence-signing-key.private.json
Licensee    : Acme Media
Server      : c5bc6e91458540caa295c4efdda1a58a
Issued      : 2026-08-31T11:14:15Z
Expires     : 2027-08-31T11:14:15Z
Fingerprint : sha256:025285f6...

VALID - expires in 364 days, and is for that server.
```

**`show` verifies the signature; it does not merely decode the token.** It runs
the same checks the plugin runs — the signature against your public key, `alg`
pinned to RS256, unsigned tokens refused — and if any of them fails it prints
*nothing at all* out of the token and exits non-zero:

```
SIGNATURE NOT VERIFIED - this was not issued with this key.
  the signature does not match this key, or there is no signature at all
```

That silence is deliberate. Anyone can write a JWT payload saying whatever they
like; the contents of a token that did not verify are whatever its author chose,
and printing them beside the word "Licensee" is how you come to believe one.

Expiry and the server binding are *reported* rather than enforced, because
"expired three weeks ago" is the answer you came for. A licence that verifies
but cannot be used says so and exits non-zero:

```
NOT USABLE, though it is genuinely signed by this key:
  - it EXPIRED 40 days ago
```

`--key` takes the private key file or a public JWK; only the public half is ever
used, and no private material is printed. Exit status is 0 only when the licence
verified *and* is usable, so `show` can be used in a script.

## What this protects, and what it does not

The licence is an RS256 JWT signed by the key above. The plugin verifies it
offline against the public half compiled into the assembly, checks that the
`aud` claim is that server's own id, and refuses anything expired, dated in the
future, signed by another key, signed with another algorithm, or unsigned. So:

- a licence for one server does not work on another;
- nobody can mint a licence without the private key.

But the plugin ships as a .NET assembly, and **a .NET assembly can be decompiled
and the check deleted**. This project itself spent a day decompiling Emby's own
binaries to build the plugin. Anyone willing to open the DLL in a decompiler,
remove one call and rebuild has an unlicensed plugin, and no amount of
obfuscation changes that — it raises the effort, it does not remove the
possibility.

What this buys is that using the plugin unlicensed is a deliberate act by
somebody with the skills to do it, not something that happens by copying a file
between two servers. Sell it on that basis and do not claim more.

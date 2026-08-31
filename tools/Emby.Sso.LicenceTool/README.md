# Licence tool

Mints the licences `Emby.Sso` checks. **The vendor runs this. It is not shipped
to anyone.** No code in this directory reaches the plugin DLL: this project holds
no reference to `src/Emby.Sso`, nothing in the plugin references it, and ILRepack
merges only the plugin's own build output.

## Where the private key lives

**Not in this repository, and not in any repository.** The tool refuses to write
a key inside a git working tree for exactly that reason, and
`licence-signing-key.private.json` is in `.gitignore` as a second line of
defence.

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

A licence must expire; `--days` has to be a positive number. There is no
revocation: the plugin checks the licence offline against the embedded public
key and never calls home, so the only way a licence stops working before its
expiry is a new keypair and a new build.

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

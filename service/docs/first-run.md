# First run

Four steps: make a key, configure, start, sign a licence.

**Activation is self-service.** A customer pastes their code, presses Activate
once, and has a licence — because the service signs it for them. That means the
signing key is mounted into the service, which is a deliberate trade:

> The private key mints a licence for **any** Emby server, forever, and there is
> no revocation. On this host it is in the process that answers the internet, so
> a break-in there takes the whole scheme with it, silently.
>
> The alternative is still supported and is one line of config away: leave the
> key off the server, and sign at `/admin/signing` with `licencetool sign` on a
> machine that answers no requests. Safer, not instant. See
> [Signing licences offline](../../docs/site/offline-signing.md).

You still generate the key on your own machine — step 1 — and copy it up.

---

## 1. Make your signing key

**On your machine, not the server.** Needs Docker. Does not need the .NET SDK.

```
git clone <this repository>
cd emby-sso
tools/Emby.Sso.LicenceTool/licencetool.sh keygen --out /keys
```

`/keys` inside the container is `~/emby-sso-licence` on your machine.

It prints a **public JWK** (one line, starts `{"kty":"RSA"`) and a **key id**
(16 hex characters). Keep both — you need the JWK in step 2.

**Back up `~/emby-sso-licence/licence-signing-key.private.json`**, encrypted,
somewhere that is not the server. Lose it and you can never issue another
licence for a plugin build carrying its public half.

Do not `sudo` this. The tool refuses a key readable by anyone but its owner, so
a root-owned key fails later in a way that looks like corruption.

---

## 2. Configure the server

Nothing to create and nothing to chown — **use a named volume** and Docker gives
it the ownership the image already set. The container runs as uid 5678, holds no
capabilities and never runs as root, so it cannot fix a directory itself; a
named volume means it never has to.

In your compose file or the `.env` beside it:

```yaml
services:
  licence:
    image: registry.koper.local:5050/graxo/emby-sso/licence-service:main
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - licence-data:/data
    environment:
      LICENCE_DATA_DIR: /data
      LICENCE_PUBLIC_KEYS: '<the public JWK from step 1>'
      LICENCE_PUBLIC_BASE_URL: https://license.koper.cloud
      PAYPAL_ENV: sandbox
      PAYPAL_CURRENCY: GBP
      PAYPAL_PRICE: "19.00"

      # Secrets. The VALUES live in .env beside this file, never in here -
      # this is the file most likely to end up in a repository.
      ADMIN_PASSWORD_HASH: ${ADMIN_PASSWORD_HASH}
      LICENCE_BACKUP_PASSPHRASE: ${LICENCE_BACKUP_PASSPHRASE}
      PAYPAL_WEBHOOK_ID: ${PAYPAL_WEBHOOK_ID}
      PAYPAL_CLIENT_ID: ${PAYPAL_CLIENT_ID}
      PAYPAL_CLIENT_SECRET: ${PAYPAL_CLIENT_SECRET}

volumes:
  licence-data:
```

> **`.env` only reaches the container through `${...}`.** A `.env` file beside
> the compose file feeds *variable substitution*, not the container's
> environment — so a value sitting in `.env` with no `${...}` naming it in the
> compose file is read by nobody, and the service starts as if you never set it.
> That is how `ADMIN_PASSWORD_HASH` ends up in `.env` while the log still says
> `admin page: off`.
>
> Either use `${...}` as above, or add `env_file: .env` to the service and drop
> the lines entirely. Not neither.

Single quotes around the JWK — it contains `"` and `:`.

That is the minimum that runs. `service/docker-compose.yml` has the same thing
with the hardening on it — read-only root filesystem, dropped capabilities,
memory and process limits — and comments explaining each. Take that one for a
real deployment.

> **Why a named volume.** A bind mount arrives owned by whoever owns it on the
> host — root, unless somebody remembered `chown -R 5678:5678`. Nothing in the
> container can fix that, and the first start dies with SQLite error 14,
> `unable to open database file`. A named volume is initialised by Docker from
> the image, ownership included, so it just works.
>
> If you want the data at a path you choose, a bind mount still works — use
> `- /srv/emby-sso/data:/data` and run `sudo chown -R 5678:5678
> /srv/emby-sso/data` **before** the first start.
>
> Either way, backups come from `/admin/backup`, which does not care which you
> picked.

**And copy the key up**, so the service can sign. From the machine that holds
it:

```
scp ~/emby-sso-licence/licence-signing-key.private.json you@server:/tmp/key.json
```

Then on the server, in one step so it is never briefly world-readable:

```
sudo mkdir -p /srv/emby-sso/secrets && sudo chmod 700 /srv/emby-sso/secrets
sudo install -o 5678 -g 5678 -m 600 /tmp/key.json \
  /srv/emby-sso/secrets/licence-signing-key.private.json
shred -u /tmp/key.json
```

Add to the compose service:

```yaml
    volumes:
      - /srv/emby-sso/secrets/licence-signing-key.private.json:/run/secrets/licence-signing-key.private.json:ro
      - licence-data:/data
    environment:
      LICENCE_SIGNING_KEY_PATH: /run/secrets/licence-signing-key.private.json
```

**The service refuses to start if any permission bit beyond the owner's is
set.** That is deliberate and not fixed for you: a key that has been
group-readable on a shared machine should be treated as leaked, not chmod-ed
quietly.

*Prefer to keep the key off the server?* Leave both of those out. Everything
else works; activation queues instead of completing, and you sign at
`/admin/signing`.

There is no `:latest` until a `vX.Y.Z` release is tagged — use `main` before
your first release.

---

## 3. Start it

The admin page is where signing happens, so set a password first:

```
read -rs ADMIN
printf '%s' "$ADMIN" | docker compose run --rm -T licence hash-password
unset ADMIN
```

`read -rs` does not echo what you type and does not put it in your shell
history. It prints one line:

```
ADMIN_PASSWORD_HASH=pbkdf2-sha256.210000.Bgx...==.DV3...=
```

Put that line in `.env` — and make sure the compose file names it, per the note
in step 2, or nothing reads it.

The fields are separated by `.` rather than the `$` that crypt-style hashes
usually use, deliberately: **Docker Compose reads `$210000` inside a value as a
variable name**, substitutes the empty string, and hands the service a hash with
holes in it. A hash that cannot contain `$` cannot be mangled that way. If you
have an older `$`-separated one it still works — it just could not survive being
pasted into a compose file.

Interactively instead of piped: `docker compose run --rm licence hash-password`,
then type the password, press enter, then **Ctrl-D**. It reads to end-of-input,
so enter alone looks like it has hung.

Use a long random password from your password manager. Sixteen characters is the
floor the service accepts, not advice.

```
docker compose pull licence
docker compose up -d licence
docker compose logs -f licence
```

**Working looks like:**

```
signing: AUTOMATIC with key <your key id> - the private key is loaded by this process
signer: ON. Licences are signed automatically with key <your key id>, every 2s.
Trusted licence keys: <your key id>
admin page: on at /admin, ...
```

Without the key mounted the first line reads `signing: off - this service cannot
sign; licences are signed elsewhere and uploaded at /admin/signing`, which is
the other supported arrangement and not an error.

Check it: `curl -s https://<your host>/healthz` → `"trustedKeys":"<your key id>"`.
That must be the key id from step 1.

### If it exits 78

It is misconfigured, and lists every problem at once:

| It says | Fix |
|---|---|
| `the signing key at ... is readable or writable by accounts other than its owner` | `sudo install -o 5678 -g 5678 -m 600` it, per step 2. Treat a key that was group-readable on a shared box as leaked |
| `No signing key at ...` | The mount names a path that is not there. It must name the FILE, not the directory |
| `LICENCE_PUBLIC_KEYS is not set` | Step 2 — the public JWK from step 1 |
| `...carries PRIVATE key material` | You pasted the key *file*; it wants the printed public JWK |
| `unable to open database file` | The message names the uid it is running as and whether the directory is writable. Easiest fix is a named volume (step 2); with a bind mount, `chown -R <that uid>` the **host** directory |
| `PAYPAL_WEBHOOK_ID` / `PAYPAL_PRICE` missing | Step 2 |
| `LICENCE_BACKUP_PASSPHRASE is shorter than 16` | Generate a real one |

### Reaching it

**`https://<your LICENCE_PUBLIC_BASE_URL>/admin`** — for example
`https://license.koper.cloud/admin`.

- **It must be HTTPS.** The session cookie is `Secure`, so over plain `http://`
  the browser discards it and you bounce back to the login form having
  apparently typed the password wrong. (`http://localhost` is the one exception
  most browsers make, which is what makes the SSH tunnel below work.)
- **The container listens on 127.0.0.1 only**, so the reverse proxy that already
  serves your public base URL has to forward `/admin` too. No proxy? Reach it
  over a tunnel instead: `ssh -L 8080:127.0.0.1:8080 you@host`, then
  `http://localhost:8080/admin`.
- **A 404 means the password is not set.** `/admin` answers exactly what
  `/nonsense` answers when `ADMIN_PASSWORD_HASH` is unset — there is no route,
  no login form and no hint that there could be. The startup log says which:
  `admin page: on at /admin, ...` or `off (no ADMIN_PASSWORD_HASH)`.
- **Behind a proxy, set `LICENCE_TRUSTED_PROXY_HOPS: 1`.** Otherwise every
  request looks like it came from the proxy, which throttles all callers
  together and fills the audit trail with one address.

Once in, the navigation is Codes, Issue a code, Signing, Outbox, Audit and
Backup. The number beside **Signing** is how many people are waiting for a
licence.

---

## 4. Prove it end to end

Do this once now, so the first activation is not a customer's.

**a. Make a code** — no payment involved. It prints once; copy it.

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll \
  issue-code --licensee "me, testing" --days 30
```

**b. Redeem it** in Emby: plugin configuration → paste the code → **Activate**.

It should say **Activated** within a few seconds. The service signs the licence
as the request waits, so one press is enough.

**c. Check the licence area** now reads `Active until <date>` with the
activation count beside it.

### If it says "being issued" instead

The request was recorded and the signer did not answer in time. Either it is not
running — the startup log says `signing: off` — or it failed, and the log says
so. Press Activate again; the code is not used up, and nothing is lost.

You can also sign by hand at any time, whether or not the signer is on:
`/admin` → **Signing** → Download → `licencetool sign` → Upload.

## After that

| I want to | Do this |
|---|---|
| See who bought what | `/admin` → Codes |
| Look up one customer | `/admin` → find |
| Stop a code working | `/admin` → Void. **It cannot recall a licence already issued** |
| Give somebody a free licence | `issue-code`, then step 4 |
| Sign what is waiting | Nothing, if the signer is on. Otherwise `/admin` → Signing |
| Take a backup | `/admin` → Backup. Keep it somewhere that is not this machine |
| Read a backup back | `restore --in <file> --out <empty dir>` with the passphrase in force **when it was taken** |

**Back up the data directory.** Nothing else can rebuild who bought what — not
PayPal, not the plugin, not your signing machine.

Every command above is
`docker compose exec licence dotnet Emby.Sso.LicenceService.dll <command>`.

---

Full detail on every setting and endpoint: [`service/README.md`](../README.md),
[`service/.env.example`](../.env.example).

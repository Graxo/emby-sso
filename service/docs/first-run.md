# First run

Four steps: make a key, configure, start, sign a licence.

**Two machines.** Keeping them apart is the point:

- **your machine** — holds the signing key, signs licences, accepts no connections
- **the server** — runs the service. **No signing key on it.** It refuses to start if you give it one.

Why: [Signing licences offline](../../docs/site/offline-signing.md). You do not
need it to follow this page.

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

**And remove any signing key.** The service will not start while one is
configured:

```
grep -rn LICENCE_SIGNING_KEY_PATH .          # compose file AND .env
```

Delete the variable, delete the volume line that mounts
`licence-signing-key.private.json`, then delete the file:

```
rmdir licence-signing-key.private.json 2>/dev/null \
  || shred -u licence-signing-key.private.json
```

(Docker creates a *directory* at a bind-mount source that does not exist, so
after deleting the key you may find a stray directory with that name.)

There is no `:latest` yet — it only exists once a `vX.Y.Z` release is tagged.
Use `main`.

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
THIS SERVICE CANNOT SIGN - no private key is loaded, by design.
Trusted licence keys: <your key id>
admin page: on at /admin, ...
```

Check it: `curl -s https://<your host>/healthz` → `"trustedKeys":"<your key id>"`.
That must be the key id from step 1.

### If it exits 78

It is misconfigured, and lists every problem at once:

| It says | Fix |
|---|---|
| `LICENCE_SIGNING_KEY_PATH is set` | Step 2 — grep the `.env` too, not just the compose file |
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

## 4. Sign a licence

Do this once now on a test code, so the first time is not while somebody waits.

**a. Make a code** — no payment involved. It prints once; copy it.

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll \
  issue-code --licensee "me, testing" --days 30
```

**b. Redeem it** in Emby: plugin configuration → paste the code → **Activate**.

You get *"Your licence has been requested and is being issued."* That is
correct, not an error, and the code is not used up.

**c. Download it** — `/admin` → **Signing** → **Download**. The number beside
*Signing* is how many people are waiting.

**d. Sign it, on your machine:**

```
cd ~/Downloads
tools/Emby.Sso.LicenceTool/licencetool.sh sign \
  --requests /work/emby-sso-signing-requests.json \
  --key /keys/licence-signing-key.private.json
```

**e. Upload** the `-signed.json` file on the same Signing page.

**f. Press Activate again** in Emby → *Activated.*

Then delete the signed file. Until it is uploaded it is the only copy of those
licences; afterwards it is somebody else's credentials in your downloads.

**If the upload is refused** with *"signed by a key this service does not
trust"*: `LICENCE_PUBLIC_KEYS` on the server and the key you signed with are
different. Compare `/healthz` with what `sign` printed.

---

## After that

| I want to | Do this |
|---|---|
| See who bought what | `/admin` → Codes |
| Look up one customer | `/admin` → find |
| Stop a code working | `/admin` → Void. **It cannot recall a licence already issued** |
| Give somebody a free licence | `issue-code`, then step 4 |
| Sign what is waiting | Step 4, c–f |
| Take a backup | `/admin` → Backup. Keep it somewhere that is not this machine |
| Read a backup back | `restore --in <file> --out <empty dir>` with the passphrase in force **when it was taken** |

**Back up the data directory.** Nothing else can rebuild who bought what — not
PayPal, not the plugin, not your signing machine.

Every command above is
`docker compose exec licence dotnet Emby.Sso.LicenceService.dll <command>`.

---

Full detail on every setting and endpoint: [`service/README.md`](../README.md),
[`service/.env.example`](../.env.example).

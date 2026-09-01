# First run: a step-by-step guide

Nine steps, in order. Each says what to do, what success looks like, and the one
thing that usually goes wrong.

**Two machines, and keeping them apart is the whole design:**

| | |
|---|---|
| **your machine** | Holds the signing key. Signs licences. Accepts no connections. |
| **the server** | Runs the service. Takes payments, records activations, hands out already-signed licences. **Has no signing key on it.** |

The reasoning is in [Signing licences offline](../../docs/site/offline-signing.md).
You do not need to read it to follow this page.

---

## Step 1 — Generate your signing key

**On your machine, not the server.** You need Docker; you do not need the .NET
SDK.

```
git clone <this repository>
cd emby-sso
tools/Emby.Sso.LicenceTool/licencetool.sh keygen --out /keys
```

Inside the container, `/keys` is `~/emby-sso-licence` on your machine. The
command writes `licence-signing-key.private.json` there, mode 600, and prints
two things you need:

- the **public JWK** — one line starting `{"kty":"RSA"`
- the **key id** — 16 hex characters

**Success:** a private key file on disk, a public JWK on screen.

**Next:** that public JWK goes in two places, and they must match — compiled
into the plugin build (`src/Emby.Sso/Protocol/LicencePublicKey.cs`), and set on
the server in step 4.

> **Back the private key up now**, encrypted, somewhere that is not the server.
> Losing it means never issuing another licence for any plugin build carrying
> the matching public key. It is deliberately **not** in the service's backup,
> because it is not on the server at all.

**What goes wrong:** running it as root. The tool refuses a key readable by
anyone but its owner, so a root-owned key fails on the next run in a way that
looks like corruption. `licencetool.sh` runs as you — do not `sudo` it.

---

## Step 2 — Prepare the server's data directory

The container runs as **uid 5678** and cannot change file ownership, so the host
has to be right first.

```
sudo mkdir -p /srv/emby-sso/data
sudo chown -R 5678:5678 /srv/emby-sso/data
```

Put the volume wherever suits the host — a relative `./data` beside the compose
file is fine. **Whatever you choose, uid 5678 must own it.**

**Success:** `ls -ln /srv/emby-sso` shows `5678 5678` on `data`.

**What goes wrong:** it is owned by root, and the service dies with `unable to
open database file`. Being readable is not enough: SQLite creates the database
*and* its `-wal` and `-shm` siblings, so the directory itself must be writable.

---

## Step 3 — Make sure no signing key is on the server

**The service refuses to start if one is configured.** It does not ignore the
setting — a key that is still mounted is still stealable whether or not anything
reads it.

Find every trace:

```
grep -rn LICENCE_SIGNING_KEY_PATH /docker-data/compose/    # wherever your compose lives
```

Check the compose file **and any `.env` beside it**. Remove both:

- the `LICENCE_SIGNING_KEY_PATH` environment line
- the volume line mounting `licence-signing-key.private.json`

Then the file itself:

```
cd <the configs directory>
rmdir licence-signing-key.private.json 2>/dev/null \
  || shred -u licence-signing-key.private.json
```

Docker creates a *directory* at a bind-mount source that does not exist, so
after deleting the key you may find a stray directory with that name — that is
what `rmdir` is for. If it is still a real file, `shred` it.

**Success:** `grep` finds nothing.

**What goes wrong:** removing the volume but not the variable. The mount error
disappears and the service then exits 78 quoting this step. Grep for both.

> **If a key was ever on this server, treat it as leaked.** It sat on a host
> that answers requests from the internet. See
> [Rotating and revoking a signing key](../../docs/site/key-rotation.md).

---

## Step 4 — Write the configuration

```
cp service/.env.example service/.env
chmod 600 service/.env
```

Fill in these. The service reports **every** problem at once and exits 78, so a
missing one costs one restart, not six.

| Variable | What it is |
|---|---|
| `LICENCE_PUBLIC_KEYS` | the **public** JWK from step 1. Not a secret. Must match the plugin build. Wrap it in single quotes — it contains `"` and `:` |
| `LICENCE_DATA_DIR` | `/data` — the path *inside* the container |
| `LICENCE_PUBLIC_BASE_URL` | the https address the plugin has compiled in, e.g. `https://license.koper.cloud` |
| `PAYPAL_ENV` | `sandbox` until a real purchase has been tested end to end |
| `PAYPAL_CLIENT_ID` / `PAYPAL_CLIENT_SECRET` | from the PayPal developer dashboard |
| `PAYPAL_WEBHOOK_ID` | from the webhook you create there. PayPal signs it into every message, so a wrong value fails every webhook closed |
| `PAYPAL_CURRENCY` / `PAYPAL_PRICE` | what you are charging |
| `LICENCE_BACKUP_PASSPHRASE` | 16+ characters — `openssl rand -base64 32`. Turns on encrypted backups. **Set it before you have customers, not after** |
| `ADMIN_PASSWORD_HASH` | from step 8. Signing licences goes through the admin page, so you need this |

Secrets go in `.env` (mode 600), never in the compose file — that is the file
most likely to end up in a repository.

---

## Step 5 — Log in to the registry

CI pushes the image to `registry.koper.local:5050`. The project is private, so
pulling needs credentials — and the server must never hold one that can write.

In GitLab: *Settings → Repository → Deploy tokens* on `Graxo/emby-sso`. Name it
after this host, tick **`read_registry` and nothing else**, set an expiry. The
password is shown once.

```
docker login registry.koper.local:5050 -u <token-username> --password-stdin
```

**Success:** `Login Succeeded`.

**What goes wrong:** using a personal access token instead. It works — and it
can push, which means the host now holds a credential that can replace the image
it runs.

---

## Step 6 — Start it

Set the image tag first:

```yaml
image: registry.koper.local:5050/graxo/emby-sso/licence-service:main
```

> **There is no `:latest` until a `vX.Y.Z` release is tagged.** Pulling it before
> then fails with `manifest unknown`, which reads like a broken registry and is
> not one. Use `main` until the first release, then pin a version.

```
docker compose pull licence
docker compose up -d licence
docker compose logs -f licence
```

**Success** — the log opens with:

```
THIS SERVICE CANNOT SIGN - no private key is loaded, by design.
Trusted licence keys: <your key id>
admin page: on at /admin, ...
encrypted backups: on, downloadable from /admin/backup
```

**If it exits 78** it is misconfigured, and every problem is listed at once:

| It says | Do this |
|---|---|
| `LICENCE_SIGNING_KEY_PATH is set` | Step 3 — it is still somewhere. Grep the `.env` too |
| `LICENCE_PUBLIC_KEYS is not set` | Step 4 — it is the public JWK from step 1 |
| `LICENCE_PUBLIC_KEYS ... carries PRIVATE key material` | You pasted the key *file*, not the printed public JWK |
| `unable to open database file` | Step 2 — `chown -R 5678:5678` the **host** directory |
| `PAYPAL_WEBHOOK_ID` / `PAYPAL_PRICE` missing | Step 4 |
| `LICENCE_BACKUP_PASSPHRASE is shorter than 16` | Generate a real one |

---

## Step 7 — Check it works

```
curl -s https://<your host>/healthz
```

**Success:** `{"status":"ok","trustedKeys":"<your key id>", ...}`

That key id must be the one from step 1. If it is not, the server and your
signing machine disagree, and every licence you sign will be refused at upload.

---

## Step 8 — Turn on the admin page

You need it: signing licences and taking backups both go through it.

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll hash-password
```

Type the password and press enter — it is read from stdin, so it never reaches
your shell history or the process list. Put the printed
`ADMIN_PASSWORD_HASH=...` line in `.env` and restart.

Use a long random password from your password manager. Sixteen characters is the
floor the service accepts, not advice.

### Put something in front of it

Optional, both off by default, both fail closed. A request that fails either
gets a **404** — the page does not exist rather than refusing, so a scanner
learns nothing.

```
ADMIN_ALLOWED_CIDRS=203.0.113.4/32, 10.0.0.0/8
ADMIN_REQUIRED_HEADER=X-From-The-Proxy
ADMIN_REQUIRED_HEADER_VALUE=<a long generated secret>
```

Two traps:

- **`ADMIN_ALLOWED_CIDRS` depends on `LICENCE_TRUSTED_PROXY_HOPS`.** Behind a
  reverse proxy with it at `0`, every request looks like it came from the proxy
  — so either everyone is allowed or nobody is. Set the hop count first and
  check the log shows real client addresses.
- **Your proxy must strip `ADMIN_REQUIRED_HEADER` from incoming requests.** A
  header a client can set is not a check, and nothing here can enforce that.

The startup line says which are on, and `PASSWORD ONLY` when neither is.

---

## Step 9 — Sign your first licence

The whole round trip. Do it now on a test code, so the first time is not while a
customer waits.

**a. Make a code** — no payment involved:

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll \
  issue-code --licensee "me, testing" --days 30
```

It prints the code **once**. Copy it.

**b. Redeem it** in Emby: plugin configuration → paste the code → **Activate**.
You get:

> Your licence has been requested and is being issued.

That is correct, not an error, and the code is not used up.

**c. Download it:** `/admin` → **Signing** → **Download**. The number beside
*Signing* is how many customers are waiting.

**d. Sign it, on your machine:**

```
cd ~/Downloads
tools/Emby.Sso.LicenceTool/licencetool.sh sign \
  --requests /work/emby-sso-signing-requests.json \
  --key /keys/licence-signing-key.private.json
```

**e. Upload** the `-signed.json` file on the same Signing page. Each licence is
checked — right key, right server, right dates — before it is stored.

**f. Press Activate again** in Emby. It says *Activated.*

Then **delete the signed file.** Until it is uploaded it is the only copy of
those licences; afterwards it is somebody else's credentials in your downloads.

**What goes wrong:** the upload is refused with *"signed by a key this service
does not trust"*. The server's `LICENCE_PUBLIC_KEYS` and the key you signed with
differ — compare `/healthz` with what `sign` printed.

---

## Day to day

| I want to | Do this |
|---|---|
| See who bought what | `/admin` → Codes, or `list-codes` |
| Look up one customer | `/admin` → find, or `show-code --code <as they typed it>` |
| Stop a code working | `/admin` → Void, or `void-code`. **It cannot recall a licence already issued** |
| Give somebody a free licence | `issue-code`, then step 9 |
| Sign what is waiting | Step 9, parts c–f. Watch the Signing badge |
| Take a backup | `/admin` → Backup. Put it somewhere that is not this machine |
| Read a backup back | `restore --in <file> --out <empty dir>`, with the passphrase in force **when it was taken** |
| See a code that was emailed | `/admin` → Outbox |
| See who logged in | `/admin` → Audit |

Every command above runs as
`docker compose exec licence dotnet Emby.Sso.LicenceService.dll <command>`.

**Back up the data directory.** Nothing else can rebuild who bought what — not
PayPal, not the plugin, not your signing machine.

---

## Reference

- [Signing licences offline](../../docs/site/offline-signing.md) — why the key is not here
- [Rotating and revoking a signing key](../../docs/site/key-rotation.md) — when one leaks
- [`service/README.md`](../README.md) — every variable, every endpoint, and the reasoning
- [`service/.env.example`](../.env.example) — every setting with its default

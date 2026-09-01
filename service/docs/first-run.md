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

Own the data directory. The container runs as **uid 5678** and cannot chown
anything itself:

```
sudo mkdir -p /srv/emby-sso/data
sudo chown -R 5678:5678 /srv/emby-sso/data
```

Then, in your compose file or the `.env` beside it:

```yaml
image: registry.koper.local:5050/graxo/emby-sso/licence-service:main

environment:
  LICENCE_DATA_DIR: /data
  LICENCE_PUBLIC_KEYS: '<the public JWK from step 1>'
  LICENCE_PUBLIC_BASE_URL: https://license.koper.cloud
  LICENCE_BACKUP_PASSPHRASE: <openssl rand -base64 32>
  ADMIN_PASSWORD_HASH: <from step 3>
  PAYPAL_ENV: sandbox
  PAYPAL_WEBHOOK_ID: <from the PayPal dashboard>
  PAYPAL_CLIENT_ID: <...>
  PAYPAL_CLIENT_SECRET: <...>
  PAYPAL_CURRENCY: GBP
  PAYPAL_PRICE: "19.00"

volumes:
  - /srv/emby-sso/data:/data
```

Single quotes around the JWK — it contains `"` and `:`.

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
docker compose run --rm licence hash-password
```

Type the password, press enter, then **Ctrl-D**. It reads to end-of-input, so
enter alone looks like it has hung.

Put the printed `ADMIN_PASSWORD_HASH=...` line in your `.env`. Use a long random
password from your password manager — 16 characters is the floor it accepts, not
advice.

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
| `unable to open database file` | `chown -R 5678:5678` the **host** directory |
| `PAYPAL_WEBHOOK_ID` / `PAYPAL_PRICE` missing | Step 2 |
| `LICENCE_BACKUP_PASSPHRASE is shorter than 16` | Generate a real one |

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

# Standing the service up for the first time

Everything below runs on the machine that will host the service.

**Read step 1 before you copy anything anywhere.** The signing key does not go
on this machine, and if a previous version of this document had you put one
there, that key has to be treated as leaked.

---

## 1. The signing key stays where it is

**The key does not go on this server, and this service refuses to start if you
tell it one is there.**

That is a change from an earlier version of this document, which had you copy
the private key onto the host and mount it read-only. It was wrong. That key
mints a valid licence for **any** Emby server, for any duration, and nothing
recalls one — the plugin verifies offline and never calls home. Putting it on a
machine with a port open to the internet meant every other control here (rate
limits, the admin password, the webhook signature check, the container
hardening) was a wall around it, and any single failure of any one of them lost
it completely and silently.

**If you followed the old instructions, that key is compromised.** Treat it as
public: generate a new one, add its public half to the plugin build alongside
the old one, reissue, and drop the old one in a later release. See
[Rotating and revoking a signing key](../../docs/site/key-rotation.md).

### What happens instead

The service records what has been paid for and hands it to you as a file. You
sign it on a machine of your choosing and upload the result. The whole round
trip is in [Signing licences
offline](../../docs/site/offline-signing.md); the short version is three steps
on the `/admin/signing` page and one `licencetool sign` in between.

The visible cost is that a customer's **first** activation is not instant — they
are told their licence is being issued and press Activate again shortly. Repeat
activations are immediate.

### If you have never generated a key

On your own machine, **not on this server**:

```
export DOTNET_ROOT=$HOME/.dotnet
dotnet run --project tools/Emby.Sso.LicenceTool -- keygen --out ~/emby-sso-licence
```

That writes `~/emby-sso-licence/licence-signing-key.private.json` (mode 600),
and prints the public JWK and its key id. The public half goes into
`TrustedJwks` in `src/Emby.Sso/Protocol/LicencePublicKey.cs` and is compiled
into the plugin. **The private half stays on that machine.**

**Back it up**, somewhere encrypted and away from this server. Losing it is as
bad as leaking it, in the other direction: you can never issue another licence
for any build carrying the matching public key, and it is deliberately *not* in
the service's encrypted backup, because it is not on that machine at all.

### What this server needs instead

`LICENCE_PUBLIC_KEYS` — the **public** half, or a JSON array of several during a
rotation. It is not a secret; it is the same value that is compiled into the
plugin. It is what lets the service check a signed licence before storing it, so
that a wrong key or a wrong file is caught on your screen rather than on a
customer's server. The service refuses to start if it carries private material.

---

## 2. Create the directories

The container runs as **uid 5678** and cannot change file ownership, so the host
has to get it right.

```
sudo mkdir -p /srv/emby-sso/secrets /srv/emby-sso/data
sudo chown 5678:5678 /srv/emby-sso/data
sudo chmod 700 /srv/emby-sso/secrets
```

`/srv/emby-sso/data` holds the SQLite store, the ledger of who bought what, and
the outbox of codes waiting to be emailed. **Back it up.** Losing it loses your
record of every customer.

!!! warning "Whichever directory you mount, uid 5678 must own it"
    These paths are only a suggestion — mount the data volume wherever suits the
    host, including a relative `./data` beside the compose file. But **the host
    directory you mount must be owned by uid 5678**, whatever it is called.

    It is not enough for the container to be able to read it. SQLite creates the
    database *and* its `-wal` and `-shm` siblings, so the directory itself has to
    be writable, and the service runs as a non-root user that cannot chown it.

    Getting this wrong is the most likely first failure, and until recently the
    only symptom was `SQLite Error 14: 'unable to open database file'` over eight
    frames of ADO.NET that named neither the directory nor the user. The service
    now says which directory and which uid instead.

---

## 3. Make sure no key is on the server

If an earlier deployment mounted one, remove it now — the variable AND the
volume AND the file:

```
# In docker-compose.yml: delete the LICENCE_SIGNING_KEY_PATH line and the
# /srv/emby-sso/secrets/... volume. Then, on the host:
sudo shred -u /srv/emby-sso/secrets/licence-signing-key.private.json
sudo rmdir /srv/emby-sso/secrets 2>/dev/null || true
```

The service will not start while `LICENCE_SIGNING_KEY_PATH` is set. It does not
ignore the variable, because a key that is still mounted is still stealable
whether or not anything reads it — and an operator who believes this host signs
licences will not think to look for the key elsewhere.

**And treat that key as compromised.** It sat on an internet-facing host. See
[Rotating and revoking a signing key](../../docs/site/key-rotation.md) for what
that costs and how to do it while nothing is wrong.

---

## 4. Configure

Start from `service/.env.example` — it lists every variable the service reads,
with the defaults, and the values a real first run was verified with:

```
cp service/.env.example service/.env
chmod 600 service/.env
```

Then copy the compose block from `service/docker-compose.yml` into whatever
compose file this host already uses. The values that must be set:

| Variable | What it is |
|---|---|
| `LICENCE_PUBLIC_KEYS` | the **public** licence key or keys the plugin build trusts — one JWK, or a JSON array of them during a rotation. Not a secret; it is the same value that is in `LicencePublicKey.cs`. The service refuses to start without it, and refuses to start if it carries private key material |
| `LICENCE_PUBLIC_BASE_URL` | the address the plugin has compiled in, e.g. `https://license.koper.cloud`. It must match, or the buy links point nowhere |
| `PAYPAL_ENV` | `sandbox` until you have tested a real purchase end to end |
| `PAYPAL_CLIENT_ID` / `PAYPAL_CLIENT_SECRET` | from the PayPal developer dashboard |
| `PAYPAL_WEBHOOK_ID` | from the webhook you create in that dashboard. PayPal signs it into every message, so a wrong value fails every webhook closed |
| `PAYPAL_CURRENCY` / `PAYPAL_PRICE` | what you are charging |
| `PAYPAL_MINIMUM_AMOUNT` | the floor a captured payment must clear. **Defaults to `PAYPAL_PRICE`**, so setting `PAYPAL_PRICE` is enough — but if neither is set the service refuses to start, because without a floor a captured payment of any size, a penny included, would buy a licence |

Secrets belong in a `.env` file beside the compose file (mode 600), or in
whatever secret store the host already uses — not in the compose file itself,
which is the file most likely to end up in a repository.

Email is **off** until `SMTP_HOST` is set, and off is a working configuration:
paid codes land in `/srv/emby-sso/data/codes-outbox.jsonl` and you send them by
hand. See `email-delivery-checklist.md` before trusting a real send.

The admin page is **off** until `ADMIN_PASSWORD_HASH` is set, and off means
there is no `/admin` at all — no login form, no route. Leave it off until you
have read step 10. **You now need it on**, because signing licences goes through
it — but read that section first, including `ADMIN_ALLOWED_CIDRS` and
`ADMIN_REQUIRED_HEADER`, which put something in front of the password.

Set `LICENCE_BACKUP_PASSPHRASE` too, before you have any customers rather than
after. It turns on `/admin/backup`, which is the only thing that can rebuild who
bought what if this volume is lost — nothing else can, not PayPal, not the
plugin, not the signing machine. There is no unencrypted option, and reading a
backup back needs the passphrase that was in force when it was **taken**, so
keep it somewhere other than beside the backups and do not change it casually.

---

## 5. Start it

**Pick a host port first.** The container listens on 8080 inside, but 8080 is a
popular number — on the machine this was first run on it was already taken by
sabnzbd, and the failure is `Bind for 0.0.0.0:8080 failed: port is already
allocated`. Check before you start, and change the left-hand side of the port
mapping if it is busy:

```
ss -tln | grep ':8080 ' && echo "8080 is taken, pick another"
```

### Log in to the registry, once

CI builds the image and pushes it to `registry.koper.cloud`, so this host never
needs a copy of the source. The project is **private**, so the pull needs
credentials of its own — the host must not be given a personal access token or
anything that can write.

Create a **deploy token** in GitLab: *Settings → Repository → Deploy tokens*,
on the `Graxo/emby-sso` project. Name it after this host, tick **`read_registry`
and nothing else**, and leave the expiry set — a token with no expiry is a
credential nobody ever revokes. GitLab shows the password **once**.

```
docker login registry.koper.cloud -u <token-username> --password-stdin
```

Paste the token password and press Ctrl-D. Treat it as a credential: it is a
password to your registry, it is written in clear in `~/.docker/config.json`
(base64 is not encryption), so the file must be `chmod 600` and owned by the
user that runs compose. If it leaks, revoke the token in GitLab — that is the
whole point of it being a deploy token rather than a personal one. When it
expires, the failure is `docker compose pull` returning `unauthorized:
authentication required`; make a new one the same way.

### Pull and start

```
docker compose pull licence
docker compose up -d licence
docker compose logs -f licence
```

`docker compose pull` fetching the image is the proof the login worked. Later
updates are the same two lines — pull, then up — and `docker compose up -d`
recreates the container only if the image actually changed.

If the registry is unreachable, or you are testing an uncommitted change, the
alternative is still there: uncomment `build:` in the compose file, comment out
`image:`, put the source on this host and run `docker compose up -d --build
licence`. That is the old way of doing it, kept deliberately, not the normal
one.

**UNVERIFIED, and worth watching the first time:** no image has ever been built
by CI, pushed to that registry, or pulled onto this host. The `docker login`
and `docker compose pull` above are the two commands that prove it; if either
fails, nothing has been deployed and the build path above still works.

A healthy first start logs the key it loaded (by fingerprint, never contents),
the data directory, the PayPal environment, and whether mail is on. Then:

```
curl -fsS http://127.0.0.1:8080/healthz && echo OK
```

The container publishes to `127.0.0.1:8080` on purpose — it holds your signing
key and should only be reachable through the reverse proxy that terminates TLS,
never directly from the network. Point your proxy's vhost for the hostname in
`LICENCE_PUBLIC_BASE_URL` at that address.

**The plugin requires HTTPS** and does not follow redirects, so the proxy must
serve the activation path directly with a valid certificate. An `http → https`
redirect at the proxy is refused by the plugin, not followed.

---

## 6. When it refuses to start

Every configuration refusal exits **78** and says which setting on the way out.
The common ones:

| What you see | What it means |
|---|---|
| the key file is not readable | wrong path, or not owned by uid 5678 |
| the key is readable by more than its owner | `chmod 600` it — and consider it leaked if it was ever otherwise |
| the key file could not be parsed | you copied the *public* key, or a truncated file |
| a required PayPal value is missing | see the table above |
| an SMTP setting is invalid | mail configuration is checked at startup, so a typo stops the service rather than silently never sending. Unset `SMTP_HOST` to fall back to the outbox |

A failure here is a refusal to start, not a running service quietly doing the
wrong thing. That is the intended trade.

---

## 7. Codes for testers, comps, and rescues

You do not need a payment to create a redemption code:

```
docker compose exec licence \
  dotnet /app/Emby.Sso.LicenceService.dll issue-code \
  --licensee "Tester - discord handle" --days 30
```

It prints the code once, stores only its hash, and records it in the same ledger
a paid code goes to. Use it for testers, for a comp, or to rescue a sale whose
code could not be delivered. `--activations` overrides how many servers it may
be re-bound to.

---

## 8. Running it day to day

These are the commands you will actually type. All of them are on the same
binary and all take `docker compose exec`. Everything here is also available as
a page in a browser — see step 10 — which is **off** until you turn it on. Set
this alias once and the rest of the page is short:

```
alias licence='docker compose exec licence dotnet /app/Emby.Sso.LicenceService.dll'
```

**Who has a code, and does anything need me?**

```
licence list-codes
licence list-codes --needs-attention
```

```
STATE        CREATED     TAG           SOURCE  USED  DAYS  EXPIRES     FOR
UNDELIVERED  2026-08-20  c3b3474f27d5  paypal  0/3   365   -           buyer@example.com
LAPSING      2025-09-14  4d1e8a77c003  paypal  1/3   365   2026-09-14  someone@example.com
unused       2026-08-31  1c9d40e6b8aa  manual  0/3   30    -           Tester - discord handle
active       2026-02-02  55e0c1a9d7f3  paypal  1/3   365   2027-02-02  happy@example.com
```

Shouted states want you; quiet ones do not. `UNDELIVERED` is the one that
matters most — somebody has paid and has nothing. Sorted so that is at the top.
`--for acme` finds one customer by name, address or tag.

**"My code does not work."** Ask them to paste it and put it straight through,
in whatever shape it arrives — any case, with or without the hyphens, spaces
instead of hyphens, `O` typed for zero:

```
licence show-code --code 'mh97k d1jp7 fc223 583r5 rdmm3 1d1hc'
```

It tells you whether the code is real, whether it is paid, spent, exhausted,
lapsed or voided, and lists every Emby server it has been activated onto with
dates. If it says *not a well-formed code*, they mistyped it; if it says *this
store has never held it*, they did not buy it here.

**I refunded someone.**

```
licence void-code --tag c3b3474f27d5 --reason 'refunded, PayPal case 12345'
```

!!! warning "Voiding does not take back a licence that has already been issued"
    The plugin checks its licence offline against a key compiled into it and
    never calls this service, so **a server that has already activated keeps
    working until the licence expires** — up to a year. Voiding stops the *next*
    activation and nothing else. The command prints this at you, with the number
    of servers already running on that code and the date they stop; read it
    before you close the ticket. The only thing that takes a running licence
    away is a new signing keypair and a new plugin build, which invalidates
    every other customer at the same time.

    A PayPal refund does exactly the same thing automatically, with the same
    limitation. This command is for the refunds PayPal does not tell you about.

**Did a code actually reach the person who paid?**

```
licence list-outbox
licence list-outbox --reveal    # prints the codes themselves
```

Everything you need to send one by hand. The codes are not in the plain listing
— they are in `/srv/emby-sso/data/codes-outbox.jsonl` in the clear, and
`--reveal` reads them back — so the plain listing is safe to screenshot.

**Send the code, then delete its line from that file.** With email off nothing
else marks it as sent, and a pruned line is both how these commands know a sale
is finished with and how a live credential stops sitting on your disk.

!!! note "No command can show you a code that was not in the outbox"
    The database stores a SHA-256 and never the code, so `list-codes` cannot
    print one and `show-code` can only confirm the one you hand it. If a code is
    lost, nothing recovers it: void it and issue another.

    `TAG` in these listings is the first twelve characters of that hash. It is
    what the log lines show as `code=`, and what `show-code --tag` and
    `void-code --tag` take.

If a command answers **"There is no licence store at ..."** it means exactly
that, and it created nothing — you are pointed at the wrong `LICENCE_DATA_DIR`,
or the service has never started. It will not invent an empty database for you
to misread as "no customers".

The last command is `healthcheck`, which is what the container's own HEALTHCHECK
runs.

---

## 9. Prove it works

1. `curl -fsS http://127.0.0.1:8080/healthz`
2. Open `https://<your host>/buy` in a browser — the purchase page renders
   without JavaScript.
3. Work through `paypal-sandbox-checklist.md` for a sandbox purchase, and
   `email-delivery-checklist.md` if you have turned mail on.

!!! warning "None of the PayPal or mail paths have ever run"
    The signature verification, order creation, certificate trust and every mail
    path are unverified against the real services — there were no credentials
    where this was written, and nothing simulated a success. The two checklists
    exist to close that, and they tell you the log lines to expect.

---

## 10. The admin page in a browser (now needed)

Everything in step 8 is also a page at `https://<your host>/admin`. It is **off
by default and there is no page at all until you set a password** — `/admin`
answers 404 exactly the way `/nonsense` does.

It used to be optional. It is not any more: **signing licences goes through it**
(`/admin/signing`), and so do encrypted backups (`/admin/backup`).

### What is behind it now, and what is not

The worst thing this page could once do is gone. It no longer sits in front of a
signing key, because there is no signing key on this host: whoever gets through
gets your customer list, the ability to hand out licences that are *already*
signed, and the ability to stop new ones being issued. They cannot mint one.
That is a large reduction and it is the whole point of
[Signing licences offline](../../docs/site/offline-signing.md).

It is still the customer list, and it is still on the public internet.

### Put something in front of the password

Both are optional, both off by default, both fail closed, and a request that
fails either gets a **404** — the page does not exist rather than refusing, so a
scanner learns nothing.

```
# Only from addresses you name. A bare address means that host.
ADMIN_ALLOWED_CIDRS=203.0.113.4/32, 10.0.0.0/8

# Or a header your own proxy adds, checked in constant time and BEFORE the
# password - so a caller who cannot produce it never costs this service a
# PBKDF2 verification.
ADMIN_REQUIRED_HEADER=X-From-The-Proxy
ADMIN_REQUIRED_HEADER_VALUE=<a long generated secret>
```

Two things to get right:

* **`ADMIN_ALLOWED_CIDRS` depends on `LICENCE_TRUSTED_PROXY_HOPS`.** Behind a
  reverse proxy with the hop count still at `0`, every request looks like it
  came from the proxy — so either everyone is allowed or nobody is. Set the hop
  count first, then check the log.
* **Your proxy must STRIP `ADMIN_REQUIRED_HEADER` from incoming requests.** A
  header a client can set is not a check, and nothing in this service can
  enforce that for you.

The startup line says which are on, and says `PASSWORD ONLY` when neither is:

```
admin page: on at /admin, ADMIN_PASSWORD_HASH, idle timeout 30m, absolute 480m;
  in front of it: PASSWORD ONLY - consider ADMIN_ALLOWED_CIDRS or ADMIN_REQUIRED_HEADER
```

The older advice still works and still costs nothing: bind the container to
`127.0.0.1` and reach it through `ssh -L 8080:127.0.0.1:8080 you@host`.

### Turn it on

```
licence hash-password
```

Type the password, press enter. It is read from **stdin**, so it does not reach
your shell history or the process list. You get one line:

```
ADMIN_PASSWORD_HASH=pbkdf2-sha256$210000$Xy...==$q7...=
```

Put it in `.env`, `docker compose up -d licence`, and open
`https://<your host>/admin`.

Use a long random password from your password manager, and keep it only there.
Sixteen characters is the minimum the service will accept; it is a floor, not
advice. There is no way to recover the password from the line above, and no way
to recover it from the service.

### Turn it off

Delete the `ADMIN_PASSWORD_HASH` line and restart. The routes stop existing.
Nothing else changes: the commands in step 8, the buy page and activation carry
on exactly as before.

### What to expect from it

* The same five jobs as step 8: list codes, show one, void one, issue one, and
  work through the outbox.
* **Signing**, which is where licences actually get made: download what is
  waiting, sign it with `licencetool sign` where the key lives, upload the
  result. The number beside it in the navigation is how many customers are
  waiting for a licence right now, and it is on every page for that reason.
  Each uploaded licence is checked against the terms this service recorded -
  right key, right server, right dates - before it is stored, so a wrong file is
  caught on your screen instead of on a customer's server.
* **Backup**, if `LICENCE_BACKUP_PASSPHRASE` is set: an encrypted copy of
  everything that cannot be rebuilt. Take one, put it somewhere that is not this
  machine, and read it back with
  `docker compose exec licence dotnet Emby.Sso.LicenceService.dll restore --in <file> --out <empty dir>`.
* **No code the store holds by hash is ever shown**, on any page. A code you
  *issue* is shown once, on the page straight after the form, and never again —
  copy it there and then. The same is true of reading one back out of the
  outbox.
* **Voiding tells you what it cannot do before you click**, not after: how many
  servers already hold a licence from that code and the date they stop working.
* Getting the password wrong buys a wait that doubles — two seconds, four,
  eight — and **never locks you out**, because you are the only person who could
  unlock it.
* Every sign-in, failed sign-in, issue and void is recorded in
  `/srv/emby-sso/data/admin-audit.jsonl` as well as in the log. It never holds
  a code or the password.

### If it will not let you in

* **The page loads but the password is refused, and you are sure it is right.**
  Check you have not set both `ADMIN_PASSWORD_HASH` and `ADMIN_PASSWORD` — the
  service refuses to start on that, so check `docker compose logs licence`.
* **The password is accepted and you land back on the login page.** The cookie
  is `Secure`, so the page only works over **https**. Reaching it over plain
  http means the browser never sends the session back.
* **`/admin` is a 404.** `ADMIN_PASSWORD_HASH` is not set in the environment the
  container actually has. `docker compose exec licence env | grep ADMIN_` will
  tell you.
* **The service will not start at all.** It says which variable and why; see
  step 6.

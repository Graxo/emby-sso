# Standing the service up for the first time

Everything below runs on the machine that will host the service. It assumes you
have already generated your signing keypair with the offline licence tool; if
you have not, start at step 1.

Read [the key is the whole business](#the-key-is-the-whole-business) before you
copy anything anywhere.

---

## 1. The signing key

**Use the key you already have.** The plugin has *one* public key compiled into
it, and only the matching private key can mint licences that plugin will accept.
Generating a new keypair here does not give you a second valid key — it gives
you a key that every already-released build refuses, and it invalidates every
licence you have issued, including any you are already testing with.

If you have never generated one, do it **on your own machine, not on the
server**, with the offline tool:

```
export DOTNET_ROOT=$HOME/.dotnet
dotnet run --project tools/Emby.Sso.LicenceTool -- keygen --out ~/emby-sso-licence
```

That writes `~/emby-sso-licence/licence-signing-key.private.json` (mode 600) and
prints the public key as one line of JSON. The public half goes into
`src/Emby.Sso/Protocol/LicencePublicKey.cs` and is compiled into the plugin. The
private half is what you are about to copy to the server.

### The key is the whole business

Until now this key has lived on a machine that does not accept connections. It
is about to live on one that does. That is a real change and it is worth being
deliberate about:

- Anyone who reads this file can mint unlimited licences for **any** Emby
  server, for any duration, and nothing you can do afterwards stops a licence
  that has already been issued — the plugin verifies offline and never calls
  home. The only remedy is a new keypair *and* a new plugin build, which
  invalidates every existing customer at once.
- So: this host should run this service and as little else as possible, and the
  key should exist on it in exactly one place, owned by one account, readable by
  nobody else.
- **Back it up before you copy it anywhere**, somewhere encrypted and not on
  this server. Losing it is as bad as leaking it, in a different direction: you
  can never issue another licence for any build carrying the matching public
  key.

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

## 3. Copy the key to the server

From the machine that holds the key:

```
scp ~/emby-sso-licence/licence-signing-key.private.json you@server:/tmp/key.json
```

Then on the server, put it in place with the right owner and mode, and remove
the copy you staged:

```
sudo install -o 5678 -g 5678 -m 600 /tmp/key.json \
  /srv/emby-sso/secrets/licence-signing-key.private.json
shred -u /tmp/key.json 2>/dev/null || rm -f /tmp/key.json
```

`install` sets ownership and permissions in one step, which matters: a file
created first and chmod-ed second is briefly readable by everyone.

**The service refuses to start if any permission bit beyond the owner's is
set.** That is deliberate and it is not fixed for you — a key that has already
been group-readable on a shared machine should be treated as one that leaked,
not one that needs a quieter `chmod`.

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

```
docker compose up -d --build licence
docker compose logs -f licence
```

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
binary, all take `docker compose exec`, and none of them is an HTTP endpoint —
there is no admin page on this service on purpose, because it holds your signing
key. Set this once and the rest of the page is short:

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

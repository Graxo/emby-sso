# The licence and purchase service

The vendor runs this. It sells licences for the Emby SSO plugin, and it is the
only thing on earth that can mint one.

```
buyer -> GET  /buy                     a page with a PayPal button
      -> POST /buy/start               creates a PayPal order, redirects to PayPal
      -> (PayPal)                      the buyer pays
PayPal -> POST /paypal/webhook         SIGNED. verified. creates one redemption code
vendor -> (sends the code to the buyer out of /data/codes-outbox.jsonl)
plugin -> POST /v1/activate            code + the Emby server id -> a signed licence
```

Licences are bound to one Emby server id, and a server id only exists at
activation time, so nothing can be pre-generated. That is why there is a
redemption code in the middle rather than a licence in the confirmation email.

**Read `tools/Emby.Sso.LicenceTool/README.md` first if you have not.** This
service is the offline tool with a shop attached, and it deliberately shares the
tool's signing logic and ledger format — see *One implementation, two front
ends*, below.

---

## The one thing to understand before deploying this

**This box holds the private signing key.** Until now that key lived offline, on
a laptop, and touched a network never. It is now on a machine with a port open
to the internet, because a service that mints licences on demand cannot do it
any other way.

An attacker who gets root on this box can:

- **read the signing key** — it is mounted read-only, which stops the container
  writing to it and stops nothing else. Root reads it in one `cat`;
- **mint unlimited licences, for any server id, with any expiry, forever.** Not
  until you notice: forever. The plugin verifies licences offline against a
  public key compiled into the assembly and never calls home, so there is no
  revocation, no CRL and no kill switch;
- **do it silently.** A licence minted with your key on their laptop leaves no
  trace here at all. The ledger only knows about licences this service issued;
- **read every redemption code that has not yet been delivered**, out of
  `/data/codes-outbox.jsonl`;
- **read the list of every customer and which servers they run**, out of
  `/data/licences.db` and the ledger. Not credentials, but a customer list.

**The only remedy is a new keypair, a new plugin release, and a reissued licence
for every customer you have.** Every licence ever issued with the old key stops
working the moment you ship a build with the new one; every customer has to
update. Plan for how you would do that before you need to.

What follows from that:

- **Run nothing else on this host.** No other site, no other container that can
  reach the Docker socket, no CI runner, no "just this one small thing". Every
  additional service on that box is another way to the key.
- **The container is the second line, not the first.** It runs as an
  unprivileged uid, read-only, with every capability dropped, and it still means
  that root on the host is game over. Compromise inside the container is enough
  to read the key too — it is mounted there.
- **Back the key up somewhere offline**, exactly as the offline tool's README
  says. Losing it is as bad as leaking it in a different direction: no further
  licence can ever be issued for the builds already in the field.
- **Keep the offline copy the master.** This service should get a copy of the
  key, not the only one.

---

## What the endpoints are

| | | |
| --- | --- | --- |
| `POST /v1/activate` | plugin → here | The contract. Code plus server id, in, signed licence out. |
| `GET /buy` | a person, in a browser | The page the plugin's config screen links to. |
| `POST /buy/start` | that page's button | Creates a PayPal order, 303s to PayPal. |
| `GET /buy/complete` | PayPal → the buyer | "Thank you." Never shows a code — see below. |
| `GET /buy/cancelled` | PayPal → the buyer | "Nothing was charged." |
| `POST /v1/checkout` | anything wanting JSON | The same as `/buy/start`, answering `{orderId, approveUrl}`. |
| `POST /paypal/webhook` | PayPal → here | **Signature verified.** The only thing that creates a code. |
| `GET /healthz` | your monitoring | Store writable, which key is loaded, sandbox or live. |

### `/v1/activate` — the contract

The request and response shapes are in the task's `contract.md` and are not
repeated here. Two things that document leaves to this side:

**Status codes.** The plugin keys on the `error` string, not the status, so
these can change without breaking it:

| `error` | status |
| --- | --- |
| `malformed_request` | 400 |
| `invalid_code` | 400 |
| `code_exhausted` | 409 |
| `rate_limited` | 429, with `Retry-After` |
| `server_error` | 500 |

**`malformed_request` versus `invalid_code`.** A code that is the wrong length
or has characters outside the alphabet is `malformed_request` — the plugin can
say "check what you typed". A well-formed code that this service has never heard
of, or that was refunded, is `invalid_code`. The distinction leaks only the
code's length and alphabet, both of which are printed on the email the code
arrived in, and it saves the vendor a support thread every time somebody
transposes two characters.

### `/buy` — the purchase page

`GET /buy?serverId=<emby system id>`, opened from the plugin's configuration
page. HTML, for a person.

**It shows a button; it does not redirect straight into a created order.** A GET
that creates a PayPal order as a side effect is fired by every link prefetcher,
crawler, dashboard reload and browser that speculatively loads a link on hover —
each one an authenticated call against your PayPal account, against a
rate-limited API, for a sale nobody asked to start. The button is a plain form
POST with no JavaScript anywhere on the page.

**`serverId` is optional metadata and binds nothing.** A redemption code is
deliberately server-agnostic until it is activated; the server the code is
activated on is the one the licence binds to, and it does not have to be this
one. The id is carried to PayPal as the order's `custom_id`, comes back on the
webhook, and is stored in `codes.origin_server_id` so that "which server started
this purchase" is answerable in support. It is a query parameter, so it is
treated as hostile: anything that is not plausibly an Emby server id is dropped
rather than rejected, and whatever survives is HTML-encoded everywhere it is
rendered. `BuyPageTests` includes the reflected-XSS attempts.

The page works with no `serverId`, with a malformed one, and with a hostile one.
People will reach it directly.

### How the buyer gets their code, and what happens if they close the tab

**The code is sent by the vendor, out of `/data/codes-outbox.jsonl`.** It is
never shown on a web page.

Closing the tab therefore loses nothing, and that is the point of doing it this
way. The code is created when PayPal's webhook confirms the payment — a
server-to-server call that has nothing to do with the buyer's browser — so the
buyer can close the tab the instant PayPal says the payment went through, lose
their connection, or have the page fail to load, and their code still exists.
`/buy/complete` says so in as many words.

The success page could have shown the code. It does not, for three reasons in
order of weight:

1. **It would often have nothing to show.** The webhook is what creates the code
   and it races the browser redirect. A page that says "your code is..." and
   sometimes does not is worse than one that never does.
2. **It would be serving a live credential keyed on a URL parameter.** The
   return URL carries a PayPal order id, and that URL lands in browser history,
   proxy logs and `Referer` headers.
3. **It would make delivery depend on a browser tab**, which fails for exactly
   the people least equipped to chase it.

**The honest gap:** this service has no mail transport, so "the vendor sends it"
means a human reading `codes-outbox.jsonl` and sending an email. That is the
largest operational weakness here and it is the obvious next thing to build —
`Delivery/CodeOutbox.cs` is the seam. Until then, watch that file.

`codes-outbox.jsonl` is **the one place a redemption code exists in readable
form.** The database holds only SHA-256 hashes, so a stolen database yields
nothing usable; this file yields every code not yet pruned from it. It is
written `0600`. Send each code, then delete its line.

---

## One implementation, two front ends

`src/Emby.Sso.Licensing` is the licence-minting half of
`tools/Emby.Sso.LicenceTool`, extracted so the offline tool and this service
cannot drift apart: same issuer, same RS256, same claim set, same
`licences-issued.jsonl`, same fingerprint. A licence minted here and one minted
by the tool are indistinguishable to the plugin, because they must be.

**The extraction is half done.** The tool has *not* been changed to reference
this library, because the task that produced this directory was forbidden from
touching `tools/`. So today there really are two copies of the same logic.
Finishing it is a one-line `ProjectReference` in
`tools/Emby.Sso.LicenceTool/Emby.Sso.LicenceTool.csproj` plus deleting the
duplicated methods from its `Program.cs`. **Do that.**

Until it happens, `LicenceToolCompatibilityTests` reads the tool's source and
fails if its constants, claim names or ledger fields stop matching this
library's. That is an unusual test and it is a stopgap, not a design.

The upshot for the vendor: `licencetool list` and `licencetool show` work
unchanged on licences this service issued.

```
licencetool list --ledger /srv/emby-sso/data/licences-issued.jsonl
```

---

## Why SQLite

State lives in `/data/licences.db` (SQLite) with `/data/licences-issued.jsonl`
(the ledger) and `/data/codes-outbox.jsonl` beside it.

SQLite for the state, because:

- **The activation cap is a security control and needs a transaction.**
  Enforcing "three servers" means read-the-count-then-insert, and that has to be
  one atomic step or two simultaneous activations both read "2 of 3" and both
  insert. `BEGIN IMMEDIATE` plus a `UNIQUE (code_id, server_key)` index gives
  that. A flat file gives it only if this code hand-rolls locking, and
  hand-rolled locking around a security cap is the thing not to hand-roll.
- **Replay protection is the same shape.** `webhook_events.event_id` is a
  primary key and `codes.paypal_capture_id` is a unique index, so a duplicate
  webhook loses in the database rather than in an `if`.
- **A crash mid-write is a no-op**, not a corrupt half-record.
- **One file to back up**, and one the vendor can query with the `sqlite3` CLI
  when a customer emails.
- **No second process, no port, nothing else to operate.** A one-person vendor
  selling a plugin does not need a database server and would not be better
  served by one.

The ledger stays a JSONL file because that is the offline tool's format and
compatibility with it is the point. The two are not redundant: the database is
the authority and the thing transactions run against; the ledger is the view the
tool reads. If the ledger cannot be written, the activation still succeeds and
the log says so loudly — the record is not lost, only the tool's view of it.

### Back up `/data`

Losing it loses who bought what, and no server can be asked what it holds — the
plugin never calls home.

```
sqlite3 /srv/emby-sso/data/licences.db ".backup '/backup/licences.db'"
cp /srv/emby-sso/data/licences-issued.jsonl /backup/
```

The outbox is a credential store; back it up only if you are willing to guard
the backup like one, and prune it as you deliver.

---

## The PayPal webhook signature

**This is the most security-critical code in the service.** The webhook creates
redemption codes. An endpoint that accepts an unverified webhook is a
free-licence dispenser for anyone who finds the URL, and finding it is one scan
away.

It implements PayPal's documented offline verification:

```
message   = transmissionId | transmissionTime | webhookId | crc32(raw body)
signature = base64(RSA-SHA256(message, PayPal's key))
verified  against the certificate at PAYPAL-CERT-URL
```

with these rules, each of which has a test:

- **`paypal-auth-algo` is pinned to `SHA256withRSA`**, not honoured. It is an
  attacker-controlled header; an implementation that switches on it is one that
  can be told to verify with something weaker.
- **`PAYPAL-CERT-URL` must be https and on `paypal.com`**, checked *before* the
  fetch. This is what stops the header aiming the service at an attacker's web
  server to be handed an attacker's certificate — which would make every other
  check pass.
- **The certificate must chain to a trusted root and be issued to a
  `paypal.com` name.** Both, not either: a perfectly valid certificate for
  `evil.example.com` chains fine.
- **Every required header must be present.** Missing is refused, not defaulted.
- **A refusal answers `401` with an empty body.** The reason is in the log. A
  caller probing the endpoint learns nothing.
- **Nothing is created before verification.** An unsigned request cannot cost so
  much as a database row.

**There is no configuration flag, no environment, and no build that skips any of
this.** `ServiceOptionsTests` asserts the absence of one. The only way to make
this service accept an unsigned webhook is to edit
`PayPal/PayPalWebhookVerifier.cs`.

### Why the offline algorithm and not PayPal's verify-webhook-signature API

Both are documented. The API version is arguably harder to get subtly wrong.
It was not chosen because **its correctness lives on PayPal's servers**: in an
environment with no credentials and no route to PayPal, there is no test that
can prove a tampered payload is refused, and the whole check would have shipped
untested. The brief was explicit that a signature check with no such test is not
a signature check. The algorithm above is verifiable offline against a key the
test generates, and `PayPalWebhookVerifierTests` proves a single flipped byte of
body is refused, along with an edited header, a signature for somebody else's
webhook, a weakened algorithm and a certificate URL that is not PayPal's.

### Replays

The same payment arriving twice creates one code, guarded twice over:
`webhook_events.event_id` is a primary key, and `codes.paypal_capture_id` is
unique — so even a genuinely new event id for a capture already seen buys
nothing. PayPal retries a lot; both are expected to fire.

### Refunds

`PAYMENT.CAPTURE.REFUNDED` and `.REVERSED` void the code that capture bought.
It will not activate a new server. **Servers that already activated keep
working** until their licence expires, because the plugin verifies offline and
there is no revocation. Say that plainly to anyone who asks.

### Amounts

A verified capture below `PAYPAL_MINIMUM_AMOUNT`, or in a different currency,
buys nothing and is logged. Without that floor, a capture for one penny — from
an order built by hand against the same PayPal account — buys a licence, because
the webhook only says money arrived. No exchange rate is guessed at.

---

## Rate limiting `/v1/activate`

Codes are bearer secrets guessed at over the internet, and this endpoint is
unauthenticated by necessity.

**What the limiter guarantees:**

1. No single client key can spend more than `LICENCE_RATE_PER_CLIENT_BURST`
   attempts without waiting, and cannot sustain more than
   `LICENCE_RATE_PER_CLIENT_PER_MINUTE` per minute.
2. Across all clients together, no more than
   `LICENCE_RATE_GLOBAL_PER_MINUTE` per minute — the one that holds when the
   attempts come from a botnet and (1) buys nothing.
3. **Every** attempt is counted — malformed, unknown, exhausted and successful
   alike — and counted *before* the code is normalised, hashed or looked up. A
   refused caller costs one dictionary lookup and no database work.
4. Memory is bounded at `LICENCE_RATE_MAX_TRACKED_CLIENTS` buckets; fully
   refilled buckets are dropped first, so eviction only forgets clients with
   nothing owing.

**What it does not do, and must not be sold as:** it is not what stops codes
being guessed. **That is the 150 bits of entropy in the code.** At a few hundred
attempts a minute, exhausting a meaningful fraction of 2¹⁵⁰ takes longer than
the universe has been here. The limiter bounds what a guesser costs in CPU and
disk, keeps one noisy caller from starving real activations, and makes an
enumeration attempt visible in the log. Entropy is the security control; this is
the resource control.

It is per-process and in-memory. There is one process, so that is the whole
system. **If this is ever run as two replicas, each enforces its own budget and
the real global ceiling doubles.**

### `LICENCE_TRUSTED_PROXY_HOPS`

Getting it wrong weakens the limiter in one direction only. Too low and every
caller is bucketed under the proxy's address — safe, but everyone is throttled
together. Too high and a caller forges `X-Forwarded-For` and gets a fresh bucket
per request. It defaults to `0`, which trusts nothing and uses the socket's peer
address. Set it to the number of proxies you actually have.

---

## Codes

30 symbols from Crockford's base32 (`0-9A-Z` minus I, L, O, U), drawn uniformly
from a random byte masked to five bits — so **150 bits of real entropy**, past
the 128 the brief asked for. Displayed in groups of five:
`H4KMP-2TQZ9-...`. Case-insensitive, separators optional, and `I`/`L` read as
`1` and `O` as `0` on input, because those are the pairs people actually
mistype.

**Stored as a SHA-256 of the normalised form, never in the clear.** A plain
hash, not argon2, and the reasoning matters: slow hashes buy time for secrets
that have too little entropy to survive an offline attack. A 150-bit code has no
dictionary and no rainbow table. What the hash is for is that a copy of the
database — a backup, a stolen volume, a support dump — contains no usable code,
and it does not.

Logs record the first 12 hex characters of the hash, never the code. To find a
customer's code in a log from the code they emailed you:

```
printf '%s' "$(echo "$CODE" | tr -d ' -_' | tr 'a-z' 'A-Z' | tr 'ILO' '110')" \
  | sha256sum | cut -c1-12
```

---

## Configuration

Everything comes from the environment. Nothing secret is in the image or in git.
**Every problem is reported at once and the service exits 78** (`EX_CONFIG`)
rather than starting half-configured.

| Variable | Default | |
| --- | --- | --- |
| `LICENCE_SIGNING_KEY_PATH` | *(required)* | The read-only mounted private key. |
| `LICENCE_DATA_DIR` | `/data` | The mounted volume. |
| `LICENCE_PUBLIC_BASE_URL` | — | The https address this service is reached on. Derives the PayPal return and cancel URLs. |
| `LICENCE_ACTIVATIONS_ALLOWED` | `3` | Servers per code. |
| `LICENCE_DAYS` | `365` | Licence term, fixed at a code's first activation. |
| `LICENCE_TRUSTED_PROXY_HOPS` | `0` | See above. |
| `LICENCE_RATE_PER_CLIENT_PER_MINUTE` | `10` | |
| `LICENCE_RATE_PER_CLIENT_BURST` | `5` | |
| `LICENCE_RATE_GLOBAL_PER_MINUTE` | `300` | |
| `LICENCE_RATE_MAX_TRACKED_CLIENTS` | `20000` | |
| `PAYPAL_ENV` | `sandbox` | `sandbox` or `live`. Nothing else. |
| `PAYPAL_WEBHOOK_ID` | *(required)* | Part of the signed message. Wrong id = every webhook refused. |
| `PAYPAL_CLIENT_ID` | — | Needed to sell; not needed to verify a webhook. |
| `PAYPAL_CLIENT_SECRET` | — | |
| `PAYPAL_CURRENCY` | `GBP` | |
| `PAYPAL_PRICE` | — | |
| `PAYPAL_MINIMUM_AMOUNT` | `PAYPAL_PRICE` | The floor a capture must clear. |
| `PAYPAL_PRODUCT_NAME` | `Emby SSO plugin licence` | |
| `PAYPAL_RETURN_URL` | derived | |
| `PAYPAL_CANCEL_URL` | derived | |

### The hostname, and reconciling it with the plugin

**The plugin currently compiles in `https://licence.koper.cloud` as its default
service base.** That is a placeholder derived from the repository's own
hostname, not a decision — *the operator must set the real one before release*,
and the two halves have to agree:

- whatever the plugin ships with **is** the hostname this service must answer
  on, over HTTPS with a certificate a plugin on someone else's server will
  accept;
- `LICENCE_PUBLIC_BASE_URL` must be that same URL, because PayPal sends buyers
  back to a URL derived from it and PayPal will not accept one that does not
  resolve;
- the webhook registered in the PayPal dashboard must be
  `<that base>/paypal/webhook`.

Three places, one hostname. Changing it later means a plugin release, so decide
before the first sale.

---

## Running it

The container listens on `:8080` and **must sit behind a reverse proxy that
terminates TLS.** The contract says HTTPS only, and this service never terminates
TLS itself — the compose file binds it to `127.0.0.1` for that reason.

**Docker was not available where this was written, so neither `Dockerfile` nor
`docker-compose.yml` has ever been built or run.** They are short and ordinary,
but treat the first build as a thing to watch.

The signing key is mounted **as a file, read-only**, so that nothing else in
that directory — the offline tool's ledger, a backup, an editor's swap file — is
inside the container at all. On the host it must be `chmod 600` and owned by uid
`5678`:

```
sudo install -o 5678 -g 5678 -m 600 \
  licence-signing-key.private.json /srv/emby-sso/secrets/
```

The service refuses to start if any bit beyond the owner's is set, if the file
is missing, if it is the public half, or if it is inside a git working tree.

### Answering "did this person's activation reach me?"

Every attempt logs one line. Ask them for their code, turn it into a tag with
the recipe above, and:

```
docker compose logs licence | grep 'code=<tag>'
```

```
activate OK code=9f2a1c3e5b7d server=c5bc6e91... NEW used=1/3 expires=2027-01-05T12:00:00Z fingerprint=sha256:0252... plugin=1.4.0
activate EXHAUSTED code=9f2a1c3e5b7d server=aaaa1111... used=3/3
activate REFUSED code=9f2a1c3e5b7d server=... reason=UnknownCode
activate RATE LIMITED client=203.0.113.7 scope=client retryAfter=6s
activate MALFORMED client=203.0.113.7 reason=code not well formed
paypal capture 3C6...L accepted: code 9f2a1c3e5b7d created for buyer@example.com, 3 activations, 365 days
paypal webhook REFUSED: the signature does not match this request. Nothing was created.
```

Nothing logs a code, a licence, or the private key. The fingerprint on an
`activate OK` line is the same one `licencetool show` prints for a licence
somebody emails back.

Or ask the database:

```
sqlite3 /srv/emby-sso/data/licences.db \
  "SELECT server_id, first_seen_utc, issue_count FROM activations
     JOIN codes ON codes.id = activations.code_id
    WHERE codes.code_hash LIKE '9f2a1c3e5b7d%';"
```

### Codes that no payment bought

Testers, comps, and recovering a sale whose code could not be delivered:

```
docker compose exec licence \
  dotnet Emby.Sso.LicenceService.dll issue-code --licensee "Beta Tester Bob"
```

The code goes to stdout; only its hash is stored. There is **no HTTP route to
this**, because an endpoint that mints saleable credentials needs an
authentication story and the only honest one at this size is "you have a shell
on the box or you do not".

### When a code cannot be delivered

If the outbox cannot be written, the log says `CODE LOST` at critical, naming
the capture and the buyer. The buyer has paid and has no code, and the code is
not recoverable — it was a local variable, and it is deliberately **not** logged,
because a log file is not where live credentials belong even in a disaster.

Fix the volume, then void the orphaned code and issue a replacement:

```
sqlite3 /srv/emby-sso/data/licences.db \
  "UPDATE codes SET status='void' WHERE paypal_capture_id='<capture id>';"

docker compose exec licence \
  dotnet Emby.Sso.LicenceService.dll issue-code --licensee "<buyer email>"
```

---

## Building and testing

Not in `Emby.Sso.sln`, and that is deliberate: `dotnet build` at the repository
root — which is what CI runs — must not build or ship any of this into the
plugin. It has its own solution.

```
export DOTNET_ROOT=$HOME/.dotnet
dotnet test service/Emby.Sso.Service.sln
```

212 tests. What they cover, and why each is there, is in the class comments; the
ones that carry weight are `PayPalWebhookVerifierTests` (a tampered payload is
refused), `PayPalCertificateValidatorTests` (an untrusted certificate is
refused), `ActivationStateMachineTests` (the cap and free re-activation),
`RateLimiterTests` (the four properties above, each asserted), and
`LicenceToolCompatibilityTests` (the offline tool has not drifted).

---

## What is UNVERIFIED

Everything that requires PayPal. There were no credentials and no network route
to them where this was written, and **nothing here has ever simulated a success
and called it working.**

- **Creating an order** (`PayPalOrdersClient`). The requests are built from
  PayPal's Orders v2 documentation. Tested: the token request is
  `client_credentials` with basic auth, the order carries the configured price
  and currency, the approval link is read back, an error becomes an exception.
  Untested: whether PayPal accepts any of it.
- **The webhook, end to end.** Tested: the signature check, against a key the
  tests own, in both directions. Untested: **that a real PayPal transmission
  satisfies it** — the message layout, the header names and the CRC come from
  PayPal's documentation.
- **Certificate trust.** Tested: that a self-signed certificate and a
  wrong-named one are *refused*. Untested: that PayPal's real certificate is
  *accepted*, which needs PayPal's real certificate.
- **The Docker image.** Never built. Docker was not available.
- **Any concurrency beyond the tests' own.** The transaction boundaries are
  argued for in `LicenceStore`'s comments, not proven under load.

`docs/paypal-sandbox-checklist.md` is the run that closes these, in order, with
the log lines to expect at each step. Do it before live money.

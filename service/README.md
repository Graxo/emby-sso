# The licence and purchase service

**Standing it up for the first time: [`docs/first-run.md`](docs/first-run.md).**
Where the signing key comes from, how to get it onto the host with the right
ownership, what to configure, and what each refusal to start means.

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

## THE SIGNING KEY IS NOT HERE

This service does not hold the private licence signing key and cannot mint a
licence. It refuses to start if `LICENCE_SIGNING_KEY_PATH` is set.

It used to. That put the one secret the whole scheme rests on — the thing that
mints a valid licence for **any** Emby server, forever, with no revocation
because the plugin verifies offline — on a host with a port open to the
internet. Every other control in this service was a wall around that one asset,
and any single failure of any one of them lost it completely and silently.

What happens now: an activation records what has been paid for and what terms
were agreed; the operator downloads that from `/admin/signing`, signs it with
`licencetool sign` on a machine of their choosing, and uploads the result, which
is checked against the recorded terms before it is stored. A total compromise of
this host yields the customer list and the ability to stop issuing. It does not
yield the ability to mint one licence.

The cost, stated plainly because it is visible to customers: **a first
activation is not instant.** It answers `pending_signature` with 202 and the
plugin tells the customer to press Activate again shortly. The code is not spent
by the wait, and repeat activations are immediate.

Full detail: [Signing licences offline](../docs/site/offline-signing.md) and
[Rotating and revoking a signing key](../docs/site/key-rotation.md).

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
- **The admin page, if you turn it on, is a second front door to all of that.**
  Not to the key itself — it cannot read it — but to issuing licences with it,
  which is most of what having the key is worth. It is off by default and it
  does not exist until a password is set. Read *The admin page* before setting
  one, and if you can live with an SSH tunnel or an IP allowlist instead, do.

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
| `/admin/*` | you, in a browser | **Only if `ADMIN_PASSWORD_HASH` is set.** See *The admin page* below. |

Everything a vendor does to what they have sold is available two ways: as a
command on this same binary — `issue-code`, `list-codes`, `show-code`,
`void-code`, `list-outbox`, run with `docker compose exec` — and, if you turn it
on, as a page at `/admin`. They are one implementation with two front ends;
neither can do anything the other cannot, and neither can show you a code the
store holds only as a hash.

**With `ADMIN_PASSWORD_HASH` unset there is no `/admin` at all** — no login
form, no 401, no route. That is the default, and if you never set it this
service has no authenticated surface and nothing to guess at. Read *The admin
page* before you turn it on: it is a public door to the box that holds the
signing key.

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

**The code is emailed if `SMTP_HOST` is set, and otherwise sent by the vendor
out of `/data/codes-outbox.jsonl`.** Either way it is written to that file
first, and it is never shown on a web page.

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

**With mail unconfigured** — which is the default, and a perfectly workable
arrangement for a one-person vendor — "the vendor sends it" means a human
reading `codes-outbox.jsonl`. With `SMTP_HOST` set, the service emails it and
the outbox becomes the fallback for when that fails. See *Emailing the code*
below; a real send is UNVERIFIED until you have run
`docs/email-delivery-checklist.md`.

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
plugin never calls home. Nothing else can rebuild it: not PayPal, not the
signing machine.

**Set `LICENCE_BACKUP_PASSPHRASE` and take one from `/admin/backup`.** It is a
single encrypted file holding the database (as a `VACUUM INTO` snapshot, not a
file copy — this store runs in WAL mode, so the `.db` on its own is an older
database than the one being served), the ledger, the outbox and the audit trail.

There is no unencrypted option, and that is not fussiness: the outbox holds
redemption codes in the clear and a redemption code is a bearer credential, the
store holds every licence that has been signed, and the entire point of a backup
is to put it somewhere less careful than this box.

Reading one back:

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll \
  restore --in /data/whatever.backup --out /data/restored
```

It needs the passphrase that was in force **when the backup was taken**, refuses
a destination that is not empty, and never writes over a live store — moving the
files into place is your own deliberate step. Rehearse it before you need it.

**The signing key is not in there.** It is not on this machine. Back it up
separately, where it lives; losing it is unrecoverable in a way that losing this
is not.

The older, manual way still works if you prefer it:

```
sqlite3 /srv/emby-sso/data/licences.db ".backup '/backup/licences.db'"
cp /srv/emby-sso/data/licences-issued.jsonl /backup/
```

...but you then encrypt it yourself, and the outbox in it is a credential store.

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

A refund that PayPal never told you about — a chargeback settled by email, a
mistake, a code that leaked — is the same operation by hand: `void-code`, which
takes the same code path and prints that same warning at you. See *Managing what
you have sold*.

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

Logs record the first 12 hex characters of the hash, never the code. `show-code
--code '<what they sent you>'` prints that tag back along with everything else
known about the code, which is the usual way in. The recipe by hand, for a shell
that has no container to exec into:

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
| `LICENCE_SIGNING_KEY_PATH` | *(refused)* | **Setting this stops the service starting.** There is no private key on this host; see *THE SIGNING KEY IS NOT HERE*. |
| `LICENCE_PUBLIC_KEYS` | *(required)* | The PUBLIC licence key or keys the plugin build trusts — one JWK, or a JSON array during a rotation. Not a secret; refused if it carries private material. |
| `LICENCE_DATA_DIR` | `/data` | The mounted volume. |
| `LICENCE_BACKUP_PASSPHRASE` | — | Turns on `/admin/backup`. At least 16 characters. There is no unencrypted backup. |
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

**In front of the admin password — both optional, both off, both fail closed.**
`ADMIN_ALLOWED_CIDRS` is a comma-separated list of networks `/admin` may be
reached from (a bare address means that host; it depends on
`LICENCE_TRUSTED_PROXY_HOPS` being right). `ADMIN_REQUIRED_HEADER` and
`ADMIN_REQUIRED_HEADER_VALUE` require a header your proxy adds — a Cloudflare
Access assertion, an oauth2-proxy header, a verified client certificate, or a
long shared secret — checked in constant time *before* the password, so a caller
who cannot produce it never costs a PBKDF2 verification. **Your proxy must strip
that header from incoming requests.** A request that fails either gets a 404.

**The admin page — all optional, and off.** `ADMIN_PASSWORD_HASH` is the switch:
with it unset the routes are never mapped. See *The admin page* for what turning
it on means.

| Variable | Default | |
| --- | --- | --- |
| `ADMIN_PASSWORD_HASH` | — | **Set this to turn `/admin` on.** A PBKDF2 verifier from `hash-password`. |
| `ADMIN_PASSWORD` | — | The plaintext alternative. Refused if short or obvious. Second best — see below. |
| `ADMIN_SESSION_IDLE_MINUTES` | `30` | Signed out after this long doing nothing. |
| `ADMIN_SESSION_ABSOLUTE_MINUTES` | `480` | Signed out after this long regardless. Must be the larger. |
| `ADMIN_LOGIN_DELAY_SECONDS` | `2` | The **first** wait a wrong password buys. It doubles from there. |
| `ADMIN_LOGIN_MAX_DELAY_SECONDS` | `60` | Where the doubling stops. Not a lockout; there is deliberately no lockout. |

Setting both `ADMIN_PASSWORD_HASH` and `ADMIN_PASSWORD`, or setting a
`ADMIN_PASSWORD` that is under 16 characters or obvious, or an
`ADMIN_PASSWORD_HASH` this service cannot read, is a **refusal to start** rather
than a page that quietly does not work.

**Email delivery — all optional.** `SMTP_HOST` is the switch: unset it and the
service behaves exactly as it did before mail existed. See *Emailing the code*
below.

| Variable | Default | |
| --- | --- | --- |
| `SMTP_HOST` | — | **Set this and only this to turn mail on.** Unset = outbox only. |
| `SMTP_SECURITY` | `starttls` | `tls` (implicit TLS), `starttls`, or `none`. Nothing else. |
| `SMTP_PORT` | `465`/`587`/`25` | Whichever matches `SMTP_SECURITY`. |
| `SMTP_USERNAME` | — | Omit for a relay that needs no login. |
| `SMTP_PASSWORD` | — | Never logged, never in `Describe()`. Not trimmed. |
| `SMTP_FROM_ADDRESS` | *(required with a host)* | |
| `SMTP_FROM_NAME` | `Emby SSO licences` | |
| `SMTP_REPLY_TO` | — | |
| `SMTP_SUBJECT` | `Your Emby SSO plugin licence code` | Never contains the code. |
| `SMTP_SUPPORT_CONTACT` | `SMTP_REPLY_TO`, else `SMTP_FROM_ADDRESS` | What the message tells the buyer to write to. |
| `SMTP_TEMPLATE_PATH` | — | A plain-text template to use instead of the built-in wording. |
| `SMTP_TIMEOUT_SECONDS` | `30` | |
| `SMTP_MAX_ATTEMPTS` | `4` | Then the outbox is the fallback. |
| `SMTP_RETRY_SECONDS` | `30` | First backoff; quadrupled each attempt. |

The message name comes from `PAYPAL_PRODUCT_NAME` rather than a variable of its
own, so the email and the PayPal receipt cannot disagree about what was sold.

### The hostname, and reconciling it with the plugin

**The plugin currently compiles in `https://license.koper.cloud` as its default
service base** (`ActivationEndpoint.DefaultServiceBase`). That is a placeholder
derived from the repository's own hostname, not a decision — *the operator must
set the real one before release*.

**Note the spelling.** Everything else in this project says *licence*; that
constant says *license*. `licence.koper.cloud` and `license.koper.cloud` are
different hostnames and only one of them will have a certificate. Whichever is
chosen, check the constant character by character rather than reading it, and
make DNS, the TLS certificate and `LICENCE_PUBLIC_BASE_URL` all say the same
thing.

The paths do match: the plugin builds `{base}/v1/activate` and
`{base}/buy?serverId=<id>`, which are the two this service serves.

The two halves have to agree on:

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

### The image CI builds

CI builds `service/Dockerfile` and pushes it to this project's own container
registry, so the deployment host pulls an image instead of being handed a copy
of the source:

```
registry.koper.local:5050/graxo/emby-sso/licence-service
```

The `service-image` job prints the exact base it pushed to — trust that over
this line, which is derived from the project path and has never been pulled.

**What gets published, and when.**

| Ref | Tags | For |
|---|---|---|
| `v1.4.0` | `1.4.0` and `latest` | what a production host runs. `1.4.0` never moves |
| `v1.4.0-rc.1` | `1.4.0-rc.1` only | a prerelease is deliberately **not** `latest` |
| a push to `main` | `main-<short sha>` and `main` | trying a commit before it is tagged |
| any other branch | nothing | a branch nobody reviewed does not get published |

`latest` means *the newest released version*, never "the tip of main" — so an
operator who types it gets something that was deliberately cut, not whatever
landed twenty minutes ago. It still moves when a release is tagged, which is why
`docker-compose.yml` tells you to pin `LICENCE_IMAGE` to an `X.Y.Z`.

**Nothing broken gets published.** The service is its own solution and nothing
in CI used to compile it, so a service that did not even build was publishable.
The `service-image` job now runs only behind `service-test`, which runs
`dotnet test service/Emby.Sso.Service.sln`.

**It is built with docker-in-docker**, following the client-portal pipeline's
`docker` job, which has been pushing to this registry from these runners for a
while. An earlier version used kaniko to avoid needing a privileged runner —
which turned out to be a cost that was not being charged, since the runner's own
`config.toml` already defines a dind service. Two things about that are worth
knowing before editing the job, because neither is guessable from its failure:

- **the service alias must not be `docker`.** The runner already uses it, GitLab
  refuses to reuse it, and `DOCKER_HOST` then quietly addresses the *runner's*
  daemon — which trusts neither the CA nor the registry, so every push fails
  with `x509: certificate signed by unknown authority`;
- **`DOCKER_TLS_CERTDIR` is emptied on purpose.** That is the client-to-daemon
  hop on the private job network, not the registry connection.

**The registry's certificate is issued by a private CA.**
`registry.koper.local:5050` presents one certificate, `CN=*.koper.local`, from a
"Homelab Root CA", with no chain. Set `REGISTRY_CA_PEM` (on a runner host,
`cat /usr/local/share/ca-certificates/ca.crt`) and the daemon installs it and
**verifies**. Without it the daemon falls back to `--insecure-registry` for that
one registry and says so in the log — which is what the client-portal pipeline
does today, and what an unverified push costs is spelled out in the job's
comments.

**Pulling needs credentials**, because the project is private: a deploy token
scoped to `read_registry`, and `docker login registry.koper.local:5050`.
`docs/first-run.md`, section 5, has the steps and says how to treat the token.

**There is no `:latest` until a `vX.Y.Z` tag is built.** `ci/image-tags.sh` is
the only thing that decides tags: main publishes `main-<short sha>` and `main`,
a full release publishes `X.Y.Z` and `latest`, and a *prerelease* tag publishes
only itself — so that the tag people pull blind is never a release candidate.
Before the first release, pull `main`. A pull of `latest` before then fails with
`manifest unknown`, which reads like a broken registry and is not one.

**UNVERIFIED — all three halves of this.** No pipeline has run, no image has
been built by anything, and no host has pulled one. Each is one command to
confirm, in order, and each tells you which half failed:

```
# 1. Does the runner build and push it? Push to main, then watch the
#    service-image job. Its first lines say which daemon answered and
#    whether the registry is verified or trusted blindly; success ends
#    with "service-image: pushed."
#    A runner that refuses privileged services fails before the build,
#    on "no Docker daemon answered at tcp://dind-registry:2375".

# 2. Did the registry accept it? On any machine that can reach the
#    registry, with a read_registry deploy token:
docker login registry.koper.local:5050 -u <token-username> --password-stdin
docker manifest inspect registry.koper.local:5050/graxo/emby-sso/licence-service:main | head

# 3. Can the deployment host pull and run it?
docker compose pull licence && docker compose up -d licence
docker compose logs licence | head -20
curl -fsS http://127.0.0.1:8080/healthz && echo OK
```

Until (1) has been watched once, the host still deploys the old way: source on
the host, `docker compose up -d --build licence`.

### Answering "did this person's activation reach me?"

`show-code --code '<what they sent you>'` answers this directly, listing every
server that code has been activated onto and when — see *Managing what you have
sold*. The log is the other half of it, for an attempt that never got as far as
a row.

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

Or ask the database, which is what `show-code` does for you:

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

The code goes to stdout; only its hash is stored. There is also an Issue form on
the admin page, if you have turned one on — the same implementation, the same
ceilings, and the code shown once. See *The admin page*. With no admin password
set, a shell on this box is the only way to mint one.

Its four siblings — `list-codes`, `show-code`, `void-code` and `list-outbox` —
are the rest of running this. They are next.

## Managing what you have sold

`issue-code` makes a code. These four read and change the ones that exist. Every
one of them runs in the container and needs nothing but a shell:

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll <command>
```

| Command | The question it answers |
|---|---|
| `list-codes` | who has a code, and has it been used? |
| `show-code` | a customer says their code does not work — what actually is it? |
| `void-code` | I refunded someone — stop the code working |
| `list-outbox` | a code was never delivered — what is sitting waiting? |

**All four are also on the admin page**, if you have turned one on — same
implementation, two front ends, and neither can do anything the other cannot.
The commands are what is left when the page is off, and the page is off unless
`ADMIN_PASSWORD_HASH` is set. See *The admin page* for what turning it on costs
you.

**Two rules hold across all four.**

1. **No command can print a code the store holds only as a hash.** `issue-code`
   prints one at creation because that is the only moment it exists in the
   clear. `list-codes` shows the twelve-character tag instead and says so in its
   own footer; `show-code` takes a code as *input* and confirms it, and does not
   echo it back, because support output gets pasted into chat windows. The one
   exception is `list-outbox --reveal`, which reads back plaintext that is
   already sitting in `codes-outbox.jsonl`.
2. **A read-only command never creates the store.** SQLite's default is to
   create the database file, which would make `list-codes` against a mistyped
   `LICENCE_DATA_DIR` print an empty table — indistinguishable from "no
   customers" — and leave a stray `licences.db` behind. Instead it says which
   path it looked at and exits **66**.

Exit codes: **0** done, **1** no such code or bad usage, **66** there is no store
at `LICENCE_DATA_DIR`, **78** the configuration is wrong.

### `list-codes` — who has what

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll list-codes
```

```
STATE        CREATED     TAG           SOURCE  USED  DAYS  EXPIRES     FOR
UNDELIVERED  2026-08-20  c3b3474f27d5  paypal  0/3   365   -           buyer@example.com
UNPAID       2026-08-22  71ba0c4e9021  paypal  0/3   365   -           PayPal capture 3C8DEF
LAPSED       2025-08-01  9ceb22fe4d19  paypal  2/3   365   2026-08-01  acme@example.com
LAPSING      2025-09-14  4d1e8a77c003  paypal  1/3   365   2026-09-14  someone@example.com
EXHAUSTED    2026-01-05  a70f21bb54ce  paypal  3/3   365   2027-01-05  three@example.com
unused       2026-08-31  1c9d40e6b8aa  manual  0/3   30    -           Tester — discord handle
active       2026-02-02  55e0c1a9d7f3  paypal  1/3   365   2027-02-02  happy@example.com
void         2026-03-03  b2f4a0d61e88  paypal  1/3   365   2027-03-03  refunded@example.com
```

Sorted by that first column, in exactly the order it is printed above, so what
needs attention is at the top and nothing has to be scrolled to. A code is
labelled with the **first** of these that is true of it:

| STATE | What it means, and what to do |
|---|---|
| `UNDELIVERED` | there is a line for it in the outbox with no delivery receipt beside it, and it has never been activated. **Somebody has paid and has nothing.** `list-outbox` |
| `UNPAID` | created but not paid for. It cannot activate |
| `LAPSED` | the licence issued from it has already run out. Sell them another |
| `LAPSING` | it runs out within `--soon` days, 21 by default — the window in which their own Emby server has already started warning them |
| `EXHAUSTED` | every activation it allows is used. A fourth server needs a new code |
| `unused` | paid for, never activated. Normal for a code just sold, or a comp nobody has redeemed |
| `active` | in use, with activations to spare and time on the licence |
| `void` | refunded, leaked or a mistake. Last on purpose: it is the one state already dealt with, so it never pushes a live problem down the page |

`--needs-attention` narrows to the first four. `--for <text>` matches a licensee,
a buyer's address or a tag, case-insensitively — the command to reach for when a
customer emails and you have only their name. `--soon <days>` moves the `LAPSING`
window.

**`TAG` is the first twelve characters of the code's SHA-256** — the same string
`code=` shows in every log line, and what `show-code --tag` and `void-code --tag`
take. It is derived from the code and is not one: it cannot be activated with.

Two notes on `UNDELIVERED`, because it is the one that could cry wolf. A code
with **no outbox line at all** is *not* reported as undelivered: that is the
normal end state of a sale you have sent and pruned, and it is every code
`issue-code` ever made, since those never go near the outbox. And a code that
has **already been activated** is not undelivered whatever the outbox says —
they plainly received it, and an unpruned line is untidiness rather than a
failed sale.

### `show-code` — what is this code?

The support command. Somebody pastes a code into a chat window and the first
question is what it actually is.

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll \
  show-code --code 'mh97k d1jp7 fc223 583r5 rdmm3 1d1hc'
```

**It takes the code in whatever shape a human sent it**: any case, with or
without the hyphens, with spaces instead, with whitespace round it, and with
`I`, `L` and `O` read as the `1`, `1` and `0` they were meant to be. That is the
same normalisation `/v1/activate` applies, so a code this refuses is a code the
service would also refuse. `--tag <hash prefix>` takes the twelve characters
from a log line instead; four or more will do, and a prefix matching two codes
is refused rather than guessed at.

```
Tag         : c3b3474f27d5   (what the logs record; give this to `void-code --tag`)
State       : active
Source      : paypal
Licensee    : buyer@example.com
Buyer       : buyer@example.com
PayPal      : capture 3C6XYZ, event WH-1
Bought from : c5bc6e91458540caa295c4efdda1a58a   (the server id on the /buy link; it binds nothing)
Created     : 2026-08-20T09:12:00Z
Licence     : 365 days from first activation
Expires     : 2027-08-20T09:12:00Z   (in 354 days)
Activations : 2 of 3 used
Delivery    : emailed to buyer@example.com at 2026-08-20T09:12:04Z

SERVER                            FIRST SEEN            LAST SEEN             ISSUES  PLUGIN  LAST LICENCE
c5bc6e91458540caa295c4efdda1a58a  2026-08-21T18:02:11Z  2026-08-30T07:40:52Z  4       1.4.0   sha256:0252...
aaaa1111bbbb2222cccc3333dddd4444  2026-08-25T11:19:03Z  2026-08-25T11:19:03Z  1       1.4.0   sha256:9ab1...
```

`LAST LICENCE` is the fingerprint `licencetool show` prints for a licence
somebody emails back, so a token in an inbox can be matched to a row here.

It distinguishes the three ways a code can fail to be found, because they mean
different things to the person on the other end of the conversation: *that is
not a well-formed code at all* (and nothing was looked up — `/v1/activate` would
refuse it too), *that is well-formed and this store has never held it* (issued
elsewhere, mistyped into something still well-formed, or invented), and *no code
has a hash starting with that tag*.

### `void-code` — a refund, a mistake, a leak

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll \
  void-code --tag c3b3474f27d5 --reason 'refunded, PayPal case 12345'
```

```
VOIDED code c3b3474f27d5 (buyer@example.com).
Reason recorded: refunded, PayPal case 12345
It will not activate again. Any attempt now answers `invalid_code`, the same
answer an unknown code gets - the caller learns nothing about your account.

THIS DOES NOT RECALL A LICENCE ALREADY ISSUED FROM THIS CODE.
  2 server(s) have already been given a licence from it, and each keeps working
  until 2027-08-20T09:12:00Z.
  `show-code` lists them.

The plugin verifies its licence offline against a public key compiled into it and
never calls this service, so no revocation exists and none can be added here.
Voiding stops the NEXT activation. That is the whole of what it does. ...
```

**That paragraph is the point of the command's output.** Somebody reaching for
this after a refund needs to know before they close the ticket, not after the
customer keeps using the plugin for another eleven months. Voiding stops the
next activation and nothing else; the only thing that takes a running licence
away is a new signing keypair and a new plugin build, which invalidates every
other customer at the same time.

`--reason` is optional and worth giving: it is stored, and `show-code` prints it
back months later beside the date. Voiding twice is **not an error** — the second
run says it was already void, shows the *first* reason, and changes nothing.

It is the same statement the refund webhook takes. `PAYMENT.CAPTURE.REFUNDED`
and this command call one method on the store, so what "voided" means cannot
drift between them, and `list-codes` shows a hand-voided code and a
PayPal-voided one identically.

### `list-outbox` — the sale that never arrived

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll list-outbox
```

```
CREATED               TAG           BUYER              SENT  ACTS  DAYS  CAPTURE  IN THE STORE
2026-08-20T09:12:00Z  c3b3474f27d5  buyer@example.com  NO    3     365   3C6XYZ   waiting
2026-08-22T09:12:00Z  ghost0000dead ghost@example.com  NO    3     365   3C8DEF   void - do not send
```

Everything needed to finish a sale by hand except the code itself. `IN THE STORE`
is what the database says about that code now — `waiting`, `already activated
2x` (they got it somehow, so there is nothing to chase), or `void - do not send`.

**The codes are not in that table.** They are in `codes-outbox.jsonl` in the
clear — it is the one place they exist in readable form — and
`list-outbox --reveal` prints them into the terminal, which is a decision worth
making deliberately rather than one a listing makes for you. `--all` includes
lines that have already been delivered.

`SENT` reads `NO` until a successful email appends a receipt, so **with
`SMTP_HOST` unset it is `NO` forever**. That is not a bug and it is why the
workflow is: send the code, then delete its line from the file. A pruned line is
how these commands know a code is finished with, and it is also how a live
credential stops sitting on the disk.

## The admin page

Everything above is also a page, at `https://<your host>/admin`, if you turn one
on. **It is off, and there is no page at all until you set a password.**

### What you are turning on

This service holds the private signing key. Whoever gets through that page can
mint a licence for any Emby server, for any duration, as many as they like —
and **nothing recalls one**, because the plugin verifies offline against a key
compiled into it and never calls home. There is no second factor, no allowlist
and no VPN in front of it. **The password is the entire barrier.**

Two safer arrangements exist and this page is neither of them:

* **Loopback plus an SSH tunnel.** Bind the container to `127.0.0.1`, and reach
  it with `ssh -L 8080:127.0.0.1:8080 you@host`. The page is then only reachable
  by somebody who already has your SSH key, and the password is a second lock
  rather than the only one.
* **An IP allowlist at the proxy.** One `allow`/`deny` block in nginx or Caddy
  in front of `/admin`. Costs you a fixed address to work from.

Both were offered and neither was chosen; the page is public behind a password
deliberately. If you change your mind, the allowlist is three lines of proxy
config and nothing in this service has to change.

**To turn it off again**, unset `ADMIN_PASSWORD_HASH` (and `ADMIN_PASSWORD`) and
restart. The routes stop being mapped and `/admin` becomes a 404 like any other
unrouted path. Nothing else is affected: the commands, the buy page and
activation all carry on exactly as before.

### Turning it on

```
docker compose exec licence dotnet Emby.Sso.LicenceService.dll hash-password
```

It reads the password on **stdin** — not from an argument, which would be in
your shell history and in the process list of everybody on the box — and prints
one line:

```
ADMIN_PASSWORD_HASH=pbkdf2-sha256$210000$Xy...==$q7...=
```

Put that in `.env` and restart. Keep the password itself in your password
manager and nowhere else; nothing can recover it from the line above.

**Use a long random one.** The verifier is PBKDF2-HMAC-SHA256 at 210,000
iterations, which makes each guess expensive, and the login delay below bounds
how many can be tried — but neither of those saves a password somebody can
guess. Sixteen characters is the minimum this service accepts and it is a floor,
not a recommendation.

`ADMIN_PASSWORD` takes a plaintext password instead, and exists because refusing
it would send you to a text file with the password in it anyway. It is second
best: anything that can read this container's environment — `docker inspect`, a
crash dump, a compose file in a backup — gets the credential rather than a
verifier. It is refused if it is short or obvious.

### What the page does

| | |
| --- | --- |
| `/admin/codes` | `list-codes`: every code, its state, who it is for. Filter by licensee, buyer or tag. |
| `/admin/code/<tag>` | `show-code`: one code and every server it has been activated onto. |
| `/admin/code/<tag>/void` | `void-code`: the confirmation, with what voiding cannot do stated **before** the button. |
| `/admin/issue` | `issue-code`: a code no payment bought. The code is shown **once**. |
| `/admin/outbox` | `list-outbox`: sales whose code has not reached its buyer, and a per-line button that reads one code back. |
| `/admin/audit` | Who signed in, who failed to, what was issued and what was voided. |

It is server-rendered HTML with **no JavaScript at all** — no framework, no CDN,
nothing loaded from anywhere. The content security policy is `default-src
'none'`, which the page can afford to say because it needs nothing.

**Two rules hold everywhere on it**, and they are the same two the commands
follow:

1. **No redemption code the store knows only by hash is ever rendered.** Not in
   a table, not on a detail page, not in an audit line. The store holds a
   SHA-256 and the page has nothing to render.
2. **The void confirmation says, in the interface, that it cannot recall a
   licence already issued from that code** — naming how many servers already
   hold one and when they stop working. The words come from the same place the
   command's do, so the two cannot drift apart.

### The two places a code IS shown, and why that is not a third rule

A code exists in the clear for exactly one moment, and that moment is the only
chance anybody has to copy it. So:

* **Issuing one** shows it once, on the page after the form. Refreshing, going
  back, or opening it in another tab shows *"that code has already been
  shown"* — the code travels from the POST to the page in server memory, never
  in a URL or a redirect, and the first render consumes it. If you lose it,
  nothing recovers it: issue another and void the one you lost.
* **The outbox** holds codes in the clear, because it has to — that is what it
  is for. The button beside a line reads **one** of them back onto the same
  show-once page. The audit trail records that you did it, and records the
  hash tag rather than the code.

Neither is an exception to rule 1: rule 1 is about codes the store knows only by
hash, and it cannot show those because it does not have them.

### Looking up a code a customer sent you

The codes page has a lookup box. It is a form **POST**, not a link, on purpose:
a code in an address bar ends up in your browser history, in any proxy log
between you and here, and in the `Referer` header of the next page you load. The
code is normalised, hashed, and answered with a redirect to the *tag*. It is
never shown back to you.

### What guards each request

* **The session.** A 256-bit id from the system CSPRNG, naming state held on
  this server — there is nothing in the cookie to forge or to tamper with. The
  cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, host-scoped with no
  `Domain`, and named with the `__Host-` prefix, which makes the browser enforce
  those last three itself and refuse the cookie outright if they ever stop being
  true. Signing out destroys the state on the server, so a copy of the cookie is
  worth nothing from that moment. Sessions are in memory only: restarting the
  service signs you out, which is correct — the alternative is writing them to
  the same disk as the signing key.
* **A CSRF token**, bound to your session, on every action that changes
  anything, compared in constant time. `SameSite=Strict` is set as well and is
  **not** what is relied on: it is a browser behaviour with a history of
  exceptions and it is not something this service can verify happened.
* **A one-shot form token** on issuing and on revealing, so that a double-tapped
  button, a refreshed POST or a back-and-submit-again creates **one** credential
  and answers *"that form had already been submitted"* to the second.
* **A login budget of its own**, described next.

### The login delay, and why there is no lockout

A wrong password buys a wait before the next attempt, and the wait doubles: 2
seconds, 4, 8, 16, up to `ADMIN_LOGIN_MAX_DELAY_SECONDS`. An attempt made during
the wait is refused *before the password is looked at*, so guessing cannot make
this service spend PBKDF2 time either. A correct password clears it.

**Nothing is ever locked.** However many times somebody guesses wrong, the wait
expires and the right password works again. This is deliberate and it is the
opposite of the usual rule: there is one operator, and an attacker who could
lock the account out could stop the only person able to fix this service from
reaching it, from anywhere, for free. A delay costs a guesser everything and
costs you a few seconds once.

There is a second, **global** delay so that guessing from ten thousand addresses
is not ten thousand times faster than guessing from one. It is capped at five
seconds, because it is the one an innocent operator can be caught by: at that
ceiling a distributed guesser gets about twelve attempts a minute, and you wait
five seconds.

**This budget has nothing to do with `/v1/activate`'s.** A flood of activation
attempts cannot delay your login, and an attack on your login cannot stop
customers activating the licences they have paid for. Two objects, two sets of
state, and a test that asserts it.

### The audit trail

`/data/admin-audit.jsonl`, one JSON object per line, **and** the service log.
Every sign-in, failed sign-in, throttled attempt, sign-out, refused token, void,
issue and outbox reveal, with the address it came from.

It is a file as well as a log because container logs rotate, get truncated by a
restart policy, and are the first thing lost when a box is rebuilt — and *"when
was this voided, and from where"* is a question that arrives months later, in an
argument. It is on the mounted volume, so the backup that saves your customer
list saves the account of what was done to it.

It never holds a redemption code, the password, or a session id — a
twelve-character fingerprint of the session goes in instead, so two lines from
one sign-in can be tied together and nothing in the file would authorise a
request if it leaked. Anything shaped like a code that reaches it is redacted
before the line is written, which is a guard against code nobody has written
yet rather than against the callers there are today.

```
docker compose exec licence sh -c 'tail -5 /data/admin-audit.jsonl'
```

```json
{"utc":"2026-08-31T18:04:11Z","event":"login","client":"203.0.113.7","session":"4f2a9c1b7e03","tag":null,"detail":"signed in"}
{"utc":"2026-08-31T18:05:02Z","event":"issue","client":"203.0.113.7","session":"4f2a9c1b7e03","tag":"9f2a1c3e5b7d","detail":"issued to 'Jane Tester', 3 activations, 365 days"}
{"utc":"2026-08-31T18:09:44Z","event":"void","client":"203.0.113.7","session":"4f2a9c1b7e03","tag":"1b0c77aa2e41","detail":"voided: refunded, ticket 4471"}
{"utc":"2026-08-31T19:22:10Z","event":"login_failed","client":"198.51.100.9","session":null,"tag":null,"detail":"wrong password"}
{"utc":"2026-08-31T19:22:12Z","event":"login_throttled","client":"198.51.100.9","session":null,"tag":null,"detail":"waiting 2s (client)"}
```

### Headers

Every response from this service now carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a content security
policy, `Permissions-Policy` and `Strict-Transport-Security`. Admin responses
carry `Cache-Control: no-store` on top, including the redirects: a browser cache
of your customer list on a laptop is a leak with no upside, and the back button
after a sign-out must not paint the page again out of it.

### What this page is still not

* **It is not multi-user.** One password, no accounts, no roles. Everything it
  can do, anyone who signs in can do.
* **There is no second factor.** If this service ever holds anything worth more
  than it does now, that is what to add next.
* **It cannot recover a code.** Nothing can. The store holds hashes.

---

## Emailing the code

**Off by default, and that is deliberate.** With no `SMTP_HOST` this service
does what it has always done: the code goes to `codes-outbox.jsonl` and a human
sends it. Nothing about that changes when you upgrade. Setting `SMTP_HOST` and
`SMTP_FROM_ADDRESS` is the whole of turning it on.

Mail is layered **on top of** the outbox, never instead of it:

```
webhook verified -> code created in one transaction -> WRITTEN TO THE OUTBOX
                 -> handed to a background sender -> 200 to PayPal
                                                       (mail happens after this)
```

The outbox write is the durable step. The email is a convenience on top of a
code that is already written down, so nothing this feature does can lose a code
that the old arrangement would have kept.

### A mail failure never fails the webhook

PayPal needs its 2xx. A webhook that answers late, or answers 500, is retried —
and a retry of a payment that was processed correctly is exactly the thing the
event-id primary key and the capture-id unique index exist to make harmless. So
the send does not happen inside the request at all. The webhook hands the code
to a bounded in-process queue and returns; a background worker does the sending,
where taking eleven minutes to give up costs nobody anything.

That makes it structural rather than a matter of catching the right exception:
the relay is not on the webhook's call stack and there is no path by which one
can fail the other. `CodeDeliveryTests` asserts it, including the case of a
relay that accepts the connection and then stops answering.

When every attempt has failed the log says `EMAIL FAILED` at error, names the
relay, the recipient and the code's hash tag, and tells you the code is in the
outbox. **That is the same file, in the same state, that you work from today.**

### Retries

Four attempts by default, at 30s, 2m and 8m, then it gives up and leaves the
outbox to it. A 5xx from the relay — no such mailbox, bad password — is **not**
retried at all: it will not get better, and retrying only delays the log line
somebody has to act on. A 4xx, a refused connection or a timeout is retried,
because a relay restarting while somebody pays should not cost a sale.

The queue holds 256 codes. If it fills, the enqueue is refused, logged at error,
and the code is in the outbox — which is to say the worst this feature can do
under load is degrade to the behaviour it replaced.

### The three transport modes

| `SMTP_SECURITY` | Port | |
| --- | --- | --- |
| `tls` | 465 | Implicit TLS. The session is inside TLS from the first byte. |
| `starttls` | 587 | **The default.** A plain connection that must upgrade. |
| `none` | 25 | No encryption. For a relay on this machine, or a network you own. |

`starttls` **fails closed**: if the relay does not offer STARTTLS the send fails
rather than continuing in the clear with a bearer credential in it. There is no
"try TLS and carry on without it" mode, no way to accept an untrusted
certificate, and no way to turn certificate validation off — the same position
this service takes on webhook signatures, for the same reason.

`SMTP_SECURITY=none` together with `SMTP_USERNAME` is **a refusal to start**.
SMTP AUTH over a cleartext socket puts the relay password on the wire on every
message; an operator who genuinely has an unauthenticated local relay only has
to leave the username unset. Starting with `none` and no username logs a warning
naming the host, every time.

### Why MailKit and not `System.Net.Mail.SmtpClient`

Two reasons, and the first is not a matter of taste:

1. **`SmtpClient` cannot do implicit TLS.** Its `EnableSsl` issues STARTTLS on a
   connection that begins in the clear, so a relay expecting TLS from the first
   byte on port 465 — which is most hosted mail today — is unreachable through
   it. Two of the three modes above is not enough.
2. Microsoft's own documentation for `SmtpClient` says it is not recommended for
   new development and names MailKit as the alternative.

Beyond that: MailKit distinguishes `StartTls` (fails closed) from
`StartTlsWhenAvailable` (downgradeable), which is the distinction that matters
here; it is async and cancellable throughout; and it reports the relay's status
code, which is what makes "retry a 451, never retry a 550" possible.

The cost is two transitive dependencies — MimeKit and BouncyCastle — **in the
vendor's service image only.** Nothing in `src/` references any of it and the
plugin does not ship it.

### What the buyer gets

Plain text, one part, no HTML. That is not a shortcut. A message carrying a
credential somebody has to retype is worse in HTML: a proportional font makes
`0`/`O` and `1`/`l` harder to tell apart, clients linkify and hyphenate, and a
remote image in an HTML part is a read receipt on a message containing a live
secret.

It tells them the code, where to paste it and which button to press, how long
the licence lasts and from when, how many servers it covers and that
re-activating the same one is free, that the code is a password, and who to
write to. `CodeMessageTests` asserts each of those, because each of them is a
support email that otherwise gets written.

**The wording is a template you can replace without rebuilding the image.** Point
`SMTP_TEMPLATE_PATH` at a plain-text file using `{code}`, `{licensee}`,
`{product}`, `{licence_days}`, `{activations_allowed}` and `{support}`. A
template with no `{code}` in it is a refusal to start, because a cheerful email
containing no code is worse than no email. Braces that are not placeholders are
left alone. It is read once at startup, so changing it needs a restart.

### What is in the outbox once mail is on

The code line is written exactly as before. A **successful** send appends a
second line — `{"record":"delivered", ...}` — carrying the code's hash tag and
the recipient, and **not** the code, so it is safe to keep after you prune the
code line. To find codes that still need sending by hand:

```
cd /srv/emby-sso/data
comm -23 \
  <(jq -r 'select(.code) | .code_tag' codes-outbox.jsonl | sort -u) \
  <(jq -r 'select(.record=="delivered") | .code_tag' codes-outbox.jsonl | sort -u)
```

With mail off, no `delivered` lines are ever written and the file is identical
to the one you have today.

### What is never logged

The redemption code, the rendered message body, and `SMTP_PASSWORD`. A send is
logged as the recipient plus the code's twelve-character hash tag — the same tag
every other line about that code uses — so *"did this reach them?"* is
answerable without the log becoming a place credentials live. This is the
treatment `PAYPAL_CLIENT_SECRET` already gets. `CodeMailerTests` drives every
path — success, transient failure, permanent refusal, no recipient — and
searches the whole rendered log, exception text included, for both.

---

### When a code cannot be delivered

Two different failures, and they are not the same size.

**`EMAIL FAILED` at error** means the relay would not take it. The code exists,
it is in the outbox, and the sale is fine — send it by hand and fix the relay.
See *Emailing the code* above.

**`CODE LOST` at critical** is the serious one: the outbox itself could not be
written. If the outbox cannot be written, the log says `CODE LOST` at critical,
naming the capture and the buyer. The buyer has paid and has no code, and the code is
not recoverable — it was a local variable, and it is deliberately **not** logged,
because a log file is not where live credentials belong even in a disaster.

Fix the volume, then void the orphaned code and issue a replacement. Find it
with `list-codes` — an orphaned code has no outbox line, so look for the one
created at the moment of the capture — and void it by tag:

```
docker compose exec licence \
  dotnet Emby.Sso.LicenceService.dll list-codes --needs-attention

docker compose exec licence \
  dotnet Emby.Sso.LicenceService.dll void-code --tag <tag> \
  --reason "outbox unwritable, code lost, replaced"

docker compose exec licence \
  dotnet Emby.Sso.LicenceService.dll issue-code --licensee "<buyer email>"
```

Do not edit `status` with `sqlite3` by hand: `void-code` records when and why as
well, which is what `show-code` prints back at you in six months.

---

## Building and testing

Not in `Emby.Sso.sln`, and that is deliberate: `dotnet build` at the repository
root must not build or ship any of this into the plugin. It has its own
solution, and CI runs it as its own job (`service-test`) — which it did not
always, and until it did, a service that failed its tests could still have been
shipped.

```
export DOTNET_ROOT=$HOME/.dotnet
dotnet test service/Emby.Sso.Service.sln
```

453 tests. What they cover, and why each is there, is in the class comments; the
ones that carry weight are `PayPalWebhookVerifierTests` (a tampered payload is
refused), `PayPalCertificateValidatorTests` (an untrusted certificate is
refused), `ActivationStateMachineTests` (the cap and free re-activation),
`RateLimiterTests` (the four properties above, each asserted), and
`LicenceToolCompatibilityTests` (the offline tool has not drifted), and the delivery set - `CodeDeliveryTests`
(a mail failure still answers PayPal and leaves the code in the outbox),
`CodeMailerTests` (no secret reaches a log) and `MailKitSmtpTransportTests`
(a loopback listener this process owns, so the suite needs no mail server and
cannot send mail anywhere) - and the management set, `CodeInventoryTests` (which
state a code is in, and what order they are shown in) and
`ManagementCommandTests` (a read-only command against a missing store creates
nothing, no listing prints a code, a code is found however a human spelled it,
and voiding says what it cannot do).

---

## What is UNVERIFIED

Everything that requires PayPal, **and every real email send.** There were no
credentials of either kind and no network route to them where this was written,
and **nothing here has ever simulated a success and called it working.**

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
- **The Docker image, and everything CI does with it.** Never built — not by
  hand, not by a runner. Docker was not available where any of this was
  written. Two of the three unknowns are now settled: a runner has built the
  image and `registry.koper.local:5050` has accepted the push (pipeline #2036,
  tags `main` and `main-5150d9b1`). What is still unproven is that the
  deployment host can pull and run it — and the first attempt failed on
  `manifest unknown` for `:latest`, which is not a registry fault: no `vX.Y.Z`
  tag has ever been built, and `latest` comes only from one of those. *The image
  CI builds*, above, has the command that settles the rest.
- **The management commands inside the container.** `list-codes`, `show-code`,
  `void-code` and `list-outbox` were run against a real store on disk and are
  covered by tests, but never through `docker compose exec` — the same reason:
  no Docker. What is unproven is the invocation itself and the path to the DLL.
  Reading the store *while another process holds the write-ahead log* was
  checked by hand — a second process took `BEGIN IMMEDIATE` and inserted a row,
  and `list-codes` read the committed rows past it and did not see the
  uncommitted one — but that was two processes under one uid on one filesystem,
  which is what the container should also be and has not been observed to be.
- **Any concurrency beyond the tests' own.** The transaction boundaries are
  argued for in `LicenceStore`'s comments, not proven under load.
- **A real email send — no message has left this machine.** There were no SMTP
  credentials, and nothing here has ever connected to a mail server on a network.
  What *is* tested: the whole of the retry, fallback and logging behaviour
  against a fake transport; the message wording; and — against a loopback
  listener this process owns, on `127.0.0.1` — that `MailKitSmtpTransport` really
  speaks EHLO/MAIL/RCPT/DATA, really puts the code on a wire, and turns a `550`
  into a permanent failure and a `451` into a retry.
  What is **not** tested: that implicit TLS or STARTTLS work against a real
  relay, that authentication works at all, and that any particular provider
  accepts the message. The mapping from `SMTP_SECURITY` to MailKit's option is
  asserted; the TLS handshake it produces is not.

`docs/paypal-sandbox-checklist.md` is the run that closes the PayPal half, in
order, with the log lines to expect at each step, and
`docs/email-delivery-checklist.md` closes the mail half the same way. Do both
before live money.

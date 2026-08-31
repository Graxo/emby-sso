# The PayPal sandbox checklist

**Nothing in this service has ever spoken to PayPal.** It was written in an
environment with no PayPal credentials and no network route to them, so the
whole PayPal path — creating an order, being redirected to approve it, the
webhook that arrives afterwards — is **UNVERIFIED**. What is tested is
everything either side of the wire: the message that gets signed, the signature
check against a key the tests own, the replay rules, the amount check, and the
shape of the requests the checkout client builds.

This is the run that closes that gap. Do it in the sandbox before you point
anything at live money, and work down the list in order — each step depends on
the one above it.

You need: a PayPal developer account, a sandbox business account and a sandbox
personal account, and this service running somewhere PayPal can reach over
HTTPS. A tunnel to your laptop is fine for the sandbox.

---

## 1. It starts at all

```
docker compose up licence
```

Expect, on the first line or two of the log:

```
signing key <16 hex chars> loaded from /run/secrets/licence-signing-key.private.json; store /data/licences.db; ...paypal sandbox; 3 activations per code; 365 day licences
```

- [ ] The thumbprint matches the key you meant to mount. Compare it against
      `/healthz`, which prints the same one.
- [ ] It says `sandbox`, not `LIVE`.
- [ ] `curl -s localhost:8080/healthz` answers `{"status":"ok",...}`.

If it exits 78 instead, the message says exactly what is wrong. That is the
intended behaviour and there is nothing to work around.

**Prove the key check is real while you are here.** On the host:
`chmod 640` the key, restart, and confirm the service refuses to start and says
why. Then `chmod 600` it again. A guard nobody has ever seen fire is a guard
nobody knows works.

## 2. The buy page

- [ ] `https://<your host>/buy` renders, shows the price and currency you
      configured, and shows a **Pay with PayPal** button.
- [ ] `https://<your host>/buy?serverId=c5bc6e91458540caa295c4efdda1a58a`
      additionally shows that server id back, with the note that the licence is
      not tied to it.
- [ ] It renders with no `serverId` at all, and with a nonsense one.

## 3. Checkout — **the first genuinely unverified step**

Set `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET` from your sandbox app.

- [ ] Press the button. You reach PayPal's sandbox approval page.
- [ ] The amount on PayPal's page is the amount `/buy` showed you. If it is
      not, `PAYPAL_PRICE` and `PAYPAL_CURRENCY` are the only things involved.
- [ ] Log in as the sandbox **personal** account and approve the payment.
- [ ] You land back on `/buy/complete`.

If PayPal refuses to create the order, the log line from `buy/start` carries
the status code. The two likely causes are credentials from the wrong
environment (live keys against the sandbox host, or the reverse) and a
`PAYPAL_RETURN_URL` that is not a real reachable address.

## 4. The webhook — **the step that matters most**

In the developer dashboard, create a webhook on your sandbox app pointing at
`https://<your host>/paypal/webhook`, subscribed to at least:

- `PAYMENT.CAPTURE.COMPLETED`
- `PAYMENT.CAPTURE.REFUNDED`
- `PAYMENT.CAPTURE.REVERSED`

Put its id in `PAYPAL_WEBHOOK_ID` and restart.

- [ ] Complete another sandbox purchase.
- [ ] The log says `paypal capture <id> accepted: code <tag> created for <email>`.
- [ ] A new line appears in `/data/codes-outbox.jsonl` with a readable code.

**If instead you see `paypal webhook REFUSED`**, read the reason on that line
before changing anything:

| Reason on the log line | What it means |
| --- | --- |
| `a required PAYPAL-* header is missing` | Something between PayPal and this service is stripping headers. A reverse proxy, usually. |
| `the signature does not match this request` | The webhook id is wrong, **or** something is altering the body in flight — a proxy that reformats JSON will do this, because the signature covers a CRC of the exact bytes. |
| `paypal-cert-url points at ...` | Should never happen from PayPal. If it does, stop and look at it properly. |
| `the certificate was not usable: ... does not chain to a trusted root` | The container's CA bundle. This is the step that proves the trust half of the check, which no test here can. |

That last row is the one this whole document exists for. The tests prove the
verifier **refuses** a certificate that does not chain to a trusted root; only
this step proves it **accepts** PayPal's.

- [ ] Send the same event again from the dashboard's "resend" button. The log
      says `REPLAY` and no second line appears in the outbox.

## 5. The code works

- [ ] Take the code out of the outbox, paste it into the plugin on a real Emby
      server, and activate.
- [ ] The service logs `activate OK code=<tag> server=<id> NEW used=1/3`.
- [ ] Activate again on the same server: `REPEAT used=1/3`. It did not cost an
      activation.
- [ ] Activate on a second and third server: `used=2/3`, `used=3/3`.
- [ ] A fourth server is refused with `code_exhausted`.
- [ ] `licencetool list --ledger /srv/emby-sso/data/licences-issued.jsonl`
      lists what was issued. This is the offline tool reading the online
      service's ledger, which is the whole reason the format is shared.

## 6. Refunds

- [ ] Refund the sandbox payment from the business account.
- [ ] The log says the code is now void.
- [ ] The code will not activate a new server.
- [ ] **A server that already activated keeps working.** That is not a bug and
      cannot be changed: the plugin verifies its licence offline against an
      embedded public key and never calls home, so there is no revocation. Know
      this before you argue with somebody about it.

## 7. Going live

Only after every box above is ticked.

- [ ] `PAYPAL_ENV: live`, live client id and secret.
- [ ] A **new** webhook created on the live app, and its **different** id in
      `PAYPAL_WEBHOOK_ID`. The sandbox id will not verify a live transmission.
- [ ] `LICENCE_PUBLIC_BASE_URL` is the real hostname the plugin ships with.
- [ ] One real purchase, with your own money, end to end.
- [ ] Refund yourself.

## What is still unverified after all of this

- Anything PayPal changes later. The message layout, the header names and the
  certificate hosts are theirs, not ours.
- Load of any kind. Nothing here has been run under concurrency beyond the
  tests' own.
- The Docker image itself, which has never been built — see the note at the top
  of `service/Dockerfile`.

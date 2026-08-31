# The email delivery checklist

**A real send is UNVERIFIED.** No SMTP credentials existed where this was
written, no message has ever left the machine it was built on, and no test in
the suite connects to anything but a loopback listener the test process owns.
Everything below is the run *you* do to make it verified — it is written to be
done in order, in about twenty minutes, before any of it touches live money.

You need: SMTP credentials for a relay you control, and a mailbox you can read
that is **not** the one the service sends from.

Nothing here needs Docker. Steps 1–4 can be done with `dotnet run` against a
scratch data directory if that is easier.

---

## 0. Before you start: mail is off, and off is safe

If you have not set `SMTP_HOST`, none of this applies to you and nothing has
changed. The code goes to `codes-outbox.jsonl` and you send it, exactly as
before. Confirm that first, so you know what you are moving away from:

```
docker compose logs licence | grep 'code delivery by email'
```

```
code delivery by email: off (no SMTP_HOST); codes go to the outbox only
```

If that is what you want, stop here.

---

## 1. It starts, and it says what it will do

Set the minimum and restart:

```
SMTP_HOST: smtp.example.com
SMTP_FROM_ADDRESS: licences@example.com
SMTP_USERNAME: licences@example.com
SMTP_PASSWORD: ${SMTP_PASSWORD}
```

Expect exactly one new line at startup:

```
code delivery by email: smtp.example.com:587 starttls, authenticating as licences@example.com, from licences@example.com
```

**Check that line for your password.** It is not supposed to be there and there
is a test asserting it is not, but this is the one place you would see it.

If the service exits 78 instead, it will have printed every problem at once.
The likely ones:

| It says | It means |
| --- | --- |
| `SMTP_HOST is not set but other SMTP_* variables are` | You filled in the credentials and missed the host. Nothing would have been emailed. |
| `SMTP_SECURITY must be exactly 'tls' ...` | `ssl`, `TLS1.2` and `auto` are not modes. There are three. |
| `SMTP_SECURITY is 'none' and SMTP_USERNAME is set` | That would put your relay password on the wire in the clear. Use `starttls`, or drop the username. |
| `SMTP_USERNAME is set but SMTP_PASSWORD is empty` | Usually a compose file quoting problem. |
| `SMTP_FROM_ADDRESS does not look like an email address` | Display names go in `SMTP_FROM_NAME`. |
| `SMTP_TEMPLATE_PATH points at ... which does not exist` | The file is not inside the container. Mount it. |

---

## 2. The first real send — **the genuinely unverified step**

Use the CLI rather than a payment, so nothing depends on PayPal yet. Mint a
code to yourself and watch what happens:

```
docker compose exec licence \
  dotnet Emby.Sso.LicenceService.dll issue-code --licensee "you@yourdomain.example"
```

`issue-code` prints the code on stdout and stores only its hash. **It does not
touch the outbox and it does not email anything** — only the webhook does that,
deliberately: `issue-code` is for codes no payment bought, and you already have
the code in front of you. So to test mail end to end you need step 3.

If you want to test the relay in isolation first, do it from the container so
you are testing the container's DNS, egress and trust store rather than your
laptop's:

```
docker compose exec licence sh -c \
  'echo | openssl s_client -starttls smtp -crlf -connect smtp.example.com:587 2>&1 | head -20'
```

(If `openssl` is not in the runtime image, run the same command from the host
and treat the result as indicative rather than conclusive — the container's DNS
and egress are what actually matter.)

You are looking for `Verify return code: 0 (ok)`. Anything else — a self-signed
relay certificate, a wrong hostname, a transparent proxy — will fail the send
with `TLS to smtp.example.com:587 failed`, and this service has no option to
ignore it.

---

## 3. A sandbox payment, end to end

Do the PayPal sandbox run in `paypal-sandbox-checklist.md` step 4, but read the
log for the two extra lines. On success:

```
paypal capture 3XY... accepted: code a1b2c3d4e5f6 created for you@yourdomain.example, 3 activations, 365 days
code a1b2c3d4e5f6 emailed to you@yourdomain.example on attempt 1
```

Then check, in this order:

1. **The message arrived**, and is not in the spam folder. If it is, your SPF,
   DKIM or DMARC is the problem, not this service — the `From` address must be
   one the relay is authorised to send as.
2. **The code in the email is the code in the outbox.**
   ```
   grep -o '"code":"[^"]*"' /srv/emby-sso/data/codes-outbox.jsonl | tail -1
   ```
3. **It activates.** Paste it into the plugin and press Activate. This is the
   only step that proves the whole chain.
4. **A second line appeared in the outbox:**
   ```
   tail -1 /srv/emby-sso/data/codes-outbox.jsonl
   {"record":"delivered","delivered_utc":"...","delivered":true,"code_tag":"a1b2c3d4e5f6","recipient":"you@yourdomain.example",...}
   ```
   That is the receipt. It carries the hash tag, never the code, so it is safe
   to keep after you prune the code line.
5. **Neither the code nor the password is anywhere in the log:**
   ```
   docker compose logs licence | grep -iF "$CODE"      # must print nothing
   docker compose logs licence | grep -iF "$SMTP_PASSWORD"  # must print nothing
   ```

---

## 4. Prove the failure path, because that is the one that will happen

Point the service at a host that does not answer — `SMTP_HOST: 127.0.0.1`,
`SMTP_PORT: 1`, `SMTP_SECURITY: none`, no username — restart, and take another
sandbox payment.

What must happen, and all four of these matter:

1. **PayPal gets a 200.** Check the webhook's delivery status in the PayPal
   dashboard: it must show delivered, not retrying. A retry here would be a
   second decision about a sale already made.
2. **The webhook answered promptly** — it did not wait out the retry schedule.
3. The log shows the attempts and then, after roughly eleven minutes:
   ```
   email attempt 1 of 4 for code a1b2... failed (could not reach 127.0.0.1:1 ...); retrying in 30s
   ...
   EMAIL FAILED for code a1b2... to you@... after 4 attempt(s) via 127.0.0.1:1 none, no authentication: ...
   ```
4. **The code is in the outbox with no delivery receipt**, and it activates.
   This is the fallback working: the file in front of you is the file you used
   before mail existed.

Put your real settings back afterwards.

---

## 5. The mode you are actually on

Run this once against your relay's real port, because the commonest mail
misconfiguration is a mode/port mismatch and it fails in a way that looks like a
network problem:

| Your relay says | Set | Port |
| --- | --- | --- |
| "SSL/TLS", "SMTPS", 465 | `SMTP_SECURITY: tls` | 465 |
| "STARTTLS", "TLS", "submission", 587 | `SMTP_SECURITY: starttls` | 587 |
| a relay on this host or a network you own | `SMTP_SECURITY: none` | 25 |

`starttls` pointed at 465 fails the handshake; `tls` pointed at 587 hangs until
the timeout. Both are reported as a TLS failure naming the host, port and mode,
which is the line to read when this bites.

`none` means every redemption code you send crosses that network readable. The
service logs a warning naming the host at every startup, and will refuse to
start if you also give it a username, because that would put the relay password
on the wire too.

---

## 6. Custom wording, if you want it

```
SMTP_TEMPLATE_PATH: /run/config/licence-email.txt
```

mounted read-only. Placeholders: `{code}`, `{licensee}`, `{product}`,
`{licence_days}`, `{activations_allowed}`, `{support}`. Anything else in braces
is left alone.

It must contain `{code}` or the service refuses to start — a friendly email
containing no code is worse than no email. It is read once at startup, so a
change needs a restart. Send yourself one after every edit; a template is
untested code.

---

## What is still unverified after all of this

- **Deliverability**, which is not a property of this service. SPF, DKIM and
  DMARC for the `From` domain, and whether the buyer's provider files a message
  containing a long random string in the spam folder, are yours to check with a
  real recipient at a real provider.
- **Bounces.** The service knows the relay accepted the message. It does not
  read a mailbox and it will never know the message bounced afterwards. Watch
  the `From` mailbox for a while.
- **Behaviour under a slow relay at volume.** The queue holds 256; a one-person
  vendor will not reach that, and nobody has proven what happens if they do
  beyond the code refusing the enqueue and saying so.

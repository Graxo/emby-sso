# Native apps with a one-time PIN

**Off by default, and a separate setting** from
[native password sign-in](native-apps.md) — "Allow native apps to sign in with
a one-time PIN". Neither setting turns the other on, and you can run either,
both or neither.

This is the answer to the question the direct grant does not answer well: how
does somebody sign in on a **television** without either typing an app-password
token with a D-pad or giving up multi-factor authentication?

!!! unverified "PIN sign-in has never run on a server"

    It is built and unit-tested; the decisions are covered by the automated
    suite. Nothing has typed a PIN into a real TV app. See
    [what specifically is unmeasured](#what-is-not-measured) below and
    [What has and has not been verified](verification-status.md).

## How a user gets one

1. On a phone or a laptop, they open the PIN URL:

    ```
    https://<your-emby-server>/sso/pin
    ```

    The configuration page shows this exact URL for your server, next to the
    ordinary sign-in URL, under "PIN URL for users to open on a phone or
    laptop".

2. They sign in through Authentik **normally** — the full interactive flow,
   with whatever MFA, passkeys and policies you have on it.
3. The page that comes back shows an eight-character PIN, like `K7RM-3XQP`.
4. On the television, they open Emby's ordinary sign-in screen, type their
   **Emby username**, and type that **PIN** where it asks for a password.

That is it. It works with **unmodified Emby apps**, because a PIN is typed into
the one field those apps already have.

## What the PIN is, exactly

- **Eight characters** from a 30-character alphabet — digits 2–9 and A–Z
  without I, L, O or U, so there is no `0`/`O` or `1`/`I`/`l` to misread. That
  is about 39 bits, or 656 billion possibilities. Case does not matter, and the
  hyphen is optional.
- **Five minutes**, from when it is shown.
- **Single use.** It is consumed by the sign-in it completes.
- **Destroyed after three wrong entries.** A PIN guessed at wrongly is gone; a
  user who mistypes theirs three times opens the PIN URL again for a new one.
  That is deliberate — see [below](#why-a-few-wrong-entries-destroy-it).
- **Bound to one Emby account.** A live PIN presented with somebody else's
  username is refused, and refusing it does not spend it.
- **Held in memory only.** Restarting Emby forgets every live PIN, which is
  correct: they are worth minutes.
- **Never logged, never in a URL.** The server log records that a PIN was
  issued and for whom, never the PIN itself.

## It inherits every guard an ordinary sign-in has

The PIN endpoint is not a second way to authenticate anybody. It starts the
**same browser flow** as `/sso/start` — the same redirect, the same
callback, the same checks — and differs only in what happens after all of them
have passed.

So a PIN is issued only to somebody who would have been signed in: the licence
must be valid, the required group must be configured *and held*, the Emby
account must already be stamped to this plugin (or be one this plugin is
allowed to create), and the Authentik `sub` must match the account's recorded
binding. **If any of those would have refused the person, no PIN exists.**

Redeeming one is checked too: the licence, the required-group setting and the
provider stamp are all re-checked at sign-in, and turning the PIN setting off
stops PINs already issued from being redeemed as well as stopping new ones.

## Why a few wrong entries destroy it

A PIN is far weaker per guess than the 256-bit secret the browser flow uses
internally, and it is typed into a field anyone on the network can reach. The
defence that has to hold is that it **cannot be ground down**: because three
wrong guesses consume the PIN, a guesser's entire chance against an issued PIN
is 3 in 656 billion, no matter how fast they send guesses or how many usernames
they spread across.

Three rather than one costs 1.6 bits of the 39.3 and buys back the person
typing eight characters with a television remote, for whom a single slip would
otherwise mean repeating a whole browser sign-in.

The property the plugin guarantees, and tests:

> The only thing a PIN attempt can consume is the PIN issued to the very
> username that attempt names. Nothing done to one account's PIN can refuse
> anything to any other account, and nothing done to it can refuse any other
> credential — browser sign-in and, if you enabled it, password sign-in are
> untouched.

There is deliberately **no server-wide PIN rate limit**, and PIN attempts are
deliberately **not** charged to the
[provisioning throttle](brute-force-protection.md). Both would be worse than
useless here: any aggregate ceiling is reachable by an unauthenticated stranger,
and a reached ceiling is a refusal for whoever asks next — the exact denial of
service that was removed from the provisioning throttle. A limit that lives on
one secret cannot be turned into a weapon against a third party.

### What an attacker can do, stated plainly

Somebody who knows a username can send PIN-shaped guesses at it and destroy
that person's PIN each time one is issued, denying **that one person** the PIN
route for as long as they keep it up. It affects nobody else and no other
sign-in path, and allowing three attempts instead of one would not fix it —
three guesses a second destroys a PIN as reliably as one.

The alternative, not consuming on failure, would let the same attacker grind
the PIN instead of denying it, and a credential that can be ground is a
credential that is eventually guessed.

### Two things that are not a problem, and are tested

- A user's own password, typed on the TV by mistake, does not destroy their
  live PIN. Only a value that is PIN-*shaped* counts as an attempt at a PIN.
- Presenting somebody's PIN under a different username does not destroy it.

## PIN versus app password

Both let a TV app sign in. They are not the same bargain.

| | One-time PIN | Authentik app password (direct grant) |
|---|---|---|
| Where it comes from | Issued by this server at the end of a full browser sign-in | Created by the user in Authentik, outside this plugin |
| MFA | **Yes** — the browser sign-in that issued it did whatever MFA you enforce | **No** — a direct grant cannot do MFA at all |
| Lifetime | 5 minutes | Until the user's chosen expiry, if they set one |
| Reuse | Once | Every sign-in, indefinitely |
| Strength per guess | ~39 bits, and one guess allowed per issuance | A long random token |
| If it leaks | Worthless within minutes, and only if unused | Library access until it is revoked |
| Typing on a remote | 8 characters | A long token |

The app-password route **stays supported** and is unchanged; nothing here
deprecates it. The honest comparison is that a PIN is weaker *per guess* than a
token and stronger *everywhere else* — it is short-lived, single-use,
account-bound, rate-limited by construction, and it is the only one of the two
that carries multi-factor authentication onto the television.

## Plain HTTP

The plain-HTTP refusal that applies to the direct grant does **not** apply to
PINs, for the same reason it does not apply to the browser flow: there is no
real password involved. A PIN is a value this server issued, single-use, and an
eavesdropper who sees one sees it inside the request that is spending it.

## What is not measured

!!! unverified "Three things, and none of them can be checked without a server and a TV"

    - **That Emby routes the new `/sso/pin` route to this plugin's service
      at all.** It is declared exactly as the two existing routes are, with the
      same `[Route]` and `[Unauthenticated]` attributes on a request DTO handled
      by the same service class, so it either works the way they do or none of
      them do — but no request has been made to it.
    - **That a native Emby app actually accepts an eight-character PIN in its
      password field and posts it unchanged.** The redemption path is the same
      `AuthenticateByName` path the handoff secret already uses, which was
      observed working with `curl`, but no TV app has typed a PIN into it.
    - **That the configuration page still renders and saves** with the new
      checkbox and PIN URL on it. Emby 4.9's plugin page loader is fragile and
      this project has broken it before. An operator must open the page after
      installing, confirm it renders, tick and untick the new setting, and
      confirm it saves. If the page comes up blank, the cause is the page, not
      the feature.

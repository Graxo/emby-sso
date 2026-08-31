# Brute-force protection

Opening the "unknown username" branch — the one
[automatic account creation](groups-and-account-creation.md) turns on — means an
unauthenticated stranger can make this server forward a guessed password to
Authentik.

Emby's own lockout (`InvalidLoginAttemptCount`) lives on a user policy and
therefore cannot help here: the whole point of this branch is that no such user
exists yet.

!!! danger "Two brakes cover it, and both are required"

    Brake 2 is **required configuration, not optional hardening**. The plugin
    cannot do what it does.

## Brake 1: the plugin's own throttle

Automatic and not configurable. It applies to the **native provisioning branch
only** — the browser flow never hands this server a password to relay, so there
is nothing there to brute-force.

- **A sign-in is refused only because of failures recorded against that same
  username**, inside a **15-minute** window measured from that username's first
  counted failure. Nothing anybody else does can refuse it. A stranger spraying
  invented usernames cannot stop a first-time user who has their password right
  — that is a guarantee with a test behind it, not a hope.
- The allowance is **10 failures per username**, dropping to **3 per username**
  while more than 100 failures have been counted across all usernames in the
  window (a "surge"). The surge tightens what any one name can push at
  Authentik; it never closes the branch.
- **Failures only**, and a success clears that username's own bucket, so a new
  user who mistypes their password a few times is not locked out by their own
  typos.
- A refusal by the throttle is **character-identical** to the ordinary "this
  account is not set up on this server" — it must not tell an attacker that a
  name was worth counting. Only the server log says a limit was hit.
- An attempt that failed because **Authentik could not be reached** is not
  counted, so a provider outage during a mass first sign-in neither locks
  individual newcomers out of their own retries nor raises a surge.
- Configuration mistakes are not counted either — every refusal above is decided
  before anything is sent anywhere.

### What the throttle deliberately does not do

It does **not** cap the total number of attempts the branch may forward in a
window.

!!! note "Why that cap was removed"

    Earlier builds had one — 100 attempts, then the branch closed for everyone —
    and that cap turned out to be a weapon: about a hundred requests carrying
    random usernames, **no valid credential needed**, shut first-time sign-in
    for every real user for 15 minutes, exactly during the mass onboarding the
    branch exists to serve.

    Any aggregate cap is reachable by an unauthenticated stranger, and a reached
    cap is a refusal for whoever asks next. So the cap had to go, and brake 2
    below had to become non-negotiable.

Per-source rate limiting belongs in front of Emby, in a reverse proxy. The
plugin cannot see a client address at all.

### One consequence to know

An attacker who knows the Authentik username of someone **not yet onboarded**
can spend that name's allowance and delay that one person's first sign-in by up
to 15 minutes — 3 attempts during a surge, 10 otherwise. It affects only that
name and clears itself.

## Brake 2: Authentik's own failed-login / reputation policy

**This is required configuration, not optional hardening.**

Configure it on the flows this plugin uses, **the direct-grant flow especially**.

The plugin's throttle only sees attempts that arrive through Emby. Authentik is:

- the only side that sees the browser flow's password *at all*;
- the only side that can rate-limit by source address.

An Emby `IAuthenticationProvider` is handed a username and a password and
nothing else — no request, no headers, no client IP — so per-source limiting is
not something this plugin can do.

## What is deliberately not throttled

[PIN attempts](pin-sign-in.md#why-a-few-wrong-entries-destroy-it) are **not**
charged to this throttle, and there is no server-wide PIN rate limit. A PIN
defends itself by being destroyed after three wrong entries; an aggregate
ceiling on PINs would be the same weapon the removed cap was.

# Buying and activating a licence

Dashboard → Plugins → **Authentik SSO** → the licence area at the bottom of the
page: **This server's id**, **Buy a licence**, **Redemption code** and
**Activate**.

Activation is how a licence gets into the [Licence key](settings.md#licence-key)
field without anybody emailing you a JWT. You buy a code, paste it in, press
Activate once, and the plugin fetches the licence for this server and saves it.

!!! note "One call, made by a person"

    Activation happens when an administrator presses Activate and at no other
    time. The licence check itself stays offline forever: it reads a string out
    of the configuration and verifies it against a public key compiled into the
    build.

    The plugin does contact the vendor once a day afterwards, from a scheduled
    task you can watch and switch off, to ask whether the licence has been
    withdrawn and whether there is a newer release. It is on no sign-in path
    and it fails open. See [Updates and the daily check](updates.md).

## What a redemption code is

A short string the vendor gives you when you buy a licence. It is not the
licence — it is what you exchange for one.

Treat it as a password:

- It is a **bearer secret**. Whoever holds it can spend an activation on their
  own server.
- The plugin sends it in the **request body, never in a URL**, because a query
  string is written to access logs, proxy logs and `Referer` headers. It is
  handled the same way the OIDC client secret is.
- It is **never written to the server log** — not in a success line, not in a
  refusal, not in an exception message. Only the exception's type name is
  logged when something throws while the request is being built.
- It is sent **as typed**, trimmed of surrounding whitespace only. Case and
  separators are the service's business, so the plugin does not normalise them.

## Buying one

**Buy a licence** on the configuration page opens
`https://license.koper.cloud/buy?serverId=<this server's id>`, so the shop does
not have to ask you which server it is for.

The link appears only when this server reported an id and the service address is
usable; otherwise the page shows no link at all rather than a broken one.

!!! note "`license`, not `licence`"

    The rest of this project spells the noun the British way. The host does not,
    because a hostname is whatever DNS answers for, and DNS answers for
    `license.koper.cloud`. The other spelling has no record at all.

## The first activation is not instant

The **first** time a code is activated onto a server, the answer is *"your
licence has been requested and is being issued"*, not a licence. Pressing
**Activate** again once the vendor has signed it returns the licence, and every
activation after that is immediate.

This is deliberate, and it is the one place the plugin's user experience pays
for a security decision. The vendor's licence service does not hold the key that
signs licences — the key that could mint one for any Emby server, forever, with
no way to recall it. A person with that key signs what has been paid for, on a
machine that answers no requests. [The full reasoning is
here](offline-signing.md).

What it means for you:

- **your code is not spent by the wait** — the activation is already recorded
  against your server, and pressing Activate again does not use up another;
- **nothing about your server's sign-ins changes while you wait** — the licence
  check only affects *new* single sign-ons, and an unlicensed server has always
  had its own Emby accounts working normally;
- **if it is still pending after a few hours**, the vendor has not signed it
  yet, and that is who to ask.

## What pressing Activate actually does

1. The page POSTs the code to this plugin's own admin-only endpoint,
   `/Sso/Activate`, with the code in the body. Both activation endpoints require
   an **administrator** access token.
2. The plugin refuses to send anything at all if there is no code, if Emby
   reported no server id, or if the activation service address is not a usable
   absolute **HTTPS** URL with no credentials, query or fragment. A redemption
   code will not be put on the wire in cleartext.
3. It POSTs `{"code", "serverId", "pluginVersion"}` as JSON to
   `https://license.koper.cloud/v1/activate`, on a dedicated HTTP client with a
   **15-second timeout** that **does not follow redirects** and reads at most
   **64 KiB** of the answer. A redirect is not an activation; an unbounded body
   is not read.
4. That client goes through the **same outbound guard** as the identity
   provider, so an activation service that resolves to a loopback or private
   address is refused unless
   [Allow an identity provider on a private or loopback address](settings.md#allow-an-identity-provider-on-a-private-or-loopback-address)
   is ticked.
5. On `200`, the answer's `licence` is read out. **This is not yet an
   activation.**
6. The licence goes through the *same* check that guards every sign-in, against
   the *same* public key compiled into this build, against *this* server's id
   and the current time. If it does not pass, the outcome is `LicenceRejected`
   and **nothing is stored**.
7. Only then is it written into the ordinary **Licence key** setting and saved
   to `plugins/configurations/Emby.Sso.xml`. The page fills the Licence key
   field in from the response, so a later Save cannot write the old field value
   back over the licence that was just stored.

### The service is not trusted, and that is the point

A licence is an RS256 JWT signed by a key that never leaves the vendor and bound
to one Emby server id, which is what makes the offline check work at all. A
plugin that stored whatever an activation service handed it would have thrown
that away: spoof the service, or point the address at your own, and you would
mint yourself a licence.

So a service that answers `200` with a forged, expired, or other-server licence
gets a refusal and nothing is written. The one thing the vendor's service can do
that a hostile one cannot is hand over a licence that verifies.

## How many servers one code covers

A code is good for a limited number of activations, counted by server id:

- Re-activating the **same** code on the **same** server does not use another
  one up. The plugin says so in the message it shows when a save fails and you
  have to press Activate again.
- When a code has been used on as many servers as it allows, the service answers
  `code_exhausted` and the page says the code has already been activated on as
  many servers as it allows, that this is therefore a different server to the
  ones it was used on, and that the vendor can release an activation.

!!! unverified "The limit is enforced by the service, not by the plugin"

    The plugin sends a code and a server id and reports what comes back. How
    many activations a code carries, what counts as the same server, and whether
    releasing one is possible are all the vendor service's rules. That service
    has never answered one of these requests.

    The service's answer also carries `activationsUsed`, `activationsAllowed`
    and `expiresUtc`, and the plugin's endpoint returns all three — but the
    configuration page currently displays **only the one-sentence message**. If
    you want the counts, they are in the endpoint's JSON response, not on the
    screen.

## What the answers on the page mean

The sentence under the Activate button is the whole of what you are told; the
server log carries the detail, under category `AuthentikSso` at **Warn** for a
refusal and **Info** for a success. Neither ever contains the code.

| What you see | What happened | What to do |
|---|---|---|
| Your licence has been requested and is being issued. | `pending_signature`. **Not an error, and your code has not been used up.** The vendor signs licences on a machine that is deliberately kept offline, so it is not instant — see [Signing licences offline](offline-signing.md) for why. | Press Activate again in a few minutes. Pressing it early costs nothing. |
| Activated. The licence for this server has been saved. | The service issued a licence, this build verified it, and it was stored. | Nothing. Sign-ins check the stored licence offline from here on. |
| That redemption code was not recognised. | `invalid_code`: the service does not know it, or the purchase has not completed. | Check for typing mistakes, then ask the vendor. |
| That redemption code has already been activated on as many servers as it allows. | `code_exhausted`. | Ask the vendor to release an activation, or buy another licence. |
| Too many activation attempts. | `rate_limited`. A numeric `Retry-After` is turned into a wait; an HTTP-date one is not, and you are told to wait a few minutes instead. | Wait and try again. |
| The licensing service reported a problem of its own. | `server_error`. Nothing is wrong with your code or your server. | Try again in a few minutes. |
| The licensing service could not be reached. | DNS, TLS, a timeout, or a connection failure. **Not a verdict on the code.** | Try again later. Sign-ins are unaffected. |
| This plugin refused to send the activation request: … | The outbound guard refused the destination. Nothing left this process. | The message names the rule. Usually a private-address service without the private-address setting ticked. |
| The licensing service gave an answer this plugin could not read. | `200` with a body that is not JSON, or with no licence in it. | Try again; if it persists, the service and this plugin version disagree and the vendor needs to know. |
| The licensing service returned a licence this plugin refused (…). NOTHING WAS SAVED. | The token did not verify against this build's public key, or names another server, or has expired. | If you set an activation service address of your own, that is the first thing to check. |
| The licence was issued and verified, but this server could not save it. | Emby could not write the plugin configuration. | Check that Emby can write `plugins/configurations/`, then press Activate again — that does not use up another activation. |
| The licensing service refused this activation and did not say why in terms this plugin understands. | A non-`200` with no error code, an error code this build does not know, or a redirect. | The log records the status code that came back. |
| The activation could not be completed. The server log has the detail. | Something threw. The log carries the exception **type** only, so that a code being handled cannot reach it. | Read the log. |

## Pointing the plugin at a different activation service

The vendor's address is compiled into the build. There is an override,
`ActivationServiceUrl`, and it is **deliberately not on the configuration
page** — it is a vendor's testing knob, and the configuration page is the most
fragile thing in this plugin.

To set it, edit `plugins/configurations/Emby.Sso.xml` and restart Emby. The
configuration page round-trips the value untouched, because it reads the whole
configuration object, edits the fields it knows, and writes the whole object
back.

!!! note "An override is safe, and that is not an accident"

    Whatever address it names, the licence that comes back is verified against
    the public key compiled into this build and against this server's own id
    before it is stored. Pointing it at a hostile server yields a refusal and
    nothing else. It must still be HTTPS.

## Activation cannot affect sign-ins

This is worth stating plainly, because it is the question an operator asks about
any feature that phones home.

- The activation call lives in its own service class, on its own HTTP client.
  There is **no call path** from the licence gate, the SSO endpoints or the
  credential validator into it. Nothing on a sign-in path can reach it.
- If the vendor's service is slow, unreachable, or **shut down forever**,
  sign-ins are completely unaffected. The licence check reads a string out of
  the configuration and validates it offline.
- Activation writes exactly one setting, the same **Licence key** field a
  manually issued licence is pasted into. There is no second source of truth.

## What has not been verified

!!! unverified "No activation has ever run against a live service, or inside Emby"

    **Under test** — 48 test methods across `ActivationEndpointTests`,
    `ActivationMessageTests` and `ActivationClientTests`, run against a stub
    HTTP handler and licences minted by a locally generated key: that the code
    never appears in the URL, that no outcome carries the code into a message or
    a log line, that a licence signed by anybody but the vendor is refused,
    along with an unsigned one, an `alg` confusion forgery, one tampered with
    after signing, one for a different server, an expired one, one for the wrong
    issuer, and any licence at all when the build carries no public key; that
    nothing is sent without a code, without a server id, or to an address the
    outbound guard refuses; that a redirect is not an activation; that the body
    read is bounded; and that each contract error code maps to the sentence
    above.

    **Never observed:**

    - the vendor's activation service answering anything, because it does not
      exist yet;
    - the buy link, the Redemption code field and the Activate button
      **rendering at all** inside Emby's plugin page. They were added to
      `configPage.html` and no one has looked at that page on a real server
      since. See
      [the configuration page](verification-status.md#the-configuration-page);
    - the endpoints being reachable, or their admin-only requirement being
      enforced, on a running Emby;
    - the licence being written to `plugins/configurations/Emby.Sso.xml` and
      surviving a restart.

    !!! inferred "That the save works at all is inferred from decompiled source"

        `SaveConfiguration` needs a directory-creation callback that Emby
        supplies at plugin load — `ApplicationHost.LoadPlugin` calls
        `IHasPluginConfiguration.SetStartupInfo`, read off a decompiled 4.9.5.0
        server. If it were wrong, the licence would not be stored and the page
        would say so rather than claiming success.

    **When you first use this**: press Activate once, then reload the
    configuration page and confirm the Licence key field is populated, and
    restart Emby and confirm it is still there.

# What has and has not been verified

This project separates what was measured on a running server from what was
worked out by reading decompiled assemblies, and from what has simply never
been run. That separation is the point of this page.

Read it before you decide how much of this to rely on. Nothing here is a
disclaimer; each item is a specific thing to check, and most of them you can
check in a few minutes on your own server.

!!! verified "Verified on a live server"

    Observed directly against a running Emby 4.9.5.0 server.

!!! inferred "Inferred from decompiled source"

    Reasoned out of Emby's own assemblies — 4.9.5.0 as running, 4.9.1.90
    reference assemblies — rather than observed.

!!! unverified "Not verified"

    Built and covered by the automated suite, but never run in the place it will
    actually run.

---

## Verified on a live server

- **Emby stamps the winning provider onto the user permanently**, and a user
  with no provider assigned is offered to every enabled provider. Confirmed
  against a live Emby 4.9.5.0 server, not assumed from documentation. See
  [Read this before you install](before-you-install.md).
- **The merged DLL loads without colliding with Emby's own assemblies.** The
  merged types resolve out of `Emby.Sso.dll` itself, never colliding with the
  server's copy of `Microsoft.IdentityModel` (7.6.2 as of Emby 4.9.5.0). See
  [Installing](installing.md#install-exactly-one-dll-and-it-must-be-the-merged-one).
- **Emby's login page cannot render a sign-in button.** The disclaimer is
  rendered with `element.textContent` and custom CSS is loaded as an external
  stylesheet; confirmed by reading the shipped 4.9.5.0 client and testing that
  the server passes both fields through unsanitized. See
  [Browser sign-in](browser-sign-in.md#there-is-no-button-on-the-login-page).
- **The authentication call, the token, and the token's acceptance by Emby's
  API** on the browser callback path — all directly observed with `curl` against
  a live server.

## Not verified

### The browser hand-off into `localStorage`

The callback page writes an access token into the Emby web client's
`localStorage` credential store (key `servercredentials3`), in the exact shape
that store's own code produces. The shape was determined by reading Emby
4.9.5.0's shipped client JavaScript, and the server side of it was verified
end-to-end with `curl`.

!!! unverified "The browser/`localStorage` behavior itself was never observed"

    No browser was available in the environment where this was tested.

    **Check on your first sign-in that you land on the Emby home screen, not the
    login screen.** If you land on the login screen, sign-in still completed on
    the server side — only the hand-off failed. See
    [the likely causes](browser-sign-in.md#what-has-not-been-observed).

### One-time PIN sign-in

!!! unverified "Built and unit-tested. Has never run on a server."

    Covered by the automated suite: how a PIN is generated, that it is
    single-use, account-bound, expiring and destroyed by a wrong guess, that a
    non-PIN value never spends one, that no account's PIN can be affected by
    anything done to another's, and that a PIN is accepted by the credential
    validator without the identity provider ever being contacted.

    **Not measured, and not measurable from here:**

    - that Emby routes `/sso/pin` to this plugin's service at all. It is
      declared exactly as the two existing routes are — same `[Route]` and
      `[Unauthenticated]` attributes, same service class — so it either works
      the way they do or none of them do. But no request has been made to it.
    - that a native Emby app accepts an eight-character PIN in its password
      field and posts it unchanged. The redemption path is the same
      `AuthenticateByName` path the handoff secret already uses, which *was*
      observed working with `curl`, but no TV app has typed a PIN into it.

    See [Native apps with a one-time PIN](pin-sign-in.md).

### Group gating and automatic account creation

!!! unverified "Built and unit-tested, but has never run inside Emby"

    At the time of writing this build is installed on no server and no Authentik
    provider is configured for it.

**Under test:** which identities the gate admits, that an unset required group
refuses before any credential is forwarded, the order of the provisioning
preconditions, the throttle's buckets and windows, and ID-token validation.

!!! inferred "How Emby reacts to them is inferred, not observed"

    That includes how an account created through the native path is finished off
    by Emby, what a native client sees when the plugin refuses, and whether a
    refused creation can leave a half-made account behind. The reasoning is
    documented in the project's own records and, where it is inference rather
    than measurement, labelled as such there too.

**Treat the first real sign-in on a new install as a test.** Do it with a
throwaway account that holds the group, with the server log open, before you
tell your users anything has changed.

### The licence check

!!! unverified "The decision is under test; it has never run inside Emby"

    21 tests cover a licence signed by the wrong key, one for another server, an
    expired one, one with no expiry, one dated in the future, one edited after
    signing, `alg: none`, an HMAC-signed token keyed on the embedded public key,
    and an algorithm the build does not accept. Each guard was confirmed to have
    a test that fails when that guard is removed. A licence produced by the
    issuing tool was validated end-to-end against the plugin's own checker.

Not observed: the configuration page rendering with the Licence key field,
`IApplicationHost` being injectable, and what `SystemId` looks like on your
server. See [Licensing](licensing.md#what-has-not-been-observed) for the detail
and for why the `IApplicationHost` inference would fail loudly rather than
silently.

### Buying and activating a licence

!!! unverified "The vendor's activation service has never answered one of these requests"

    The decision layer is covered by 48 test methods — that the redemption code
    never reaches a URL, a log line or a message; that a licence the vendor did
    not sign, or that names another server, or that has expired, is refused and
    nothing is stored; that a redirect is not an activation; and that each
    contract error code maps to a sentence an administrator can act on.

    Never observed: the service itself, the new controls rendering on Emby's
    plugin page, the endpoints being reachable, or the licence surviving a
    restart. See
    [Buying and activating a licence](activation.md#what-has-not-been-verified).

### The configuration page

!!! unverified "Emby 4.9's plugin page loader is fragile and this project has broken it before"

    It strips script tags and needs an exact `emby-scroller` + `data-controller`
    structure. New fields' markup is copied structurally from the fields beside
    them, with no new markup shapes — but nothing has looked at it on a real
    server.

    **An operator must open Dashboard → Plugins → Authentik SSO after installing
    this build, confirm the page renders, tick and untick a setting, and confirm
    it saves.** If the page comes up blank, the cause is the page, not the
    feature behind it.

### The release pipeline

!!! unverified "No tag has been pushed since the release jobs were written"

    The download URLs in [Installing](installing.md) describe what the pipeline
    is built to produce, not something already sitting on the server.

    **Checked locally, outside CI:** the version derivation, the merged-artifact
    check, and the release notes were run as scripts against a real Release
    build, and the version in the tag was confirmed to land in the merged
    assembly's identity by reading the DLL's metadata back.

    **Only a real pipeline run can confirm GitLab's side:** that the runner
    accepts the file, that the package upload and the Release are created, and
    that the asset links resolve for someone who is not signed in.

    **Treat the first tag as a rehearsal:** push `v0.1.0`, then download the DLL
    from the release page as an anonymous user and check its checksum before
    telling anyone the link exists.

### This documentation site

!!! unverified "Nothing here has confirmed that GitLab Pages publishes it"

    The site builds locally and the `pages` job follows GitLab's contract, but
    there is no HTTPS access to `git.koper.cloud` (which is SSH only - the web
    and API host is `gitlab.koper.cloud`) from the environment this was
    written in. Whether Pages is enabled on the instance or the project, what
    the resulting URL is, and whether a pipeline run actually publishes are all
    unconfirmed.

    If the project is **private**, GitLab Pages may be access-controlled, and
    anyone you send here would need an account on the instance to read it.

### Offline signing

!!! unverified "The round trip has been run in tests, not on the real service"

    **Checked, and by more than a passing test:**
    `licencetool sign` was run for real, on this machine, against the actual
    signing key: it read a requests file, produced a signed file at mode 600,
    appended to the ledger, and wrote a token whose `kid` header names the key.
    That token is checked into the plugin's suite
    (`RealLicenceTests`) and the **shipped build accepts it**, which is the one
    thing no generated-key test can prove.

    The upload side - verification against the recorded terms, the refusals for
    a wrong key, a wrong server, an extended expiry, an unknown request, a
    replayed file - is covered by `OfflineSigningTests` against a real store, and
    the audience check was confirmed to fail those tests when removed.

    **Not yet done on the deployed service:** nobody has pressed Download on a
    live `/admin/signing`, signed that file, and uploaded it. The exchange format
    is shared code and the file this tool wrote by hand parses, but the browser
    round trip - the multipart upload, the download's `Content-Disposition` - has
    only been exercised through a TestServer.

### The admin network gate and required header

!!! unverified "Correct over a TestServer; never tried behind the real proxy"

    `AdminAccessGateTests` and `AdminGateEndpointTests` cover the parsing, the
    CIDR maths, the fail-closed directions and the 404. What they cannot cover is
    the thing most likely to be wrong in practice: **whether
    `LICENCE_TRUSTED_PROXY_HOPS` is set correctly for the reverse proxy actually
    in front of the service.** Set it, then check the log lines name real client
    addresses, *before* relying on `ADMIN_ALLOWED_CIDRS` - with the hop count
    wrong, the restriction either allows everyone or nobody.

    Nothing here can check that your proxy strips `ADMIN_REQUIRED_HEADER` from
    incoming requests, and a header a client can set is not a check.

### Encrypted backups

!!! unverified "Round-tripped in tests, including a real store; never restored in anger"

    **Checked:** a backup of a live test service - WAL-mode database included,
    via `VACUUM INTO` rather than a file copy - restores to a database that opens
    and holds the right rows. The wrong passphrase fails, a single flipped byte
    fails, the iteration count cannot be lowered, two backups of the same data
    differ, and an archive entry that would escape the destination is refused.

    **Not checked:** that a restore into the real deployment's `/data` produces a
    service that starts. The `restore` command deliberately never writes over a
    live store, so the last step - stop, move the files, fix ownership, start -
    is by hand and has not been rehearsed. Rehearse it before you need it.

### The dependency audit and the wiki

!!! unverified "New CI jobs, not yet run by a runner"

    `ci/audit-packages.sh` was run locally against both solutions and **found a
    real High-severity advisory on the first run** (`SQLitePCLRaw.lib.e_sqlite3`
    2.1.6, GHSA-2m69-gcr7-jv3q), which is fixed in the same commit that added
    the gate. Its detector was negative-tested against a synthetic finding.

    `ci/publish-wiki.sh` has never pushed to a wiki: it needs a `WIKI_TOKEN` that
    does not exist yet, and `CI_JOB_TOKEN` cannot push to a wiki. The markdown
    conversion it does was run over these pages locally; the push was not.

## Anything else on a page

Where a specific claim is measured, inferred or unrun, the page that makes the
claim marks it with one of the three boxes above. If a statement carries no
mark, it is a statement about this plugin's own code, which is what the test
suite covers.

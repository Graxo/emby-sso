# Installing and upgrading

!!! danger "Upgrading in place? Set *Required group* first"

    Every sign-in is gated on an Authentik group and an empty *Required group*
    refuses everyone, including users who were signing in fine before the
    upgrade. Read
    [the required-group lockout](before-you-install.md#the-required-group-lockout)
    before you restart Emby.

## What you download

The shipped artifact is a **single file**, `Emby.Sso.dll`. The current release
and its SHA256 checksum are served by the licence service, at a fixed address
that needs no account and no token:

```bash
base=https://license.koper.cloud/v1/release
curl -fLo Emby.Sso.dll $base/download
curl -fLo Emby.Sso.dll.sha256 $base/download.sha256
sha256sum -c Emby.Sso.dll.sha256
```

That address always serves the **current** release, so it is what you want for
a first install and for catching up a server that has fallen behind.

!!! warning "Check the checksum before you copy anything onto a server"

    It is also the only way to tell two builds of the same version apart if
    you have been building locally.

!!! tip "You only have to do this once"

    Once the plugin is installed and licensed, it checks for a new release
    daily and offers a **Download and install** button on its configuration
    page. That path verifies the download against the vendor's signature
    before writing anything, which this manual one cannot.

Building from source produces the same file, at
`src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll` — see
[Building from source](building.md).

## Install exactly one DLL, and it must be the merged one

**Do not install any other DLL from the build output.** `Emby.Sso.dll` is
deliberately produced by merging (ILRepack) the plugin together with its
dependencies — `Microsoft.IdentityModel.*`, `System.IdentityModel.Tokens.Jwt`
and `Newtonsoft.Json` — and internalizing their types inside `Emby.Sso.dll`
itself.

This is not a packaging convenience; it is required. Emby Server already ships
its own copy of `Microsoft.IdentityModel` (version 7.6.2 as of Emby 4.9.5.0), a
different version than the one this plugin builds against (6.35.0). Dropping
unmerged dependency DLLs next to the plugin would put two incompatible assembly
identities in the same load context and fail at runtime.

!!! verified "Verified on a live server"

    The merged build was verified on a live Emby 4.9.5.0 server: the merged
    types resolve out of `Emby.Sso.dll` itself, never colliding with the
    server's own copies.

The merged DLL is about 1.8 MB; the unmerged one, one directory away, is about
108 KB. If the file you are about to copy is small, it is the wrong file.

## The three steps

1. Copy `Emby.Sso.dll` into Emby's `plugins` directory (for example
   `/config/plugins` in the linuxserver.io Docker image), replacing any
   earlier copy.
2. Restart Emby Server.
3. Confirm it loaded: Dashboard → Plugins should list **Authentik SSO**, at
   the version you downloaded.

!!! tip "The version number tells you whether the upgrade actually happened"

    The version shown is the release tag — a release built from `v1.4.0`
    reports `1.4.0`, and a build you made yourself reports `0.0.0`. If the
    number is not the one you just installed, the old DLL is still in place
    and Emby is still running it.

Upgrading is the same three steps.

## Immediately after installing

In this order:

1. **Set *Required group*.** Nobody can sign in until you do. See
   [Every setting, explained](settings.md#required-group).
2. **Paste the licence key** issued for this server. Without a valid one, new
   sign-ons are refused. See [Licensing](licensing.md).
3. **Fill in the rest of the configuration** — issuer URL, client ID, and the
   Emby public base URL at minimum. See
   [Every setting, explained](settings.md).
4. **Open the configuration page and confirm it renders and saves.** This is
   not a formality:

    !!! unverified "The configuration page has not been checked on a real server for this build"

        Emby 4.9's plugin page loader is fragile — it strips script tags and
        needs an exact `emby-scroller` + `data-controller` structure — and this
        project has broken it before. The newest fields' markup is copied
        structurally from the fields beside them, with no new markup shapes,
        but nothing has looked at it on a real server.

        **Open Dashboard → Plugins → Authentik SSO, confirm the page renders,
        tick and untick a setting, and confirm it saves.** If the page comes up
        blank, the cause is the page, not the feature.

5. **Assign each user's login provider.** Nothing works per user until this is
   done — see [Assigning each user's login provider](login-providers.md).

!!! tip "If the settings page renders oddly right after an update"

    For example, as an overlay on top of the plugin catalog instead of
    replacing the view — reload the Emby dashboard in your browser. Emby caches
    configuration pages, and the old version may still be in the browser's
    cache.

## Treat the first sign-in as a test

**Do it with a throwaway account that holds the group, with the server log
open, before you tell your users anything has changed.**

**On first sign-in, check that you land on the Emby home screen, not the login
screen.** If you land on the login screen instead, the most likely causes, in
order, are:

1. the plugin's public base URL not matching the address your browser actually
   uses (reverse-proxy sub-paths are the usual culprit);
2. a future Emby client update changing the credential store's key or shape.

Either way, sign-in through the plugin still completes on the server side — the
account is not locked out — it is only the automatic hand-off into the
already-signed-in home screen that would need a second look.

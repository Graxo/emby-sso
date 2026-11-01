# Building from source

You do not need to build anything to use the plugin. This page is for reading
and testing the code.

## Build and test

Requires the .NET SDK.

```bash
dotnet build -c Release
dotnet test tests/Emby.Sso.Tests
```

The installable plugin is
`src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll` (about 1.8 MB).
Its dependencies are merged into it, because Emby ships its own, incompatible
version of `Microsoft.IdentityModel`. Do not install the unmerged DLL one folder
up (about 100 KB).

A local build reports version `0.0.0-dev`, so it can never be mistaken for a
release. To set a version: `dotnet build -c Release -p:Version=1.4.0`.

The tests need no Emby server and no network. They cover the `Protocol/`
folder, where every decision is made (token validation, group gate,
provisioning, throttle, PINs, licence). The Emby-facing code in `Auth/` and
`Api/` needs a running Emby and is not unit-tested.

## Releases

Pushing a tag `vMAJOR.MINOR.PATCH` (optionally `-rc.N`) makes CI run the tests,
build the DLL with that version, check it, and publish it as a GitLab release
with its checksum, `LICENSE` and `THIRD-PARTY-NOTICES`. The annotated tag's
message becomes the release notes.

The update button in the plugin only offers a release after the vendor has
signed it separately; see `service/docs/signing-a-release.md`.

## This documentation

The site is MkDocs with the Material theme; sources are in `docs/site/`.

```bash
python3 -m venv .venv
.venv/bin/pip install -r docs/requirements.txt
.venv/bin/mkdocs serve           # preview on http://127.0.0.1:8000
.venv/bin/mkdocs build --strict  # what CI runs
```

The same pages are published to the project wiki on every push, so edits made
in the wiki are overwritten.

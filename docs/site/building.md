# Building from source

Requires the .NET SDK (matching `netstandard2.0`/`net8.0` tooling).

```bash
dotnet build -c Release
```

produces the merged, installable plugin at:

```
src/Emby.Sso/bin/Release/netstandard2.0/merged/Emby.Sso.dll
```

!!! warning "Install only that file"

    The unmerged DLL one directory away is about 108 KB; the merged one is about
    1.8 MB. Installing the wrong one puts two incompatible copies of
    `Microsoft.IdentityModel` in the same load context and fails at runtime. See
    [Installing](installing.md#install-exactly-one-dll-and-it-must-be-the-merged-one).

## Versions

A build with no version given reports `0.0.0-dev`, deliberately: a DLL you built
yourself should never look like a release in Emby's plugin list.

To build one that names itself:

```bash
dotnet build -c Release -p:Version=1.4.0
```

That is all CI does — with the version taken from the tag.

## The test suite, and what it does not cover

```bash
dotnet test tests/Emby.Sso.Tests
```

No Emby server or network is required: the tests run against a fake identity
provider built from a locally generated RSA key.

!!! note "The suite compiles the plugin's `Protocol/` layer only"

    Every decision — the group gate, the ordered provisioning preconditions, the
    throttle, token validation, the licence check — is under test. The
    Emby-facing shell that calls them (`Auth/`, `Api/`) is **not**, because those
    types reference `MediaBrowser.*` and need a running server.

    That boundary is why so much of
    [What has and has not been verified](verification-status.md) is about how
    Emby reacts, rather than about what the plugin decides.

## Cutting a release

Releases are made by pushing a tag. There is nothing to build by hand and
nothing to upload.

```bash
git tag -a v1.4.0 -m "What changed in this release."
git push origin v1.4.0
```

!!! danger "Before the first release, and only once: generate the licence signing keypair"

    Paste its public half into `src/Emby.Sso/Protocol/LicencePublicKey.cs`. The
    licence tool that generates it is not in this repository; it lives with the
    keys, and its own README explains it.

    A build whose `LicencePublicKey.Jwk` is still empty **refuses every single
    sign-on** and says so in the server log — deliberately, because a build with
    no key cannot verify a licence and so cannot honestly accept one.

The tag pipeline then, in order:

1. **runs the test suite.** Every later job hangs off it through `needs:`, so a
   tag cannot produce a release with a red suite behind it.
2. **builds `-c Release` with the version derived from the tag** by
   `ci/version.sh`. A tag that is not `vMAJOR.MINOR.PATCH` — optionally with a
   `-rc.1`-style suffix — fails the build instead of quietly shipping something.
3. **checks that `THIRD-PARTY-NOTICES` still names every assembly ILRepack
   merges** (`ci/verify-notices.sh`), so a new dependency cannot quietly turn a
   release into a licence violation.
4. **checks the artifact** with `ci/verify-artifact.sh` before it leaves the job.
   The file must be over a megabyte, and it must carry `1.4.0+<commit>` as its
   assembly informational version — which shows both that the tag's version
   reached the assembly and that this file came from this build.
5. **uploads the DLL, its `.sha256`, `LICENSE` and `THIRD-PARTY-NOTICES`** to the
   project's generic package registry, which is what gives them a permanent
   download URL. The last two are not optional: the merged DLL physically
   contains a dozen MIT- and Apache-licensed libraries and their notices have to
   travel with it.
6. **creates the GitLab Release** for the tag, linking all four files as assets
   and describing it with notes generated from the tag's own message and the
   checksum.

!!! tip "Write the annotated tag's message for the operator who will read it"

    It becomes the release notes' "What changed" section.

An untagged push runs steps 1–4 only, and versions the build
`0.0.0-dev.<short sha>`.

## Building this documentation site

The site is MkDocs with the Material theme. Sources are in `docs/site/`; the
configuration is `mkdocs.yml` at the repository root.

```bash
python3 -m venv .venv
.venv/bin/pip install -r docs/requirements.txt
.venv/bin/mkdocs serve          # live preview on http://127.0.0.1:8000
.venv/bin/mkdocs build --strict # what CI runs; warnings are errors
```

`docs/requirements.txt` is a **full** freeze, not just the top-level package: a
documentation toolchain that silently changes what it renders is not acceptable
here.

`site_url` is read from `CI_PAGES_URL`, which GitLab sets in the `pages` job to
whatever address the site is actually published at, falling back to
`http://127.0.0.1:8000/` for a local build. Do not hard-code an address there: a
wrong `site_url` produces wrong canonical links and a wrong sitemap.

!!! danger "`docs_dir` is `docs/site`, and must stay that way"

    `docs/superpowers/` holds this project's internal development record —
    specs, plans, spikes, verification notes. **None of it is user
    documentation and none of it may be published.** Pointing `docs_dir` at
    `docs/` would sweep every one of those files into the site.

    The `pages` job re-checks the built output for the same thing and fails if
    anything from that directory reaches `public/`.

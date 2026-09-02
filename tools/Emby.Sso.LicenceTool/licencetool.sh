#!/bin/sh
# Runs the licence tool in a container, so the machine that holds the signing
# key does not need the .NET SDK installed on it.
#
# WHY THIS EXISTS. The signing key belongs on a machine that answers no
# requests - that is the whole of the security argument for moving it off the
# licence service. Requiring that machine to also carry a development toolchain
# works against it: the fewer things installed where the key lives, the better,
# and "I have to install an SDK on my laptop to sell a licence" is how a key
# ends up back on a server because that is where the SDK already was.
#
# Docker (or podman - set CONTAINER=podman) is the only thing needed.
#
#   ./licencetool.sh keygen --out /keys
#   ./licencetool.sh sign --requests /work/requests.json --key /keys/licence-signing-key.private.json
#   ./licencetool.sh list --ledger /keys/licences-issued.jsonl
#
# THE RELEASE KEY IS A DIFFERENT KEY IN A DIFFERENT DIRECTORY, and it has the
# same filename, so every release command has to say which directory it means:
#
#   LICENCE_KEY_DIR="$HOME/emby-sso-release" ./licencetool.sh sign-release \
#       --dll /work/Emby.Sso.dll --version 1.0.3 \
#       --url https://.../Emby.Sso.dll \
#       --key /keys/licence-signing-key.private.json
#
# Omitting it signs a release with the LICENCE key, which every plugin rejects.
# release.sh beside this file does all of that for you and checks the key it
# used; prefer it. docs/site/signing-a-release.md is the whole procedure.
#
# TWO PATHS EXIST INSIDE THE CONTAINER, and they are the only two:
#
#   /keys   the key directory, $HOME/emby-sso-licence by default. Override with
#           LICENCE_KEY_DIR. This is where the private key and the ledger live.
#   /work   whatever directory you are standing in. This is where a downloaded
#           signing-requests file is, and where the signed one is written.
#
# Everything else - the repository, the SDK, the package cache - is inside the
# container and is gone when it exits. Nothing is installed on this machine.
set -eu

CONTAINER="${CONTAINER:-docker}"

# The same SDK the pipeline builds with, pinned. A signing tool that behaves
# differently from the one CI compiled is not a tool anybody can reason about.
SDK_IMAGE="${SDK_IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0.424-bookworm-slim}"

KEYS="${LICENCE_KEY_DIR:-$HOME/emby-sso-licence}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

if [ "$#" -eq 0 ]; then
    echo "usage: $0 <keygen|issue|sign|sign-release|list|show> [arguments]" >&2
    echo "" >&2
    echo "  Inside the container, the key directory is /keys and the directory you" >&2
    echo "  are standing in is /work. Use those paths in the arguments:" >&2
    echo "" >&2
    echo "    $0 keygen --out /keys" >&2
    echo "    $0 sign --requests /work/requests.json --key /keys/licence-signing-key.private.json" >&2
    echo "" >&2
    echo "  sign-release signs CODE, not a licence, and uses a different key:" >&2
    echo "" >&2
    echo "    LICENCE_KEY_DIR=\"\$HOME/emby-sso-release\" $0 sign-release --dll /work/Emby.Sso.dll \\" >&2
    echo "      --version 1.0.3 --url https://.../Emby.Sso.dll --key /keys/licence-signing-key.private.json" >&2
    exit 2
fi

if ! command -v "$CONTAINER" >/dev/null 2>&1; then
    echo "$0: no '$CONTAINER' on this machine." >&2
    echo "  Install Docker, or set CONTAINER=podman if that is what you have." >&2
    exit 1
fi

# Created here rather than by the tool, so that the mode is right before
# anything is written into it. 700: the private key inside is owner-only, and a
# directory anyone can list is a directory anyone can watch.
mkdir -p "$KEYS"
chmod 700 "$KEYS"

# Run as the invoking user, so the key and the ledger belong to them and not to
# root. The tool refuses to load a key that is readable by anyone but its owner,
# and a root-owned key would fail that check on the next run in a way that looks
# like corruption.
exec "$CONTAINER" run --rm -i \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --env DOTNET_CLI_HOME=/tmp \
    --env NUGET_PACKAGES=/tmp/nuget \
    --env DOTNET_NOLOGO=1 \
    --env DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    `# The SDK image prints "An issue was encountered verifying workloads" on` \
    `# a first run in a fresh container, because the workload manifests it` \
    `# wants to check live in a HOME that does not persist. It is noise - this` \
    `# tool uses no workloads - but it is noise printed immediately above the` \
    `# tool's own output, where somebody signing licences will read it as the` \
    `# reason nothing happened.` \
    --env DOTNET_SKIP_WORKLOAD_INTEGRITY_CHECK=1 \
    --volume "$REPO":/src \
    --volume "$KEYS":/keys \
    --volume "$PWD":/work \
    --workdir /src \
    "$SDK_IMAGE" \
    dotnet run --project tools/Emby.Sso.LicenceTool --verbosity quiet -- "$@"

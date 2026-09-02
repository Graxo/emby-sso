#!/bin/sh
# Signs a plugin build for release. ONE COMMAND, on the machine that holds the
# release key:
#
#   ./release.sh 1.0.3 ~/Downloads/Emby.Sso.dll
#   ./release.sh 1.0.3 ~/Downloads/Emby.Sso.dll <sha256 from the pipeline>
#
# It prints a manifest. Publish that manifest and that same DLL together on the
# licence service's /admin/release page, and every licensed server is offered
# the update on its next daily check.
#
# WHY THIS IS A WRAPPER AND NOT A DOCUMENTED COMMAND. Signing a release is the
# most dangerous thing anybody does to this project - the result installs and
# runs on every customer's media server - and it happens a few times a year.
# That combination is exactly how a wrong flag gets typed. Every argument that
# can be derived is derived here, and the two that cannot be are checked:
#
#   * THE KEY. The release key and the licence key have the same filename and
#     differ only by directory. Signing with the wrong one produces a manifest
#     that verifies here and is rejected by every plugin. So the thumbprint of
#     whatever key was used is compared against the one compiled into the
#     plugin, and a mismatch throws the manifest away rather than printing it.
#
#   * THE FILE. Pass the SHA-256 the pipeline published as a third argument and
#     it is checked before anything is signed. Skipping it is allowed and is
#     the weaker path: you are then trusting that the file on this machine is
#     the file that was built.
#
# The address is derived from LICENCE_SERVICE, because the manifest has to name
# the address the plugin will actually fetch - and that is the licence service,
# which is the one host every plugin can already reach without a credential.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"

# The public half of the release key, as the plugin knows it. Copied from
# src/Emby.Sso/Protocol/ReleasePublicKey.cs, which is what every customer's
# server checks against - so this is the value that decides whether a manifest
# is worth anything, and it is not a secret.
EXPECTED_KEY_ID="${RELEASE_KEY_ID:-56468f4a15dd461e}"

# Where the release key lives. NOT the licence key's directory, and the
# difference is the directory alone: both files are called
# licence-signing-key.private.json.
KEY_DIR="${RELEASE_KEY_DIR:-$HOME/emby-sso-release}"

# The licence service. Its /v1/release/download is where the plugin file is
# served from and therefore what the manifest is signed for.
SERVICE="${LICENCE_SERVICE:-https://license.koper.cloud}"

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <version> <Emby.Sso.dll> [expected-sha256]" >&2
    echo "" >&2
    echo "  $0 1.0.3 ~/Downloads/Emby.Sso.dll" >&2
    echo "" >&2
    echo "  Environment: RELEASE_KEY_DIR (default $HOME/emby-sso-release)" >&2
    echo "               LICENCE_SERVICE  (default https://license.koper.cloud)" >&2
    exit 2
fi

VERSION="$1"
DLL="$2"
EXPECTED_SHA="${3:-}"

if [ ! -f "$DLL" ]; then
    echo "$0: no file at $DLL" >&2
    exit 1
fi

if [ ! -f "$KEY_DIR/licence-signing-key.private.json" ]; then
    echo "$0: no release key at $KEY_DIR/licence-signing-key.private.json" >&2
    echo "  This machine is meant to hold the RELEASE key. If this is the first" >&2
    echo "  release, generate one:" >&2
    echo "" >&2
    echo "    LICENCE_KEY_DIR=\"$KEY_DIR\" $HERE/licencetool.sh keygen --out /keys" >&2
    echo "" >&2
    echo "  Do not point this at the licence key's directory." >&2
    exit 1
fi

# Checked here, before the container is started and before the key is touched.
# A wrong file is the failure this catches, and the earlier it is caught the
# less there is to undo.
ACTUAL_SHA="$(sha256sum "$DLL" | cut -d' ' -f1)"

if [ -n "$EXPECTED_SHA" ] && [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    echo "$0: that is not the build you named." >&2
    echo "  expected $EXPECTED_SHA" >&2
    echo "  actual   $ACTUAL_SHA" >&2
    echo "" >&2
    echo "  Nothing was signed. Download the file again from the pipeline that" >&2
    echo "  published it, and find out why they differ before signing anything." >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

cp "$DLL" "$WORK/Emby.Sso.dll"

# licencetool.sh mounts the directory it is invoked from as /work, so this is
# what makes --dll /work/Emby.Sso.dll the copy above and nothing else.
cd "$WORK"

set +e
LICENCE_KEY_DIR="$KEY_DIR" "$HERE/licencetool.sh" sign-release \
    --dll /work/Emby.Sso.dll \
    --version "$VERSION" \
    --url "$SERVICE/v1/release/download" \
    --key /keys/licence-signing-key.private.json \
    > "$WORK/manifest.txt" 2> "$WORK/summary.txt"
STATUS=$?
set -e

cat "$WORK/summary.txt" >&2

if [ "$STATUS" -ne 0 ]; then
    exit "$STATUS"
fi

SIGNED_BY="$(awk '/^Signed by: / { print $3 }' "$WORK/summary.txt")"

if [ "$SIGNED_BY" != "$EXPECTED_KEY_ID" ]; then
    echo "" >&2
    echo "$0: THAT WAS SIGNED WITH THE WRONG KEY. Nothing usable was produced." >&2
    echo "  signed by $SIGNED_BY" >&2
    echo "  plugins trust $EXPECTED_KEY_ID" >&2
    echo "" >&2
    echo "  $KEY_DIR holds a key that is not the release key - most likely the" >&2
    echo "  LICENCE key, which has the same filename. Every plugin would have" >&2
    echo "  rejected this manifest." >&2
    exit 1
fi

# Beside the DLL rather than in the temporary directory, because the next thing
# that happens is a person opening a file picker.
OUT="$(cd "$(dirname "$DLL")" && pwd)/Emby.Sso-$VERSION.manifest"
cp "$WORK/manifest.txt" "$OUT"

cat >&2 <<NEXT
Signed. Now publish it:

  1. Open $SERVICE/admin and go to Release.
  2. Choose the file $DLL
  3. Paste the manifest, which is the one line in
     $OUT
  4. Press Publish.

The page refuses the pair unless that file hashes to $ACTUAL_SHA, which is what
the manifest was signed for. Publishing installs nothing: each licensed server
is offered the update on its next daily check.
NEXT

cat "$WORK/manifest.txt"

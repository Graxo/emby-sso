#!/bin/sh
# Refuse to ship a merged DLL whose contents are not covered by
# THIRD-PARTY-NOTICES.
#
# The plugin is one file that physically contains a dozen MIT- and
# Apache-licensed libraries. Every one of those licences requires its notice to
# travel with the code, so adding a dependency to ILRepack.targets without
# updating the notices file turns a release into a licence violation - silently,
# because nothing else in the build would notice.
#
# This reads the MergeInput list out of ILRepack.targets, which is the actual
# authority on what is merged, and requires each assembly name to appear
# somewhere in the notices file. It does NOT check versions: a name is what a
# human reviewer needs to be pointed at, and a version check would fail on every
# routine bump and be turned off within a month.
set -eu

usage='usage: verify-notices.sh <ilrepack.targets> <notices file>'
targets="${1:?$usage}"
notices="${2:?$usage}"

for f in "$targets" "$notices"; do
    if [ ! -f "$f" ]; then
        echo "verify-notices: $f does not exist." >&2
        exit 1
    fi
done

missing=0

# Each MergeInput is <MergeInput Include="$(OutputPath)Name.dll" />. The
# plugin's own assembly is $(AssemblyName).dll and is not a third party.
names=$(sed -n 's/.*<MergeInput Include="\$(OutputPath)\([^"]*\)\.dll".*/\1/p' "$targets" \
        | grep -v '^\$(AssemblyName)$' || true)

if [ -z "$names" ]; then
    echo "verify-notices: found no MergeInput entries in $targets - the parse is wrong." >&2
    exit 1
fi

for name in $names; do
    # Microsoft.IdentityModel.* is a wildcard covering six packages; check the
    # prefix in that case.
    pattern=$(printf '%s' "$name" | sed 's/\*$//')

    if grep -qF "$pattern" "$notices"; then
        continue
    fi

    echo "verify-notices: '$pattern' is merged into the plugin but is not named in $notices." >&2
    missing=1
done

if [ "$missing" -ne 0 ]; then
    echo "verify-notices: update $notices before releasing - merging is redistribution." >&2
    exit 1
fi

echo "verify-notices: every merged assembly in $targets is named in $notices"

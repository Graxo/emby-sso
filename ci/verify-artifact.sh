#!/bin/sh
# Refuse to ship anything but the ILRepack-merged plugin, built at the version
# and commit this pipeline is building.
#
# A Release build produces two files called Emby.Sso.dll, one directory apart:
# the ~108 KB compiler output, and the ~1.8 MB merged one under merged/. Only
# the merged one works. The unmerged one installs fine, loads fine, and then
# fails at runtime looking for Microsoft.IdentityModel — which is a miserable
# way for an operator to discover a packaging mistake. This check exists so
# that shipping the wrong one is impossible rather than merely unlikely.
set -eu

usage='usage: verify-artifact.sh <dll> <informational-version>'
dll="${1:?$usage}"
info="${2:?$usage}"

# The merged assembly is ~1.8 MB; the unmerged one is ~108 KB. Anything under
# a megabyte is either the unmerged plugin or a half-written file.
min_bytes=1048576

if [ ! -f "$dll" ]; then
    echo "verify: $dll was not produced by the build." >&2
    exit 1
fi

size=$(wc -c < "$dll")
if [ "$size" -lt "$min_bytes" ]; then
    echo "verify: $dll is $size bytes, below the $min_bytes-byte floor for a merged build." >&2
    echo "verify: this is the unmerged plugin or a partial write, and would fail at runtime." >&2
    exit 1
fi

# AssemblyInformationalVersion is "<version>+<commit>" and ILRepack carries the
# primary assembly's metadata into the merged output, so finding that exact
# string proves both that the version we asked for landed in the file we are
# about to ship and that the file came from this build rather than a stale one.
if ! grep -qaF "$info" "$dll"; then
    echo "verify: $dll does not carry informational version '$info'." >&2
    echo "verify: the version did not reach the assembly, or this artifact is stale." >&2
    exit 1
fi

echo "verify: $dll is $size bytes and carries version $info"

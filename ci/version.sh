#!/bin/sh
# Print the version this build should carry.
#
# On a tag pipeline the version is the tag with its leading "v" removed, so
# pushing v1.4.0 produces a plugin that reports 1.4.0 in Emby's dashboard.
# Tagging is how a release is cut here, so a tag that is not a version is a
# hard error: a mistyped tag should stop the pipeline loudly rather than
# quietly build something nobody asked for.
#
# Off a tag there is no release to name, so the build gets a version that
# cannot be mistaken for one and still records the commit it came from.
set -eu

tag="${CI_COMMIT_TAG:-}"

if [ -n "$tag" ]; then
    version="${tag#v}"
    if [ "$version" = "$tag" ] ||
        ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
        echo "version: '$tag' is not a release tag." >&2
        echo "version: expected vMAJOR.MINOR.PATCH, optionally with a -prerelease suffix (v1.4.0, v1.4.0-rc.1)." >&2
        exit 1
    fi
    printf '%s\n' "$version"
    exit 0
fi

printf '0.0.0-dev.%s\n' "${CI_COMMIT_SHORT_SHA:-local}"

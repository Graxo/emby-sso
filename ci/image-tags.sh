#!/bin/sh
# Print the registry tags this pipeline should publish for the service image,
# one per line, the primary one first. Nothing else decides what gets pushed.
#
#   v1.4.0        ->  1.4.0
#                     latest
#   v1.4.0-rc.1   ->  1.4.0-rc.1        a prerelease is never `latest`
#   main          ->  main-a1b2c3d4     the immutable one an operator pins
#                     main              the moving one, for "track the tip"
#   anything else ->  nothing, and a non-zero exit
#
# Why `latest` only on a release tag: `latest` is what a hurried operator
# types, so it has to mean "the newest thing that was deliberately released",
# never "whatever landed on main ten minutes ago". A branch build is
# addressable, but only by a name that says which commit it is.
#
# The tag regex is the same one ci/version.sh enforces; the two must agree,
# because a tag that builds a plugin numbered 1.4.0 has to build an image
# numbered 1.4.0.
#
#   sh ci/image-tags.sh
set -eu

tag="${CI_COMMIT_TAG:-}"
branch="${CI_COMMIT_BRANCH:-}"
default_branch="${CI_DEFAULT_BRANCH:-main}"
short_sha="${CI_COMMIT_SHORT_SHA:-}"

if [ -n "$tag" ]; then
    version="${tag#v}"
    if [ "$version" = "$tag" ] ||
        ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
        echo "image-tags: '$tag' is not a release tag." >&2
        echo "image-tags: expected vMAJOR.MINOR.PATCH, optionally with a -prerelease suffix (v1.4.0, v1.4.0-rc.1)." >&2
        exit 1
    fi
    printf '%s\n' "$version"
    # A hyphen is the prerelease marker semver gives us, and the only thing
    # this has to test: 1.4.0-rc.1 must not become the tag people pull blind.
    case "$version" in
        *-*) ;;
        *) printf 'latest\n' ;;
    esac
    exit 0
fi

if [ -n "$branch" ] && [ "$branch" = "$default_branch" ]; then
    if [ -z "$short_sha" ]; then
        echo "image-tags: on '$branch' but CI_COMMIT_SHORT_SHA is empty; refusing to push an unidentifiable image." >&2
        exit 1
    fi
    printf '%s-%s\n' "$branch" "$short_sha"
    printf '%s\n' "$branch"
    exit 0
fi

echo "image-tags: nothing to publish from ref '${tag:-${branch:-unknown}}'." >&2
echo "image-tags: only a vX.Y.Z tag or the default branch publish an image." >&2
exit 1

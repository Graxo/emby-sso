#!/bin/sh
# Print the release description for a tag.
#
# KEEP THIS SHORT. Whatever is written here is repeated on every release
# forever, and a Release is a notice rather than documentation: the one line
# that matters - "the service image must be redeployed", "set the required
# group first" - is lost if it sits in four paragraphs of background. The
# background belongs in the commit message and in docs/site/, where it can be
# corrected after the fact; a published Release cannot.
#
# The tag message is the only part that varies, and it is the part people read.
set -eu

usage='usage: release-notes.sh <version> <commit> <sha256-file> <package-url> [tag-message]'
version="${1:?$usage}"
commit="${2:?$usage}"
sha_file="${3:?$usage}"
package_url="${4:?$usage}"
tag_message="${5:-}"

checksum=$(cut -d' ' -f1 < "$sha_file")

printf 'Emby SSO %s, built from `%s`.\n\n' "$version" "$commit"

if [ -n "$tag_message" ]; then
    printf '%s\n\n' "$tag_message"
fi

cat <<NOTES
## Install

\`Emby.Sso.dll\` below is the whole plugin; installing any other DLL beside it
breaks it.

1. \`sha256sum -c Emby.Sso.dll.sha256\` — expect \`$checksum\`
2. Copy it into Emby's \`plugins\` directory, replacing the old copy.
3. Restart Emby Server.

It needs a licence key issued for this server, and a **Required group**, before
anyone can sign in. Both are on the plugin's configuration page; the project
wiki explains them.

All files: $package_url
NOTES

#!/bin/sh
# Print the release description for a tag.
#
# An operator arriving at a release page has to answer two questions before
# they copy a DLL onto a running server: is this the file the maintainer
# published, and what will it do to the users who can sign in today. The notes
# answer both, so keep the checksum and the required-group warning in them.
set -eu

usage='usage: release-notes.sh <version> <commit> <sha256-file> <package-url> [tag-message]'
version="${1:?$usage}"
commit="${2:?$usage}"
sha_file="${3:?$usage}"
package_url="${4:?$usage}"
tag_message="${5:-}"

checksum=$(cut -d' ' -f1 < "$sha_file")

printf 'The installable plugin for Emby Server, version %s, built from commit `%s`.\n\n' \
    "$version" "$commit"

if [ -n "$tag_message" ]; then
    printf '## What changed\n\n%s\n\n' "$tag_message"
fi

cat <<NOTES
## Install

1. Download \`Emby.Sso.dll\` below. It is the only file you need: the plugin
   and its dependencies are merged into that one assembly, and installing any
   other DLL alongside it breaks the plugin at runtime.
2. Check what you downloaded against the published checksum:

   \`\`\`
   sha256sum -c Emby.Sso.dll.sha256
   \`\`\`

   The expected SHA256 is \`$checksum\`.
3. Copy \`Emby.Sso.dll\` into Emby's \`plugins\` directory — \`/config/plugins\`
   in the linuxserver.io Docker image — replacing any earlier copy.
4. Restart Emby Server. Dashboard → Plugins should list **Authentik SSO** at
   version $version. A different version there means the old DLL is still in
   place.

## Before you restart, you also need a licence key

This plugin is licensed software. Paste the licence issued for **this** Emby
server into Dashboard → Plugins → Authentik SSO → **Licence key**. Without a
valid one the plugin refuses NEW single sign-ons and automatic account
creation, and says so in the server log; sessions that are already signed in
keep working and Emby's own local accounts are unaffected, so you are never
locked out of your server. A licence names one server id — the \`ServerId\`
Emby writes to its log at startup.

## Before you restart, if you are upgrading

Every sign-on this build performs is gated on an Authentik group, and until
**Required group** is set the plugin refuses everyone — including users who
were signing in fine before the upgrade. Set it in Dashboard → Plugins →
Authentik SSO as soon as the server is back up, and keep one administrator on
Emby's default authentication provider as a break-glass account. The README's
"Upgrading an existing install: set the required group FIRST" section explains
what a refusal looks like in the log.

## Files

| File | What it is |
| --- | --- |
| \`Emby.Sso.dll\` | The merged plugin. Install this. |
| \`Emby.Sso.dll.sha256\` | \`sha256sum -c\` input for the above. |
| \`LICENSE\` | The terms this plugin is licensed to you under. |
| \`THIRD-PARTY-NOTICES\` | Licences of the libraries merged into the DLL. Keep it with the DLL if you pass it on. |

All four are also downloadable directly from $package_url.
NOTES

#!/bin/sh
# Print the instructions for signing a published build.
#
# WHY THIS IS A PRINTOUT AND NOT A SIGNING STEP. Everything else about a
# release is automated here: the build, the version stamp, the checksum, the
# upload. The signature is not, and that is deliberate. A release manifest
# authorises CODE to install itself on every customer's Emby server, so the key
# that signs one is the single most dangerous secret this project has - more
# dangerous than the licence key, which can only mint free licences.
#
# A key in a CI variable is a key held by every runner, every job, every person
# who can push a branch, and every dependency any job pulls. That is the whole
# argument, and no amount of masking changes it.
#
# So the pipeline does all of the work that does not need the key, and hands
# the operator one command that does. The commands below are complete and
# filled in - the version, the address, the expected hash - so signing is
# copy, paste, read one line of output, paste it back.
set -eu

usage='usage: release-signing.sh <version> <sha256-file>'
version="${1:?$usage}"
sha_file="${2:?$usage}"

checksum=$(cut -d' ' -f1 < "$sha_file")

cat <<NOTES
# Signing $version

This build is published but NOT yet offered to anybody. No server will see it
until a manifest signed with the release key is uploaded to the licence
service, and that key is not in this pipeline.

## 1. On the machine that holds the release key

Download \`Emby.Sso.dll\` from this release, then:

    tools/Emby.Sso.LicenceTool/release.sh $version ~/Downloads/Emby.Sso.dll $checksum

Passing the checksum is not optional here: it is what makes this the build the
pipeline made rather than whatever was in the downloads folder. The script
refuses to produce anything if the file disagrees, or if the key it used is not
the release key the plugin trusts.

## 2. On the licence service's admin page

Open **Release**, choose that same \`Emby.Sso.dll\`, paste the manifest the
script printed, and press **Publish**. The page refuses the pair unless the
file hashes to:

    $checksum

Publishing installs nothing. Each licensed server is offered the update on its
next daily check and installs it when its administrator chooses, after checking
the download against that hash.

Full procedure, including the first time: docs/site/signing-a-release.md
NOTES

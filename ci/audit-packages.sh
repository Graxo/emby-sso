#!/bin/sh
# Fails if any NuGet package, direct or transitive, has a known advisory.
#
# `dotnet list package --vulnerable` exits 0 whether or not it found anything -
# it is a reporting command, not a check - so the exit code has to come from
# reading its output. That is done here rather than inline in .gitlab-ci.yml
# because it needs to be runnable by hand, before pushing, by whoever is about
# to add a dependency.
#
#     sh ci/audit-packages.sh Emby.Sso.sln service/Emby.Sso.Service.sln
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: $0 <solution or project> [...]" >&2
    exit 2
fi

status=0

for target in "$@"; do
    echo "==> $target"

    # Restore first, explicitly. --vulnerable needs a restored graph and the
    # error it gives without one ("No assets file") reads like a broken
    # checkout rather than a missing step.
    dotnet restore "$target" >/dev/null

    output="$(dotnet list "$target" package --vulnerable --include-transitive)"

    echo "$output"

    # The command prints "has no vulnerable packages given the current sources"
    # for a clean project. Anything with a severity column is a finding; grep
    # for the severities rather than for the absence of that sentence, so that a
    # reworded message cannot turn this check off silently.
    if echo "$output" | grep -qiE '(Critical|High|Moderate|Low)[[:space:]]*$|>[[:space:]]+[A-Za-z0-9._]+.*(Critical|High|Moderate|Low)'; then
        echo "AUDIT FAILED: $target depends on a package with a known advisory." >&2
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    cat >&2 <<'WHY'

This is a gate rather than a warning because of how this project ships. The
plugin is ONE merged DLL: ILRepack folds its dependencies in and internalises
them, so an operator who installs it cannot see what is inside, cannot patch a
dependency without a new build from here, and has no scanner that would tell
them. Publishing a known-vulnerable dependency into that is not something the
person running it can do anything about.

Raise the package version, or - if there is no fixed version yet - decide
deliberately, in a commit that says so, whether the advisory applies to how this
code uses the package.
WHY
    exit 1
fi

echo "No known advisories against any package, direct or transitive."

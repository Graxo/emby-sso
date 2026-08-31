#!/bin/sh
# Catch the .gitlab-ci.yml mistake that costs a whole pipeline.
#
# `- echo "pages: built 12 pages"` is not a string. The colon-space makes YAML
# read it as a mapping, GitLab rejects the file at validation time, and NOTHING
# runs - not the failing job, the whole config. The error it gives back
# ("script config should be a string or a nested array of strings") does not
# name the line, so it is worth ten seconds to find it here instead.
#
# This has happened twice: once in publish, once in pages.
#
#   sh ci/lint-ci.sh
set -eu

file="${1:-.gitlab-ci.yml}"

python3 - "$file" <<'PY'
import sys, yaml

path = sys.argv[1]
with open(path) as handle:
    document = yaml.safe_load(handle)

problems = []
for job, config in (document or {}).items():
    if not isinstance(config, dict):
        continue
    for key in ("script", "before_script", "after_script"):
        for index, entry in enumerate(config.get(key) or []):
            if not isinstance(entry, str):
                problems.append((job, key, index, entry))

for job, key, index, entry in problems:
    print(f"{path}: {job}.{key}[{index}] is a {type(entry).__name__}, not a string.", file=sys.stderr)
    print(f"    {entry!r}", file=sys.stderr)
    print("    Almost certainly an unquoted 'echo \"word: word\"'. Wrap the entry", file=sys.stderr)
    print("    in a block scalar (- |) or quote the whole thing.", file=sys.stderr)

if problems:
    raise SystemExit(1)

jobs = [k for k in (document or {}) if not k.startswith(".")
        and k not in ("stages", "variables", "default", "workflow", "include")]
print(f"{path}: parses, {len(jobs)} jobs, every script entry is a string ({', '.join(jobs)})")
PY

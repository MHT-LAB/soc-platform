#!/usr/bin/env bash
# Refuse to publish a release from a commit that is not on main.
#
#   check-tag-on-main.sh <commit> [main-ref]     (main-ref defaults to origin/main)
#
# Catches a mistake: tagging a commit that is not on main (unreviewed, unmerged).
# It is NOT a security boundary on its own. On a tag push GitHub runs the
# release.yml stored in the tagged commit, so whoever can tag an arbitrary
# commit also controls whether this check runs. The boundaries are the tag
# rulesets (who may create v*.*.* tags) and deploy.sh refusing images whose
# signed source commit is not on main. Anything that cannot be checked
# (missing ref, shallow clone) is a failure, never a pass.
set -euo pipefail

sha="${1:?usage: check-tag-on-main.sh <commit> [main-ref]}"
main_ref="${2:-origin/main}"

if ! git rev-parse --verify -q "$main_ref^{commit}" > /dev/null; then
  echo "ERROR: $main_ref not found; the checkout needs full history (fetch-depth: 0)."
  exit 1
fi
if ! git merge-base --is-ancestor "$sha" "$main_ref"; then
  echo "ERROR: $sha is not on $main_ref; refusing to publish a release from it."
  exit 1
fi
echo "ok: $sha is on $main_ref"

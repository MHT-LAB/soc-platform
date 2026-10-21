#!/usr/bin/env bash
# Refuse to publish a release from a commit that is not on main.
#
#   check-tag-on-main.sh <commit> [main-ref]     (main-ref defaults to origin/main)
#
# deploy.sh trusts any image signed by release.yml on a v*.*.* tag. Without this
# check, a tag pushed on an unmerged PR commit would be built, signed and
# deployable even though it never passed review. Anything that cannot be
# checked (missing ref, shallow clone) is a failure, never a pass.
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

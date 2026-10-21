#!/usr/bin/env bash
# Scrub gate: fail if anything headed for this public repository contains
# identifiers that must never reach it.
#
# What is checked (generic patterns, email addresses, and the private denylist
# of real names, hosts and ids):
#   - the tracked files of the checked-out tree;
#   - every line added by every commit in the range being merged, so a name
#     that is added and removed within one PR is still caught (it would stay
#     public in the PR ref);
#   - commit messages and author/committer emails in that range;
#   - the PR title and body (SCRUB_PR_TITLE, SCRUB_PR_BODY), because a squash
#     merge turns them into the commit message on main.
#
# The denylist never lives in this repo. CI passes it in SCRUB_DENYLIST; locally
# it is read from SCRUB_DENYLIST_FILE (default: the sibling private deploy repo).
# In CI a missing or empty denylist FAILS the gate. The one exception is a
# Dependabot PR that changes only dependency files (SCRUB_DEPENDABOT=1).
#
# Environment:
#   SCRUB_BASE          revision the range starts from (CI: PR base or push "before")
#   SCRUB_ALL_HISTORY   set to scan every commit instead of only base..HEAD
#   SCRUB_PR_TITLE, SCRUB_PR_BODY   PR text to check (body ignored for Dependabot)
#
# Implementation rules, learned the hard way (see scripts/test-scrub-check.sh):
#   - Never judge a pipeline by its exit status: `git log | grep -q` is killed
#     by SIGPIPE when grep matches early, and `xargs` hides matches in earlier
#     batches. Read output into a file or variable, then look at the content.
#   - Anything that cannot run is a failure, never a pass.
#   - In CI the log is public and outlives a force-push, so never print matched
#     text there. Locally, print it so the fix is obvious.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
fail=0
self="scripts/scrub-check.sh"
in_ci="${GITHUB_ACTIONS:-}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

report() { echo "SCRUB: $1"; fail=1; }

# Pathspecs left out of the file scan: this script (it names the patterns) and
# lock files (hashes look like everything).
excl=(":(exclude)$self" ":(exclude)*.lock")

generic=(
  '/Users/[A-Za-z]'                                          # macOS home paths
  '/home/[a-z]'                                              # Linux home paths
  '(^|[^0-9.])10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'        # RFC 1918
  '(^|[^0-9.])192\.168\.[0-9]{1,3}\.[0-9]{1,3}'              # RFC 1918
  '(^|[^0-9.])172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}'  # RFC 1918
  '(^|[^0-9.])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}'  # CGNAT / mesh VPN
)
# Email addresses, except GitHub noreply and documentation domains.
email_re='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
email_ok='@(users\.noreply\.github\.com|example\.(com|org|net))$'

# --- denylist ------------------------------------------------------------------
terms="$tmp/terms"
: > "$terms"
raw=""
if [[ -n "${SCRUB_DENYLIST:-}" ]]; then
  raw="$tmp/raw"; printf '%s\n' "$SCRUB_DENYLIST" > "$raw"
elif [[ -f "${SCRUB_DENYLIST_FILE:-../mht-soc-deploy/scrub/denylist.txt}" ]]; then
  raw="${SCRUB_DENYLIST_FILE:-../mht-soc-deploy/scrub/denylist.txt}"
fi

# --- range of commits being checked --------------------------------------------
base=""
if [[ -n "${SCRUB_ALL_HISTORY:-}" ]]; then
  :  # whole history
elif [[ -n "${SCRUB_BASE:-}" ]]; then
  base="$(git merge-base "$SCRUB_BASE" HEAD 2>/dev/null || true)"
elif git rev-parse -q --verify origin/main > /dev/null; then
  if [[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]]; then
    base="$(git rev-parse HEAD)"   # nothing new beyond main
  else
    base="$(git merge-base origin/main HEAD 2>/dev/null || true)"
  fi
fi
if [[ -n "$base" ]]; then range="$base..HEAD"; else range="HEAD"; fi

# A Dependabot PR that touches only dependency files may run without the denylist.
dependency_only() {
  [[ -n "$base" ]] || return 1
  local files
  files="$(git log --name-only --format= "$range")"
  [[ -n "$files" ]] || return 1
  ! grep -vE '^(api/uv\.lock|api/pyproject\.toml|api/Dockerfile|\.github/workflows/[^/]+\.ya?ml)$' <<< "$files" > /dev/null
}

if [[ -n "$raw" ]]; then
  # Strip CR and surrounding space (a CRLF-edited list silently matches nothing),
  # drop comments and blank lines.
  tr -d '\r' < "$raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | grep -vE '^(#|$)' > "$terms" || true
  if [[ ! -s "$terms" ]]; then
    report "the denylist was loaded but holds no terms (fail closed)"
  fi
elif [[ -n "$in_ci" ]]; then
  if [[ "${SCRUB_DEPENDABOT:-}" == "1" ]] && dependency_only; then
    echo "scrub: Dependabot dependency-only change, no denylist: generic checks only"
  else
    report "the private denylist is missing in CI (fail closed)"
  fi
else
  echo "scrub: no private denylist available, generic checks only"
fi

# --- checks over the tracked files (git grep: no xargs batching) ----------------
# tree_grep <label> <git grep options...>: report every match in tracked files.
tree_grep() {
  local label="$1" out rc=0
  shift
  out="$(git grep -nI "$@" -- . "${excl[@]}")" || rc=$?
  if [[ $rc -gt 1 ]]; then
    report "git grep failed (exit $rc) while checking files: $label"
  elif [[ -n "$out" ]]; then
    report "$label in tracked files"
    if [[ -n "$in_ci" ]]; then
      printf '%s\n' "$out" | cut -d: -f1,2 | sed 's/^/  at /'   # place only, never the text
    else
      printf '%s\n' "$out"
    fi
  fi
}

for pattern in "${generic[@]}"; do
  tree_grep "generic pattern matched ($pattern)" -E -e "$pattern"
done

rc=0
emails="$(git grep -nIoE -e "$email_re" -- . "${excl[@]}")" || rc=$?
if [[ $rc -gt 1 ]]; then
  report "git grep failed while checking email addresses"
else
  bad="$(printf '%s\n' "$emails" | grep -viE "$email_ok" || true)"
  if [[ -n "$bad" ]]; then
    report "email address in tracked files"
    if [[ -n "$in_ci" ]]; then printf '%s\n' "$bad" | cut -d: -f1,2 | sed 's/^/  at /'; else printf '%s\n' "$bad"; fi
  fi
fi

if [[ -s "$terms" ]]; then
  rc=0
  out="$(git grep -nIiF -l -f "$terms" -- . "${excl[@]}")" || rc=$?
  if [[ $rc -gt 1 ]]; then
    report "git grep failed while checking the denylist"
  elif [[ -n "$out" ]]; then
    report "private denylist matched in tracked files (terms hidden):"
    printf '%s\n' "$out" | sed 's/^/  in /'
  fi
fi

# --- checks over plain text: added lines, messages, PR text ----------------------
# check_text <label> <file>
check_text() {
  local label="$1" file="$2" pattern found
  [[ -s "$file" ]] || return 0
  for pattern in "${generic[@]}"; do
    if grep -qE -e "$pattern" "$file"; then
      report "$label: generic pattern matched ($pattern)"
      if [[ -z "$in_ci" ]]; then grep -nE -e "$pattern" "$file" | head -5; fi
    fi
  done
  found="$(grep -oE "$email_re" "$file" | grep -viE "$email_ok" || true)"
  if [[ -n "$found" ]]; then
    report "$label: email address"
    if [[ -z "$in_ci" ]]; then printf '%s\n' "$found"; fi
  fi
  if [[ -s "$terms" ]] && grep -qiF -f "$terms" "$file"; then
    report "$label: private denylist matched (terms hidden)"
  fi
}

# Lines added by any commit in the range, found by walking each diff: a "+"
# line only counts after its "@@" header, so file headers are not mistaken for
# content. A line added then removed in the same range still appears here.
git log -p -U0 --no-renames --no-color --no-ext-diff --format= "$range" > "$tmp/patch"
awk '/^diff --git /{h=0;next} /^@@ /{h=1;next} h && /^\+/ {print substr($0,2)}' "$tmp/patch" > "$tmp/added"
check_text "added lines in commits $range" "$tmp/added"

git log --format='%B%n' "$range" > "$tmp/messages"
check_text "commit messages" "$tmp/messages"

# Commit authors and committers must use a noreply address.
git log --format='%ae%n%ce' "$range" | sort -u > "$tmp/authors"
bad_authors="$(grep -vE '@users\.noreply\.github\.com$|^noreply@github\.com$|^$' "$tmp/authors" || true)"
if [[ -n "$bad_authors" ]]; then
  report "commit metadata uses a non-noreply address"
  if [[ -z "$in_ci" ]]; then printf '%s\n' "$bad_authors"; fi
fi

# PR title and body. The body of a Dependabot PR is generated release notes, not
# our text, so only its title is checked.
{
  printf '%s\n' "${SCRUB_PR_TITLE:-}"
  if [[ "${SCRUB_DEPENDABOT:-}" != "1" ]]; then printf '%s\n' "${SCRUB_PR_BODY:-}"; fi
} > "$tmp/prtext"
check_text "PR title/body" "$tmp/prtext"

if [[ $fail -ne 0 ]]; then
  echo "Scrub gate FAILED. Remove or generalize the items above."
  exit 1
fi
echo "Scrub gate passed."

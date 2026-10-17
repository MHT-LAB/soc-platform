#!/usr/bin/env bash
# Scrub gate: fail if tracked files or commit metadata contain identifiers that
# must never reach a public repository.
#
# Two layers:
#   1. Generic patterns below (private addresses, home paths, stray emails).
#   2. A private denylist of real names, hosts and ids. It never lives in this
#      repo. CI passes it in the SCRUB_DENYLIST secret; locally it is read from
#      SCRUB_DENYLIST_FILE (default: the sibling private deploy repo).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
fail=0
self="scripts/scrub-check.sh"

files() { git ls-files -z -- . ":!:$self" ":!:*.lock" ":!:uv.lock"; }

report() { echo "SCRUB: $1"; fail=1; }

# --- 1. generic patterns -----------------------------------------------------
generic=(
  '/Users/[A-Za-z]'                                          # macOS home paths
  '/home/[a-z]'                                              # Linux home paths
  '(^|[^0-9.])10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'        # RFC 1918
  '(^|[^0-9.])192\.168\.[0-9]{1,3}\.[0-9]{1,3}'              # RFC 1918
  '(^|[^0-9.])172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}'  # RFC 1918
  '(^|[^0-9.])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}'  # CGNAT / mesh VPN
)
for pattern in "${generic[@]}"; do
  if hits=$(files | xargs -0 grep -nIE -- "$pattern" 2>/dev/null); then
    report "generic pattern matched: $pattern"; echo "$hits"
  fi
done

# Email addresses, except GitHub noreply and documentation domains.
if hits=$(files | xargs -0 grep -nIoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' 2>/dev/null \
    | grep -vE '@(users\.noreply\.github\.com|example\.(com|org|net))$'); then
  report "email address in tracked files"; echo "$hits"
fi

# Commit authors and committers must use a noreply address.
if bad=$(git log --format='%ae%n%ce' 2>/dev/null | sort -u | grep -vE '@users\.noreply\.github\.com$|^noreply@github\.com$'); then
  report "commit metadata uses a non-noreply address"; echo "$bad"
fi

# --- 2. private denylist -------------------------------------------------------
denylist=""
if [[ -n "${SCRUB_DENYLIST:-}" ]]; then
  denylist="$(mktemp)"; printf '%s\n' "$SCRUB_DENYLIST" > "$denylist"
elif [[ -f "${SCRUB_DENYLIST_FILE:-../mht-soc-deploy/scrub/denylist.txt}" ]]; then
  denylist="${SCRUB_DENYLIST_FILE:-../mht-soc-deploy/scrub/denylist.txt}"
fi

if [[ -n "$denylist" ]]; then
  # Fixed strings, case-insensitive, comments and blank lines ignored.
  terms="$(mktemp)"; grep -vE '^\s*(#|$)' "$denylist" > "$terms" || true
  if [[ -s "$terms" ]]; then
    if files | xargs -0 grep -qIiF -f "$terms" 2>/dev/null; then
      # Print file and line only, never the matched term itself, so CI logs
      # don't leak the denylist.
      report "private denylist matched (terms hidden):"
      files | xargs -0 grep -nIiF -l -f "$terms" 2>/dev/null | sed 's/^/  in /'
    fi
    # Messages only. Author names are the public account profile name;
    # author emails are enforced by the noreply rule above.
    if git log --format='%s%n%b' 2>/dev/null | grep -qiF -f "$terms"; then
      report "private denylist matched in commit messages (terms hidden)"
    fi
  fi
else
  echo "scrub: no private denylist available, generic checks only"
fi

if [[ $fail -ne 0 ]]; then
  echo "Scrub gate FAILED. Remove or generalize the items above."
  exit 1
fi
echo "Scrub gate passed."

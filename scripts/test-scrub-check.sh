#!/usr/bin/env bash
# Tests for the scrub gate itself. Each case builds a throwaway git repo, plants
# a leak (or doesn't), runs scripts/scrub-check.sh in it, and checks that the
# gate fails (or passes) as it should. Terms, addresses and IPs are fake and are
# assembled at run time, so this file never trips the gate it tests.
#
# Every "must fail" case below is a way a real leak could have slipped through.
set -euo pipefail

# SCRUB_GATE_UNDER_TEST lets the tests be pointed at another version of the gate.
GATE="${SCRUB_GATE_UNDER_TEST:-$(cd "$(dirname "$0")" && pwd)/scrub-check.sh}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

TERM_X="zzprivateterm"                          # fake denylist term
AT="@"
BAD_EMAIL="someone${AT}corp.invalid"            # an address that must never be committed
PRIVATE_IP="$(printf '%s.%s.%s.%s' 192 168 1 77)"
printf '%s\n' "# fake denylist" "$TERM_X" > "$work/denylist"

pass=0
failed=0
R="" BASE="" out="" rc=0

new_repo() {
  R="$work/$1"; mkdir -p "$R"
  git -C "$R" init -q -b main
  git -C "$R" config user.name "Test"
  git -C "$R" config user.email "1+test@users.noreply.github.com"
  git -C "$R" config commit.gpgsign false
  git -C "$R" config core.hooksPath /dev/null
  echo "hello" > "$R/README.md"
  git -C "$R" add -A
  git -C "$R" commit -q -m "base"
  BASE="$(git -C "$R" rev-parse HEAD)"
}

# commit <path> <content> [message]
commit() {
  mkdir -p "$(dirname "$R/$1")"
  printf '%s\n' "$2" > "$R/$1"
  git -C "$R" add -A
  git -C "$R" commit -q -m "${3:-change}"
}

remove() { git -C "$R" rm -q "$1"; git -C "$R" commit -q -m "remove $1"; }

# gate [VAR=value ...]: run the gate in $R with a clean environment.
gate() {
  rc=0
  out="$(cd "$R" && env -i PATH="$PATH" HOME="$HOME" SCRUB_BASE="$BASE" \
    SCRUB_DENYLIST_FILE="$work/denylist" "$@" bash "$GATE" 2>&1)" || rc=$?
}

check() {
  local label="$1" want="$2"
  if [[ "$rc" -eq "$want" ]]; then
    pass=$((pass + 1)); echo "ok    $label"
  else
    failed=$((failed + 1)); echo "FAIL  $label (exit $rc, wanted $want)"
    printf '%s\n' "$out" | sed 's/^/        | /'
  fi
}

# output_lacks <label> <text>: the gate output must not contain the text.
output_lacks() {
  if [[ "$out" == *"$2"* ]]; then
    failed=$((failed + 1)); echo "FAIL  $1 (output contains the matched text)"
  else
    pass=$((pass + 1)); echo "ok    $1"
  fi
}
output_has() {
  if [[ "$out" == *"$2"* ]]; then
    pass=$((pass + 1)); echo "ok    $1"
  else
    failed=$((failed + 1)); echo "FAIL  $1 (output lacks: $2)"
  fi
}

# --- the baseline ---------------------------------------------------------------
new_repo clean;               commit a.txt "nothing private here";          gate; check "clean change passes" 0

# --- S1: commit messages (the SIGPIPE fail-open) --------------------------------
new_repo msg-newest;          commit a.txt "ok" "mentions $TERM_X in the newest message"
gate; check "denylist term in the NEWEST commit message fails" 1
# git log must still be writing when grep exits on the first (newest) match, or
# the old pipeline never hit SIGPIPE. A few hundred long messages guarantee it.
new_repo msg-long-history
pad="$(head -c 3000 /dev/zero | tr '\0' 'x')"
for i in $(seq 1 300); do git -C "$R" commit -q --allow-empty -m "filler $i $pad"; done
git -C "$R" commit -q --allow-empty -m "newest message mentions $TERM_X"
gate; check "term in the newest message of a long history fails" 1
new_repo msg-older;           commit a.txt "ok" "mentions $TERM_X";  commit b.txt "ok" "fine"
gate; check "denylist term in an older commit message in the range fails" 1

# --- S2: many files (xargs batching hid matches) --------------------------------
# Long paths so the file list is split into several xargs batches (a batch with
# no match makes xargs exit 123, which hid matches in the other batches).
new_repo many-files
long="$(head -c 120 /dev/zero | tr '\0' 'd')"
mkdir -p "$R/$long"; for i in $(seq 1 6000); do echo "file $i" > "$R/$long/file-$i.txt"; done
echo "has $TERM_X inside" > "$R/$long/file-10.txt"
git -C "$R" add -A; git -C "$R" commit -q -m "many files"
gate; check "term in the first of 6000 long-path files fails" 1
echo "clean again" > "$R/$long/file-10.txt"; echo "has $TERM_X inside" > "$R/$long/file-5990.txt"
git -C "$R" add -A; git -C "$R" commit -q -m "move it"
gate; check "term in the last of 6000 long-path files fails" 1
echo "clean again" > "$R/$long/file-5990.txt"; git -C "$R" add -A; git -C "$R" commit -q -m "fix"
gate SCRUB_BASE="$(git -C "$R" rev-parse HEAD)"; check "6000 clean files pass" 0

# --- S3: missing, empty or CRLF denylist ----------------------------------------
new_repo no-list-ci;          commit a.txt "ok"
gate SCRUB_DENYLIST_FILE=/nonexistent GITHUB_ACTIONS=true;  check "missing denylist FAILS in CI" 1
gate SCRUB_DENYLIST_FILE=/nonexistent;                       check "missing denylist only warns locally" 0
gate SCRUB_DENYLIST_FILE=/nonexistent GITHUB_ACTIONS=true SCRUB_DENYLIST="";  check "empty secret (fork PR) FAILS in CI" 1
printf '# only a comment\n\n' > "$work/empty-list"
gate SCRUB_DENYLIST_FILE="$work/empty-list";                 check "denylist with no terms fails" 1
printf '%s\r\n' "$TERM_X" > "$work/crlf-list"
new_repo crlf;                commit a.txt "has $TERM_X here"
gate SCRUB_DENYLIST_FILE="$work/crlf-list";                  check "CRLF denylist still matches" 1

# Dependabot exception: dependency files only.
new_repo dependabot-ok;       commit api/uv.lock "bump"; commit .github/workflows/ci.yml "bump"
gate SCRUB_DENYLIST_FILE=/nonexistent GITHUB_ACTIONS=true SCRUB_DEPENDABOT=1
check "Dependabot dependency-only change may skip the denylist" 0
new_repo dependabot-bad;      commit api/uv.lock "bump"; commit api/src/app.py "not a dependency file"
gate SCRUB_DENYLIST_FILE=/nonexistent GITHUB_ACTIONS=true SCRUB_DEPENDABOT=1
check "Dependabot change touching source still FAILS without the denylist" 1
new_repo not-dependabot;      commit api/uv.lock "bump"
gate SCRUB_DENYLIST_FILE=/nonexistent GITHUB_ACTIONS=true
check "the exception needs the Dependabot flag" 1

# --- S4: added then removed within one PR ---------------------------------------
new_repo add-remove;          commit leak.txt "contains $TERM_X";  remove leak.txt
gate; check "term added then removed in the same PR fails (tree is clean)" 1
new_repo ip-add-remove;       commit leak.txt "server at $PRIVATE_IP";  remove leak.txt
gate; check "private IP added then removed in the same PR fails" 1
new_repo tree-hit;            commit leak.txt "contains $TERM_X"
gate; check "term in a tracked file fails" 1
new_repo scoped;              commit old.txt "has $TERM_X" "old";  BASE="$(git -C "$R" rev-parse HEAD)"; commit b.txt "fine" "fine"
git -C "$R" rm -q old.txt; git -C "$R" commit -q -m "cleanup"
gate; check "history before the base is out of scope" 0
gate SCRUB_ALL_HISTORY=1; check "SCRUB_ALL_HISTORY scans older history" 1

# --- S5: PR title and body --------------------------------------------------------
new_repo pr-text;             commit a.txt "ok"
gate SCRUB_PR_TITLE="fine title" SCRUB_PR_BODY="body mentions $TERM_X"
check "term in the PR body fails" 1
gate SCRUB_PR_TITLE="title mentions $TERM_X" SCRUB_PR_BODY="fine"
check "term in the PR title fails" 1
gate SCRUB_PR_TITLE="fine" SCRUB_PR_BODY="fine"
check "clean PR text passes" 0
gate SCRUB_PR_TITLE="fine" SCRUB_PR_BODY="release notes mention $TERM_X" SCRUB_DEPENDABOT=1
check "Dependabot PR body is not checked (title is)" 0
gate SCRUB_PR_TITLE="mentions $TERM_X" SCRUB_PR_BODY="fine" SCRUB_DEPENDABOT=1
check "Dependabot PR title is checked" 1

# --- S5b: what a squash merge adds to the message on main ------------------------
# An "update branch" merge commit is authored under the account's display name;
# the squash turns it into a Co-authored-by line on main.
new_repo squash-coauthor;     commit a.txt "ok"
echo "more" >> "$R/a.txt"; git -C "$R" add -A
GIT_AUTHOR_NAME="Person $TERM_X" git -C "$R" commit -q -m "Merge branch 'main' into feature"
gate SCRUB_PR=1;              check "author name that a squash would add as Co-authored-by fails on a PR" 1
gate;                         check "author names are not checked on push (GitHub sets them on main)" 0
new_repo squash-committer;    commit a.txt "ok"
echo "more" >> "$R/a.txt"; git -C "$R" add -A
GIT_COMMITTER_NAME="$TERM_X" git -C "$R" commit -q -m "fine"
gate SCRUB_PR=1;              check "committer name with a denylist term fails on a PR" 1
new_repo squash-clean;        commit a.txt "ok"
gate SCRUB_PR=1 SCRUB_PR_TITLE="fine" SCRUB_PR_BODY="fine"
check "clean names pass on a PR" 0
new_repo dependabot-notes;    commit api/uv.lock "bump"
gate SCRUB_PR=1 SCRUB_DEPENDABOT=1 SCRUB_PR_TITLE="bump x" SCRUB_PR_BODY="notes: route $PRIVATE_IP and $TERM_X"
check "Dependabot release notes that would fail on main only warn" 0
output_has   "the warning tells the merger to set an explicit message" "--body"
gate SCRUB_PR=1 SCRUB_DEPENDABOT=1 SCRUB_PR_TITLE="bump x" SCRUB_PR_BODY="notes: route $PRIVATE_IP" GITHUB_ACTIONS=true SCRUB_DENYLIST="$TERM_X"
check "the warning does not fail in CI" 0
output_has   "CI gets a warning annotation" "::warning title=scrub gate::"
output_lacks "CI warning never prints the matched address" "$PRIVATE_IP"
gate SCRUB_PR=1 SCRUB_DEPENDABOT=1 SCRUB_PR_TITLE="bump x" SCRUB_PR_BODY="plain notes"
check "clean Dependabot notes pass" 0
output_lacks "no warning for clean notes" "WARNING"
gate SCRUB_PR=1 SCRUB_DEPENDABOT=1 SCRUB_PR_TITLE="bump $TERM_X" SCRUB_PR_BODY="notes $PRIVATE_IP"
check "a real failure (title) still fails when the notes only warn" 1
output_has   "the notes warning is still shown next to a real failure" "WARNING, not a failure"

# --- S6: email addresses in messages and authors ----------------------------------
new_repo msg-email;           commit a.txt "ok" "Co-authored-by: Person <$BAD_EMAIL>"
gate; check "email address in a commit message fails" 1
new_repo author;              commit a.txt "ok"
echo "more" >> "$R/a.txt"; git -C "$R" add -A
GIT_AUTHOR_EMAIL="$BAD_EMAIL" GIT_COMMITTER_EMAIL="$BAD_EMAIL" git -C "$R" commit -q -m "wrong author"
gate; check "non-noreply author or committer fails" 1

# Dependabot signs off as support@github.com; that must not fail its PRs.
new_repo dependabot-signoff;  commit api/uv.lock "bump" "Bump x from 1 to 2

Signed-off-by: dependabot[bot] <support${AT}github.com>"
gate; check "Dependabot sign-off address is allowed" 0

# --- .gitattributes must not blind the gate ---------------------------------------
new_repo attrs-tree;          commit .gitattributes "* -diff";  commit notes.txt "server $PRIVATE_IP"
gate; check "private IP in a file marked binary by .gitattributes fails" 1
new_repo attrs-diff;          commit .gitattributes "* -diff";  commit leak.txt "has $TERM_X";  remove leak.txt
gate; check "term added then removed under '* -diff' still fails" 1

# --- S8: CI logs must not echo the matched text -----------------------------------
new_repo quiet;               commit leak.txt "server at $PRIVATE_IP and $TERM_X"
gate GITHUB_ACTIONS=true;     check "leak fails in CI" 1
output_lacks "CI output never prints the private address" "$PRIVATE_IP"
output_lacks "CI output never prints the denylist term"   "$TERM_X"
gate;                         check "leak fails locally" 1
output_has   "local output shows the address so it is easy to fix" "$PRIVATE_IP"

echo
echo "scrub gate self-test: $pass passed, $failed failed"
[[ $failed -eq 0 ]]

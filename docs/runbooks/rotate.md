# Key rotation: the plan, the approval and the record

`deploy/rotate.sh` works out which keys are due, shows the plan, and writes down rotations a
person did by hand. **This build changes no key anywhere.** It cannot: the container it runs
has no network, no secret and no way to reach a vendor. A later build adds the step that
rotates automatic keys; this one is the part that decides what is due and keeps the dates.

The list of keys is a private repository, the key register: one small file per key (its name,
permissions, where each copy lives, how often it is rotated, how to prove a new one works). It
holds no value, and its own CI refuses any file that looks like it does. The rotator reads it
read-only.

## Rules this follows

- A key is rotated every 90 days, or every 30 days when it could do great damage to this
  platform or a customer's systems (`sensitive`).
- Automatic keys are rotated when due. Manual keys share one monthly session, the first Monday
  of the month; a key that would go overdue before the session after next is done at the next
  session, so nothing trickles in between.
- Keys replaced only on exposure (no schedule) are not tracked here.
- Nothing here reads, prints or stores a key value. The state file holds ids, dates and
  outcomes.

## What a run does

1. **The register clone** (default `/opt/key-register`) is fetched and fast-forwarded to
   `origin/main`. It is refused if the tree is not clean, if the head commit is not exactly
   `origin/main`, or if the head commit's signature does not verify (git status `G`). The host
   needs the signer's public key in its keyring, set up the same way as for the rules deploy.
   A squash merge on GitHub is signed by GitHub, so a change that went through a pull request
   passes; an unsigned push to `main` stops planning instead of slipping through.
2. **The one-shot `rotate` service** (compose profile `rotate`; `deploy.sh` never turns it on)
   re-checks every key file for the few things the plan relies on (id, method, period,
   readiness), reads `state.json`, and works out each key's status.
3. It prints the plan and, in the interactive form, asks for a typed `yes`. No terminal, or
   anything but `yes`, changes nothing.
4. A one-line record goes to `rotate.log` and the screen, for the vault Build Log.

Statuses: **overdue** (past its due date), **no record** (nothing says when it was last
rotated), **due soon** (within 7 days), **this session** (would go overdue before the session
after next), **ok**, **not ready** (the key does not exist yet or its permissions are
unconfirmed: skipped, never nagged).

## Commands (on the host, as root)

| Command | What it does |
|---|---|
| `deploy/rotate.sh` | the plan, then a typed `yes`. Approving writes the plan's short hash and the register commit to `state.json`, good for 30 minutes. This build does not use the approval yet; it only records it. |
| `deploy/rotate.sh --plan` | the plan only, asks nothing |
| `deploy/rotate.sh --plan --quiet` | one summary line (what the daily timer runs) |
| `deploy/rotate.sh --record <id> [--date YYYY-MM-DD] [--due YYYY-MM-DD]` | a person rotated this key by hand: write it down after a typed `yes`. The date defaults to today (New York time) and cannot be in the future. `--due` is for a key whose due date was set by hand and differs from the date plus the period. Makes no vendor call. |

Exit codes: `0` done or nothing due, `1` could not write its files, `2` refused before
changing anything, `3` not confirmed, `4` (plan only) something is overdue, has no record, or
has an old key still live.

## Setting up a host (once)

1. The host has been deployed (`deploy.sh`), so `env/image.env` exists. The service needs no
   settings file.
2. Clone the key register with a **read-only deploy key** that has its own entry in root's
   ssh config, so git needs no extra settings:
   `git clone <ssh alias>:<owner>/<register repository>.git /opt/key-register`
   (or set `SOC_KEYS_SSH_KEY` to the key file for a run). Add that deploy key to the register
   itself, as a manual key like any other.
3. The signer's public key is in root's gpg keyring and marked trusted (see the rules deploy
   runbook); without it git reports `U` and the script refuses.
4. **Seed the dates.** With an empty state every key shows "no record", the plan exits `4`,
   and the daily unit shows as failed. For each tracked key, take its last rotation date from
   the rotation register (kept outside this repository) and run
   `deploy/rotate.sh --record <id> --date <last rotated> [--due <date>]`. Then
   `deploy/rotate.sh --plan` should say the counts you expect.
5. Install the daily plan (as for the backup timers, see `database.md`):
   `cp deploy/systemd/soc-rotate-plan.* /etc/systemd/system/ && systemctl daemon-reload &&
   systemctl enable --now soc-rotate-plan.timer`

## The files

All in `$SOC_STATE_DIR/rotate/` (mode 700, owned by the container's user), written whole and
renamed into place, so a crash leaves the old file or the new one:

| File | What it holds |
|---|---|
| `state.json` | per key: last rotated, outcome, "old key still live", an optional hand-set due date; and the current approval. Never a value. A file that does not parse is refused, never overwritten. |
| `status.json` | counts only (overdue, no record, due soon, this session, ok, not ready, old key still live, automatic and manual keys in the plan) and the next session date. No key names. For the console and pager (a later step). |
| `record.txt` | the last record line; the script appends it to `$SOC_STATE_DIR/rotate.log`. |

## Refusals

| You see | Meaning |
|---|---|
| `... is not a git clone of the key register`, `cannot be fast-forwarded`, `uncommitted or untracked files`, `is not at origin/main` | the clone is not the register as published; fix the clone, never edit it in place |
| `the head commit's signature does not verify` | the head commit is unsigned or signed by a key the host does not trust |
| `<file>: ...` then `problem(s) in the key register` | a key file is wrong; the message names the file and the field, never a value |
| `refused: the state file cannot be read as JSON` (or similar) | `state.json` is damaged. Look at it, then move it aside; the next `--record` run rebuilds it |
| `refused: that id is not a tracked key` | the id is not in the register, or the key is replaced only on exposure |
| `refused: the date is in the future, or the due date is before it` | check the dates |

## Not built yet

- **Applying the plan:** creating the new key, storing it, updating the consumer, the health
  check and revoking the old key. A later build does this, attended, with the rights handed
  over on standard input for that one run and never kept on the host. It will refuse unless a
  saved approval covers exactly the plan it recomputes (same register commit, same keys, under
  30 minutes old); `soc_api.rotate.state.approval_problem` already answers that.
- **Paging:** the pager reading `status.json` for overdue keys, and an overdue-keys count on
  the Ops Overview. Until then the daily unit failing (`systemctl --failed`) and the monthly
  calendar hold are the reminders.

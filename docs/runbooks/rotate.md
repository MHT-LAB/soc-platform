# Key rotation: plan, approve, record, apply

`deploy/rotate.sh` works out which keys are due, shows the plan, records an approval for that
exact plan, writes down rotations a person did by hand, and, attended, rotates the automatic
keys of an approved plan.

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
- **Nothing reads, prints or stores a key value.** The state file holds ids, dates and
  outcomes. The rights an apply needs arrive on standard input for that one run, are held in
  memory in a wrapper that cannot be printed, and are never written anywhere.
- Rotation is attended. Nothing on the host can rotate a key by itself: the vendor key that
  can make keys and the login to the secrets manager are not stored here.

## What each mode does

| Command | Runs | What it does |
|---|---|---|
| `deploy/rotate.sh` | container, no network | the plan, then a typed `yes`. Approving writes the plan's short hash and the register commit to `state.json`, good for 30 minutes and for one apply. |
| `deploy/rotate.sh --plan [--quiet]` | container, no network | the plan only, asks nothing (the daily timer runs `--plan --quiet`) |
| `deploy/rotate.sh --record <id> [--date YYYY-MM-DD] [--due YYYY-MM-DD]` | container, no network | a person rotated this key by hand: write it down after a typed `yes`. The date defaults to today (New York time) and cannot be in the future. `--due` is for a key whose due date was set by hand. Makes no vendor call. |
| `deploy/rotate.sh --preflight` | **host**, rights on stdin | the read calls of an apply: log in to both services, list the vendor's keys, check each automatic key's live permissions and that its stored value can be read. **Changes nothing**, needs no approval. |
| `deploy/rotate.sh --apply <plan-hash>` | **host**, rights on stdin | rotate the automatic keys of the plan that was approved (below). |

Exit codes: `0` done or nothing due, `1` failed (see the record), `2` refused before changing
anything, `3` not confirmed, `4` something is overdue, has no record, has an old key still
live, or (apply) was skipped because this build cannot rotate it yet.

## Why the apply runs on the host

An apply must rewrite a consumer's env file, recreate that service and run its health check. A
hardened container cannot do that without the Docker socket, which is root-equivalent, so the
apply is standard-library Python started by `rotate.sh` as root. What keeps that safe:

- `rotate.sh` runs the same signed-clone gate as `rules-deploy.sh` on the key register, and
  for these two modes also refuses unless this checkout (`/opt/soc-platform`) is clean and its
  head commit's signature verifies, so the code that will hold the rights is the reviewed code.
- Its input is standard input. `rotate.sh` saves it on a spare descriptor and gives every
  command before the final run `/dev/null`, so nothing else (git, ssh, gpg) can read the
  rights. The Python gets an empty environment and no PYTHON variables.
- Child processes (the service recreate and the health check) get no standard input and a
  minimal environment, and their output is discarded.
- The vendor and secrets-manager clients accept https, named hosts only, no redirects, a size
  cap and a timeout, and report short codes, never a URL, header or body.

## The rights, on standard input

Five lines, `NAME=value`, then one blank line (a sixth, `SECRETS_ENVIRONMENT`, is optional and
defaults to `dev`):

```
LC_ROTATOR_KEY=<the vendor key that can create and delete keys>
SECRETS_CLIENT_ID=<the rotator's login to the secrets manager>
SECRETS_CLIENT_SECRET=<its secret>
SECRETS_URL=<https://host name of the secrets manager; no path, no port; not secret>
SECRETS_PROJECT_ID=<which project holds the values; not secret>

```

An input that is not exactly that is refused, and the error names the field, never what was
typed. A terminal is refused: rights are piped in, never typed. The address is the only host
the secrets-manager calls may reach, and it comes from the operator's side, not from this
repository.

From the operator's own machine, with the values held in the password manager, the shape is:

```
<password manager> run --env LC_ROTATOR_KEY=<ref> --env SECRETS_CLIENT_ID=<ref> \
  --env SECRETS_CLIENT_SECRET=<ref> -- sh -c \
  'printf "LC_ROTATOR_KEY=%s\nSECRETS_CLIENT_ID=%s\nSECRETS_CLIENT_SECRET=%s\nSECRETS_URL=<url>\nSECRETS_PROJECT_ID=<id>\n\n" \
   "$LC_ROTATOR_KEY" "$SECRETS_CLIENT_ID" "$SECRETS_CLIENT_SECRET" \
   | ssh <host> pct exec <container> -- /opt/soc-platform/deploy/rotate.sh --apply <plan-hash>'
```

`printf` is a shell built-in, so no value is ever in a process's argument list (check this on
your own machine once with a throwaway value).

## What an apply does, per key

Only the keys of the approved plan, one at a time, stopping at the first failure:

1. **Check the live old key.** It is found by the id recorded last time. With no id on record
   (the first rotation, or a state rebuilt with `--record`) it is found by name: exactly the
   console name, or the console name, a hyphen and an eight-digit date (the name a rotation
   gives the keys it makes). Exactly one must match; two (an unfinished rotation) is refused. Its permissions must equal the key file's list exactly; any
   difference refuses the key with nothing changed. The new key's name (the old name plus the
   date) must be free.
2. **Create the new key** with the same permissions.
3. **Store the new value** in the secrets manager (the old value is held in memory for rollback).
4. **Rewrite the consumer's env file** (written whole, same owner and mode, the old file kept as
   `<name>.prev`), read it back to be sure it holds the new value (otherwise the check would
   pass on the old key), and **recreate its service**.
5. **Run its named health check, wait the grace period, run it again.**
6. **Only now revoke the old key**, by the exact id found in step 1.

Before step 1 the approval is used up (it is good for one apply however it ends) and the host's
apply lock is taken, so two applies cannot overlap.

### When something goes wrong

Anything before step 6 is undone, newest first: the env file and service are put back and
checked, the old value is written back to the secrets manager, the new key is deleted. **The
old key is never revoked unless both checks passed.** Each undo step is tried even if an earlier
one fails.

| Record says | Meaning | What to do |
|---|---|---|
| `refused-perms_differ`, `refused-old_key_missing`, `refused-old_key_ambiguous`, `refused-new_name_taken`, `refused-recorded_key_missing` | the live vendor key is not what the key file says; nothing was changed | look at the vendor's key list; fix the key file (by pull request) or the key, never edit around it |
| `failed-<code>-rolled-back` | a step failed and everything was undone; the old key is still the one in use | read the code, fix the cause, plan and approve again |
| `failed-<code>-ROLLBACK-INCOMPLETE` plus "NEEDS A PERSON" | an undo step could not be done (the steps that could not are listed) | follow the listed steps by hand before anything else; the old key was not revoked |
| `rotated-REVOKE-PENDING` | the new key works and the old one could not be revoked | run an apply again after a new approval: it only finishes the revoke |
| `prev_exists` | a `.prev` copy of the env file is left over from a failed run | compare it with the file, then remove it |

A dropped connection or a terminate signal is treated like Ctrl-C: the work is undone and the
record is still written. `INTERRUPTED` is printed.

## First time

The vendor and secrets-manager request and reply shapes this code expects are **not confirmed
against a live call** (they are marked `[C]` in the source), and the code refuses anything
unexpected rather than guess. So:

1. **Remove the stale copy.** If a key's value is also kept somewhere the rotator does not
   write (an older project or folder in the secrets manager), delete that copy first, or point
   the restore steps at the rotator's project: after a rotation the old copy is a revoked key,
   and restoring a host from it would fail.
2. Run `--preflight`. It makes only the read calls, shows whether each automatic key is
   ready, and exercises both logins and the list and read reply shapes without changing
   anything. It does not exercise the writes (create, store, delete): the first apply does,
   and a write that fails is undone before the old key is touched.
3. If it reports `problem-bad_shape` (or similar), stop: the source needs a small fix before an
   apply, and nothing was touched.
4. Then a normal run: plan, approve, apply, attended, for one key.

## Files

All in `$SOC_STATE_DIR/rotate/` (mode 700, owned by the container's user; files the host writes
keep that owner), written whole and renamed into place:

| File | What it holds |
|---|---|
| `state.json` | per key: last rotated, outcome, the vendor's id of the key in use, an old key still to revoke, an optional hand-set due date; and the current approval. Ids only, never a value. A file that does not parse is refused, never overwritten. |
| `status.json` | counts only. No key names. For the console and pager (a later step). |
| `record.txt` | the last run's record lines (one per key for an apply); the script appends them to `$SOC_STATE_DIR/rotate.log`. Key ids appear as their last four characters. |
| `apply.lock` | held while an apply runs |

## Setting up a host (once)

1. The host has been deployed (`deploy.sh`), so `env/image.env` exists, and has `python3` (3.11
   or newer) for `--preflight` and `--apply`. The plan, record and approve modes need only the
   container.
2. Clone the key register with a **read-only deploy key** that has its own entry in root's ssh
   config, so git needs no extra settings:
   `git clone <ssh alias>:<owner>/<register repository>.git /opt/key-register`
   (or set `SOC_KEYS_SSH_KEY` to the key file for a run). Add that deploy key to the register
   itself, as a manual key like any other.
3. The signer's public key is in root's gpg keyring and marked trusted (see the rules deploy
   runbook); without it git reports `U` and the script refuses.
4. **Seed the dates.** With an empty state every key shows "no record", the plan exits `4`, and
   the daily unit shows as failed. For each tracked key, take its last rotation date from the
   rotation register (kept outside this repository) and run
   `deploy/rotate.sh --record <id> --date <last rotated> [--due <date>]`.
5. Install the daily plan (as for the backup timers, see `database.md`):
   `cp deploy/systemd/soc-rotate-plan.* /etc/systemd/system/ && systemctl daemon-reload &&
   systemctl enable --now soc-rotate-plan.timer`

## Refusals

| You see | Meaning |
|---|---|
| `... is not a git clone of the key register`, `cannot be fast-forwarded`, `uncommitted or untracked files`, `is not at origin/main` | the clone is not the register as published; fix the clone, never edit it in place |
| `the head commit's signature does not verify` | the head commit is unsigned or signed by a key the host does not trust |
| `<file>: ...` then `problem(s) in the key register` | a key file is wrong; the message names the file and the field, never a value. An automatic vendor key whose permissions break the rules (anything under `output.*` or `apikey.*`, or a list that does not refuse them) refuses the whole register. |
| `refused: ... there is no approval`, `... not the one that was approved`, `... older than 30 minutes`, `... register changed` | plan and approve again, then apply with the new hash |
| `refused: rights ...` | the standard input was not the four lines and a blank line; the approval is not used up |
| `refused: ... the apply lock` | another apply is running |
| `refused: the state file cannot be read as JSON` (or similar) | `state.json` is damaged. Look at it, then move it aside; the next `--record` run rebuilds it |
| `refused: that id is not a tracked key` | the id is not in the register, or the key is replaced only on exposure |

## What this build can rotate

Automatic keys from the detection vendor whose single stored value goes into one env file on
this host and whose health check is one this build knows (today: the posture collector's).
Any other automatic key is **named and skipped** by an apply (exit `4`), not guessed at. Later
builds add the rules deploy key and its follow-up step, the catch-up worker's key, the signing
key, and the CI keys.

## Not built yet

- **Paging:** the pager reading `status.json` for overdue keys, and an overdue-keys count on the
  Ops Overview. Until then the daily unit failing (`systemctl --failed`) and the monthly calendar
  hold are the reminders.

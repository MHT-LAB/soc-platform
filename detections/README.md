# detections

Detection rules as code: each rule is one JSON file with its own test events. CI checks every file
against the rule contract and replays its tests before anything can deploy. This folder holds the
**format, the tools and synthetic examples**; real rules for real organizations live in a private
repository and use the same tools.

```
python -m soc_api.rules check  detections [--base <git ref>]   # the contract
python -m soc_api.rules replay detections                      # every test event through the evaluator
```

Run from `api/` (`uv run python -m soc_api.rules ...`; use `../detections`). Exit code 0 = clean,
1 = problems (printed one per line, `file: what is wrong`), 2 = the directory is missing or holds
no rule files (an empty or mistyped directory never passes quietly).

## A rule file

```json
{
  "name": "EXAMPLE - LINUX - Crontab Replaced From A Pipe",
  "pack": "examples",
  "status": "ready",
  "platform": "linux",
  "description": "What the rule looks for and why it matters.",
  "notes": "Known noise and how to tune it.",
  "detect": {
    "event": "NEW_PROCESS",
    "op": "and",
    "rules": [
      {"op": "is platform", "name": "linux"},
      {"op": "matches", "path": "event/COMMAND_LINE", "re": "\\|\\s*crontab\\s+-(\\s|['\"]|$)"}
    ]
  },
  "respond": [{"action": "report", "name": "EXAMPLE_LINUX_Crontab_From_Pipe", "priority": 3}],
  "tests": {
    "positive": [{"routing": {"event_type": "NEW_PROCESS", "plat": 536870912},
                  "event": {"COMMAND_LINE": "sh -c 'echo job | crontab -'"}}],
    "negative": [{"routing": {"event_type": "NEW_PROCESS", "plat": 536870912},
                  "event": {"COMMAND_LINE": "crontab -l"}}]
  }
}
```

| Field | Meaning |
|---|---|
| `name` | Unique across the tree, at most 255 characters |
| `pack` / `org` | `pack` for shared rules; `org` (only under `orgs/<org>/`) for one organization's own |
| `status` | `ready` or `draft` |
| `platform` | Optional: `windows`, `linux`, `macos` or `any`. Defaults to the pack name when that is one of the three, else `any`. A rule for one system must contain the matching `is platform` check |
| `detect` | The detection: `event` (one event type) or `events` (a list), then a tree of `and`/`or` groups and operators |
| `respond` | Actions. A `report` needs a `name`, the category the pager's policy routes on |
| `gate` | Required when an overlay rule tags or isolates: the name of the response gate that decides when |
| `tests` | `positive` and `negative` lists of events (`routing` with `event_type` and `plat`, plus `event`) |

## The contract (`check`)

1. The file is valid JSON and a rule: `name`, `description`, `status`, `pack` or `org`, `detect`, `respond`, `tests`.
2. **Report only.** Outside `orgs/<org>/` the only action is `report`. An org overlay may also `add tag`, `remove tag` and `isolate network`, and then must name its `gate`.
3. **Platform check.** A rule for one operating system contains an `is platform` check for it.
4. **A pair of tests.** At least one positive and one negative event, each well formed.
5. **Windows command lines are quoted.** A rule that can fire on Windows (declared `windows`, or `any` platform with no `is platform` check or one that names windows) and matches on `event/COMMAND_LINE` has at least one positive whose command line starts with a quoted full program path, like `"C:\Windows\System32\x.exe" args`. Real process creation events look like that; a rule tested only with bare names can pass every test and miss real commands.
6. **RE2 only.** Every regex compiles in Google RE2, the engine the platform uses: no lookahead, lookbehind or backreferences.
7. **Known operators only**, so replay never skips something it does not understand.
8. **Nothing that identifies a real org outside an overlay:** no non-documentation IP address, org or sensor id, or non-example email address.
9. **Unique names.**
10. **Positives are append-only** (`--base <ref>`): every positive an existing rule had at the base commit is still there, unchanged. A rule file that is new at that commit is free. In CI the base is the pull request's base commit. One edit is allowed: taking a real-looking IP address out of a positive (the same event, only its addresses changed, the old one had a non-documentation address and the new one has none). Anything else, including swapping one documentation address for another, counts as removing the positive.

`replay` then runs every positive of a detection rule (must fire) and every negative (must not) through the evaluator.

## Other kinds of file

A file says what it is with `"kind"`: `rule` (the default, everything above), `fp` or `fim`. Any other kind is refused, so nothing slips past the checks by naming itself something else. All kinds share the basics: `name`, `description`, `status`, `pack` or `org`, and the same place rules (below). Neither kind is replayed: the platform cannot dry-run them either, so the test lines are the record.

- **`fp`**: a false-positive rule. An `fp` tree (the same `and`/`or`/`is`/`matches` operators; regexes must be RE2) and `tests` with non-empty lists `match_command_lines` and `no_match_command_lines`. The match lines are append-only against `--base`, like positives.
- **`fim`**: a file-integrity watch list. `fim_rules` (the default tier, required) and optionally `fim_rules_optional`, each an object of groups with `filters.platforms` exactly `["linux"]` and a non-empty list of absolute `patterns`. A pattern may not name a user: `/home/*/.ssh/*` is fine, a pattern with a real user name in that position is refused.

## Where a file sits

- A file under `orgs/<org>/` is an org overlay (its `org` must match the folder); a file directly under `orgs/` is refused. The tool recognizes this when you scan `detections`, `orgs`, or one org's folder. It looks only at the scanned folder and its parent, so scanning a folder deeper than `orgs/<org>/` is never treated as an overlay.
- A file under `baseline/` must have status `ready`; drafts belong under `draft/`.

## Operators

`and`, `or`, `matches`, `contains`, `starts with`, `ends with`, `is`, `exists`, `is platform`, `is tagged`, and `"not": true` on any node. Behaviour matches the platform's rule tester, checked 2026-11-16:

| | Default | Flag |
|---|---|---|
| `is`, `contains`, `starts with`, `ends with` | case-sensitive | `"case sensitive": false` ignores case |
| `matches` | **case-insensitive** | `"case sensitive": true` respects case |

A path that is missing makes a leaf false (so `not` makes it true). A list met before the end of a path is walked element by element, and a condition holds if it holds for any element (each condition is judged on its own, so an `and` can be met by different elements); a list at the very end of a path is just a value, and `exists` only asks that the key is there. `is tagged` reads `routing/tags`.
`is platform` compares `routing/plat` (windows `0x10000000`, linux `0x20000000`, macos `0x30000000`).

The local evaluator is a model, not the platform. It lets CI replay every rule with no key and no
network; the private pipeline also replays each changed rule through the platform's own tester, which
stays the authority. Adding an operator means adding it to `soc_api/rules/evaluate.py`, with tests
for it, and checking its behaviour on the platform first.

## Examples

`examples/` holds three synthetic rules: a Windows command-line rule (with the quoted-path positive),
a Linux rule, and a platform-independent DNS rule that shows the case-insensitive `matches` default.
They use reserved example domains and documentation addresses only.

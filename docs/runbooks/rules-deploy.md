# Rules deploy: detection rules from git to the detection source

`deploy/rules-deploy.sh` puts the rules in the private rules repository onto the detection
source's general namespace. It is a separate step from `deploy.sh` on purpose: the stack never
holds a key that can change rules, and the only thing that does is a container that exists for
the length of one run, after a person has read the difference and typed `yes`.

## What a run does

1. **The rules clone** (default `/opt/detection-packs`) is fetched and fast-forwarded to
   `origin/main`. It is refused if the tree is not clean, if the head commit is not exactly
   `origin/main`, or if the head commit's signature does not verify (git status `G`). The host
   needs the signer's public key in its keyring. A squash merge on GitHub is signed with
   GitHub's key, so that key goes in the root user's keyring on the host.
2. **The one-shot `rules` service** (compose profile `rules`; `deploy.sh` never turns it on)
   runs the contract and replay over the whole tree, as CI does, then reads the live rules.
3. It works out the difference for the **managed set only**: rules named in git, rules whose
   name starts with a managed prefix, and rules that carry a stamp. Everything else is listed
   and left alone.
4. It prints the names, then the body difference, and asks for a typed `yes` on the terminal.
   With nothing to change it says so and asks nothing. No terminal, or anything but `yes`,
   changes nothing.
5. It writes adds and changes first, then removals, then the manifest rule. Every rule it
   writes gets a stamp tag (`git:<12 hex>`, an HMAC of its `detect`, `respond` and `enabled`)
   and `git <commit>` as its comment. The vendor's API replaces a rule's metadata as a whole,
   so the rule's other tags and fields are sent back as they were, with its etag: a rule
   changed in the web app between the read and the write is refused, not overwritten.
6. A one-line record goes to `rules-deploy.log` and the screen, for the vault Build Log.

Exit codes: 0 done or nothing to do, 1 failed part-way (run it again: it works out what is
left), 2 refused before changing anything, 3 not confirmed.

## What the host needs (once)

| What | How | Where |
|---|---|---|
| Rules clone with a read-only deploy key | `git clone` the private repository over SSH with a deploy key; set `SOC_RULES_SSH_KEY` if git does not already know the key | host, as root |
| Signer's public key | import GitHub's commit-signing key into root's gpg keyring, then mark it trusted (`gpg --import-ownertrust` with `<fingerprint>:6:`); without the trust line git reports `U` (good signature, unknown key), not `G`, and the deploy refuses | host, as root |
| Vendor key `soc-rules-deploy` | in the vendor's console: `dr.list`, `dr.set`, `dr.del` only (never `output.*`, sensor writes, `org.*`, billing); rotate every 90 days | vendor console |
| Settings file | `deploy/init-rules-lc.sh` asks for the vendor key (hidden), the organization id, the stamp key (hidden), the organization's folder name under `detections/orgs/`, and the managed name prefixes; writes `env/rules-lc.env` mode 600 and never overwrites | host, as root |

`init-rules-lc.sh --restore` rebuilds the file from `SOC_LC_RULES_DEPLOY_KEY`, `SOC_LC_OID`,
`SOC_RULES_STAMP_KEY`, `SOC_RULES_ORG` and `SOC_RULES_PREFIXES` after a lost host. Only the
`rules` service is given this file.

## The stamp, and why it is an HMAC

Someone who can only change rules in the vendor's web app, or who holds a leaked deploy key
but not the stamp key, can change a rule but cannot make a matching stamp, so the change shows
as drift (checked by the posture collector, Sprint 4 E4). The vendor never sees the stamp key.
`soc_api.rules.stamp` is the one place the stamp is computed.

### Drift checking on the host (E4)

The posture collector checks stamps when `env/posture-rules.env` (mode 600, read by the
`posture` service only) holds two lines:

    SOC_POSTURE_STAMP_KEY=<the same value as SOC_RULES_STAMP_KEY in rules-lc.env>
    SOC_POSTURE_RULES_PREFIXES=<the managed name prefixes, separated by |>

Without the file the collector runs as before and the Rules tab says "Not checked". Never
print the file. Per general rule the collector stores one word: `ok`; `changed` (the body or
flag no longer matches the stamp, the stamp is missing or doubled, or the rule is listed in a
valid manifest but its stamp was removed); or `unmanaged` (a managed prefix, no stamp). It also
stores the manifest state (`ok`; `bad`: the comment is not one this key made, or the manifest
itself was edited; `absent`: stamped rules exist but no manifest, or a manifest was seen before
and is gone; `stale`: a good manifest older than one already seen; `none`: nothing deployed
yet) and the names of listed rules that are no longer live. A stamped rule whose stamp is not
the one the manifest lists for its name is `changed` (an older version put back). Rule bodies are compared and dropped.

Any change, unmanaged or missing rule, or a bad or absent manifest makes the pager push
"SOC STALE: N detection rule changes outside git" (a count, never a name; repeats every 6 hours
while it holds). The Rules tab and the System page's posture row name them. The first run after
a deploy that adopts old rules shows them as `changed` until the deploy has stamped them.

## The manifest rule

A disabled rule named `soc-manifest` that can never fire. Its comment (format version 2) holds
each managed rule name with the stamp it was deployed with, and the deploy time, all under one
keyed check. So:

- a managed rule deleted in the web app is found missing;
- a rule put back to an older deployed version (its old stamp is valid for that old body) does
  not match the stamp the manifest lists for it, and shows as `changed`;
- a whole older deploy put back by hand, with that deploy's own manifest, carries an older
  deploy time than one already seen, and the manifest shows as `stale` until a newer deploy.

A run with nothing to change keeps the existing manifest and its time; the manifest is
rewritten, with a new time, only when the set of managed rules or their stamps changes. A
manifest in the old format is replaced on the next run.

## Not done by this tool

Only rules of kind `rule` in the organization's own folder are deployed. False-positive rules
and file-integrity lists are other hives; they are checked in CI but not deployed here yet.
Rules in the baseline and draft folders are not deployed: a rule reaches the platform by being
in the organization's folder, with an explicit `enabled`.

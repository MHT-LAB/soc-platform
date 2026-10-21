# Release runbook

`deploy.sh` trusts any image signed by `release.yml` on `main` or on a `v*.*.*`
tag. These controls keep a tag from being a back door:

| Control | Where | What it stops |
|---|---|---|
| Tag guard | `scripts/check-tag-on-main.sh`, first step of `release.yml` on tag pushes | **Mistakes only:** tagging a commit that is not on `main`. It cannot stop a deliberate bypass, because GitHub runs the `release.yml` stored in the tagged commit, and that copy can leave the guard out. |
| Image scan | `release.yml`, between push and sign | A pushed image with a fixable CRITICAL or HIGH vulnerability getting a signature. No signature means `deploy.sh` refuses it |
| Tag rulesets | `.github/rulesets/*.json` | Moving or deleting a published version tag; creating one without repo-admin rights. **This is the boundary today.** |
| Deploy-side source check | `deploy.sh`, step 2b | An image built from a commit that is not on `main`. Reads the image's commit label, requires it on `origin/main` in the host's clone, then has cosign prove the signature names that exact commit. Runs on the host, where a branch cannot change it, and before anything on the host changes. |

## Apply the tag rulesets (repo admin, once)

Run from any machine with `gh` logged in as the repo owner, in a clone of this repo.
Both files are the full definition; review them first.

```bash
gh api repos/MHT-LAB/soc-platform/rulesets --method POST --input .github/rulesets/release-tags-immutable.json
gh api repos/MHT-LAB/soc-platform/rulesets --method POST --input .github/rulesets/release-tags-create.json
gh api repos/MHT-LAB/soc-platform/rulesets --jq '.[] | "\(.name) \(.target) \(.enforcement)"'
```

`release-tags-immutable` has no bypass: nobody can move or delete a `v*.*.*` tag
or push an unsigned one. `release-tags-create` lets only repository admins create
one. A mistaken tag is fixed by publishing the next version, not by editing it.

## Cut a release

1. Merge to `main`; wait for CI and the `release` run on `main` to go green.
2. Tag that commit with a signed tag: `git tag -s v0.1.0 <sha> -m "v0.1.0"` then `git push origin v0.1.0`.
3. The `release` run on the tag checks the commit is on `main`, builds, scans, signs and attests.
4. Deploy with `deploy/deploy.sh v0.1.0` on the host (see `deploy.md`).

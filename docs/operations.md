# Operations

## Secrets and variables

| Name | Kind | Used by | Content |
|---|---|---|---|
| `ALT_DENYLIST` | repository secret | every step that scans: `stage.yml`, the gate job of `build.yml`, `ingest.yml`, `catalog.yml`, and `poll.yml` for the run titles it would create (never the macOS build job) | denylist terms, one per line |
| `ALT_PAYLOAD_IDENTITY` | repository secret | the gate job of `build.yml` | `age` identity that decrypts the payload artifact |
| `ALT_PAYLOAD_RECIPIENT` | variable | the build job of `build.yml` | its `age` recipient; the built IPA is encrypted to it before it is uploaded |
| `ALT_LOG_RECIPIENT` | variable | `build.yml` | `age` recipient that build logs are encrypted to |
| `ALT_KEY` | secret of the environment `alt-<ALIAS>`, one per app | `build.yml`, `poll.yml` | private half of the read-only deploy key on the app's private repository |
| `ALT_APP` | secret of the environment `alt-<ALIAS>`, one per app | `build.yml`, `poll.yml` | JSON `{"repo": "owner/name", "build": {...}}`; `build` is optional and takes the `.alt.json` keys |

`<ALIAS>` is the bundle id in upper case with every character other than a letter or digit replaced by
`_`. Get it with `PYTHONPATH=tools python3 -m altsource alias BID`. `bin/alt register` and
`bin/alt unregister` manage the app environments, `bin/alt payload-key` the payload key pair; see
[onboarding.md](onboarding.md).

Every secret is referenced by a fixed name, so a job receives only the secrets it names. The per-app
secrets sit in one environment per app (with exactly one deployment branch policy, `main`, and used
with `deployment: false`), so the macOS runner that runs a private build gets only that app's
`ALT_KEY` and `ALT_APP`: no denylist, no payload identity and nothing of other apps. Repository
secrets named `ALT_KEY_<ALIAS>` or `ALT_APP_<ALIAS>` come from an earlier version and are not read any
more; `bin/alt register --rotate` removes them.

The workflows need no personal token: they use the job's `GITHUB_TOKEN`, and each job is granted only
the permissions it needs. Releases created with `GITHUB_TOKEN` trigger no `release` events, so
`stage.yml`, `build.yml` and `ingest.yml` call `catalog.yml` directly, passing it only the
`ALT_DENYLIST` secret. Release events from elsewhere (a release published or edited by hand, a
takedown run locally) start `catalog.yml` on the tag; that run only sends a `repository_dispatch`
event of type `catalog`, which runs the sync and the Pages deployment on `main`.

Environment variables read by the tools:

| Variable | Used by | Meaning |
|---|---|---|
| `GH_TOKEN` | `altsource` in workflows | token for the `gh` client |
| `ALT_REPO` | `altsource`, `bin/alt` | target repository, default `xuniv/alt` |
| `ALT_OWNER` | `bin/alt` | expected `gh` login, default `xuniv` |
| `ALT_DENYLIST` | `altsource` | denylist, unless `--denylist-file` is given; `bin/alt` ignores it and always passes its local file |
| `ALT_APP_CONFIG` | `altsource resolve-build` | the `ALT_APP` JSON of the app's environment |
| `ALT_CONFIG_DIR` | `bin/alt` | directory of the local files below, default `~/.config/xuniv-alt` |
| `ALT_DENYLIST_FILE` | `bin/alt` | local denylist, default `<ALT_CONFIG_DIR>/ipa-denylist` |
| `ALT_CACHE_DIR` | `bin/alt`, the pre-push hook | directory of `hook.log`, default `~/.cache/xuniv-alt` |
| `ALT_HOOK_TIMEOUT`, `ALT_HOOK_INTERVAL` | the pre-push hook | how long (default 600 s) and how often (default 10 s) it checks that the remote tag points at the pushed object |
| `GITHUB_OUTPUT` | `altsource` | file that receives the outputs listed below; nothing is written when it is unset |
| `GITHUB_ACTIONS` | `altsource` | `true` in workflows: error messages leave out argument values, private key names and foreign exception text, private build values are masked, and `sync` may refresh its checkout when `main` moved |

Local files used only by `bin/alt` (never by CI):

| Path | Content |
|---|---|
| `~/.config/xuniv-alt/ipa-denylist` | local denylist, the same terms as the `ALT_DENYLIST` secret; `bin/alt` refuses to run without it |
| `~/.config/xuniv-alt/log-identity.txt` | `age` identity for `bin/alt diag` |
| `~/.cache/xuniv-alt/hook.log` | pre-push hook log |

## Workflows

| Workflow | Triggers | Job summary |
|---|---|---|
| `catalog.yml` | release published, edited, unpublished, deleted, released, prereleased (relayed to `main` as `repository_dispatch` type `catalog`); push to `main` touching `apps/**/app.json`, `apps/**/icon.png`, `source.base.json` or `site/**`; daily at 04:43 UTC; manual (optional `rescan`); called by the other workflows | `sync --exit-zero`; deploy Pages when sync committed a change, and on every push or manual run; then a `report` job fails the run when sync blocked releases or hit errors |
| `stage.yml` | manual (optional `tag`); scheduled windows | gate and publish pending drafts; `catalog.yml` when something was published; then a `report` job fails the run when a draft was rejected or failed |
| `build.yml` | manual (`app`, `ref`, `publish`, `notes`); started by `bin/alt build`, the pre-push hook and `poll.yml` | route 2 build, gate, publish, then `catalog.yml` |
| `ingest.yml` | `repository_dispatch` type `ingest`; manual (`url`, `sha256`, `semver`, `notes`, `bundle_id`, `allow_home_paths`) | route 3 fetch, gate, publish, then `catalog.yml` |
| `poll.yml` | manual only (optional `app`, `dry_run`); no schedule | start `build.yml` for new private tags |
| `ci.yml` | push, pull request | unit tests and `validate`; `generate --check` on pull requests only; both catalog checks are skipped until `source.json` exists; no secrets |

The scheduled windows of `stage.yml` are `17 1,7,13,19 * * *`: 01:17, 07:17, 13:17 and 19:17 UTC. They
only finalize pending drafts. GitHub may start scheduled runs late. `poll.yml` has no schedule: new
private tags are built through the pre-push hook. Only the `sync` job of `catalog.yml` uses the
concurrency group `alt-catalog`; the jobs that create releases in `stage.yml`, `build.yml` and
`ingest.yml` share the group `alt-release`, and the Pages deploys share `alt-pages`. Queued runs are
never cancelled. Each `sync` rebuilds everything from the full release list and each deploy publishes
the current `main`, so any queued run catches up with all earlier changes.

## `bin/alt`

| Command | Purpose |
|---|---|
| `publish IPA [--semver V] [--notes-file F] [--defer]` | route 1: local gate, draft, then `stage.yml` |
| `mirror OWNER/REPO TAG [--semver V] [--notes-file F] [--defer]` | route 1 from the single `*.ipa` of another repository's release |
| `build BID REF [--no-publish]` | route 2: start `build.yml` |
| `ingest URL [--sha256 H] [--semver V] [--notes-file F] [--app-json F]` | route 3: send the `ingest` dispatch |
| `register OWNER/REPO --bid BID [--tag-pattern RE] [--build-json F] [--rotate]` | create the deploy key and the app's environment `alt-<ALIAS>` with its secrets |
| `unregister BID OWNER/REPO` | delete the deploy key and the app's environment |
| `payload-key [--rotate]` | create the `age` key pair that encrypts `build.yml`'s payload artifact |
| `hook install PATH --bid BID [--tag-glob G]` / `hook uninstall PATH` | pre-push hook in a local clone of a private repository |
| `status [--limit N]` | recent build, ingest, stage and catalog runs |
| `diag RUN_ID` | download and decrypt a build's log |
| `doctor` | check the login, the local denylist, workflows, secrets, variables, app environments and Pages |

Every command except `hook uninstall` first checks that the local denylist exists, that `gh` is logged
in as `ALT_OWNER` and that `ALT_REPO` is reachable; commands that write also need push access.
`--dry-run`, before or after the command name, still runs the read-only queries but prints each
mutating `gh` call and local file write as a `+ ...` line instead of running it. Exit codes are those
of `python3 -m altsource` below.

## `python3 -m altsource`

Run with `PYTHONPATH=tools` from the repository root.

| Command | Purpose |
|---|---|
| `inspect IPA [--json]` | print IPA facts |
| `normalize IN OUT` | re-pack an IPA deterministically |
| `scan IPA [--allow-home-paths]` | run the leak scan only |
| `stage IPA [--bid B] [--semver V] [--notes-file F] [--app-json F] [--no-publish] [--dry-run] [--allow-home-paths]` | gate, draft and publish |
| `stage-draft TAG` or `stage-draft --all`, with `[--notes-file F] [--no-publish] [--dry-run] [--allow-home-paths] [--exit-zero]` | gate and publish existing drafts |
| `sync [--no-commit] [--dry-run] [--rescan] [--exit-zero]` | regenerate and commit the catalog |
| `generate [--check]` | write `source.json`, or check that it is up to date |
| `validate` | validate `source.json` and every `app.json` |
| `fetch URL OUT [--sha256 H]` | guarded https download |
| `parse-tag TAG` | split a tag into bundle id and semver |
| `alias BID` | print the alias that names the app's environment |
| `resolve-build --bid B --ref R --checkout DIR [--json-out F]` | validate route 2 build settings |

- Commands that scan take `--denylist-file F` (default: `ALT_DENYLIST`).
- `sync`, `generate`, `validate` and `resolve-build` take `--root DIR`.
- Exit codes: `0` success, `2` gate rejected or release blocked, `3` conflict, `1` anything else.
- With `--exit-zero`, `sync` and `stage-draft` exit `0` and report the counts only as outputs.

Outputs, written to `$GITHUB_OUTPUT` when it is set:

| Command | Outputs |
|---|---|
| `stage`, `stage-draft TAG` | `tag`, `release_id`, `asset`, `sha256`, `size`, `published`, `noop` |
| `stage-draft` | `staged` (with `--all`), `rejected`, `failed` |
| `sync` | `changed`, `commit`, `blocked`, `errors` |
| `fetch` | `sha256`, `size` |
| `parse-tag` | `bid`, `semver`, `prerelease`, `alias` |
| `resolve-build` | `runner`, `xcode`, `setup`, `version`, `tag`; `command`, `env` and `ipa_glob` go only to `--json-out` |

## What is public

Releases, release notes, assets, commits and the Pages site are public. Any signed-in user can also
read this repository's workflow runs: run titles (`build <bundleId> <ref>`), job and step names,
timing, logs and artifacts. That is why `build.yml` uploads the built IPA only encrypted (to
`ALT_PAYLOAD_RECIPIENT`) and deletes it after the gate job, and its logs only encrypted (to
`ALT_LOG_RECIPIENT`). The workflows mask private values such as the private repository name, the
build command and dispatch URLs. Masking does not cover run titles, step names or anything you type
into notes, commit messages or other inputs, so keep private data out of them. A build's run title
(`build <bundleId> <ref>`) is public as soon as the build is dispatched; `bin/alt build`, the pre-push
hook and `poll.yml` refuse a ref that `build.yml` would reject or a title with a denylist term or a
home path (see [routes.md](routes.md#what-the-public-can-see)).

Only the routes that stage a draft protect an IPA before it is public. A release published directly on
GitHub is public at once; `sync` checks it afterwards and takes it down or normalizes it, which cannot
undo the time it was public (see [routes.md](routes.md#publishing-a-release-directly)).

Do not use the GitHub web editor for commits: it records the browser's time zone in the author date.
Use `git` or the tools.

## Never enable Actions debug logging

Do not set `ACTIONS_STEP_DEBUG` or `ACTIONS_RUNNER_DEBUG`, as a secret or as a variable. Do not tick
"Enable debug logging" when re-running a job. Debug logs print evaluated expressions, inputs and
environment values into logs that any signed-in user can read. That includes dispatch URLs and private
build settings.

## Recovery

All steps are safe to repeat. `sync` regenerates the catalog from the releases every time, and
`stage` does nothing for a tag that is already published with the same IPA.

### Re-run the catalog

```sh
gh workflow run catalog.yml -R xuniv/alt
bin/alt status
```

Use this when `source.json` or Pages looks stale, after a failed catalog run, or after changing
repository settings. A manual run always deploys Pages, even when the catalog did not change. If `main`
moves during a run, `sync` refreshes and retries up to five times on its own.

To preview locally what a sync would change, without writing anything to GitHub:

```sh
PYTHONPATH=tools python3 -m altsource sync --dry-run --denylist-file ~/.config/xuniv-alt/ipa-denylist
```

### Re-run stage

```sh
gh workflow run stage.yml -R xuniv/alt -f tag=io.example.demo-v1.4.0   # one draft
gh workflow run stage.yml -R xuniv/alt                                 # every pending draft
```

Without a tag, drafts titled `[blocked] <tag>` are skipped. A draft staged by tag is retried even when
it is marked; once it passes, it is retitled and published.

### A release was blocked

The catalog run fails, and its log lists `<tag>: blocked (<rules>)` with the action taken.

- **Unpublished:** the release is now a draft titled `[blocked] <tag>`. To see why, download its IPA
  and scan it locally:

  ```sh
  gh release download io.example.demo-v1.4.0 -R xuniv/alt --pattern '*.ipa' -D blocked
  PYTHONPATH=tools python3 -m altsource scan blocked/*.ipa --denylist-file ~/.config/xuniv-alt/ipa-denylist
  ```

  If a denylist term was a false positive, fix the denylist (both copies) and stage the draft by tag.
  Otherwise fix the build, publish a new version and delete the blocked draft.
- **Deleted (immutable release):** the tag cannot be used again. Publish a new version.
- **Left in place (immutable, `home-path` or `ci-workspace-path` only):** set
  `"allowHomePaths": true` in the app's `app.json` to accept it, or delete the release. This
  repository keeps immutable releases off, so this and the deletion above only happen if that
  setting is changed.
- **Release notes or title:** leaky notes have already been cleared and a leaky title reset to
  `<bundleId> <semver>`. Edit them on GitHub if needed; the next sync checks them again.
- **`<tag>: asset name blocked (<rules>)`:** the IPA's file name contains a denylist term or a home
  path, so the release was unpublished. Staging the draft by tag renames the IPA to
  `<Name>-<semver>.ipa` and publishes it again once the IPA itself passes.
- **`release <id>: tag blocked (<rules>)`:** the tag itself contains a denylist term or a home path.
  The release was unpublished as `[blocked] release <id>`, so neither the title nor the log repeats
  the tag. A tag cannot be renamed: delete the release and the tag, then publish under a clean tag.
- **`<tag>: asset label blocked (<rules>); cleared`:** GitHub shows an asset label in place of the
  file name, so the leaky label was removed and the release stays public. If clearing failed, the
  release was unpublished instead.
- **`<tag>: catalog record blocked (<rules>)`:** a string of the release's record under
  `apps/<bundleId>/versions/` failed the check (also a record kept from an earlier run), and the
  release was unpublished.
- **`generated source.json failed the leak check; nothing changed`:** a string of the generated
  catalog, usually from a curated `apps/<bundleId>/app.json`, failed the check. The log names the app
  by position and, when it is clean, the key. Fix the file; nothing was committed.

### A normalization did not finish

`sync` replaces a directly published IPA that is not in normalized form (see
[routes.md](routes.md#publishing-a-release-directly)). When a step fails, the log says what happened.
Every case below except the last is an error, so the catalog run fails.

- **`not normalized: ... published again unchanged`** or **`not normalized: unpublishing failed`:**
  the release is public with its original IPA, and the catalog lists that IPA. Fix the cause and try
  again with `gh workflow run catalog.yml -R xuniv/alt -f rescan=true`.
- **`publishing again failed; left as a draft for stage-draft`**, **`restoring failed; left as a
  draft`**, **`the old IPA is gone and the upload could not be verified; left as a draft`** or
  **`the release's assets could not be listed; left as a draft`:** the release is a draft and drops
  out of the catalog. If it carries exactly one `.ipa`, the next scheduled `stage.yml` run publishes
  it; to do it now, stage it by tag (`gh workflow run stage.yml -R xuniv/alt -f tag=<tag>`). Stage
  gates and normalizes that IPA again.
- **A draft with two IPAs** (for example `Demo.ipa` and `Demo-1.4.0.normalized-<id>.ipa` after a
  cancelled run or a listing that failed): `stage-draft` refuses it. Delete the temporary one, then
  stage the draft by tag; stage normalizes the remaining IPA again.

  ```sh
  gh release delete-asset io.example.demo-v1.4.0 Demo-1.4.0.normalized-123.ipa -R xuniv/alt -y
  gh workflow run stage.yml -R xuniv/alt -f tag=io.example.demo-v1.4.0
  ```

- **`the normalized IPA keeps its upload name`:** the rename failed. The release is published with
  the normalized IPA under its temporary name, and the catalog links to that name. No action is needed.

### Conflict (exit code 3)

The tag is already published with a different IPA. `stage` never replaces a published IPA, so publish
the build as a new version. Because normalization is deterministic, staging the same input again is not
a conflict; it does nothing.

### Denylist changed

Cached records are not scanned again, so check every published IPA against the new list once:

```sh
gh secret set ALT_DENYLIST -R xuniv/alt < ~/.config/xuniv-alt/ipa-denylist
gh workflow run catalog.yml -R xuniv/alt -f rescan=true
```

The run downloads and scans every published IPA, takes failing releases down and commits the
catalog. To see what it would do first, run a local dry run in a throwaway clone:

```sh
git clone https://github.com/xuniv/alt.git alt-rescan && cd alt-rescan
PYTHONPATH=tools python3 -m altsource sync --rescan --dry-run --denylist-file ~/.config/xuniv-alt/ipa-denylist
cd .. && rm -rf alt-rescan
```

### A private build failed

```sh
bin/alt status
bin/alt diag RUN_ID
```

`diag` downloads the run's encrypted `diag` artifact, decrypts it with
`~/.config/xuniv-alt/log-identity.txt` and prints each log it holds (git, tool setup, build and
normalize output), without writing them to disk. The build job uploads it on every run, so it is also
there when the gate job rejected the IPA; it is kept for 3 days. The gate's findings are in the public
log of the gate job, as rule ids, counts and paths inside the IPA. After fixing the cause, run
`bin/alt build BID REF` again, or tag a new version. `poll.yml` does not retry a tag that had a build
run in the last 30 days.

The build command runs under `env -i` (see [routes.md](routes.md#the-build-environment)). A script that
reads runner variables (`RUNNER_TEMP`, `GITHUB_WORKSPACE`, `JAVA_HOME` and the like) finds them unset:
use `ALT_OUT` or `TMPDIR` for scratch files and pass anything else through the `env` build setting.

If the gate job says `the payload could not be decrypted`, `ALT_PAYLOAD_RECIPIENT` does not belong to
`ALT_PAYLOAD_IDENTITY` (for example after an interrupted rotation): run `bin/alt payload-key --rotate`
and build again.

### Pages deployment refused

Every deployment runs on `main`: a `catalog.yml` run started by a release event runs on the tag and
only relays the event to `main`. If the deployment still fails with "not allowed to deploy to
github-pages due to environment protection rules", check under Settings, Environments, github-pages
that `main` may deploy, then re-run the catalog with `gh workflow run catalog.yml -R xuniv/alt`.

### Scheduled runs stopped

GitHub disables scheduled workflows in public repositories after 60 days without activity. A disabled
workflow cannot be started by hand either. `bin/alt doctor` reports this. Re-enable them:

```sh
gh workflow enable stage.yml -R xuniv/alt
gh workflow enable catalog.yml -R xuniv/alt
```

### Generated `source.json` failed validation

`sync` stops and commits nothing. The log lists the errors, which usually come from a hand-edited file.
Reproduce them locally:

```sh
PYTHONPATH=tools python3 -m altsource generate
PYTHONPATH=tools python3 -m altsource validate
```

Fix the hand-edited file and push it; the catalog workflow regenerates `source.json`.

### GitHub's SSH host keys changed

Route 2 clones fail host key verification when GitHub rotates its SSH host keys. Compare the new keys
with GitHub's published fingerprints, then refresh the pinned file and commit it:

```sh
gh api meta --jq '.ssh_keys[] | "github.com " + .' > .github/known_hosts
```

### Rotate a deploy key

```sh
bin/alt register owner/private-repo --bid io.example.demo --rotate
```

This deletes the old `alt-build` deploy key, then creates and stores a new one. Both secrets of the
app's environment are written again, so pass the same `--build-json` option as at registration;
without it the stored build settings are dropped. `--tag-pattern` lives in `app.json` and is kept when
omitted. Registering again also moves an app from the per-app repository secrets of an earlier
version to its environment.

### Rotate the payload key

```sh
bin/alt payload-key --rotate
```

Run it while no build is running: a build that encrypted its IPA to the old recipient cannot be
decrypted by the new identity.

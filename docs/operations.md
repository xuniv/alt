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
| `~/.cache/xuniv-alt/retract.log` | one line per `bin/alt retract`: time, tag, what changed and the `--reason` text |

## Workflows

| Workflow | Triggers | Job summary |
|---|---|---|
| `catalog.yml` | release published, edited, unpublished, deleted, released, prereleased (relayed to `main` as `repository_dispatch` type `catalog`); push to `main` touching `apps/**/app.json`, `apps/**/icon.png`, `source.base.json` or `site/**`; daily at 04:43 UTC; manual (optional `rescan`); called by the other workflows | `sync --exit-zero`; deploy Pages when sync committed a change, and on every push or manual run; then a `report` job fails the run when sync blocked releases or hit errors |
| `stage.yml` | manual (optional `tag`); scheduled windows | gate and publish pending drafts (without `tag`: not those of a [withdrawn version](#withdraw-a-version)); `catalog.yml` when something was published; then a `report` job fails the run when a draft was rejected or failed |
| `build.yml` | manual (`app`, `ref`, `publish`, `notes`, `force`); started by `bin/alt build`, the pre-push hook and `poll.yml` | route 2 build, gate, publish, then `catalog.yml`; refuses a [withdrawn version](#withdraw-a-version) in its first job unless `force` is true |
| `ingest.yml` | `repository_dispatch` type `ingest`; manual (`url`, `sha256`, `semver`, `notes`, `bundle_id`, `allow_home_paths`) | route 3 fetch, gate, publish, then `catalog.yml` |
| `poll.yml` | manual (optional `app`, `dry_run`, `loop`); with `loop`, each run starts the next one after the wait timer of the environment `alt-poll-timer` (15 minutes) | start `build.yml` for private tags from `privateBuild.minVersion` on that have no release yet; withdrawn versions are skipped |
| `poll-watch.yml` | hourly at minute 41; manual | start the poll loop when no loop run is active |
| `ci.yml` | push, pull request | unit tests and `validate`; `generate --check` on pull requests only; both catalog checks are skipped until `source.json` exists; no secrets |

The scheduled windows of `stage.yml` are `17 1,7,13,19 * * *`: 01:17, 07:17, 13:17 and 19:17 UTC. They
only finalize pending drafts. GitHub starts the scheduled runs of this repository late, so far by two
to five hours. `poll.yml` therefore has no schedule: it runs as a loop (see [The poll loop](#the-poll-loop)),
which builds the tags that no pre-push hook announced, such as tags pushed from another machine or
created on GitHub, within about 15 minutes of the push; the hook starts a build at once. Only the `sync` job of `catalog.yml` uses the
concurrency group `alt-catalog`; the jobs that create releases in `stage.yml`, `build.yml` and
`ingest.yml` share the group `alt-release`, and the Pages deploys share `alt-pages`. Queued runs are
never cancelled. Each `sync` rebuilds everything from the full release list and each deploy publishes
the current `main`, so any queued run catches up with all earlier changes.

## `bin/alt`

| Command | Purpose |
|---|---|
| `publish IPA [--semver V] [--notes-file F] [--defer]` | route 1: local gate, draft, then `stage.yml` |
| `mirror OWNER/REPO TAG [--semver V] [--notes-file F] [--defer]` | route 1 from the single `*.ipa` of another repository's release |
| `build BID REF [--no-publish] [--force]` | route 2: start `build.yml`; refuses a withdrawn version unless `--force` |
| `ingest URL [--sha256 H] [--semver V] [--notes-file F] [--app-json F]` | route 3: send the `ingest` dispatch |
| `retract BID VERSION [--unpublish] [--delete-tag] [--reason TEXT]` | [withdraw a version](#withdraw-a-version): delete its release (or turn it into a draft), then run `catalog.yml` |
| `register OWNER/REPO --bid BID [--tag-pattern RE] [--build-json F] [--rotate]` | create the deploy key and the app's environment `alt-<ALIAS>` with its secrets |
| `unregister BID OWNER/REPO` | delete the deploy key and the app's environment |
| `payload-key [--rotate]` | create the `age` key pair that encrypts `build.yml`'s payload artifact |
| `hook install PATH --bid BID [--tag-glob G]` / `hook uninstall PATH` | pre-push hook in a local clone of a private repository |
| `status [--limit N]` | recent build, ingest, stage and catalog runs, and the withdrawn versions of every app |
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
| `stage IPA [--bid B] [--semver V] [--notes-file F] [--app-json F] [--no-publish] [--dry-run] [--allow-home-paths]` | gate, draft and publish; warns when the version is withdrawn |
| `stage-draft TAG` or `stage-draft --all`, with `[--notes-file F] [--no-publish] [--dry-run] [--allow-home-paths] [--exit-zero]` | gate and publish existing drafts. `--all` skips drafts titled `[blocked] ...` or `[withdrawn] ...` and drafts of a withdrawn version, and names a draft as `release <id>:` in its messages until the gate passed its tag; `TAG` stages a withdrawn version with a warning |
| `sync [--no-commit] [--dry-run] [--rescan] [--exit-zero]` | regenerate and commit the catalog and `retracted.json`; prints `retracted=N restored=N` (tombstones added and removed) |
| `generate [--check]` | write `source.json`, or check that it is up to date |
| `validate` | validate `source.json`, every `app.json` and every `retracted.json` |
| `fetch URL OUT [--sha256 H]` | guarded https download |
| `parse-tag TAG` | split a tag into bundle id and semver |
| `alias BID` | print the alias that names the app's environment |
| `resolve-build --bid B --ref R --checkout DIR [--json-out F]` | validate route 2 build settings |
| `retracted --bid B [--version V]` | exit `0` when `apps/<B>/retracted.json` lists the version (without `--version`: any version), `4` when not |

- Commands that scan take `--denylist-file F` (default: `ALT_DENYLIST`).
- `sync`, `generate`, `validate`, `resolve-build` and `retracted` take `--root DIR`, and so do `stage` and
  `stage-draft`, which read `apps/<bid>/retracted.json` below it (default: the current directory).
- Exit codes: `0` success, `2` gate rejected or release blocked, `3` conflict, `4` not withdrawn
  (`retracted` only), `1` anything else (for `retracted`, a `retracted.json` that is not valid).
- With `--exit-zero`, `sync` and `stage-draft` exit `0` and report the counts only as outputs.

Outputs, written to `$GITHUB_OUTPUT` when it is set:

| Command | Outputs |
|---|---|
| `stage`, `stage-draft TAG` | `tag`, `release_id`, `asset`, `sha256`, `size`, `published`, `noop` |
| `stage-draft` | `staged` and `withdrawn` (with `--all`), `rejected`, `failed` |
| `sync` | `changed`, `commit`, `blocked`, `errors`, `retracted` |
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

## Withdraw a version

A version leaves the source as soon as its release is no longer published. Withdraw it with
`bin/alt retract`:

```sh
bin/alt retract io.example.demo 1.4.0                  # delete the release
bin/alt retract io.example.demo 1.4.0 --delete-tag     # also delete the tag io.example.demo-v1.4.0
bin/alt retract io.example.demo 1.4.0 --unpublish      # turn the release into a draft instead
bin/alt retract io.example.demo 1.4.0 --dry-run        # print the changes only
```

The same works on GitHub: delete the release in the web UI or with
`gh release delete io.example.demo-v1.4.0 -R xuniv/alt`, or turn it into a draft with
`gh release edit io.example.demo-v1.4.0 -R xuniv/alt --draft=true`.

`bin/alt retract` checks the login, push access and the local denylist like every command that writes.
It finds the release `<bundleId>-v<version>`, published or draft, then:

- by default deletes it, and every other release with the same tag, drafts included (a leftover draft
  could be published again);
- with `--unpublish` turns the published release into a draft titled `[withdrawn] <tag>`, which keeps
  its IPA privately. A pending draft of the version gets the same title; a draft titled
  `[blocked] <tag>` keeps its title;
- with `--delete-tag` (only together with deleting) also deletes the tag, after the release;
- starts `catalog.yml` on `main`, so the removal does not depend on the release event, and prints the
  source URL.

It commits nothing. `--reason TEXT` (one line, at most 200 characters) is written only to the local
log `~/.cache/xuniv-alt/retract.log`, with the time, the tag and what changed; it is never sent to
GitHub.

What happens next:

1. The deletion or the change to a draft starts `catalog.yml` through its release event as well. In
   that run or the dispatched one, whichever comes first, sync deletes the version's record and
   `source.json` no longer lists the version. Pages then deploys the result.
2. Sync adds the version to `apps/<bundleId>/retracted.json` with the date and the reason `deleted`
   or `unpublished` (see [app-json.md](app-json.md#generated-withdrawn-versions)). Releases that sync
   takes down itself, such as a draft titled `[blocked] <tag>`, get no entry. Do not edit the file.
3. Builders skip the version. `poll.yml` does not start a build for it, not even before sync has
   committed the entry: a version whose record is on `main` without a published release counts as
   withdrawn. `build.yml` refuses it in its first job, which holds no secret, unless `force` is true,
   and its gate job checks `main` once more just before publishing, so a build that was already
   running when you withdrew the version does not publish it. `bin/alt build` refuses it unless
   `--force`. The pre-push hook never passes `--force`, so pushing the tag again builds nothing. A tag
   of a new version builds as usual.
4. Publishing it on purpose still works: `bin/alt publish`, `bin/alt mirror`, `stage.yml` with a tag
   and `ingest.yml` only warn about a withdrawn version. With `--defer`, `bin/alt publish` and
   `bin/alt mirror` upload the draft, but scheduled `stage.yml` runs do not publish it (see below).
   The command says so and prints the `stage.yml` command that publishes it by tag.

`bin/alt status` lists the withdrawn versions of every app.

Sync adds an entry only for a version that `source.json` listed, that is, one whose record is on
`main`. A version that was never listed, such as a pending draft or a draft titled `[blocked] <tag>`,
gets no entry. `bin/alt retract` says so, because then nothing keeps `poll.yml`, `build.yml` or the
pre-push hook from building that version again.

A draft left by `--unpublish` (or by unpublishing in the GitHub UI) stays a draft. `stage.yml` runs
without a tag, scheduled or manual, skip such drafts and only count them:

- A draft titled `[withdrawn] <tag>`, which `bin/alt retract --unpublish` sets, is skipped at once,
  whether or not its version was ever listed and whether or not a catalog run has succeeded since.
- Any other draft, such as one unpublished in the GitHub UI, is skipped only once its version is in
  `retracted.json`, that is, once a catalog run has committed the entry. If sync stops before its
  commit, for example because `source.json` fails validation, every scheduled run publishes such a
  draft again until a catalog run succeeds. To keep it back at once, also run
  `bin/alt retract <bundleId> <version> --unpublish`, which only gives the draft the mark.
- A draft of a withdrawn version that was uploaded later, for example with `bin/alt publish --defer`,
  is skipped as well. That includes a draft uploaded after a listed release was deleted but before
  the catalog run noticed it: sync then lists the version as `deleted`. Stage such a draft by tag.

### Publish a withdrawn version again

Publish a release for the version; `retracted.json` needs no edit. The next sync sees the published
release and removes the entry (and the file when it is empty).

- **Unpublished:** `gh workflow run stage.yml -R xuniv/alt -f tag=io.example.demo-v1.4.0` gates the
  draft again, publishes it and gives it its usual title back.
  `gh release edit io.example.demo-v1.4.0 -R xuniv/alt --draft=false` publishes it directly, without
  the gate and with its current title (add `--title` to replace `[withdrawn] <tag>`); sync checks it
  afterwards.
- **Deleted, private build:** `bin/alt build io.example.demo v1.4.0 --force`.
- **Deleted, other routes:** publish the IPA again with `bin/alt publish`, `bin/alt mirror` or
  `bin/alt ingest`.

### What clients see

AltStore, SideStore and Feather treat the first listed version as the latest. Withdrawing the newest
version makes the previous one the latest, and a device that installed the withdrawn build is offered
the older one as an "update", because the clients compare version strings. `bin/alt retract` prints a
note when this applies. It compares the versions that `source.json` lists: prereleases count only when
the app's `app.json` in your checkout sets `includePrereleases`. If users already installed the
version, publish a fixed higher version rather than only withdrawing it.

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

Without a tag, drafts titled `[blocked] <tag>` or `[withdrawn] <tag>` are skipped, and so are drafts of
a withdrawn version. A draft staged by tag is retried even when it is marked; once it passes, it is
retitled and published.

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
  gates and normalizes that IPA again. If the catalog run failed before it committed, the next one
  takes the draft for a withdrawal and lists the version in `retracted.json` (`bin/alt status` shows
  it); scheduled runs then skip the draft, so stage it by tag.
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
run in the last 30 days, nor a [withdrawn version](#withdraw-a-version). After 30 days the poll loop
tries a tag without a release again; to stop that, delete the tag in the private repository or raise
`privateBuild.minVersion` above it. Withdrawing does not help here: a version that `source.json` never
listed gets no entry in `retracted.json`.

If the gate rejects `home-path` hits inside a prebuilt third-party framework (for example
`/Users/videolanci/` in MobileVLCKit), check that the paths name the vendor's build account and not
yours (`python3 -m altsource scan IPA --allow-home-user NAME` shows the effect), then list the account
in the app's `allowHomeUsers` ([app-json.md](app-json.md)).

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
workflow cannot be started by hand either. `bin/alt doctor` reports this, and `bin/alt build` (so also
the pre-push hook) enables `poll-watch.yml`, `stage.yml` and `catalog.yml` again when GitHub disabled
them for inactivity. The poll loop has no schedule and keeps running meanwhile. To do it by hand:

```sh
gh workflow enable poll-watch.yml -R xuniv/alt
gh workflow enable stage.yml -R xuniv/alt
gh workflow enable catalog.yml -R xuniv/alt
```

### The poll loop

`poll.yml` with `loop=true` ends with the job `next`. That job waits for the wait timer of the
environment `alt-poll-timer`, without holding a runner, and then starts `poll.yml` with `loop=true`
again. Its runs are titled `poll loop`. `next` starts nothing when a newer loop run is active (two
loops become one), and stops the loop when its run started less than 5 minutes before, which means
the environment has no wait timer. `poll-watch.yml` runs hourly and starts the loop when no loop run
is active, and so does `bin/alt build` (and so the pre-push hook) when the environment is set up.

```sh
bin/alt poller [--minutes 15]   # set the wait timer (5 to 1440 minutes) and start the loop if it stopped
gh workflow run poll.yml -R xuniv/alt [-f app=BID] [-f dry_run=true]   # one poll now, outside the loop
```

`bin/alt doctor` checks the environment and reports a stopped loop. To stop the loop, disable
`poll-watch.yml` and cancel the active `poll loop` run; `bin/alt build` starts it again unless the
environment is deleted as well. Each loop run takes about a minute of runner time.

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

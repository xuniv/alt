# Routes

An IPA can get into the catalog three ways. All of them use the same gate (`stage`) and the same
catalog regeneration (`sync`):

| Route | Input | Started by | Workflow |
|---|---|---|---|
| 1 | an IPA you already have | `bin/alt publish`, `bin/alt mirror` | `stage.yml` |
| 2 | a tag in a private source repository | `bin/alt build`, the pre-push hook, `poll.yml` | `build.yml` |
| 3 | an IPA at an https URL | `repository_dispatch`, `workflow_dispatch`, `bin/alt ingest` | `ingest.yml` |

Every route ends in `catalog.yml`, which runs `sync` and deploys Pages when `sync` committed a change.
A release published directly on GitHub, without any of the three routes, is gated by `sync` after
publication (see [Publishing a release directly](#publishing-a-release-directly)).

## Tags and versions

A release tag is `<bundleId>-v<semver>`:

- `bundleId` is the IPA's `CFBundleIdentifier`. It may contain letters, digits, `.` and `-`, and must
  start and end with a letter or digit. A bundle id that contains `-v` followed by a digit is refused,
  because the tag would be ambiguous.
- `semver` is `MAJOR.MINOR.PATCH` without leading zeros, with an optional pre-release suffix
  (`-beta.1`). Build metadata (`+5`) is not allowed.
- The semver core must equal `CFBundleShortVersionString`, padded with zeros (`1.4` matches
  `1.4.0`). When no semver is given, it is taken from `CFBundleShortVersionString`. A pre-release
  suffix therefore has to be passed explicitly (`--semver 1.4.0-beta.1`).

| Tag | Valid |
|---|---|
| `io.example.demo-v1.4.0` | yes |
| `io.example.demo-v2.0.0-rc.1` | yes, published as a GitHub pre-release |
| `io.example.demo-1.4.0` | no, `v` missing |
| `io.example.demo-v1.4` | no, three components required |
| `io.example.demo-v01.4.0` | no, leading zero |
| `io.example.demo-v1.4.0+5` | no, build metadata |
| `io.example.app-v2-v1.0.0` | no, bundle id contains `-v2` |

Check a tag with `PYTHONPATH=tools python3 -m altsource parse-tag TAG`.

GitHub creates each tag when its release is published. Do not push tags to this repository by hand.
Releases are published with `make_latest=false`; the catalog works out the newest version of each app
itself.

## The gate (`stage`)

`stage` runs the same steps for every route, in this order, before it makes any GitHub call:

1. **Inspect** the IPA: bundle id, versions, executables, signatures, entitlements, privacy keys.
2. **Check the identity:** the bundle id matches the expected one (when given), the semver matches
   `CFBundleShortVersionString`, and the tag fits the grammar.
3. **Normalize:** re-pack the IPA deterministically. Junk entries (`__MACOSX/`, `.DS_Store`, `._*`,
   `Thumbs.db`, and `iTunesMetadata.plist` at the archive root) are dropped. Entries are sorted, timestamps fixed to 1980-01-01, file modes fixed, and
   extra fields and comments removed. `BuildMachineOSBuild` is removed from every `Info.plist`. The
   same input always gives the same bytes.
4. **Scan** the normalized IPA, the release notes, the app name and an optional `app.json` seed.
5. **Release:** create a draft (or reuse the existing draft for the tag) and upload
   `<Name>-<semver>.ipa`. Check that the release carries exactly one `.ipa` (plus an optional
   `app.json`) and that GitHub's sha256 digest matches the local file. Then publish.

If a release with the tag is already published with the same IPA, `stage` does nothing. If it is
published with a different IPA, `stage` stops with a conflict (exit 3). Publish a new version instead.

### What the gate rejects

The scan reads the raw bytes of every entry, including binaries. It matches case-insensitively in
ASCII/UTF-8, UTF-16LE and UTF-16BE.

| Rule | Rejects |
|---|---|
| `denylist` | any term from the denylist (`ALT_DENYLIST`) |
| `home-path` | macOS home paths `/Users/<name>/`. `/home/<name>/` and `C:\Users\<name>\` are only warnings in an IPA: they mostly come from third-party help text, and the Linux runners build under `/home/runner`. The CI accounts `runner`, `runneradmin`, `builder` and `Shared` and generic placeholder names such as `user`, `username`, `yourname`, `admin` or `test` are not counted (any letter case) |
| `signed` | binaries signed with a certificate, or carrying a team identifier (ad-hoc and linker signatures are fine) |
| `signature-unknown` | a signature state the inspection could not classify |
| `provisioning-profile` | any `*.mobileprovision` or `*.provisionprofile`, anywhere in the bundle |
| `code-signature-dir` | `_CodeSignature/` directories |
| `dsym` | `*.dSYM/` bundles and DWARF files |
| `vcs-dir` | `.git/`, `.svn/`, `.hg/` |
| `xcuserdata` | `xcuserdata/`, `*.xcuserstate` |
| `swiftsourceinfo` | `*.swiftsourceinfo` files and `*.swiftmodule/` directories |
| `itunes-metadata` | an `iTunesMetadata.plist` file (App Store exports keep the purchaser's account in it). Normalization drops the one at the archive root, so this only stops a directly published IPA or one inside the bundle |
| `xcent` | `*.xcent` entitlement files such as `archived-expanded-entitlements.xcent` (they carry the team identifier) |
| `localization-non-en` | warning only: `.lproj` folders other than `Base`, `English` and `en` (including `en-GB` and the like) |

The gate also rejects:

- an archive that is unsafe or malformed:
  - absolute paths, `..`, backslashes or NUL bytes in names;
  - duplicate names, or names that differ only by case;
  - encrypted entries, or symlinks that point outside the bundle;
  - names that are not valid UTF-8, or zip features the reader does not support (such as a
    "version needed to extract" above 6.3);
  - more than 50,000 entries, more than 4 GiB in total or 2 GiB in one entry, or a compression ratio
    above 200:1;
  - not exactly one `Payload/<Name>.app/`, or a missing or unreadable `Info.plist`;
- `bundle-id-missing`, `bundle-id-mismatch`, `version-mismatch` and `tag-grammar` failures from step 2;
- a denylist term or home path in the release notes or the app name (here all three home path forms
  block);
- an `app.json` seed that is too large (`app-json-size`, over 64 KiB), malformed or contains a leak
  (`app-json-invalid`, `denylist`, `home-path`).

A rejection prints rule ids, counts and up to five paths inside the IPA. It never prints the matched
text. A path that contains a home path or a denylist term is printed as `<redacted>`.

Check an IPA locally before publishing it:

```sh
PYTHONPATH=tools python3 -m altsource scan Demo.ipa --denylist-file ~/.config/xuniv-alt/ipa-denylist
PYTHONPATH=tools python3 -m altsource stage Demo.ipa --dry-run --denylist-file ~/.config/xuniv-alt/ipa-denylist
```

`stage --dry-run` runs the whole gate and makes no GitHub calls.

## Sync

`sync` (run by `catalog.yml`) is the only writer of derived files. It never trusts earlier runs:

1. List every release. If the listing is incomplete, it stops without changing anything. Drafts and
   releases whose tag does not follow the grammar are ignored.
2. For each published release with a grammar tag, reuse the version record if the release, the IPA
   asset and the `app.json` asset are unchanged. Otherwise download the IPA, check its digest, inspect
   it, compare bundle id and version with the tag, and scan it again. A release without an uploaded
   `.ipa` is skipped with a warning.
3. Take down a release that fails. It is unpublished back to a draft titled `[blocked] <tag>`. An
   immutable release is deleted instead, unless only `home-path` blocked it; then it is left in place
   and reported. A release that carries a second `.ipa` or any other file besides `app.json` is taken
   down the same way (`unexpected-asset`), and so is a release whose IPA file name contains a denylist
   term or a home path (`asset name blocked`). Leaky release notes are cleared, and a leaky title is
   reset to `<bundleId> <semver>`.
4. Replace an IPA that passed but is not in normalized form (it was published directly rather than
   through stage). See [Publishing a release directly](#publishing-a-release-directly).
5. Delete records of releases that are no longer published. Create `apps/<bundleId>/icon.png` and
   `app.json` if they are missing.
6. Generate and validate `source.json`. Any validation error stops the run before a commit.
7. Commit the changed files to `main` in one commit (`catalog: sync <n> app(s), <m> version(s)`). If
   `main` moved meanwhile, refresh and start again, up to five attempts.

A cached record is not scanned again. After the denylist or the gate rules change, run
`sync --rescan` once (see [operations.md](operations.md#denylist-changed)).

`sync` replaces a published IPA only with its normalized form, as described below. `catalog.yml` runs
it with `--exit-zero`, deploys Pages when it committed (and on every push or manual run), and then fails
the run if any release was blocked or any error occurred.

## Route 1: publish an IPA you have

Use this for an IPA built on your machine or downloaded from a private release.

```sh
bin/alt publish Demo.ipa [--semver 1.4.0-beta.1] [--notes-file notes.md] [--defer]
bin/alt mirror owner/private-repo v1.4.0 [--semver V] [--notes-file notes.md] [--defer]
```

- `publish` runs the gate locally with the local denylist. It then creates a draft release and uploads
  the normalized IPA. Unless `--defer` is given, it starts `stage.yml` for the new tag right away.
  With `--defer`, the draft waits for the next scheduled `stage.yml` run.
- `mirror` downloads only the `*.ipa` asset of a release in another repository. The release must have
  exactly one. It then runs `publish`. Release notes are not copied: pass `--notes-file` to set them.
- `stage.yml` downloads the draft's IPA and runs the full gate again in CI with the `ALT_DENYLIST`
  secret, then publishes and calls `catalog.yml`.
  - Without a tag it processes every pending draft with a grammar tag, oldest first.
  - Drafts titled `[blocked] ...` are skipped; stage one by tag to retry it.
  - A draft the gate rejects gets that title.

### Publishing a release directly

Publishing a release by other means also works: through the web UI, or with
`gh release create io.example.demo-v1.4.0 Demo.ipa`. The release event starts `catalog.yml` on the
tag, which hands over to a run on `main`, and `sync` gates the IPA after the fact. It takes the
release down if the IPA fails. Keep in mind:

- The IPA is public from the moment the release is published until that sync, so prefer the staged
  route.
- If the IPA passes the gate but normalizing it changes its bytes (junk entries such as `__MACOSX/`
  or `.DS_Store`, the `BuildMachineOSBuild` key, timestamps), `sync` replaces it. The normalized file
  is inspected and scanned like stage does. If the IPA cannot be normalized or the result fails, the
  release is taken down. Otherwise the release goes back to draft and the normalized IPA is uploaded
  under a temporary name (`Demo-1.4.0.normalized-<id>.ipa`) and its digest checked. The old asset is
  then deleted, the new one is renamed to `<Name>-<semver>.ipa` (the name stage gives an IPA, so
  `Demo.ipa` becomes `Demo-1.4.0.ipa` and the download URL changes with it), and the release is
  published again with the same pre-release flag. The log says
  `<tag>: IPA replaced by its normalized form`, and `sync` prints `normalized=<n>`. Publishing again
  updates the release date shown in the catalog.
- If a step fails while the old IPA is still listed, the upload is removed and the release is
  published again unchanged; the run reports an error and lists the original IPA. `sync --rescan`
  tries again. If the old IPA is already gone (a request that reported an error took effect), the
  verified upload completes the replacement. If neither can be confirmed, the release is left as a
  draft. See [operations.md](operations.md#a-normalization-did-not-finish) for these cases.
- An immutable release cannot be changed: its IPA is listed as uploaded, with a warning.
- The release must carry exactly one `.ipa`, plus an optional `app.json` seed (see
  [app-json.md](app-json.md#seed-appjson-on-a-release)), and nothing else. The `.ipa` file name is
  public too (it is part of the download URL), so it is checked like the release notes.
- This repository keeps immutable releases off, so a failed release is turned back into a draft. If
  they were enabled, a failed release would be deleted instead (unless only `home-path` blocked it),
  and the tag of a deleted immutable release can never be reused.

## Route 2: build from a private repository

`build.yml` builds an app from a tag in a private repository on a GitHub-hosted macOS runner, gates the
IPA and publishes it. To register an app, see
[onboarding.md](onboarding.md#add-an-app-built-from-a-private-repository).

### How a build runs

1. **app** (ubuntu, no secrets): validate the inputs, check that `apps/<bundleId>/app.json` enables
   `privateBuild`, and work out the alias.
2. **resolve** (ubuntu, environment `alt-<ALIAS>`):
   - Read the environment's secrets `ALT_KEY` (deploy key) and `ALT_APP` (repository and build
     settings). If either is empty, the build fails.
   - Clone the tag over SSH, with GitHub's host keys pinned in `.github/known_hosts`.
   - Read `.alt.json` at the tag and validate the merged settings. The private repository name is
     masked in the log.
3. **build** (the selected macOS runner, environment `alt-<ALIAS>`):
   - Fetch the private repository with its tags, delete the key and check out the resolved commit. If
     the tag moved since the resolve job, the build fails. (The runner withholds a job output that
     happens to contain a masked value; the build then uses the tag's current commit, with a warning.)
   - Resolve and validate the settings again from the checkout; the runner must still match.
   - Select Xcode and install the `setup` tools.
   - Run `command` with `bash -eo pipefail` in the checkout, with no input. Its output goes to a log
     file, never to the job log, which shows only "build finished" or "build failed", the exit code
     and the duration. The `env` entries are set for this step only.
   - Find the IPA with `ipa_glob`, first in `ALT_OUT`, then in the checkout; symbolic links are
     ignored and exactly one file must match. Normalize it and check that its bundle id and version
     match; there is no gate on this runner.
   - Encrypt the normalized IPA with `age` to the `ALT_PAYLOAD_RECIPIENT` variable and keep it as
     artifact `payload` for 1 day. Artifacts of a public repository can be downloaded by any
     signed-in user, so the IPA is never uploaded in plain form.
   - The collected logs (git, tool setup, build, normalize) are packed into one archive, encrypted to
     the `ALT_LOG_RECIPIENT` variable and kept as artifact `diag` for 3 days, after a success as well
     as after a failure. A failed resolve job uploads its git log the same way.
4. **gate** (ubuntu): download `payload`, decrypt it with the `ALT_PAYLOAD_IDENTITY` secret and run
   the full gate with `ALT_DENYLIST`, then publish the release. With `publish` false, it runs the
   gate only (`stage --dry-run`).
5. **cleanup** (ubuntu): delete the `payload` artifact. It runs after the gate job whatever its result,
   also when the gate job was skipped or the run was cancelled.
6. **catalog**: when `publish` is true, call `catalog.yml`.

The private build command and whatever it downloads (Swift packages, Go modules, Homebrew formulas)
run on the macOS runner as the same user as every later step of that job, and could change the
checkout, the tools or files between steps. So that job holds no denylist and no payload identity, and
nothing it checks is relied on: the gate that decides publication runs on a fresh ubuntu runner. Each
secret is referenced by a fixed name, so the macOS runner receives only the app's own `ALT_KEY` and
`ALT_APP`. The encryption of the payload protects against an IPA that leaks by accident; a build
command that is itself malicious has network access and is not contained by it.

`<ALIAS>` is the bundle id in upper case with every character other than a letter or digit replaced by
`_` (`io.example.demo` becomes `IO_EXAMPLE_DEMO`, and its environment is `alt-IO_EXAMPLE_DEMO`). Print
it with `PYTHONPATH=tools python3 -m altsource alias io.example.demo`. Two bundle ids that differ only
in punctuation share an alias, so do not register both.

The build command gets these environment variables:

| Variable | Value |
|---|---|
| `VERSION` | the semver from the tag (`1.4.0`, or `1.4.0-beta.1`) |
| `ALT_OUT` | an empty scratch directory outside the checkout |
| the `env` entries | from the build settings |

### Which tags are built

`privateBuild.tagPattern` in `app.json` decides which tags of the private repository are versions. It
is a regular expression with a named group `version`, matched against the whole tag name. The default
is `v` followed by a semver (`^v(?P<version>...)$`), so `v1.4.0` becomes release
`io.example.demo-v1.4.0`. The captured version must be a valid semver as defined above.

### Build settings: `.alt.json`

Put `.alt.json` at the root of the private repository. It is read at the tag being built and must be a
JSON object of at most 64 KiB.

```json
{
  "runner": "xcode-27",
  "xcode": "27.0",
  "setup": ["xcodegen"],
  "command": "scripts/build-unsigned-ipa.sh",
  "ipa_glob": "build/ipa/*.ipa",
  "env": {"SCHEME": "Demo"}
}
```

| Key | Required | Rules | Default |
|---|---|---|---|
| `command` | yes | non-empty string, at most 8192 characters; may span several lines | |
| `runner` | no | `xcode-27`, `macos-26`, `macos-15` or `macos-latest` | `macos-latest` |
| `xcode` | no | `27`, `27.0` or `27.0.1`; selects `/Applications/Xcode_<xcode>.app`, which must exist on the runner | the runner's default Xcode |
| `setup` | no | list (or space-separated string) of `go`, `xcodegen`, `xcbeautify`, `ldid`; installed with Homebrew | none |
| `ipa_glob` | no | relative glob ending in `.ipa`, without `..`, `$` or backticks; matched in `ALT_OUT` first, then in the checkout, and must match exactly one file | `**/*.ipa` |
| `env` | no | up to 32 entries; names match `[A-Z][A-Z0-9_]*`; values are single-line strings of at most 4096 characters | `{}` |

Unknown keys are errors. `env` may not set names the runner or common tools rely on: for example
`PATH`, `HOME`, `VERSION`, `ALT_OUT`, `CI`, `DEVELOPER_DIR` and `NODE_OPTIONS`. It also may not use
names starting with `GITHUB_`, `RUNNER_`, `ACTIONS_`, `ALT_`, `GH_`, `INPUT_`, `DYLD_`, `LD_`, `PYTHON`,
`PERL`, `RUBY`, `BASH_`, `GIT_`, `SSH_`, `HOMEBREW_`, `XDG_`, `SSL_`, `CURL_`, `OPENSSL_` or `SUDO_`.

The same keys can be stored in the `build` object of the app environment's `ALT_APP` secret
(`bin/alt register --build-json F`). Registered values win over `.alt.json`, and `env` objects are
merged key by key. Settings can be kept out of the private repository this way, or overridden without
a new tag.

The command must produce an unsigned IPA that passes the gate:

- Build without code signing; no `embedded.mobileprovision`, no `_CodeSignature/`.
- Keep dSYMs and other debug files out of `Payload/`.
- Keep home directory paths out of the binaries (for Go, build with `-trimpath`). Paths under the
  runner's own home directory are fine.
- Set `CFBundleShortVersionString` to the core of `VERSION` (`1.4.0` for `1.4.0-beta.1`).
- Give every tag its own `CFBundleVersion`. Clients identify a version by the pair
  (`CFBundleShortVersionString`, `CFBundleVersion`). The catalog keeps only the higher semver of two
  versions with the same pair.

### What the public can see

Workflow runs of a public repository can be read by any signed-in user. A build shows its run title
`build <bundleId> <ref>` (`ref` is the private tag), the commit id the tag points at, the runner label,
the Xcode version, the `setup` tools, the version, the gate's rule ids and counts, and the timing.
The private repository name, every line of `command`, the `env` values and a custom `ipa_glob` are
masked. They never become job outputs. Error messages in CI name no keys from
the private settings.

### Triggers

- **On demand:** `bin/alt build io.example.demo v1.4.0 [--no-publish]` starts `build.yml` with
  `app`, `ref` and `publish`. With `--no-publish`, the build and the gate run, but no release is
  created (the encrypted payload artifact is deleted as usual).
- **On push, from your machine (the normal way to build new tags):**
  `bin/alt hook install <path-to-private-clone> --bid io.example.demo [--tag-glob 'v*']` installs a
  pre-push hook in that clone (default glob `v*`).
  - An existing pre-push hook is kept as `pre-push.alt-chained`. It runs first, with the same
    arguments and input, and its exit status still decides the push.
  - For every pushed tag that matches the glob (deletions excluded), the hook starts a background
    job. It waits until the tag on the remote being pushed to points at the pushed object, for up to
    10 minutes, then runs `bin/alt build <bid> <tag>`. A rejected push (for example a tag that already
    exists on the remote at another commit) therefore starts no build. The push itself is never
    delayed and the hook prints nothing.
  - The background job needs what every `bin/alt` command needs: `gh` logged in as `ALT_OWNER` and the
    local denylist. Its output, including any failure, goes only to `~/.cache/xuniv-alt/hook.log`.
  - The tag must also match `privateBuild.tagPattern`, or the build fails in its resolve job.
  - The hook stores the absolute path of `bin/alt`; after moving this checkout, run `hook install`
    again. Installing twice with the same options changes nothing. `hook install` refuses a
    repository that sets `core.hooksPath`.
  - Remove it with `bin/alt hook uninstall <path-to-private-clone>`, which restores a chained hook.
- **Polling (manual repair):** `gh workflow run poll.yml -R xuniv/alt [-f app=BID] [-f dry_run=true]`
  checks every app whose `app.json` enables `privateBuild`, or only `app`. It lists the private tags
  with `git ls-remote` and keeps those that match `tagPattern`. It then starts `build.yml` for each
  version that has no published release yet and no `build <bundleId> <ref>` run in the last 30 days
  (its read-only token cannot see drafts). At most two builds start per app and run, newest first.
  With `dry_run` it only counts them. `poll.yml` has no schedule; new tags are built through the
  pre-push hook.

A tag whose build failed is not retried by `poll.yml` for 30 days. Start it again with `bin/alt build`
once the cause is fixed.

## Route 3: ingest an IPA from a URL

`ingest.yml` downloads an IPA over https, gates it and publishes it. Use it only for builds you may
redistribute.

The download is checked:

- https only, and no user name or password in the URL;
- the host must resolve to public addresses only, and the connection goes to the vetted address;
- every redirect (at most 5) is checked the same way;
- at most 2 GB, with a 60 second timeout for each network operation;
- the sha256 is verified when given.

### `repository_dispatch`

Send event type `ingest`. The token needs write access to this repository's contents (fine-grained
token: Contents, read and write).

```sh
curl -fsS -X POST https://api.github.com/repos/xuniv/alt/dispatches \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -d '{
    "event_type": "ingest",
    "client_payload": {
      "url": "https://downloads.example.com/Demo-1.4.0.ipa",
      "sha256": "<64 hex digits>",
      "semver": "1.4.0",
      "notes": "Bug fixes.",
      "bundleIdentifier": "io.example.demo",
      "app": {"name": "Demo", "developerName": "Example Developer", "category": "utilities"}
    }
  }'
```

Only `url` is required. GitHub answers `204 No Content`.

| Payload key | Meaning |
|---|---|
| `url` | https URL of the IPA |
| `sha256` | expected sha256 of the download |
| `semver` | version for the tag (default: `CFBundleShortVersionString`) |
| `notes` | release notes |
| `bundleIdentifier` | expected bundle id; the IPA is rejected if it differs |
| `app` | `app.json` fields attached to the release as a seed (see [app-json.md](app-json.md#seed-appjson-on-a-release)) |

`bin/alt ingest URL [--sha256 H] [--semver V] [--notes-file F] [--app-json F]` sends the same event,
without `bundleIdentifier`. It first checks the URL and scans the notes (at most 4000 characters) and
the `app.json` file with the local denylist; notes or an `app.json` that the gate would reject are not
sent.

### `workflow_dispatch`

```sh
gh workflow run ingest.yml -R xuniv/alt \
  -f url=https://downloads.example.com/Demo-1.4.0.ipa \
  -f sha256=<64 hex digits> \
  -f semver=1.4.0 \
  -f notes='Bug fixes.' \
  -f bundle_id=io.example.demo \
  -f allow_home_paths=false
```

`allow_home_paths=true` (or `"allowHomePaths": true` in the `app` object of a `repository_dispatch`)
is meant for third-party builds that embed their developers' paths: `/Users/<name>/` findings become
warnings like the other home path forms. The release then carries
`allowHomePaths: true` in its `app.json` seed, so later syncs accept it. If the app already has a
committed `apps/<bundleId>/app.json`, set `"allowHomePaths": true` there first. Otherwise the next
sync takes the release down. Denylist hits are never allowed.

The URL is masked in the job log. Other inputs and payload values can appear in the public log, so do
not put private data in them.

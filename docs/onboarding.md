# Onboarding

## One-time setup

You need:

- `git`;
- Python 3.9 or later;
- the GitHub CLI `gh`, logged in as the repository owner;
- the `age` encryption tool (for example `brew install age`), for reading build logs.

Before doing anything, `bin/alt` checks that `gh api user --jq .login` equals `ALT_OWNER` (default
`xuniv`) and that the local denylist exists. It works on `ALT_REPO` (default `xuniv/alt`).

### Repository settings

- **Pages:** Settings, Pages, Build and deployment, Source: **GitHub Actions**.
- **Releases:** keep immutable releases off. `stage` never replaces a published IPA by itself, and a
  published release that later fails the gate is turned back into a draft. With immutable releases it
  would be deleted instead, and its tag could never be used again.
- **Actions:**
  - allow only actions created by GitHub;
  - keep the default `GITHUB_TOKEN` permissions read-only (each workflow job asks for what it needs);
  - require approval of fork pull request workflows for all external contributors.
- **Branch protection for `main`:** block force pushes and deletion. Do not require pull requests,
  because the catalog commits straight to `main` through the API.

### Denylist

The denylist holds private terms that identify you and must never appear in a published IPA or its
release text, such as account names, machine names or internal host names. Put one term per line.
Blank lines and lines starting with `#` are ignored, and matching is case-insensitive.

Keep one copy locally for `bin/alt` and one as a secret for the workflows:

```sh
mkdir -p ~/.config/xuniv-alt
$EDITOR ~/.config/xuniv-alt/ipa-denylist
chmod 600 ~/.config/xuniv-alt/ipa-denylist
gh secret set ALT_DENYLIST -R xuniv/alt < ~/.config/xuniv-alt/ipa-denylist
```

`bin/alt` reads `ipa-denylist` (or the file named by `ALT_DENYLIST_FILE`). Every step that scans
fails closed: without a denylist, nothing is published. Terms are matched as substrings, also inside
binaries, so keep the list to identifying terms; a short or generic word also matches inside unrelated
identifiers in third-party code and blocks good builds.

### Build log key

Private builds keep their log only in encrypted form. Create an `age` identity and publish its
recipient as a repository variable:

```sh
age-keygen -o ~/.config/xuniv-alt/log-identity.txt
gh variable set ALT_LOG_RECIPIENT -R xuniv/alt --body "$(age-keygen -y ~/.config/xuniv-alt/log-identity.txt)"
```

### Payload key

`build.yml` hands the built IPA from the macOS runner to the job that gates it as an artifact, and any
signed-in GitHub user can download the artifacts of a public repository. The IPA is therefore
encrypted with a second `age` key pair whose identity only the gate job can read:

```sh
bin/alt payload-key
```

This creates the key pair in a temporary directory, stores the identity (the key line only) as the
secret `ALT_PAYLOAD_IDENTITY` and its recipient as the variable `ALT_PAYLOAD_RECIPIENT`, and removes
the temporary copy. Nothing is kept locally. `bin/alt payload-key --rotate` replaces the pair; do it
while no build is running.

### Poll loop

```sh
bin/alt poller
```

This creates the environment `alt-poll-timer` with a wait timer of 15 minutes (`--minutes N` for
another interval, 5 to 1440), lets only `main` use it, and starts the poll loop that builds private
tags pushed without the hook (see [operations.md](operations.md#the-poll-loop)).

### Check

```sh
bin/alt doctor
```

`doctor` checks, and reports each result instead of stopping at the first problem:

- that the local denylist exists and is not empty (and warns if other users can read it);
- the `gh` login and push access to the repository; if these fail, the remote checks are skipped;
- that GitHub Actions is enabled (and warns if the default `GITHUB_TOKEN` permissions are not
  read-only);
- that all seven workflows exist and are enabled;
- that the secrets `ALT_DENYLIST` and `ALT_PAYLOAD_IDENTITY` and the variables `ALT_LOG_RECIPIENT`
  and `ALT_PAYLOAD_RECIPIENT` are set (and warns about per-app repository secrets of an earlier
  version, `ALT_KEY_<ALIAS>` and `ALT_APP_<ALIAS>`, which no workflow reads any more);
- for every app whose `app.json` in your checkout enables `privateBuild`, that its environment
  `alt-<ALIAS>` exists, lets only `main` use its secrets (selected branches only, with exactly one
  deployment policy: the branch `main`; any other branch or tag policy is reported), and holds
  `ALT_KEY` and `ALT_APP`;
- that the environment `alt-poll-timer` exists with a wait timer of at least 5 minutes and lets only
  `main` use it (and warns when the poll loop is not running);
- that Pages is built by GitHub Actions;
- that `ssh-keygen`, `age`, `age-keygen`, `git` and the log identity are available locally (warnings
  only).

It does not check the deployment rules of the `github-pages` environment. Every deployment runs on
`main`, so those rules only have to allow `main` (see
[operations.md](operations.md#pages-deployment-refused)).

## Add an app from an IPA

Use route 1 ([routes.md](routes.md#route-1-publish-an-ipa-you-have)).

1. Gate the IPA locally. Nothing is uploaded:

   ```sh
   PYTHONPATH=tools python3 -m altsource stage Demo.ipa --dry-run --denylist-file ~/.config/xuniv-alt/ipa-denylist
   ```

2. Publish it:

   ```sh
   bin/alt publish Demo.ipa --notes-file notes.md
   ```

3. Follow the runs with `bin/alt status`. When `catalog.yml` has finished, the app is in
   `source.json`.
4. The first sync creates `apps/<bundleId>/app.json` and `icon.png`. Pull, edit them (see
   [app-json.md](app-json.md)), and push.

## Add an app built from a private repository

Use route 2 ([routes.md](routes.md#route-2-build-from-a-private-repository)). The private repository
must be able to build an unsigned IPA from a tag on a GitHub-hosted macOS runner.

1. **Find the alias** that names the app's environment (`alt-<ALIAS>`):

   ```sh
   PYTHONPATH=tools python3 -m altsource alias io.example.demo    # IO_EXAMPLE_DEMO
   ```

2. **Describe the build.** Add `.alt.json` to the private repository, commit it and tag a release
   (`v1.4.0` with the default tag pattern). See
   [routes.md](routes.md#build-settings-altjson) for the keys.

   To keep the settings out of the private repository instead, write the same object to a local
   file and pass it as `--build-json` in the next step.

3. **Register the repository:**

   ```sh
   bin/alt register owner/private-repo --bid io.example.demo \
     [--tag-pattern '^release-(?P<version>\d+\.\d+\.\d+)$'] [--min-version 1.4.0] [--build-json build.json]
   ```

   This:
   - creates or updates the GitHub environment `alt-IO_EXAMPLE_DEMO` and lets only the `main` branch
     use it: its deployment policies become exactly one branch policy `main`, and every other branch
     or tag policy (for example `*` from an earlier setup) is deleted;
   - creates an ed25519 key pair in a temporary directory;
   - adds the public key to the private repository as a **read-only** deploy key titled `alt-build`;
   - stores the private key as the environment secret `ALT_KEY`;
   - stores `{"repo": "owner/private-repo", "build": {...}}` as the environment secret `ALT_APP`;
   - shreds the temporary key;
   - deletes the repository secrets `ALT_KEY_IO_EXAMPLE_DEMO` and `ALT_APP_IO_EXAMPLE_DEMO` of an
     earlier version, if they exist;
   - makes sure `apps/io.example.demo/app.json` in your checkout enables `privateBuild`, and tells you
     to commit it. It never commits by itself;
   - sets `privateBuild.minVersion` to the newest version tag of the repository, unless you pass
     `--min-version` or `app.json` already has one. The poll loop (`poll.yml`) never builds older tags,
     so the history of the repository is not published. A repository without version tags gets no
     floor: every version tag pushed later is built. `app.json` becomes public, so register refuses a
     floor that contains a denylist term (pass `--min-version` then).

   Each app has its own environment, and the workflows name the secrets `ALT_KEY` and `ALT_APP`
   directly. A job then receives only the secrets of the one environment it uses, so a private build
   never sees another app's deploy key or configuration (a computed name such as
   `secrets[format('ALT_KEY_{0}', alias)]` would make GitHub send every secret of the repository).
   The environment is used without deployment records (`deployment: false`).

4. **Commit `app.json`.** Sync does not change an existing `app.json`, so fill in the metadata now:

   ```json
   {
     "name": "Demo",
     "developerName": "Example Developer",
     "localizedDescription": "What the app does.",
     "category": "utilities",
     "privateBuild": {"enabled": true, "minVersion": "1.4.0"}
   }
   ```

   Run `PYTHONPATH=tools python3 -m altsource validate`, then commit and push to `main`. From then on
   the poll loop builds and publishes every tag from `minVersion` on that has no release, within about
   15 minutes. To try a build first, start it right after the push
   (step 5): `poll.yml` skips a tag that already has a build run. To publish only future tags, pass the
   lowest pre-release of the next version, for example `--min-version 1.4.1-0` when the newest tag is
   `v1.4.0` (`1.4.1` would skip `v1.4.1-rc.1`).

5. **Try a build without publishing,** then publish:

   ```sh
   bin/alt build io.example.demo v1.4.0 --no-publish
   bin/alt build io.example.demo v1.4.0
   ```

   The run title `build io.example.demo v1.4.0` is public from the moment of the dispatch, so
   `bin/alt build` first refuses a tag that `build.yml` would reject, and one whose title contains a
   denylist term or a home path (exit code 2). If the build fails, `bin/alt diag RUN_ID` shows its
   log (see [operations.md](operations.md#a-private-build-failed)).

6. **Build new tags automatically.** Install the pre-push hook in your clone of the private
   repository:

   ```sh
   bin/alt hook install <path-to-private-clone> --bid io.example.demo --tag-glob 'v*'
   ```

   Every tag you push that matches the glob then starts `bin/alt build` in the background, once the
   tag has reached the remote; see [routes.md](routes.md#triggers) for the details. Check
   `~/.cache/xuniv-alt/hook.log` if no build appears. The hook is optional: without it (for example
   when you push from another machine), the poll loop builds the tag within about 15 minutes. Start a
   poll at once with `gh workflow run poll.yml -R xuniv/alt` (optionally
   `-f app=io.example.demo -f dry_run=true`). It skips a version below `minVersion`, one that already
   has a published release or a build run in the last 30 days, and one that was withdrawn (see
   [operations.md](operations.md#withdraw-a-version)).

To rotate the deploy key, run `bin/alt register` again with the same `--build-json` plus `--rotate`. It
deletes the old `alt-build` key first. To remove an app's build access, run
`bin/alt unregister io.example.demo owner/private-repo`. That deletes the deploy key and the
environment `alt-IO_EXAMPLE_DEMO` with its secrets (and old per-app repository secrets, if any). Then
set `privateBuild.enabled` to `false`. Releases that are already published stay listed; to take a
version down, see [operations.md](operations.md#withdraw-a-version).

## Add an app from a URL

Use route 3 ([routes.md](routes.md#route-3-ingest-an-ipa-from-a-url)). Send an `ingest` dispatch with
the URL, its sha256, and optional `app` metadata for the new app's `app.json`.

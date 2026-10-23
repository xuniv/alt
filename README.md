# alt

An AltStore-compatible app source. Every app version is an unsigned IPA attached to a GitHub Release
of this repository. The catalog, `source.json`, is generated from those releases and served by GitHub
Pages.

## Add the source

Source URL (permanent):

```
https://xuniv.github.io/alt/source.json
```

On the device, open <https://xuniv.github.io/alt/> and tap the button for your store. Or use one of
these links (GitHub does not render custom-scheme links, so copy them into Safari):

| Store | Link |
|---|---|
| AltStore | `altstore://source?url=https%3A%2F%2Fxuniv.github.io%2Falt%2Fsource.json` |
| AltStore Classic | `altstore-classic://source?url=https%3A%2F%2Fxuniv.github.io%2Falt%2Fsource.json` |
| SideStore | `sidestore://source?url=https%3A%2F%2Fxuniv.github.io%2Falt%2Fsource.json` |
| Feather | no link: add a source in Feather and paste the source URL |

Any client can also add the plain source URL by hand. AltStore PAL is not supported, because it only
accepts marketplace apps.

The IPAs are unsigned. Your store signs each app when you install it. The source lists every app's
entitlements and privacy usage descriptions (`appPermissions`), so the store can check them and show
them before installing.

## How releases get here

There are three ways in. All of them end with the same two steps:

```
route 1  IPA built locally ------+
route 2  private repository -----+--> stage: gate, draft, publish --> sync: records, source.json --> Pages
route 3  IPA at an https URL ----+
```

- **stage** is the pre-publication gate. It re-packs the IPA deterministically and scans it for leaks
  and signing material. Only then does it upload the IPA to a draft release and publish it. On these
  three routes nothing is public before the gate passes.
- **sync** rebuilds every derived file from the full list of published releases and commits the
  result. It gates every published IPA it has not checked before (all of them on a rescan) and takes
  down any release that fails. Pages is deployed after a sync that committed a change, and on pushes
  and manual runs of the catalog workflow.

A release published directly on GitHub skips stage and its draft, so it has no pre-publication
protection: it is public at once, and sync gates it only afterwards. Sync takes it down if it fails,
and if the IPA passes but was not re-packed, sync replaces it with the normalized form and publishes
the release again. Neither undoes what was public in between. Route 2 builds new private tags when
they are pushed, through an optional local pre-push hook.

Release tags follow `<bundleId>-v<semver>`, for example `io.example.demo-v1.4.0`.

## Documentation

- [docs/routes.md](docs/routes.md): the three routes, the tag grammar, what the gate rejects.
- [docs/onboarding.md](docs/onboarding.md): one-time setup, then adding an app.
- [docs/app-json.md](docs/app-json.md): `source.base.json`, `apps/<bundleId>/app.json` and the
  generated files.
- [docs/operations.md](docs/operations.md): secrets, variables, workflows, recovery.

## Repository layout

```
source.base.json               source metadata and defaults (edited by hand)
source.json                    generated catalog (do not edit)
apps/<bundleId>/app.json       app metadata (edited by hand; sync creates it once if missing)
apps/<bundleId>/icon.png       app icon (edited by hand, or extracted from the IPA once)
apps/<bundleId>/versions/*.json  per-version records (generated)
site/                          Pages landing page and fallback icon
tools/altsource/               Python package behind every workflow step
bin/alt                        operator command line
.github/workflows/             catalog, stage, build, ingest, poll, ci
tests/                         unit tests
```

## Development

The tools use only the Python standard library and support Python 3.9 and later.

```sh
PYTHONPATH=tools python3 -m altsource --help
PYTHONPATH=tools python3 -m unittest discover -s tests -t .
```

Exit codes of `python3 -m altsource`: `0` success, `2` gate rejected, `3` conflict with a published
release, `1` any other error (including usage errors).

# Catalog files

Some files are edited by hand and some are generated. Edit only the hand-edited ones. Pushing a change
to `source.base.json`, an `app.json`, an `icon.png` or `site/` to `main` starts `catalog.yml`, which
regenerates everything else.

| File | Kind |
|---|---|
| `source.base.json` | hand-edited |
| `apps/<bundleId>/app.json` | hand-edited; created once by sync if missing |
| `apps/<bundleId>/icon.png` | hand-edited; extracted once from the IPA if missing |
| `apps/<bundleId>/versions/<semver>.json` | generated |
| `apps/<bundleId>/retracted.json` | generated: withdrawn versions |
| `source.json` | generated |

Check everything locally:

```sh
PYTHONPATH=tools python3 -m altsource generate --check   # is source.json up to date?
PYTHONPATH=tools python3 -m altsource validate           # source.json and every app.json
```

Clients reject the whole source when one app in it is invalid. `sync` therefore validates the
generated `source.json` and commits nothing if there is any error.

## `source.base.json`

Source-level metadata.

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | source name |
| `identifier` | yes | `io.github.xuniv.alt`; keep it unchanged |
| `subtitle` | no | short line under the name |
| `description` | no | longer description |
| `website` | no | absolute URL |
| `tintColor` | no | 6 hex digits without `#` |
| `iconURL` | no | source icon, an absolute http(s) URL; defaults to the first app's icon, else `site/icon.png` on Pages. An invalid value is reported and replaced by that default |
| `headerURL` | no | header image |
| `featuredApps` | no | bundle ids to feature; ids without a listed app are dropped, and when none remain the key is left out (clients then feature every app) |
| `news` | no | news items; each needs `identifier` (unique), `title`, `caption` and `date` |
| `defaults` | no | `developerName`, `category` and `tintColor` for apps whose `app.json` does not set them; not written to `source.json` |

Keys that are set, except `defaults`, are copied to `source.json` and validated there; an empty
`featuredApps` or `news` list is left out. The current file sets every key except `iconURL` and
`headerURL`.

The generated source never contains `marketplaceID`, a source-level `version`, or the legacy
`permissions` array.

## `apps/<bundleId>/app.json`

App metadata, validated strictly: an unknown key is an error.

```json
{
  "name": "Demo",
  "developerName": "Example Developer",
  "subtitle": "A short tagline",
  "localizedDescription": "What the app does.",
  "category": "utilities",
  "tintColor": "5B6CFF",
  "screenshots": ["https://example.com/demo/screen-1.png"],
  "includePrereleases": false,
  "maxVersions": 10
}
```

| Key | Type | Meaning | Default |
|---|---|---|---|
| `name` | non-empty string | display name | name from the newest IPA |
| `developerName` | non-empty string | developer shown in the store | `defaults.developerName`, else the source name |
| `subtitle` | non-empty string | short tagline | none |
| `localizedDescription` | non-empty string | app description | `subtitle`, else `name` |
| `category` | one of `developer`, `entertainment`, `games`, `lifestyle`, `other`, `photo-video`, `social`, `utilities` | store category | `defaults.category`, else `other` |
| `tintColor` | 6 hex digits without `#` | accent color | `defaults.tintColor`, else the source `tintColor` |
| `iconURL` | absolute http(s) URL | icon | the Pages URL of `icon.png` if it exists, else the source icon, else `site/icon.png` |
| `screenshots` | list of absolute http(s) URLs | iPhone screenshots (iPad screenshots are not supported) | none |
| `includePrereleases` | boolean | list pre-release versions | `false` |
| `maxVersions` | integer 1 to 100 | how many versions to list | `10` |
| `hidden` | boolean | leave the app out of `source.json` | `false` |
| `allowHomePaths` | boolean | accept `/Users/<name>/` home paths in this app's IPAs as warnings (third-party builds, route 3); the other home path forms are warnings anyway | `false` |
| `privateBuild` | object | route 2 settings, see below | none |

`privateBuild`:

| Key | Type | Meaning |
|---|---|---|
| `enabled` | boolean | `true` lets `build.yml` and `poll.yml` build this app from its private repository |
| `tagPattern` | regex string with a named group `version` | which private tags are versions; default: `v` followed by a semver |
| `windowed` | boolean | optional; accepted by the validator but not read by the current tools |

When an app gets its first published release and has no `app.json`, sync creates one. It sets `name`
from the IPA and copies `developerName`, `category` and `tintColor` from `source.base.json` defaults.
It sets `includePrereleases: false` and `maxVersions: 10`, and adds any descriptive keys from the
newest release's `app.json` seed. After that, sync never changes the file.

`icon.png` works the same way: if it is missing, sync extracts the best icon from the newest IPA the
catalog lists (pre-releases only with `includePrereleases`). If that IPA has no usable icon, it tries
the next older version, and versions the catalog does not list last. Each IPA is tried once. For a
better icon, commit a square PNG (1024 x 1024 recommended). Sync never overwrites it.

## Seed `app.json` on a release

A release may carry one extra asset named `app.json` next to its IPA. It is used only to create
`apps/<bundleId>/app.json` when that file does not exist yet. It must be at most 64 KiB and pass the
same validation, and it is scanned for leaks. A seed that fails gets its release blocked like a bad
IPA.

Only these keys are taken from a seed: `name`, `developerName`, `subtitle`, `localizedDescription`,
`category`, `tintColor`, `iconURL`, `screenshots`, `allowHomePaths`. Attach a seed with
`python3 -m altsource stage --app-json F`, or with the `app` object of a route 3 dispatch.

## Generated: version records

`apps/<bundleId>/versions/<semver>.json` caches the facts of one published release. Sync rewrites it
and deletes it when its release is no longer published. Do not edit it.

| Key | Content |
|---|---|
| `schemaVersion` | `1` |
| `tag`, `bundleIdentifier`, `semver` | from the tag |
| `version`, `buildVersion` | `CFBundleShortVersionString`, `CFBundleVersion` |
| `prerelease` | the release is a GitHub pre-release or the semver has a pre-release suffix |
| `date` | release publication time, `YYYY-MM-DDTHH:MM:SSZ` |
| `localizedDescription` | release notes, trimmed to 4000 characters, or `Version <semver>` |
| `downloadURL`, `size`, `sha256` | the asset's `browser_download_url`, size and digest |
| `minOSVersion` | `MinimumOSVersion` |
| `releaseId`, `assetId`, `assetDigest` | cache key |
| `name` | app name from the IPA |
| `privacy`, `entitlements` | usage descriptions and entitlements of the app and its extensions |
| `appJsonAssetId` | id of the release's `app.json` seed, if any (part of the cache key) |
| `iconUnavailable` | `true` when the IPA had no usable icon, so it is not downloaded again |

## Generated: withdrawn versions

`apps/<bundleId>/retracted.json` lists the versions of an app that were withdrawn: their release was
deleted, or turned back into a draft by someone other than sync (see
[operations.md](operations.md#withdraw-a-version)). Only sync writes it, and only after a complete
release listing. Do not edit it.

```json
{
  "schemaVersion": 1,
  "versions": {
    "1.4.0": {
      "date": "2026-10-23T07:13:00Z",
      "reason": "deleted"
    }
  }
}
```

| Key | Content |
|---|---|
| `schemaVersion` | `1` |
| `versions` | one entry per withdrawn semver |
| `date` | when sync noticed the withdrawal, `YYYY-MM-DDTHH:MM:SSZ` |
| `reason` | `deleted` (the release is gone) or `unpublished` (the release is a draft) |

- A release that sync takes down itself (a gate block, an unexpected asset, a draft titled
  `[blocked] <tag>`) gets no entry.
- When a release of the version is published again, sync removes its entry, and the file once it is
  empty.
- The file does not change `source.json`, which lists the published releases. It tells the builders
  what not to build: `poll.yml`, `build.yml` (unless its `force` input is true) and `bin/alt build`
  (unless `--force`) skip a listed version. `bin/alt status` shows the entries of every app, and
  `PYTHONPATH=tools python3 -m altsource retracted --bid BID --version V` checks one version.
- Deleting `apps/<bundleId>/` removes an app. Sync does not create the file again for an app without
  releases unless it drops one of the app's records in that run.

## Generated: `source.json`

Each listed app has its `app.json` fields with the defaults above, plus:

- `versions`:
  - sorted newest first by semver;
  - pre-releases are left out unless `includePrereleases` is set;
  - of two versions with the same `version` and `buildVersion`, only the higher semver is kept;
  - at most `maxVersions` are listed.

  Each entry has `version`, `buildVersion`, `marketingVersion` (the semver), `date`,
  `localizedDescription`, `downloadURL`, `size`, `sha256` and `minOSVersion`.
- `appPermissions`: the union of the entitlements and privacy descriptions of all listed versions. For
  privacy keys, the newest description wins.
- The legacy app-level fields `version`, `versionDate`, `versionDescription`, `downloadURL` and `size`,
  copied from the newest listed version.

An app with no listed version, or with `hidden: true`, is left out.

Clients treat the first listed version as the latest. If a bad version has to go, publish a higher
version rather than only withdrawing the newest release. Withdrawing it would offer the older version
as an "update" (see [operations.md](operations.md#what-clients-see)).

"""Mirror verified public Feather release assets through the existing ingest gate.

No cross-repository personal token is needed: this runs in alt's own poll job.
Only public upstream metadata and local release state are read; private-build
settings are not accessed. A withdrawal or existing release always wins over polling.
"""
from __future__ import annotations
import base64
import json
import re
from typing import Any, Callable, Dict, Optional
from . import gh

BUNDLE = "thewonderofyou.Feather"
UPSTREAM = "xuniv/feather"
ASSET = "Feather-unsigned.ipa"
SEMVER = re.compile(r"v(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\Z")
FORK_TAG = re.compile(r"v(?P<upstream>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))-(?P<fix>[1-9]\d*)\Z")
DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")
NOTES = "Unsigned Feather app manager with local installation and user-managed patches. Sign with your own certificate before installing."


def candidate(release: Dict[str, Any]) -> Optional[Dict[str, str]]:
    if not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False:
        return None
    tag = release.get("tag_name")
    match = SEMVER.fullmatch(tag) if isinstance(tag, str) else None
    fork = FORK_TAG.fullmatch(tag) if isinstance(tag, str) else None
    notes = NOTES
    if fork:
        # Public fork labels have an upstream-revision suffix, while the IPA
        # keeps an independent numeric version for iOS and catalog ordering.
        # The ingest gate still validates this version against the actual IPA.
        body = release.get("body")
        if not isinstance(body, str):
            return None
        labels = re.findall(r"^Fork version: `([^`]+)`$", body, re.M)
        packages = re.findall(r"^Package version: `([^`]+)`$", body, re.M)
        if labels != [tag[1:]] or len(packages) != 1 or not SEMVER.fullmatch("v" + packages[0]):
            return None
        version = packages[0]
        if tuple(map(int, version.split("."))) < (2, 9, 5):
            return None
        notes = "Feather fork " + tag[1:] + ". " + NOTES
    elif match:
        version = match["version"]
        if tuple(map(int, version.split("."))) < (2, 9, 3):
            return None
    else:
        return None
    raw_assets = release.get("assets")
    if not isinstance(raw_assets, list):
        return None
    assets = [asset for asset in raw_assets if isinstance(asset, dict) and asset.get("name") == ASSET]
    if len(assets) != 1:
        return None
    asset = assets[0]
    raw_digest = asset.get("digest")
    digest = DIGEST.fullmatch(raw_digest) if isinstance(raw_digest, str) else None
    expected = "https://github.com/%s/releases/download/%s/%s" % (UPSTREAM, tag, ASSET)
    if not digest or asset.get("browser_download_url") != expected or type(asset.get("size")) is not int or asset["size"] <= 0:
        return None
    return {"url": expected, "sha256": digest[1], "semver": version,
            "bundle_id": BUNDLE, "notes": notes, "allow_home_paths": "false"}


def poll(api: Callable[..., Any] = gh.api) -> str:
    try:
        release = api("GET", "repos/%s/releases/latest" % UPSTREAM)
    except gh.NotFound:
        return "No eligible public Feather release"
    inputs = candidate(release)
    if inputs is None:
        return "No hash-verified unsigned package on the latest Feather release"
    repository = gh.client().repo
    version = inputs["semver"]
    tag = "%s-v%s" % (BUNDLE, version)
    # The tag endpoint only returns published releases. List with push access
    # so an intentionally saved or blocked draft cannot be auto-published.
    releases = api("GET", "repos/%s/releases" % repository, paginate=True)
    if not isinstance(releases, list) or any(not isinstance(item, dict) or not isinstance(item.get("tag_name"), str) for item in releases):
        raise gh.GhError("Invalid local release listing")
    if any(item["tag_name"] == tag for item in releases):
        return "Feather version already published or staged"
    try:
        record = api("GET", "repos/%s/contents/apps/%s/retracted.json" % (repository, BUNDLE))
    except gh.NotFound:
        record = None
    if record is not None:
        data = json.loads(base64.b64decode(record["content"], validate=False))
        if not isinstance(data, dict) or not isinstance(data.get("versions"), dict):
            raise gh.GhError("Invalid Feather withdrawal record")
        if version in data["versions"]:
            return "Feather version was withdrawn; no automatic re-publication"
    # A record without its release can mean a withdrawal that sync has not
    # recorded yet. Never re-create it during that window.
    try:
        api("GET", "repos/%s/contents/apps/%s/versions/%s.json" % (repository, BUNDLE, version))
        return "Feather version record exists; waiting for catalog reconciliation"
    except gh.NotFound:
        pass
    runs = api("GET", "repos/%s/actions/workflows/ingest.yml/runs" % repository, fields={"per_page": 30})
    if any(run.get("status") in {"queued", "in_progress", "waiting", "pending", "requested"}
           for run in runs.get("workflow_runs", [])):
        return "An ingest run is already pending"
    api("POST", "repos/%s/actions/workflows/ingest.yml/dispatches" % repository,
        json_body={"ref": "main", "inputs": inputs})
    return "Dispatched the hash-verified Feather package to the ingest gate"


if __name__ == "__main__":
    print(poll())

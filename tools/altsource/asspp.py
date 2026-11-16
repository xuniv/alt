"""Mirror verified public Asspp release assets through the existing ingest gate.

No cross-repository personal token is needed: this runs in alt's own poll job.
Only public release metadata is read; credentials and private-build settings are
not accessed. A withdrawal or existing release always wins over polling.
"""
from __future__ import annotations
import base64
import json
import re
from typing import Any, Callable, Dict, Optional
from . import gh

BUNDLE = "wiki.qaq.Asspp"
UPSTREAM = "xuniv/Asspp"
ASSET = "Asspp-AltStore.ipa"
SEMVER = re.compile(r"4\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")
DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")
NOTES = "On-device Apple authentication and Store downloads, with local IPA import. English source package."


def candidate(release: Dict[str, Any]) -> Optional[Dict[str, str]]:
    version = release.get("tag_name")
    if release.get("draft") or release.get("prerelease") or not isinstance(version, str) or not SEMVER.fullmatch(version):
        return None
    assets = [asset for asset in release.get("assets", []) if asset.get("name") == ASSET]
    if len(assets) != 1:
        return None
    asset = assets[0]
    digest = DIGEST.fullmatch(asset.get("digest") or "")
    expected = "https://github.com/%s/releases/download/%s/%s" % (UPSTREAM, version, ASSET)
    if not digest or asset.get("browser_download_url") != expected or not isinstance(asset.get("size"), int) or asset["size"] <= 0:
        return None
    return {"url": expected, "sha256": digest[1], "semver": version,
            "bundle_id": BUNDLE, "notes": NOTES, "allow_home_paths": "false"}


def poll(api: Callable[..., Any] = gh.api) -> str:
    try:
        release = api("GET", "repos/%s/releases/latest" % UPSTREAM)
    except gh.NotFound:
        return "No eligible public Asspp release"
    inputs = candidate(release)
    if inputs is None:
        return "No hash-verified AltStore package on the latest Asspp release"
    repository = gh.client().repo
    version = inputs["semver"]
    tag = "%s-v%s" % (BUNDLE, version)
    try:
        api("GET", "repos/%s/releases/tags/%s" % (repository, tag))
        return "Asspp version already published or staged"
    except gh.NotFound:
        pass
    try:
        record = api("GET", "repos/%s/contents/apps/%s/retracted.json" % (repository, BUNDLE))
    except gh.NotFound:
        record = None
    if record is not None:
        data = json.loads(base64.b64decode(record["content"], validate=False))
        if version in data.get("versions", {}):
            return "Asspp version was withdrawn; no automatic re-publication"
    runs = api("GET", "repos/%s/actions/workflows/ingest.yml/runs" % repository, fields={"per_page": 30})
    if any(run.get("status") in {"queued", "in_progress", "waiting", "pending", "requested"}
           for run in runs.get("workflow_runs", [])):
        return "An ingest run is already pending"
    api("POST", "repos/%s/actions/workflows/ingest.yml/dispatches" % repository,
        json_body={"ref": "main", "inputs": inputs})
    return "Dispatched the hash-verified Asspp package to the ingest gate"


if __name__ == "__main__":
    print(poll())

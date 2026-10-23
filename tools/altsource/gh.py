"""Thin GitHub layer over the ``gh`` command line client.

Every request is an argument array passed to a runner callable (no shell). The runner is injectable,
so tests can replace the whole layer without touching the network. Error messages only carry the
HTTP method, the API path of this repository, the status code and GitHub's generic error message.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
import urllib.parse
import uuid
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

DEFAULT_REPO = "xuniv/alt"
API_VERSION = "2022-11-28"
UPLOADS_HOST = "https://uploads.github.com"
PER_PAGE = 100
MAX_PAGES = 200
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_STATUS_RE = re.compile(r"\(HTTP (\d{3})\)")
_STALE_MARKERS = (
    "expected branch to point to",
    "expectedheadoid",
    "is not the head of the branch",
)

COMMIT_MUTATION = """mutation($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) {
    commit { oid }
  }
}"""


class GhError(Exception):
    """A GitHub request failed. ``status`` is the HTTP status when known."""

    def __init__(self, message: str, *, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class NotFound(GhError):
    """HTTP 404."""


class GraphQLError(GhError):
    """The GraphQL endpoint returned errors."""


class HeadMoved(GhError):
    """createCommitOnBranch rejected the expected head oid (the branch moved)."""


Runner = Callable[..., "subprocess.CompletedProcess[bytes]"]


def run_gh(
    args: Sequence[str],
    *,
    input: Optional[bytes] = None,
    stdout_path: Optional[str] = None,
    timeout: Optional[float] = None,
) -> "subprocess.CompletedProcess[bytes]":
    """Run ``gh`` with an argument array. stdout goes to ``stdout_path`` when given."""
    cmd = ["gh"] + [str(a) for a in args]
    env = dict(os.environ)
    env.update({"GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1", "GH_PAGER": ""})
    kwargs: Dict[str, Any] = {"env": env, "timeout": timeout, "stderr": subprocess.PIPE}
    if input is not None:
        kwargs["input"] = input
    else:
        kwargs["stdin"] = subprocess.DEVNULL
    if stdout_path is not None:
        with open(stdout_path, "wb") as fh:
            proc = subprocess.run(cmd, stdout=fh, **kwargs)
        return subprocess.CompletedProcess(cmd, proc.returncode, b"", proc.stderr)
    return subprocess.run(cmd, stdout=subprocess.PIPE, **kwargs)


def _with_query(path: str, params: Mapping[str, Any]) -> str:
    if not params:
        return path
    items = []
    for key, value in params.items():
        if isinstance(value, bool):
            value = "true" if value else "false"
        items.append((key, str(value)))
    sep = "&" if "?" in path else "?"
    return path + sep + urllib.parse.urlencode(items)


def _parse_json(data: bytes) -> Any:
    text = data.decode("utf-8", "replace").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError as exc:
        raise GhError("response was not valid JSON") from exc


def _page_items(data: Any) -> List[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        lists = [v for v in data.values() if isinstance(v, list)]
        if len(lists) == 1:
            return lists[0]
    raise GhError("unexpected shape of a paginated response")


def _is_stale(errors: Iterable[Any]) -> bool:
    for err in errors:
        if not isinstance(err, dict):
            continue
        if str(err.get("type", "")).upper() == "STALE_DATA":
            return True
        msg = str(err.get("message", "")).lower()
        if any(marker in msg for marker in _STALE_MARKERS):
            return True
    return False


def _short(text: Any, limit: int = 120) -> str:
    text = " ".join(str(text).split())
    return text[:limit]


class GitHub:
    """GitHub REST/GraphQL access for one repository through the ``gh`` client."""

    def __init__(
        self,
        repo: Optional[str] = None,
        *,
        runner: Optional[Runner] = None,
        sleep: Callable[[float], None] = time.sleep,
        retries: int = 3,
    ):
        repo = repo or os.environ.get("ALT_REPO") or DEFAULT_REPO
        if not REPO_RE.match(repo):
            raise GhError("ALT_REPO must look like owner/name")
        self.repo = repo
        self._runner = runner or run_gh
        self._sleep = sleep
        self._retries = max(1, retries)

    # -- transport -----------------------------------------------------------------------------

    def _base_args(self, method: str) -> List[str]:
        return [
            "api",
            "--method",
            method,
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: " + API_VERSION,
        ]

    def _call(self, args: List[str], *, what: str, input: Optional[bytes] = None,
              stdout_path: Optional[str] = None, retry: bool = False) -> bytes:
        attempts = self._retries if retry else 1
        last: Optional[GhError] = None
        for attempt in range(attempts):
            proc = self._runner(args, input=input, stdout_path=stdout_path)
            if proc.returncode == 0:
                return proc.stdout or b""
            last = self._error(what, proc)
            transient = last.status is None or last.status >= 500 or last.status == 429
            if not transient or attempt + 1 >= attempts:
                break
            self._sleep(2.0 * (attempt + 1))
        assert last is not None
        raise last

    @staticmethod
    def _error(what: str, proc: "subprocess.CompletedProcess[bytes]") -> GhError:
        stderr = (proc.stderr or b"").decode("utf-8", "replace")
        match = _STATUS_RE.search(stderr)
        status = int(match.group(1)) if match else None
        detail = ""
        try:
            body = json.loads((proc.stdout or b"").decode("utf-8", "replace") or "null")
        except ValueError:
            body = None
        if isinstance(body, dict) and body.get("message"):
            detail = ": " + _short(body["message"])
        label = "HTTP %d" % status if status else "exit %d" % proc.returncode
        cls = NotFound if status == 404 else GhError
        return cls("%s failed (%s)%s" % (what, label, detail), status=status)

    def api(
        self,
        method: str,
        path: str,
        fields: Optional[Mapping[str, Any]] = None,
        json_body: Any = None,
        paginate: bool = False,
    ) -> Any:
        """Call a REST endpoint. ``fields`` become query parameters for GET, JSON members otherwise."""
        method = method.upper()
        if paginate:
            if method != "GET":
                raise ValueError("pagination is only supported for GET")
            return self._paginate(path, fields)
        url = path
        body = json_body
        if fields:
            if method in ("GET", "HEAD"):
                url = _with_query(path, fields)
            else:
                merged = dict(json_body or {})
                merged.update(fields)
                body = merged
        args = self._base_args(method)
        data = None
        if body is not None:
            args += ["-H", "Content-Type: application/json", "--input", "-"]
            data = json.dumps(body).encode("utf-8")
        args.append(url)
        out = self._call(args, what="%s %s" % (method, path), input=data, retry=method == "GET")
        return _parse_json(out)

    def _paginate(self, path: str, fields: Optional[Mapping[str, Any]]) -> List[Any]:
        items: List[Any] = []
        for page in range(1, MAX_PAGES + 1):
            params = dict(fields or {})
            params["per_page"] = PER_PAGE
            params["page"] = page
            batch = _page_items(self.api("GET", path, fields=params))
            items.extend(batch)
            if len(batch) < PER_PAGE:
                return items
        raise GhError("GET %s: more than %d pages" % (path, MAX_PAGES))

    def graphql(self, query: str, variables: Optional[Mapping[str, Any]] = None) -> Any:
        body = json.dumps({"query": query, "variables": dict(variables or {})}).encode("utf-8")
        args = ["api", "graphql", "-H", "Content-Type: application/json", "--input", "-"]
        proc = self._runner(args, input=body, stdout_path=None)
        try:
            data = _parse_json(proc.stdout or b"")
        except GhError:
            data = None
        errors = data.get("errors") if isinstance(data, dict) else None
        if errors:
            if _is_stale(errors):
                raise HeadMoved("branch head moved")
            first = errors[0].get("message", "") if isinstance(errors[0], dict) else errors[0]
            raise GraphQLError("GraphQL request failed: " + _short(first))
        if proc.returncode != 0:
            stderr = (proc.stderr or b"").decode("utf-8", "replace").lower()
            if any(marker in stderr for marker in _STALE_MARKERS):
                raise HeadMoved("branch head moved")
            raise self._error("POST graphql", proc)
        if not isinstance(data, dict) or "data" not in data:
            raise GraphQLError("GraphQL response had no data")
        return data["data"]

    # -- releases ------------------------------------------------------------------------------

    def _repo_path(self, suffix: str) -> str:
        return "repos/%s/%s" % (self.repo, suffix)

    def list_releases(self) -> List[Dict[str, Any]]:
        """All releases (drafts included when the token may see them). Raises on any page error."""
        raw = self.api("GET", self._repo_path("releases"), paginate=True)
        seen = set()
        out: List[Dict[str, Any]] = []
        for rel in raw:
            if not isinstance(rel, dict) or not isinstance(rel.get("id"), int) or "tag_name" not in rel:
                raise GhError("release listing contained an unexpected item")
            if rel["id"] in seen:
                continue
            seen.add(rel["id"])
            out.append(rel)
        return out

    def get_release(self, release_id: int) -> Dict[str, Any]:
        return self.api("GET", self._repo_path("releases/%d" % int(release_id)))

    def get_release_by_tag(self, tag: str) -> Optional[Dict[str, Any]]:
        """The release for ``tag``: published via the tag endpoint, drafts via the full listing."""
        try:
            return self.api("GET", self._repo_path("releases/tags/" + urllib.parse.quote(tag, safe="")))
        except NotFound:
            pass
        matches = [r for r in self.list_releases() if r.get("tag_name") == tag]
        published = [r for r in matches if not r.get("draft")]
        if published:
            return published[0]
        if len(matches) > 1:
            raise GhError("more than one draft release uses tag %s" % tag)
        return matches[0] if matches else None

    def list_assets(self, release_id: int) -> List[Dict[str, Any]]:
        return self.api("GET", self._repo_path("releases/%d/assets" % int(release_id)), paginate=True)

    def create_draft(self, tag: str, target: str, name: str, body: str, prerelease: bool) -> Dict[str, Any]:
        return self.api("POST", self._repo_path("releases"), json_body={
            "tag_name": tag,
            "target_commitish": target,
            "name": name,
            "body": body,
            "draft": True,
            "prerelease": bool(prerelease),
        })

    def update_release(self, release_id: int, **fields: Any) -> Dict[str, Any]:
        # A PATCH without tag_name, sent with a workflow token, can detach a draft from its tag:
        # GitHub then publishes it under an "untagged-..." tag. Always restate the tag.
        if "tag_name" not in fields:
            tag = str(self.get_release(release_id).get("tag_name") or "")
            if tag and not tag.startswith("untagged-"):
                fields["tag_name"] = tag
        return self.api("PATCH", self._repo_path("releases/%d" % int(release_id)), json_body=fields)

    def upload_asset(self, release_id: int, path: str, name: str,
                     content_type: str = "application/octet-stream") -> Dict[str, Any]:
        url = "%s/repos/%s/releases/%d/assets?name=%s" % (
            UPLOADS_HOST, self.repo, int(release_id), urllib.parse.quote(name, safe=""))
        args = self._base_args("POST") + ["-H", "Content-Type: " + content_type,
                                          "--input", os.path.abspath(path), url]
        out = self._call(args, what="POST release asset upload")
        return _parse_json(out)

    def update_asset(self, asset_id: int, **fields: Any) -> Dict[str, Any]:
        """PATCH a release asset (``name``, ``label``)."""
        return self.api("PATCH", self._repo_path("releases/assets/%d" % int(asset_id)), json_body=fields)

    def delete_asset(self, asset_id: int) -> None:
        self.api("DELETE", self._repo_path("releases/assets/%d" % int(asset_id)))

    def publish(self, release_id: int, prerelease: bool, make_latest: str = "false") -> Dict[str, Any]:
        return self.update_release(release_id, draft=False, prerelease=bool(prerelease), make_latest=make_latest)

    def unpublish(self, release_id: int, name: Optional[str] = None) -> Dict[str, Any]:
        """Turn a published release back into a draft (optionally retitled in the same request)."""
        if name is None:
            return self.update_release(release_id, draft=True)
        return self.update_release(release_id, draft=True, name=name)

    def delete_release(self, release_id: int) -> None:
        self.api("DELETE", self._repo_path("releases/%d" % int(release_id)))

    def download_asset(self, asset_id: int, dest: str) -> str:
        args = ["api", "--method", "GET", "-H", "Accept: application/octet-stream",
                "-H", "X-GitHub-Api-Version: " + API_VERSION,
                self._repo_path("releases/assets/%d" % int(asset_id))]
        try:
            self._call(args, what="GET release asset download", stdout_path=dest, retry=True)
        except GhError:
            if os.path.exists(dest):
                os.unlink(dest)
            raise
        return dest

    # -- actions -------------------------------------------------------------------------------

    def dispatch_workflow(self, file: str, ref: str, inputs: Optional[Mapping[str, Any]] = None) -> Any:
        path = self._repo_path("actions/workflows/%s/dispatches" % urllib.parse.quote(file, safe=""))
        return self.api("POST", path, json_body={"ref": ref, "inputs": dict(inputs or {})})

    def delete_artifact(self, artifact_id: int) -> None:
        self.api("DELETE", self._repo_path("actions/artifacts/%d" % int(artifact_id)))

    # -- git data ------------------------------------------------------------------------------

    def head_oid(self, branch: str = "main") -> str:
        ref = self.api("GET", self._repo_path("git/ref/heads/" + urllib.parse.quote(branch, safe="")))
        return ref["object"]["sha"]

    def commit_files(self, branch: str, expected_head: str, additions: Mapping[str, bytes],
                     deletions: Iterable[str], message: str) -> str:
        """Create one commit on ``branch`` via createCommitOnBranch; returns the new commit oid."""
        deletions = sorted(set(deletions))
        if not additions and not deletions:
            raise ValueError("commit_files needs at least one change")
        changes: Dict[str, Any] = {}
        if additions:
            changes["additions"] = [
                {"path": path, "contents": base64.b64encode(additions[path]).decode("ascii")}
                for path in sorted(additions)
            ]
        if deletions:
            changes["deletions"] = [{"path": path} for path in deletions]
        payload = {
            "branch": {"repositoryNameWithOwner": self.repo, "branchName": branch},
            "expectedHeadOid": expected_head,
            "message": {"headline": message},
            "fileChanges": changes,
        }
        data = self.graphql(COMMIT_MUTATION, {"input": payload})
        try:
            return data["createCommitOnBranch"]["commit"]["oid"]
        except (KeyError, TypeError) as exc:
            raise GraphQLError("createCommitOnBranch returned no commit") from exc


# -- module-level API backed by a replaceable default client -------------------------------------

_client: Optional[GitHub] = None


def client() -> GitHub:
    global _client
    if _client is None:
        _client = GitHub()
    return _client


def set_client(new: Optional[GitHub]) -> Optional[GitHub]:
    """Replace the default client (tests); returns the previous one."""
    global _client
    previous, _client = _client, new
    return previous


def api(method, path, fields=None, json_body=None, paginate=False):
    return client().api(method, path, fields=fields, json_body=json_body, paginate=paginate)


def graphql(query, variables=None):
    return client().graphql(query, variables)


def list_releases():
    return client().list_releases()


def get_release(release_id):
    return client().get_release(release_id)


def get_release_by_tag(tag):
    return client().get_release_by_tag(tag)


def list_assets(release_id):
    return client().list_assets(release_id)


def create_draft(tag, target, name, body, prerelease):
    return client().create_draft(tag, target, name, body, prerelease)


def update_release(release_id, **fields):
    return client().update_release(release_id, **fields)


def upload_asset(release_id, path, name, content_type="application/octet-stream"):
    return client().upload_asset(release_id, path, name, content_type)


def update_asset(asset_id, **fields):
    return client().update_asset(asset_id, **fields)


def delete_asset(asset_id):
    return client().delete_asset(asset_id)


def publish(release_id, prerelease, make_latest="false"):
    return client().publish(release_id, prerelease, make_latest)


def unpublish(release_id, name=None):
    return client().unpublish(release_id, name)


def delete_release(release_id):
    return client().delete_release(release_id)


def download_asset(asset_id, dest):
    return client().download_asset(asset_id, dest)


def dispatch_workflow(file, ref, inputs=None):
    return client().dispatch_workflow(file, ref, inputs)


def delete_artifact(artifact_id):
    return client().delete_artifact(artifact_id)


def head_oid(branch="main"):
    return client().head_oid(branch)


def commit_files(branch, expected_head, additions, deletions, message):
    return client().commit_files(branch, expected_head, additions, deletions, message)


# -- GitHub Actions step outputs ----------------------------------------------------------------

_OUTPUT_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


def format_output(key: str, value: Any) -> str:
    if not _OUTPUT_KEY_RE.match(key):
        raise ValueError("invalid output name")
    if isinstance(value, bool):
        value = "true" if value else "false"
    value = "" if value is None else str(value)
    if "\n" in value or "\r" in value:
        delim = "ALT_EOF_" + uuid.uuid4().hex
        return "%s<<%s\n%s\n%s\n" % (key, delim, value, delim)
    return "%s=%s\n" % (key, value)


def write_outputs(values: Mapping[str, Any], path: Optional[str] = None,
                  environ: Optional[Mapping[str, str]] = None) -> bool:
    """Append ``values`` to ``$GITHUB_OUTPUT`` (or ``path``). Returns False when there is no target."""
    env = os.environ if environ is None else environ
    target = path or env.get("GITHUB_OUTPUT")
    if not target:
        return False
    with open(target, "a", encoding="utf-8") as fh:
        for key, value in values.items():
            fh.write(format_output(key, value))
    return True

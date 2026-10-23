"""Command line entry point: ``python3 -m altsource <command> ...``.

Exit codes: 0 ok, 2 gate rejected, 3 conflict, 1 anything else (including command line usage
errors, which argparse would otherwise report with 2). Output is limited to rule ids,
counts, in-IPA relative paths and public catalog data; error details of foreign exceptions are
withheld when running inside GitHub Actions.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import sys
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, TextIO

from .gh import GhError, write_outputs
from .stage import (
    ARCHIVE_ERRORS,
    Conflict,
    GateRejected,
    StageError,
    Toolkit,
    blocking,
    draft_tags,
    errors_of,
    field,
    finding_dicts,
    parse_semver,
    rule_of,
    stage,
    stage_existing_draft,
    validate_app_json,
)
from .sync import SyncAborted, SyncError, dumps_json, sync

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REJECTED = 2
EXIT_CONFLICT = 3

RUNNERS = ("xcode-27", "macos-26", "macos-15", "macos-latest")
DEFAULT_RUNNER = "macos-latest"
SETUP_TOOLS = ("go", "xcodegen", "xcbeautify", "ldid")
BUILD_KEYS = ("runner", "xcode", "setup", "command", "ipa_glob", "env")
DEFAULT_IPA_GLOB = "**/*.ipa"
XCODE_RE = re.compile(r"^\d+(\.\d+){0,2}$")
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
# Names a private build configuration may not set: the runner's own variables, and variables that
# make an interpreter, shell, git, ssh, brew or a TLS client load code or trust from elsewhere. The
# build job must still scope the build env to the build step alone.
RESERVED_ENV = frozenset((
    "PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "OLDPWD", "TMPDIR", "TMP", "TEMP", "IFS", "ENV",
    "CI", "VERSION", "ALT_OUT", "CDPATH", "GLOBIGNORE", "PROMPT_COMMAND", "PS4", "SHELLOPTS", "BASHOPTS",
    "ZDOTDIR", "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED",
    "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "DEVELOPER_DIR", "EDITOR", "VISUAL", "PAGER",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "REQUESTS_CA_BUNDLE",
))
RESERVED_ENV_PREFIXES = ("GITHUB_", "RUNNER_", "ACTIONS_", "ALT_", "GH_", "INPUT_", "DYLD_", "LD_",
                         "PYTHON", "PERL", "RUBY", "BASH_", "GIT_", "SSH_", "HOMEBREW_", "XDG_",
                         "SSL_", "CURL_", "OPENSSL_", "SUDO_")
# resolve-build outputs that may appear in job outputs and logs; command, env and ipa_glob come from
# the private repository and are only written to --json-out
PUBLIC_BUILD_OUTPUTS = ("runner", "xcode", "setup", "version", "tag")
MASK_MIN_LENGTH = 3
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SEMVER_PATTERN = (r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
                  r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
DEFAULT_TAG_PATTERN = r"^v(?P<version>" + SEMVER_PATTERN + r")$"
BUILD_CONFIG_MAX_BYTES = 64 * 1024
_HOME_PATH = re.compile(r"(/Users/|/home/|[A-Za-z]:\\Users\\)", re.I)


class CliError(Exception):
    """A usage or configuration problem; the message is safe to print."""


class UsageError(Exception):
    """Invalid command line. Raised instead of argparse's ``sys.exit(2)``: exit 2 means "gate rejected"."""

    def __init__(self, usage: str, message: str):
        super().__init__(message)
        self.usage = usage


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # type: ignore[override]
        raise UsageError(self.format_usage(), message)


def _redact_usage(message: str) -> str:
    """Drop argument values from an argparse message (they may come from private workflow inputs)."""
    message = re.sub(r"^(unrecognized arguments):.*$", r"\1", message, flags=re.S)
    return re.sub(r"'[^']*'", "'…'", message)


@dataclasses.dataclass
class Context:
    deps: Any
    environ: Mapping[str, str]
    out: TextIO
    err: TextIO
    gh_factory: Callable[[], Any]
    git: Any = None
    _gh: Any = None

    @property
    def gh(self) -> Any:
        if self._gh is None:
            self._gh = self.gh_factory()
        return self._gh

    @property
    def in_ci(self) -> bool:
        return self.environ.get("GITHUB_ACTIONS") == "true"

    def print(self, text: str = "") -> None:
        self.out.write(text + "\n")

    def eprint(self, text: str) -> None:
        self.err.write(text + "\n")

    def outputs(self, values: Mapping[str, Any]) -> None:
        write_outputs(values, environ=self.environ)


# -- shared helpers -------------------------------------------------------------------------------

def load_denylist(path: Optional[str], environ: Mapping[str, str]) -> List[str]:
    """Denylist from ``--denylist-file`` or ``ALT_DENYLIST`` (newline separated); fail closed."""
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                text: Optional[str] = fh.read()
        except (OSError, UnicodeDecodeError):
            raise CliError("denylist file cannot be read") from None
    else:
        text = environ.get("ALT_DENYLIST")
    if text is None:
        raise CliError("denylist missing: set ALT_DENYLIST or pass --denylist-file")
    words = [line.strip() for line in text.splitlines()]
    words = [w for w in words if w and not w.startswith("#")]
    if not words:
        raise CliError("denylist is empty")
    return words


def safe_path(path: str, denylist: Sequence[str]) -> str:
    lowered = path.lower()
    if _HOME_PATH.search(path) or any(w.lower() in lowered for w in denylist):
        return "<redacted>"
    return path


def print_findings(ctx: Context, findings: Sequence[Dict[str, Any]], denylist: Sequence[str],
                   to_stderr: bool = False) -> None:
    emit = ctx.eprint if to_stderr else ctx.print
    for f in findings:
        emit("%s %s %d" % (f.get("rule"), f.get("severity"), int(f.get("count") or 0)))
        for path in f.get("paths") or []:
            emit("  " + safe_path(str(path), denylist))


def read_text_file(path: Optional[str]) -> str:
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        raise CliError("file cannot be read as UTF-8 text") from None


def to_plain(obj: Any) -> Any:
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return obj.to_dict()
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, dict):
        return obj
    return dict(vars(obj))


def _policy(ctx: Context, allow_home_paths: bool) -> Any:
    if allow_home_paths:
        return ctx.deps.GatePolicy(allow_home_paths=True)
    return ctx.deps.GatePolicy()


def _stage_outputs(ctx: Context, result: Any) -> None:
    values = {
        "tag": result.tag,
        "release_id": result.release_id or "",
        "asset": result.asset or "",
        "sha256": result.sha256,
        "size": result.size,
        "published": result.published,
        "noop": result.noop,
    }
    for key, value in values.items():
        if isinstance(value, bool):
            value = "true" if value else "false"
        ctx.print("%s=%s" % (key, value))
    ctx.outputs(values)
    for warning in result.warnings:
        ctx.eprint("warning: %s %s %d" % (warning.get("rule"), warning.get("severity"), warning.get("count", 0)))


# -- commands -------------------------------------------------------------------------------------

def cmd_inspect(args, ctx: Context) -> int:
    info = ctx.deps.inspect_ipa(args.ipa)
    data = to_plain(info)
    if args.json:
        ctx.print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False, default=str))
        return EXIT_OK
    for key in ("bundle_id", "short_version", "build_version", "name", "min_os", "signature"):
        if key in data:
            ctx.print("%s: %s" % (key, data[key]))
    for key in ("entitlements", "extensions", "localizations"):
        if key in data:
            ctx.print("%s: %d" % (key, len(data[key] or [])))
    return EXIT_OK


def cmd_normalize(args, ctx: Context) -> int:
    report = ctx.deps.normalize_ipa(args.src, args.dst)
    ctx.print(json.dumps(to_plain(report), indent=2, sort_keys=True, ensure_ascii=False, default=str))
    return EXIT_OK


def cmd_scan(args, ctx: Context) -> int:
    denylist = load_denylist(args.denylist_file, ctx.environ)
    try:
        result = ctx.deps.scan_ipa(args.ipa, denylist=denylist, policy=_policy(ctx, args.allow_home_paths))
    except errors_of(ctx.deps, "IpaError") + ARCHIVE_ERRORS as exc:
        ctx.print("%s block 1" % rule_of(exc, "ipa-invalid"))
        return EXIT_REJECTED
    findings = finding_dicts(field(result, "findings", []))
    print_findings(ctx, findings, denylist)
    if blocking(findings) or not field(result, "ok", True):
        ctx.eprint("gate: rejected")
        return EXIT_REJECTED
    ctx.eprint("gate: passed")
    return EXIT_OK


def cmd_stage(args, ctx: Context) -> int:
    denylist = load_denylist(args.denylist_file, ctx.environ)
    notes = read_text_file(args.notes_file)
    result = stage(
        args.ipa,
        expected_bid=args.bid,
        semver=args.semver,
        notes=notes,
        denylist=denylist,
        policy=_policy(ctx, args.allow_home_paths),
        publish=not args.no_publish,
        dry_run=args.dry_run,
        app_json=args.app_json,
        gh=None if args.dry_run else ctx.gh,
        deps=ctx.deps,
    )
    _stage_outputs(ctx, result)
    return EXIT_OK


def cmd_stage_draft(args, ctx: Context) -> int:
    if bool(args.tag) == bool(args.all):
        raise CliError("pass either TAG or --all")
    denylist = load_denylist(args.denylist_file, ctx.environ)
    notes = read_text_file(args.notes_file) if args.notes_file else None
    policy = _policy(ctx, args.allow_home_paths)
    if args.tag:
        tags = [args.tag]
    else:
        tags, blocked = draft_tags(ctx.gh, ctx.deps)
        ctx.eprint("pending drafts: %d" % len(tags))
        if blocked:
            ctx.eprint("blocked drafts skipped: %d (stage one by tag to retry it)" % len(blocked))
    worst = EXIT_OK
    staged = []
    rejected = failed = 0
    for tag in tags:
        try:
            result = stage_existing_draft(tag, notes=notes, denylist=denylist, policy=policy,
                                          publish=not args.no_publish, dry_run=args.dry_run,
                                          gh=ctx.gh, deps=ctx.deps)
        except Exception as exc:  # one bad draft must not stop the others
            code = report_error(ctx, exc, denylist, prefix=tag + ": ")
            if code == EXIT_REJECTED:
                rejected += 1
            else:
                failed += 1
            worst = max(worst, code)
            continue
        if args.tag:
            _stage_outputs(ctx, result)
        else:
            ctx.print("%s published=%s noop=%s" % (
                tag, "true" if result.published else "false", "true" if result.noop else "false"))
        staged.append(tag)
    counts: Dict[str, Any] = {"staged": len(staged)} if args.all else {}
    counts.update(rejected=rejected, failed=failed)
    ctx.outputs(counts)
    return EXIT_OK if args.exit_zero else worst


def cmd_sync(args, ctx: Context) -> int:
    denylist = load_denylist(args.denylist_file, ctx.environ)
    result = sync(args.root, commit=not args.no_commit, dry_run=args.dry_run, denylist=denylist,
                  rescan=args.rescan, gh=ctx.gh, git=ctx.git, deps=ctx.deps, log=ctx.eprint,
                  environ=ctx.environ)
    ctx.print("changed=%s" % ("true" if result.changed else "false"))
    ctx.print("apps=%d versions=%d" % (result.apps, result.versions))
    if result.commit:
        ctx.print("commit=%s" % result.commit)
    ctx.print("blocked=%d errors=%d" % (len(result.blocked), len(result.errors)))
    ctx.print("normalized=%d" % len(result.normalized))
    if args.exit_zero:
        return EXIT_OK
    if result.blocked:
        return EXIT_REJECTED
    if result.errors:
        return EXIT_ERROR
    return EXIT_OK


def cmd_generate(args, ctx: Context) -> int:
    data = dumps_json(ctx.deps.generate_source(os.path.abspath(args.root)))
    path = os.path.join(args.root, "source.json")
    if args.check:
        try:
            with open(path, "rb") as fh:
                current = fh.read()
        except OSError:
            current = None
        if current != data:
            ctx.eprint("source.json is out of date; run generate")
            return EXIT_ERROR
        ctx.eprint("source.json is up to date")
        return EXIT_OK
    with open(path, "wb") as fh:
        fh.write(data)
    ctx.eprint("source.json written")
    return EXIT_OK


def cmd_validate(args, ctx: Context) -> int:
    failed = False
    path = os.path.join(args.root, "source.json")
    try:
        with open(path, "rb") as fh:
            obj = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        ctx.eprint("source.json: missing or not valid JSON")
        return EXIT_ERROR
    for message in ctx.deps.validate_source(obj) or []:
        message = str(message)
        if message.lower().startswith("warning"):
            ctx.eprint("source.json: " + message)
        else:
            failed = True
            ctx.print("source.json: " + message)
    apps_dir = os.path.join(args.root, "apps")
    for bid in sorted(os.listdir(apps_dir)) if os.path.isdir(apps_dir) else []:
        app_path = os.path.join(apps_dir, bid, "app.json")
        if not os.path.exists(app_path):
            continue
        try:
            with open(app_path, "rb") as fh:
                app = json.loads(fh.read().decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            app = None
        errors = validate_app_json(app) if app is not None else ["not valid JSON"]
        for message in errors:
            failed = True
            ctx.print("apps/%s/app.json: %s" % (bid, message))
    if failed:
        return EXIT_ERROR
    ctx.eprint("valid")
    return EXIT_OK


def cmd_fetch(args, ctx: Context) -> int:
    kwargs = {"sha256": args.sha256} if args.sha256 else {}
    try:
        ctx.deps.fetch(args.url, args.out, **kwargs)
    except errors_of(ctx.deps, "FetchError") as exc:
        raise CliError("fetch rejected (%s)" % rule_of(exc, "fetch-error")) from None
    digest = hashlib.sha256()
    with open(args.out, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    values = {"sha256": digest.hexdigest(), "size": os.path.getsize(args.out)}
    for key, value in values.items():
        ctx.print("%s=%s" % (key, value))
    ctx.outputs(values)
    return EXIT_OK


def cmd_parse_tag(args, ctx: Context) -> int:
    try:
        bid, semver = ctx.deps.parse_tag(args.tag)
    except errors_of(ctx.deps, "TagError") + (ValueError,):
        raise CliError("tag does not match the grammar") from None
    values = {
        "bid": str(bid),
        "semver": str(semver),
        "prerelease": bool(field(parse_semver(ctx.deps, str(semver)), "prerelease")),
        "alias": ctx.deps.alias_for(str(bid)),
    }
    for key, value in values.items():
        if isinstance(value, bool):
            value = "true" if value else "false"
        ctx.print("%s=%s" % (key, value))
    ctx.outputs(values)
    return EXIT_OK


def cmd_alias(args, ctx: Context) -> int:
    ctx.print(ctx.deps.alias_for(args.bid))
    return EXIT_OK


# -- resolve-build ----------------------------------------------------------------------------------

def _read_json_limited(path: str, what: str) -> Any:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(BUILD_CONFIG_MAX_BYTES + 1)
    except OSError:
        raise CliError("%s cannot be read" % what) from None
    if len(raw) > BUILD_CONFIG_MAX_BYTES:
        raise CliError("%s is too large" % what)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise CliError("%s is not valid JSON" % what) from None


def _names(names: Sequence[str], reveal: bool) -> str:
    """Key names from private configuration are shown only outside CI."""
    return ": " + ", ".join(names) if reveal else ""


def _build_section(obj: Any, what: str, reveal: bool = False) -> Dict[str, Any]:
    if obj is None:
        return {}
    if not isinstance(obj, dict):
        raise CliError("%s must be a JSON object" % what)
    unknown = sorted(str(k) for k in obj if k not in BUILD_KEYS)
    if unknown:
        raise CliError("%s has %d unknown key(s)%s" % (what, len(unknown), _names(unknown, reveal)))
    return obj


def _validate_env(env: Any, reveal: bool = False) -> Dict[str, str]:
    if not isinstance(env, dict):
        raise CliError("build env must be an object of strings")
    if len(env) > 32:
        raise CliError("build env has too many entries")
    out = {}
    for position, key in enumerate(sorted(env, key=str), 1):
        value = env[key]
        label = "build env entry %d%s" % (position, " (%s)" % key if reveal else "")
        if not isinstance(key, str) or not ENV_KEY_RE.match(key):
            raise CliError("%s: names must match [A-Z][A-Z0-9_]*" % label)
        if key in RESERVED_ENV or key.startswith(RESERVED_ENV_PREFIXES):
            raise CliError("%s: the name is reserved" % label)
        if not isinstance(value, str) or len(value) > 4096 or any(c in value for c in "\0\r\n"):
            raise CliError("%s: the value must be a single-line string" % label)
        out[key] = value
    return out


def _validate_glob(pattern: Any) -> str:
    if not isinstance(pattern, str) or not pattern or len(pattern) > 256:
        raise CliError("ipa_glob must be a non-empty string")
    if pattern.startswith(("/", "~")) or "\\" in pattern or any(c in pattern for c in "\0\r\n$`"):
        raise CliError("ipa_glob must be a relative glob")
    if any(part == ".." for part in pattern.split("/")):
        raise CliError("ipa_glob must stay inside the checkout")
    if not pattern.lower().endswith(".ipa"):
        raise CliError("ipa_glob must end with .ipa")
    return pattern


def resolve_build(bid: str, ref: str, checkout: str, *, root: str, config_json: Optional[str],
                  deps: Any, reveal_names: bool = False) -> Dict[str, Any]:
    """Merge ``.alt.json`` (checkout) with the registered build config and validate the result.

    Error messages name keys of the private configuration only when ``reveal_names`` is set.
    The result has ``repo`` removed; the caller decides which values may leave the job.
    """
    tag_errors = errors_of(deps, "TagError") + (ValueError,)
    try:
        deps.make_tag(bid, "0.0.0")
    except tag_errors:
        raise CliError("invalid bundle identifier") from None

    app = _read_json_limited(os.path.join(root, "apps", bid, "app.json"), "app.json")
    private = app.get("privateBuild") if isinstance(app, dict) else None
    if not isinstance(private, dict) or private.get("enabled") is not True:
        raise CliError("app.json does not enable privateBuild")
    pattern = private.get("tagPattern") or DEFAULT_TAG_PATTERN
    try:
        match = re.fullmatch(pattern, ref)
    except re.error:
        raise CliError("privateBuild.tagPattern is not a valid regex") from None
    if not match or "version" not in match.re.groupindex:
        raise CliError("ref does not match privateBuild.tagPattern")
    version = match.group("version")
    if not re.fullmatch(SEMVER_PATTERN, version or ""):
        raise CliError("version taken from ref is not semver")
    try:
        tag = deps.make_tag(bid, version)
    except tag_errors:
        raise CliError("version taken from ref does not fit the tag grammar") from None

    if not config_json:
        raise CliError("ALT_APP_CONFIG is empty")
    try:
        config = json.loads(config_json)
    except ValueError:
        raise CliError("ALT_APP_CONFIG is not valid JSON") from None
    if not isinstance(config, dict) or not isinstance(config.get("repo"), str) \
            or not REPO_RE.match(config["repo"]):
        raise CliError("ALT_APP_CONFIG must contain repo as owner/name")
    unknown = sorted(str(k) for k in config if k not in ("repo", "build"))
    if unknown:
        raise CliError("ALT_APP_CONFIG has %d unknown key(s)%s" % (len(unknown), _names(unknown, reveal_names)))
    registered = _build_section(config.get("build"), "ALT_APP_CONFIG build", reveal_names)

    file_path = os.path.join(checkout, ".alt.json")
    in_repo = _build_section(_read_json_limited(file_path, ".alt.json"), ".alt.json", reveal_names) \
        if os.path.exists(file_path) else {}

    merged: Dict[str, Any] = {"runner": DEFAULT_RUNNER, "xcode": "", "setup": [], "ipa_glob": DEFAULT_IPA_GLOB}
    env: Dict[str, Any] = {}
    for layer in (in_repo, registered):  # the registered config wins
        for key, value in layer.items():
            if key == "env":
                if not isinstance(value, dict):
                    raise CliError("build env must be an object of strings")
                env.update(value)
            else:
                merged[key] = value

    runner = merged["runner"]
    if runner not in RUNNERS:
        raise CliError("runner must be one of %s" % ", ".join(RUNNERS))
    xcode = merged["xcode"]
    if not isinstance(xcode, str) or (xcode and not XCODE_RE.match(xcode)):
        raise CliError("xcode must look like 27 or 27.0 or 27.0.1")
    setup = merged["setup"]
    if isinstance(setup, str):
        setup = setup.split()
    if not isinstance(setup, list) or not all(isinstance(s, str) and s in SETUP_TOOLS for s in setup):
        raise CliError("setup may only list %s" % ", ".join(SETUP_TOOLS))
    command = merged.get("command")
    if not isinstance(command, str) or not command.strip() or len(command) > 8192 or "\0" in command:
        raise CliError("command must be a non-empty string")
    return {
        "runner": runner,
        "xcode": xcode,
        "setup": " ".join(dict.fromkeys(setup)),
        "command": command,
        "ipa_glob": _validate_glob(merged["ipa_glob"]),
        "env": json.dumps(_validate_env(env, reveal_names), sort_keys=True, separators=(",", ":")),
        "version": version,
        "tag": tag,
        "repo": config["repo"],
    }


def _mask_values(resolved: Mapping[str, Any]) -> List[str]:
    """Private strings of a resolved build: the repo, each command line, env values, the IPA glob."""
    values = [resolved["repo"]]
    values += resolved["command"].splitlines()
    values += list(json.loads(resolved["env"]).values())
    if resolved["ipa_glob"] != DEFAULT_IPA_GLOB:
        values.append(resolved["ipa_glob"])
    out = []
    for value in values:
        value = value.strip()
        if len(value) >= MASK_MIN_LENGTH and value not in out:
            out.append(value)
    return out


def _command_data(value: str) -> str:
    """Escape a value for a workflow command (the runner unescapes %25, %0D and %0A)."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def cmd_resolve_build(args, ctx: Context) -> int:
    """Validate the private build configuration.

    Only runner, xcode, setup, version and tag become outputs. The build command, its env and the IPA
    glob are written to ``--json-out`` only: job outputs end up in ``env:``/``run:`` lines that the
    public job log prints, and masked values are dropped from job outputs. The build job therefore
    runs resolve-build again with ``--json-out`` and reads the file. In GitHub Actions every private
    value is masked first, which covers the rest of the calling job.
    """
    resolved = resolve_build(args.bid, args.ref, args.checkout, root=args.root,
                             config_json=ctx.environ.get("ALT_APP_CONFIG"), deps=ctx.deps,
                             reveal_names=not ctx.in_ci)
    if ctx.in_ci:
        for value in _mask_values(resolved):
            ctx.print("::add-mask::" + _command_data(value))
    ctx.outputs({key: resolved[key] for key in PUBLIC_BUILD_OUTPUTS})
    if args.json_out:
        private = {k: v for k, v in resolved.items() if k != "repo"}
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(private, fh, indent=2, sort_keys=True)
            fh.write("\n")
    for key in PUBLIC_BUILD_OUTPUTS:
        ctx.print("%s=%s" % (key, resolved[key]))
    ctx.print("env=%d variable(s)" % len(json.loads(resolved["env"])))
    return EXIT_OK


# -- parser and dispatch ----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="altsource", description="Maintain an AltStore source from GitHub Releases.")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    denylist = _Parser(add_help=False)
    denylist.add_argument("--denylist-file", metavar="F", help="newline separated denylist "
                          "(default: ALT_DENYLIST environment variable)")
    rooted = _Parser(add_help=False)
    rooted.add_argument("--root", default=".", metavar="DIR", help="repository root (default: .)")

    p = sub.add_parser("inspect", help="print IPA facts")
    p.add_argument("ipa")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("normalize", help="deterministically re-pack an IPA")
    p.add_argument("src", metavar="IN")
    p.add_argument("dst", metavar="OUT")
    p.set_defaults(func=cmd_normalize)

    p = sub.add_parser("scan", parents=[denylist], help="run the leak gate on an IPA")
    p.add_argument("ipa")
    p.add_argument("--allow-home-paths", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("stage", parents=[denylist], help="gate an IPA, then draft and publish it")
    p.add_argument("ipa")
    p.add_argument("--bid", help="expected bundle identifier")
    p.add_argument("--semver", help="version for the tag (default: CFBundleShortVersionString)")
    p.add_argument("--notes-file", metavar="F")
    p.add_argument("--app-json", metavar="F", help="app.json seed attached to the release")
    p.add_argument("--no-publish", action="store_true", help="leave the release as a draft")
    p.add_argument("--dry-run", action="store_true", help="run the gate only; no GitHub calls")
    p.add_argument("--allow-home-paths", action="store_true")
    p.set_defaults(func=cmd_stage)

    p = sub.add_parser("stage-draft", parents=[denylist], help="gate and publish existing drafts")
    p.add_argument("tag", nargs="?")
    p.add_argument("--all", action="store_true", help="every pending draft with a grammar tag")
    p.add_argument("--notes-file", metavar="F", help="replace the draft's release notes")
    p.add_argument("--no-publish", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--allow-home-paths", action="store_true")
    p.add_argument("--exit-zero", action="store_true", help="exit 0 even when drafts were rejected or "
                   "failed; the counts are written as outputs rejected= and failed=")
    p.set_defaults(func=cmd_stage_draft)

    p = sub.add_parser("sync", parents=[denylist, rooted], help="regenerate and commit the catalog")
    p.add_argument("--no-commit", action="store_true", help="write files locally instead of committing")
    p.add_argument("--dry-run", action="store_true", help="report planned changes only")
    p.add_argument("--rescan", action="store_true", help="download and scan every published IPA again "
                   "(after a denylist change); cached records are not re-checked otherwise")
    p.add_argument("--exit-zero", action="store_true", help="exit 0 once the catalog is committed even "
                   "when releases were blocked; outputs blocked= and errors= carry the counts so a "
                   "later step can fail the run after the site is deployed")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("generate", parents=[rooted], help="write source.json from the repository")
    p.add_argument("--check", action="store_true", help="fail when source.json is out of date")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("validate", parents=[rooted], help="validate source.json and app.json files")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("fetch", help="download an IPA over https with SSRF checks")
    p.add_argument("url")
    p.add_argument("out")
    p.add_argument("--sha256", metavar="H")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("parse-tag", help="split a release tag into bundle id and semver")
    p.add_argument("tag")
    p.set_defaults(func=cmd_parse_tag)

    p = sub.add_parser("alias", help="secret-name alias for a bundle id")
    p.add_argument("bid")
    p.set_defaults(func=cmd_alias)

    p = sub.add_parser("resolve-build", parents=[rooted], help="resolve the private build configuration")
    p.add_argument("--bid", required=True)
    p.add_argument("--ref", required=True)
    p.add_argument("--checkout", required=True, metavar="DIR")
    p.add_argument("--json-out", metavar="F", help="write the full configuration (command, env, ipa_glob) "
                   "as JSON; outputs only carry runner, xcode, setup, version and tag")
    p.set_defaults(func=cmd_resolve_build)
    return parser


_SAFE_ERRORS = (CliError, StageError, SyncError, GhError)


def report_error(ctx: Context, exc: BaseException, denylist: Sequence[str] = (), prefix: str = "") -> int:
    if isinstance(exc, GateRejected):
        ctx.eprint("%sgate rejected: %s" % (prefix, exc))
        print_findings(ctx, exc.findings, denylist, to_stderr=True)
        return EXIT_REJECTED
    if isinstance(exc, Conflict):
        ctx.eprint("%sconflict: %s" % (prefix, exc))
        return EXIT_CONFLICT
    if isinstance(exc, SyncAborted):
        ctx.eprint("%serror: %s" % (prefix, exc))
        for detail in exc.details:
            ctx.eprint("  " + str(detail))
        return EXIT_ERROR
    if isinstance(exc, _SAFE_ERRORS):
        ctx.eprint("%serror: %s" % (prefix, exc))
        return EXIT_ERROR
    if isinstance(exc, ImportError) and str(getattr(exc, "name", "") or "").startswith("altsource."):
        ctx.eprint("%serror: module %s is not available" % (prefix, exc.name))
        return EXIT_ERROR
    rule = rule_of(exc, "")
    if rule:
        ctx.eprint("%serror: %s (%s)" % (prefix, type(exc).__name__, rule))
    elif ctx.in_ci:
        ctx.eprint("%serror: %s" % (prefix, type(exc).__name__))
    else:
        ctx.eprint("%serror: %s: %s" % (prefix, type(exc).__name__, exc))
    return EXIT_ERROR


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    deps: Any = None,
    gh: Any = None,
    git: Any = None,
    environ: Optional[Mapping[str, str]] = None,
    out: Optional[TextIO] = None,
    err: Optional[TextIO] = None,
) -> int:
    env = os.environ if environ is None else environ
    err = err or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except UsageError as exc:
        message = str(exc)
        if env.get("GITHUB_ACTIONS") == "true":
            message = _redact_usage(message)
        err.write(exc.usage)
        err.write("altsource: error: %s\n" % message)
        return EXIT_ERROR

    def make_gh() -> Any:
        if gh is not None:
            return gh
        from . import gh as ghmod

        return ghmod.client()

    ctx = Context(
        deps=deps if deps is not None else Toolkit(),
        environ=env,
        out=out or sys.stdout,
        err=err,
        gh_factory=make_gh,
        git=git,
    )
    try:
        return args.func(args, ctx)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        denylist: Sequence[str] = ()
        if isinstance(exc, GateRejected):
            try:
                denylist = load_denylist(getattr(args, "denylist_file", None), ctx.environ)
            except CliError:
                denylist = ()
        return report_error(ctx, exc, denylist)

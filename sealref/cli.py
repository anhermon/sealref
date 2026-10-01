"""CLI entry points."""
import base64
import os
import subprocess
import sys
import urllib.parse

from . import store

PROG = os.environ.get("SEALREF_PROG", "sealref")  # "vaultlet" when run via the legacy command

REDACT_MIN_LEN = 4
DEFAULT_PORT = 8765
DEFAULT_TIMEOUT = 300

USAGE = """usage: {prog} <command> [args...]

commands:
  groups
  keys <group>
  ui [--port N]
  request <group> <key> [--reason TEXT]
  run [--group G]... [--ref sealref://g/k[=ENVNAME]]... -- <cmd> [args...]

refs: sealref://group/key and legacy vaultlet://group/key are both accepted.
Output refs default to vaultlet://; use --ref-scheme sealref (before the
command) or SEALREF_REF_SCHEME=sealref to print sealref://.
"""


def _build_needles(secrets):
    """secrets: list of (group, key, value). Returns [(needle, replacement), ...]
    sorted longest-needle-first so a value containing another value is
    replaced correctly."""
    needles = []
    for group, key, value in secrets:
        if len(value) < REDACT_MIN_LEN:
            print(
                f"{PROG}: warning: value for {group}/{key} is shorter than "
                f"{REDACT_MIN_LEN} chars, not redacting",
                file=sys.stderr,
            )
            continue
        replacement = f"«redacted:{group}/{key}»"
        variants = {
            value,
            base64.b64encode(value.encode()).decode(),
            urllib.parse.quote(value, safe=""),
        }
        for v in variants:
            needles.append((v, replacement))
    needles.sort(key=lambda pair: len(pair[0]), reverse=True)
    return needles


def _redact_line(line, needles):
    for needle, replacement in needles:
        if needle:
            line = line.replace(needle, replacement)
    return line


def cmd_groups(rest):
    for group in store.list_groups():
        print(group)
    return 0


def cmd_keys(rest):
    if len(rest) != 1:
        print(f"{PROG}: usage: {PROG} keys <group>", file=sys.stderr)
        return 2
    group = rest[0]
    for key in store.list_keys(group):
        print(f"{key}  {store.ref(group, key)}")
    return 0


def cmd_ui(rest):
    port = DEFAULT_PORT
    if "--port" in rest:
        try:
            port = int(rest[rest.index("--port") + 1])
        except (IndexError, ValueError):
            raise ValueError("--port requires an integer")
    try:
        from .ui import serve
    except ImportError:
        print(f"{PROG}: ui.py not implemented yet", file=sys.stderr)
        return 1
    serve(port=port)
    return 0


def cmd_request(rest):
    reason = None
    positional = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--reason":
            i += 1
            if i >= len(rest):
                raise ValueError("--reason requires an argument")
            reason = rest[i]
        else:
            positional.append(a)
        i += 1
    if len(positional) != 2:
        print(f"{PROG}: usage: {PROG} request <group> <key> [--reason TEXT]", file=sys.stderr)
        return 2
    group, key = positional
    try:
        from .ui import serve_until
    except ImportError:
        print(f"{PROG}: ui.py not implemented yet", file=sys.stderr)
        return 1
    ok = serve_until(group, key, reason, timeout=DEFAULT_TIMEOUT)
    if not ok:
        print(f"{PROG}: timed out waiting for secret", file=sys.stderr)
        return 1
    print(store.ref(group, key))
    return 0


def _parse_run_args(rest):
    """Returns (groups, refs, child_cmd) or raises ValueError."""
    groups = []
    refs = []
    i = 0
    child_cmd = None
    while i < len(rest):
        a = rest[i]
        if a == "--":
            child_cmd = rest[i + 1:]
            break
        elif a == "--group":
            i += 1
            if i >= len(rest):
                raise ValueError("--group requires an argument")
            groups.append(rest[i])
        elif a == "--ref":
            i += 1
            if i >= len(rest):
                raise ValueError("--ref requires an argument")
            refs.append(rest[i])
        else:
            raise ValueError(f"unexpected argument {a!r}")
        i += 1
    if child_cmd is None or not child_cmd:
        raise ValueError("run requires -- <cmd> [args...]")
    return groups, refs, child_cmd


def cmd_run(rest):
    try:
        groups, refs, child_cmd = _parse_run_args(rest)
    except ValueError as e:
        print(f"{PROG}: {e}", file=sys.stderr)
        return 2

    import os

    env = os.environ.copy()
    secrets = []  # (group, key, value)

    for group in groups:
        for key, value in store._resolve_group(group).items():
            env[key] = value
            secrets.append((group, key, value))

    for r in refs:
        ref_str, _, envname = r.partition("=")
        group, key = store.parse_ref(ref_str)
        value = store._resolve(group, key)
        env[envname or key] = value
        secrets.append((group, key, value))

    needles = _build_needles(secrets)

    # Known limit: line-buffered redaction. A value split across a line boundary,
    # or emitted without a trailing newline right at a read chunk edge, can
    # slip through unredacted. Upgrade to a rolling-buffer scanner if that
    # ever bites for this personal tool.
    proc = subprocess.Popen(
        child_cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        bufsize=1,
    )
    try:
        for line in proc.stdout:
            sys.stdout.write(_redact_line(line, needles))
            sys.stdout.flush()
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        return 130
    return proc.returncode


COMMANDS = {
    "groups": cmd_groups,
    "keys": cmd_keys,
    "ui": cmd_ui,
    "request": cmd_request,
    "run": cmd_run,
}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE.format(prog=PROG), end="")
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    if argv[0] == "--ref-scheme" and len(argv) > 1:
        os.environ["SEALREF_REF_SCHEME"], argv = argv[1], argv[2:]
    elif argv[0].startswith("--ref-scheme="):
        os.environ["SEALREF_REF_SCHEME"], argv = argv[0].split("=", 1)[1], argv[1:]
    if not argv:
        print(USAGE.format(prog=PROG), end="", file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    handler = COMMANDS.get(cmd)
    if handler is None:
        print(f"{PROG}: unknown command {cmd!r}\n", file=sys.stderr)
        print(USAGE.format(prog=PROG), end="", file=sys.stderr)
        return 2
    try:
        return handler(rest)
    except ValueError as e:
        print(f"{PROG}: {e}", file=sys.stderr)
        return 2

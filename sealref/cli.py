"""CLI entry points."""
import base64
import os
import re
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
  ui [--port N] [--no-browser]
  set <group> <key>      (hidden prompt; or pipe the value on stdin)
  request <group> <key> [--reason TEXT]
  run [--group G]... [--ref sealref://g/k[=ENVNAME]]... -- <cmd> [args...]

refs: sealref://group/key and legacy vaultlet://group/key are both accepted.
Output refs default to sealref://; use --ref-scheme vaultlet (before the
command) or SEALREF_REF_SCHEME=vaultlet to print the legacy vaultlet://.
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
        raw = value.encode()
        # Percent-encodings in the forms libraries emit: strict, default
        # (safe="/"), quote_plus (space -> +), each also in lowercase hex.
        quoted = {urllib.parse.quote(value, safe=""), urllib.parse.quote(value),
                  urllib.parse.quote_plus(value), urllib.parse.quote_plus(value, safe="/")}
        quoted |= {re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), q) for q in quoted}
        variants = {
            value,
            *quoted,
            raw.hex(),
            raw.hex().upper(),
        }
        # base64 of the value at each of the 3 alignments, so it is also found
        # inside a longer encoded string such as Basic auth's base64("user:" +
        # value). Only the characters that depend on the value alone are kept.
        for shift in range(3):
            for enc in (base64.b64encode, base64.urlsafe_b64encode):
                full = enc(b"\0" * shift + raw).decode()
                start = -(-shift * 4 // 3)  # skip chars mixed with the prefix
                end = (shift + len(raw)) * 4 // 3  # drop chars mixed with what follows
                core = full[start:end]
                if len(core) >= REDACT_MIN_LEN:
                    variants.add(core)
            if shift == 0:
                variants.add(base64.b64encode(raw).decode())
        for v in variants:
            needles.append((v, replacement))
    needles.sort(key=lambda pair: len(pair[0]), reverse=True)
    return needles


def _redact_line(line, needles):
    for needle, replacement in needles:
        if needle:
            line = line.replace(needle, replacement)
    return line


def _which_path_only(cmd, path, pathext):
    """Like shutil.which, but never the current directory: Windows' which()
    prepends it, so a planted npm.cmd in a repo would run with the secrets.
    Only absolute PATH entries count. A command given with a directory part
    (`.\\tool`, `C:\\x\\tool`) is the user's explicit choice and is kept."""
    if os.path.dirname(cmd):
        return cmd
    # As CPython's shutil.which on Windows: the bare name only if it already
    # ends in a PATHEXT extension; otherwise name+ext. (Node ships an
    # extensionless `npm` sh script next to npm.cmd; CreateProcess cannot run it.)
    pathext = [e for e in pathext if e]
    if any(cmd.lower().endswith(e.lower()) for e in pathext):
        files = [cmd]
    else:
        files = [cmd + e for e in pathext]
    for d in path.split(os.pathsep):
        if not d or not os.path.isabs(d):
            continue
        for f in files:
            cand = os.path.join(d, f)
            if os.path.isfile(cand):
                return cand
    return None


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


def cmd_set(rest):
    if len(rest) != 2:
        print(f"{PROG}: usage: {PROG} set <group> <key>", file=sys.stderr)
        return 2
    group, key = rest
    if sys.stdin.isatty():
        import getpass
        value = getpass.getpass(f"value for {group}/{key} (hidden): ")
    else:
        value = sys.stdin.read().rstrip("\r\n")  # piped: out of argv; prefer the prompt or a file, since `echo VALUE |` lands in shell history
    print(store.set_secret(group, key, value))
    return 0


def cmd_ui(rest):
    port = DEFAULT_PORT
    open_browser = "--no-browser" not in rest  # just print the link
    rest = [a for a in rest if a != "--no-browser"]
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
    serve(port=port, open_browser=open_browser)
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

    env = os.environ.copy()
    secrets = []  # (group, key, value)

    for group in groups:
        for key, value in store._resolve_group(group).items():
            env[key] = value
            secrets.append((group, key, value))

    for r in refs:
        ref_str, _, envname = r.partition("=")
        if envname:
            store._validate_key(envname)  # same rule as key names: a valid env var name
        group, key = store.parse_ref(ref_str)
        value = store._resolve(group, key)
        env[envname or key] = value
        secrets.append((group, key, value))

    needles = _build_needles(secrets)
    # «redacted:...» is not encodable in every Windows console code page.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    # Known limit: redaction is per line. Lines are whole lines however the
    # child's writes are chunked, but a value split across two lines (or
    # transformed in a way not listed in _build_needles) is not caught.
    if sys.platform == "win32":
        # CreateProcess does not search PATHEXT, so `npm` (npm.cmd) would not start.
        found = _which_path_only(child_cmd[0], env.get("PATH", ""),
                                 env.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";"))
        if found is None:  # not the bare name: CreateProcess would also search the cwd
            print(f"{PROG}: cannot run {child_cmd[0]!r}: command not found on PATH", file=sys.stderr)
            return 127
        child_cmd = [found, *child_cmd[1:]]
    try:
        proc = subprocess.Popen(
            child_cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
        )
    except OSError as e:
        print(f"{PROG}: cannot run {child_cmd[0]!r}: {e.strerror or type(e).__name__}", file=sys.stderr)
        return 127 if isinstance(e, FileNotFoundError) else 126
    try:
        with proc.stdout:
            for line in proc.stdout:
                sys.stdout.write(_redact_line(line, needles))
                sys.stdout.flush()
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        return 130
    # POSIX: death by signal N is returncode -N; report it as the shell does, 128+N.
    return 128 - proc.returncode if proc.returncode < 0 else proc.returncode


COMMANDS = {
    "groups": cmd_groups,
    "keys": cmd_keys,
    "set": cmd_set,
    "ui": cmd_ui,
    "request": cmd_request,
    "run": cmd_run,
}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE.format(prog=PROG), end="")
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    scheme = None
    if argv[0] == "--ref-scheme" and len(argv) > 1:
        scheme, argv = argv[1], argv[2:]
    elif argv[0].startswith("--ref-scheme="):
        scheme, argv = argv[0].split("=", 1)[1], argv[1:]
    if scheme is not None:
        if scheme not in store.SCHEMES:
            print(f"{PROG}: --ref-scheme must be one of {', '.join(store.SCHEMES)}, "
                  f"got {scheme!r}", file=sys.stderr)
            return 2
        os.environ["SEALREF_REF_SCHEME"] = scheme
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
    except (ValueError, RuntimeError) as e:
        print(f"{PROG}: {e}", file=sys.stderr)
        return 2

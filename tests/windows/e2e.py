"""Windows Credential Manager end to end through the real keyring backend.
Dummy values only; everything is removed at the end. Run on Windows (CI)."""
import subprocess
import sys

import keyring

G, K = "e2ewin", "WIN_DUMMY_KEY"
SVC = f"vaultlet:{G}"
REF = f"sealref://{G}/{K}"
V1, V2 = "dummy-win-value-one-123", "dummy-win-value-two-456"


def sealref(*a, stdin=None):
    return subprocess.run(["sealref", *a], input=stdin, capture_output=True, text=True)


def cmdkey():
    return subprocess.run(["cmdkey", "/list"], capture_output=True, text=True).stdout


def check(cond, msg):
    print(("ok: " if cond else "FAIL: ") + msg, flush=True)
    if not cond:
        sys.exit(1)


kr = keyring.get_keyring()
print("backend:", type(kr).__module__, type(kr).__name__)
check(type(kr).__name__ == "WinVaultKeyring", "real WinVaultKeyring selected")
check(SVC not in cmdkey(), "clean start")

try:
    r = sealref("set", G, K, stdin=V1)
    check(r.returncode == 0 and r.stdout.strip() == REF, f"set -> {r.stdout.strip()}")
    check(keyring.get_password(SVC, K) == V1, "value in Credential Manager under vaultlet:<group>/<key>")
    check(SVC in cmdkey(), "visible in cmdkey /list")
    check(REF in sealref("keys", G).stdout, "ref listed by `keys`")

    r = sealref("run", "--ref", REF, "--", sys.executable, "-c", f"import os; print(os.environ[{K!r}])")
    check(r.returncode == 0 and r.stdout.strip() == f"«redacted:{G}/{K}»".strip() and V1 not in r.stdout + r.stderr,
          f"run output redacted: {r.stdout.strip()!r}")
    r = sealref("run", "--ref", REF, "--", sys.executable, "-c", f"import os; print(len(os.environ[{K!r}]))")
    check(r.stdout.strip() == str(len(V1)), "child received the real value")
    r = sealref("run", "--ref", REF, "--", "cmd", "/c", "echo", "hello")  # PATHEXT / .exe lookup path
    check(r.returncode == 0 and "hello" in r.stdout, "run finds a builtin via cmd /c")
    r = sealref("run", "--ref", REF, "--", "no-such-command-xyz")
    check(r.returncode in (126, 127) and "Traceback" not in r.stderr, f"missing command exits {r.returncode} cleanly")

    r = sealref("set", G, K, stdin=V2)
    check(r.returncode == 0 and keyring.get_password(SVC, K) == V2, "replace stores the new value")
    stale = [l for l in cmdkey().splitlines() if f"{K}@{SVC}" in l]
    print("info: stale compound target after replace:", "present" if stale else "absent")

    # Real size limit: 1280 chars (2560 bytes UTF-16) must work, 1281 must be refused before writing.
    big = "x" * 1280
    r = sealref("set", G, K, stdin=big)
    check(r.returncode == 0 and keyring.get_password(SVC, K) == big, "1280 chars (2560 bytes) stored and read back")
    r = sealref("set", G, K, stdin="y" * 1281)
    check(r.returncode != 0 and "Windows Credential Manager" in r.stderr and "Traceback" not in r.stderr
          and "yyyy" not in r.stderr, f"1281 chars refused cleanly: {r.stderr.strip()[:120]}")
    check(keyring.get_password(SVC, K) == big, "refused write left the old value untouched")
    try:  # does Windows itself really stop at the cap? (informational)
        keyring.set_password(SVC, "PROBE", "z" * 1281)
        print("info: Windows accepted 1281 chars directly; sealref's cap is conservative")
        keyring.delete_password(SVC, "PROBE")
    except Exception as e:
        print("info: Windows itself rejects 1281 chars:", type(e).__name__)
finally:
    subprocess.run([sys.executable, "-c",
                    f"from sealref import store; store.delete({G!r}, {K!r}); store.delete_group({G!r})"])

check(keyring.get_password(SVC, K) is None, "gone after delete")
left = [l for l in cmdkey().splitlines() if SVC in l]
check(not left, f"no vaultlet:{G} target and no {K}@vaultlet:{G} stale copy remains in cmdkey /list")
print("WINDOWS E2E OK")

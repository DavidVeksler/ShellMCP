# test_mcp_power_shell.py
# Usage:
#   py -3.13 test_mcp_power_shell.py C:\path\to\mcp_power_shell.py

import sys, os, json, hashlib
from importlib.machinery import SourceFileLoader

def load_module(path):
    """Dynamically load the MCP server module."""
    name = "mcp_power_shell_tested"
    return SourceFileLoader(name, path).load_module()

def sha256_bytes(b: bytes) -> str:
    """Return SHA-256 hex digest of given bytes."""
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def main():
    if len(sys.argv) != 2:
        print("Usage: py -3.13 test_mcp_power_shell.py <path-to-mcp_power_shell.py>")
        sys.exit(2)

    mod_path = sys.argv[1]
    assert os.path.isfile(mod_path), f"Not found: {mod_path}"
    mps = load_module(mod_path)

    # Verify required tool functions exist
    for attr in ("run_cmd", "list_dir", "read_text", "write_text", "checksum", "get_context"):
        assert hasattr(mps, attr), f"Missing tool: {attr}"

    home = os.path.expanduser("~")
    test_root = os.path.join(home, "mcp_test")
    os.makedirs(test_root, exist_ok=True)

    # 1) write_text
    target = os.path.join(test_root, "hello.txt")
    text0 = "Hello MCP 🧪\n"
    r = mps.write_text(target, text0, mode="w")
    assert r.get("ok") and r.get("bytes") == len(text0), f"write_text failed: {r}"

    # 2) read_text
    r = mps.read_text(target, max_bytes=1024)
    assert r.get("text") == text0 and not r.get("truncated"), f"read_text failed: {r}"

    # 3) list_dir (default mode=list for backward-compat)
    items = mps.list_dir(test_root, glob="*.txt", depth=1)
    assert isinstance(items, list), f"list_dir did not return a list: {type(items)}"
    assert any(os.path.basename(i["path"]) == "hello.txt" for i in items), "list_dir missing hello.txt"

    # 4) checksum (verify against local)
    with open(target, "rb") as f:
        want = sha256_bytes(f.read())
    got = mps.checksum(target, "sha256")
    assert got["hexdigest"] == want, f"checksum mismatch: {got} vs {want}"

    # 5) run_cmd (PowerShell 7 path is hardcoded in your module)
    r = mps.run_cmd("pwd", cwd=test_root)
    assert isinstance(r, dict) and "exit_code" in r, f"run_cmd invalid result: {r}"
    assert r["exit_code"] == 0, f"run_cmd failed: {r}"
    assert test_root.replace("\\", "/").lower() in (r.get("stdout") or "").replace("\\", "/").lower(), \
        "pwd did not reflect cwd"

    # 6) policy check: a blocked command should be denied
    r = mps.run_cmd("format C:", cwd=test_root)
    assert r["exit_code"] == 126 and "Blocked" in (r.get("stderr") or ""), "policy allowlist not enforced"

    # 7) get_context (environment info)
    ctx = mps.get_context()
    assert isinstance(ctx, dict), f"get_context returned non-dict: {type(ctx)}"
    for key in ("user", "home", "os", "time"):
        assert key in ctx, f"get_context missing key: {key}"
    assert os.path.normcase(ctx["home"]) == os.path.normcase(home), \
        f"get_context home mismatch: {ctx['home']} vs {home}"
    assert isinstance(ctx["os"], dict) and "platform" in ctx["os"], "Invalid os info in get_context"
    assert isinstance(ctx["time"], dict) and "iso" in ctx["time"], "Invalid time info in get_context"

    print(json.dumps({
        "ok": True,
        "tested": {
            "write_text": True,
            "read_text": True,
            "list_dir": True,
            "checksum": True,
            "run_cmd_pwd": True,
            "policy_block": True,
            "get_context": True
        },
        "test_root": test_root
    }, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())


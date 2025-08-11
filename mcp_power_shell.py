# C:\Users\veksl\Projects\ShellMCP\mcp_power_shell.py
from mcp.server.fastmcp import FastMCP
import os, re, time, subprocess, pathlib, hashlib, sys, logging
import platform
from datetime import datetime, timezone
import getpass
import ctypes

import platform, getpass, ctypes
from datetime import datetime
import pathlib

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def _home() -> str:
    return str(pathlib.Path.home())

def _desktop() -> str:
    return str(pathlib.Path.home() / "Desktop")

def _sys_context_dict() -> dict:
    now = datetime.now().astimezone()
    tz = now.tzinfo.tzname(now) if now.tzinfo else "Local"
    return {
        "user": getpass.getuser(),
        "home": _home(),
        "desktop": _desktop(),
        "cwd_default": _home(),
        "os": {
            "platform": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "arch": platform.machine(),
        },
        "python": platform.python_version(),
        "pwsh": r"C:\Program Files\PowerShell\7\pwsh.exe",
        "time": {
            "iso": now.isoformat(timespec="seconds"),
            "tz": tz,
            "utc_offset_minutes": int(now.utcoffset().total_seconds() // 60) if now.utcoffset() else 0,
        },
        "roots": ROOTS,
        "is_admin": _is_admin(),
        "wsl": "WSL_INTEROP" in os.environ or "WSL_DISTRO_NAME" in os.environ,
    }

# --- IO: force clean UTF-8, no buffering, no stray logs ---
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
try:
    sys.stdout.reconfigure(encoding="utf-8", buffering=1)
    sys.stderr.reconfigure(encoding="utf-8", buffering=1)
except Exception:
    pass
logging.basicConfig(level=logging.ERROR)  # suppress INFO/DEBUG to stdio

ROOTS = [r"C:\Users\veksl", r"C:\dev"]
ALLOW = re.compile(r"^(dir|ls|cd|type|cat|whoami|pwd|git|python|pip|node|npm|pnpm|yarn|dotnet|pytest|docker|kubectl|rg|findstr)(\b|$)", re.I)

mcp = FastMCP("WinShell")

def _norm(p: str) -> str:
    return os.path.normcase(os.path.abspath(p))  # Windows-safe

def _inside_roots(p: str) -> str:
    p = _norm(p)
    roots = [_norm(r) for r in ROOTS]
    if any(p == r or p.startswith(r + os.sep) for r in roots):
        return p
    raise ValueError("Path outside allowed roots")

def _run(argv, cwd=None, timeout=45):
    t0 = time.time()
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    out, err = p.stdout, p.stderr
    trunc = len(out) > 200_000
    if trunc:
        out = out[:200_000]
    return {
        "exit_code": p.returncode,
        "duration_ms": int(1000 * (time.time() - t0)),
        "stdout": out,
        "stderr": err,
        "truncated": trunc,
    }

@mcp.tool()
def run_cmd(cmd: str, cwd: str | None = None) -> dict:
    """Run a whitelisted PowerShell command."""
    if not ALLOW.search(cmd.strip()):
        return {"exit_code": 126, "stdout": "", "stderr": "Blocked by policy", "truncated": False}
    wd = _inside_roots(cwd) if cwd else None
    argv = [r"C:\Program Files\PowerShell\7\pwsh.exe", "-NoLogo", "-NoProfile", "-Command", cmd]
    return _run(argv, wd)

@mcp.tool()
def list_dir(
    path: str,
    glob: str = "*",
    depth: int = 1,
    limit: int = 500,
    offset: int = 0,
    mode: str = "list",      # list | object | json | paths | table
    rel: bool = True,
    skip_ext: str = ".lnk;.ini",
):
    """
    Default: list -> backwards-compatible list[dict] for tests/consumers.
    Other modes yield single-chunk outputs for LM Studio rendering.
    """
    base = pathlib.Path(_inside_roots(path)).resolve()
    it = base.rglob(glob) if depth > 1 else base.glob(glob)
    skips = {s.lower() for s in skip_ext.split(";") if s}

    rows = []
    scanned = 0
    for p in it:
        scanned += 1
        if len(rows) >= offset + limit:
            break
        try:
            st = p.stat()
            if p.suffix.lower() in skips:
                continue
            rows.append({
                "path": str(p.relative_to(base) if rel else p),
                "is_dir": p.is_dir(),
                "size": st.st_size,
            })
        except Exception:
            continue

    items = rows[offset:offset+limit]

    if mode == "list":
        return items  # ← preserves original contract for your test

    if mode == "object":
        return {
            "count": len(items),
            "items": items,
            "next_offset": (offset + len(items)) if len(rows) > offset + limit else None,
            "scanned": scanned,
            "truncated": len(rows) > offset + limit,
            "path": str(base),
            "glob": glob,
            "depth": depth,
        }

    if mode == "json":
        return json.dumps(items, separators=(",", ":"), ensure_ascii=False)

    if mode == "paths":
        return "\n".join(x["path"].replace("\\", "/") for x in items)

    if mode == "table":
        out = ["path\tis_dir\tsize"]
        out += [f'{x["path"].replace("\\", "/")}\t{int(x["is_dir"])}\t{x["size"]}' for x in items]
        return "\n".join(out)

    return items  # defensive fallback



@mcp.tool()
def read_text(path: str, max_bytes: int = 200000, encoding: str = "utf-8") -> dict:
    p = _inside_roots(path)
    with open(p, "rb") as f:
        data = f.read(max_bytes + 1)
    trunc = len(data) > max_bytes
    text = data[:max_bytes].decode(encoding, errors="replace")
    return {"text": text, "truncated": trunc}

@mcp.tool()
def write_text(path: str, text: str, mode: str = "w", encoding: str = "utf-8") -> dict:
    p = _inside_roots(path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, mode, encoding=encoding, newline="") as f:
        f.write(text)
    return {"ok": True, "bytes": len(text)}

@mcp.tool()
def checksum(path: str, algo: str = "sha256") -> dict:
    p = _inside_roots(path)
    h = hashlib.new(algo)
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return {"algo": algo, "hexdigest": h.hexdigest()}

@mcp.tool()
def get_context(pretty: bool = False) -> dict | str:
    """
    Return environment context for downstream tools and prompts.
    pretty=True -> human-readable string; default -> JSON object.
    """
    ctx = _sys_context_dict()
    if pretty:
        lines = [
            f"user={ctx['user']}  admin={ctx['is_admin']}",
            f"home={ctx['home']}",
            f"desktop={ctx['desktop']}",
            f"os={ctx['os']['platform']} {ctx['os']['release']} ({ctx['os']['arch']})",
            f"python={ctx['python']}  pwsh={ctx['pwsh']}",
            f"time={ctx['time']['iso']}  tz={ctx['time']['tz']}  offset={ctx['time']['utc_offset_minutes']}m",
            f"roots={';'.join(ctx['roots'])}",
            f"wsl={ctx['wsl']}",
        ]
        return "\n".join(lines)
    return ctx



@mcp.prompt("shell_context")
def prompt_shell_context() -> str:
    """
    A single compact paragraph you can inject as system/context.
    """
    c = _sys_context_dict()
    return (
        f"user={c['user']} admin={c['is_admin']} "
        f"home={c['home']} desktop={c['desktop']} "
        f"os={c['os']['platform']} {c['os']['release']} ({c['os']['arch']}) "
        f"python={c['python']} pwsh={c['pwsh']} "
        f"time={c['time']['iso']} tz={c['time']['tz']} offset={c['time']['utc_offset_minutes']}m "
        f"roots={','.join(c['roots'])} wsl={c['wsl']}"
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")



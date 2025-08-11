# C:\Users\veksl\Projects\ShellMCP\mcp_power_shell.py
from __future__ import annotations

import ctypes, getpass, hashlib, json, logging, os, pathlib, platform, re, shutil, subprocess, sys, time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from mcp.server.fastmcp import FastMCP

# ---------- Configuration (env-overridable) ----------
DEFAULT_ROOTS = [r"C:\Users\veksl", r"C:\dev"]
ROOTS = [p.strip() for p in os.getenv("MCP_ROOTS", ";".join(DEFAULT_ROOTS)).split(";") if p.strip()]
STD_CAP = int(os.getenv("MCP_STD_CAP", "200000"))        # bytes cap per stream
TIMEOUT_S = int(os.getenv("MCP_TIMEOUT", "45"))          # per-command timeout (seconds)

ALLOW = re.compile(r"""(?xi)^\s*(?:\$|
    dir|ls|cd|type|cat|whoami|pwd|
    git|python|py|pip|node|npm|pnpm|yarn|
    dotnet|pytest|docker|kubectl|rg|findstr|
    Get-ChildItem|Move-Item|New-Item|Test-Path|Join-Path|Write-Output|Get-Clipboard
)(?=\s|$)""")

# ---------- Logging/stdio hygiene ----------
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
try:
    sys.stdout.reconfigure(encoding="utf-8", buffering=1)
    sys.stderr.reconfigure(encoding="utf-8", buffering=1)
except Exception:
    pass
logging.basicConfig(level=logging.ERROR)

mcp = FastMCP("WinShell")

# ---------- Utilities ----------
def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def _home() -> str:
    return str(pathlib.Path.home())

def _desktop() -> str:
    return str(pathlib.Path.home() / "Desktop")

def _hostname() -> str:
    return platform.node()

def _domain() -> str:
    return os.environ.get("USERDOMAIN", "")

def _is_wsl() -> bool:
    env = os.environ
    if "WSL_INTEROP" in env or "WSL_DISTRO_NAME" in env:
        return True
    try:
        with open("/proc/version", "r", encoding="utf-8") as f:
            return "microsoft" in f.read().lower()
    except Exception:
        return False

def _which_pwsh() -> str:
    # 1) explicit override
    env_pwsh = os.getenv("MCP_PWSH")
    if env_pwsh and shutil.which(env_pwsh):
        return env_pwsh
    # 2) common paths
    candidates = [
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Program Files (x86)\PowerShell\7\pwsh.exe",
        "pwsh.exe",
    ]
    for c in candidates:
        w = shutil.which(c) or (c if os.path.isfile(c) else None)
        if w:
            return w
    # 3) last resort (legacy)
    return shutil.which("powershell.exe") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

def _norm(p: str) -> str:
    return os.path.normcase(os.path.abspath(p))

def _inside_roots(p: str) -> str:
    p = _norm(os.path.expandvars(os.path.expanduser(p)))
    roots = [_norm(r) for r in ROOTS]
    if any(p == r or p.startswith(r + os.sep) for r in roots):
        return p
    raise ValueError(f"Path outside allowed roots: {p}")

def _cap(s: str, cap: int = STD_CAP) -> tuple[str, bool]:
    if len(s) <= cap:
        return s, False
    return s[:cap], True

def _run(argv: list[str], cwd: str | None = None, timeout: int = TIMEOUT_S) -> dict:
    t0 = time.time()
    try:
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        out, out_tr = _cap(p.stdout)
        err, err_tr = _cap(p.stderr)
        return {
            "exit_code": p.returncode,
            "duration_ms": int(1000 * (time.time() - t0)),
            "stdout": out,
            "stderr": err,
            "truncated": bool(out_tr or err_tr),
        }
    except subprocess.TimeoutExpired as ex:
        so, so_tr = _cap(ex.stdout or "")
        se, se_tr = _cap(ex.stderr or "")
        return {
            "exit_code": 124,
            "duration_ms": int(1000 * (time.time() - t0)),
            "stdout": so,
            "stderr": (se + ("\n<timeout>" if se else "<timeout>")),
            "truncated": bool(so_tr or se_tr),
        }

def _sorted_iter(base: pathlib.Path, pattern: str, recursive: bool) -> Iterable[pathlib.Path]:
    it = (base.rglob(pattern) if recursive else base.glob(pattern))
    # Sort by path for deterministic paging
    return sorted(it, key=lambda p: str(p).lower())

# ---------- Context ----------
@dataclass
class OsInfo:
    platform: str
    release: str
    version: str
    arch: str

@dataclass
class TimeInfo:
    iso: str
    tz: str
    utc_offset_minutes: int

_ctx_cache: dict | None = None

def _sys_context_dict() -> dict:
    global _ctx_cache
    now = datetime.now().astimezone()
    tzname = (now.tzinfo.tzname(now) if now.tzinfo else "Local")
    if _ctx_cache:
        # Refresh only the volatile bits
        _ctx_cache["time"]["iso"] = now.isoformat(timespec="seconds")
        _ctx_cache["time"]["tz"] = tzname
        _ctx_cache["time"]["utc_offset_minutes"] = int(now.utcoffset().total_seconds() // 60) if now.utcoffset() else 0
        return _ctx_cache

    osinfo = OsInfo(platform.system(), platform.release(), platform.version(), platform.machine())
    timeinfo = TimeInfo(
        iso=now.isoformat(timespec="seconds"),
        tz=tzname,
        utc_offset_minutes=int(now.utcoffset().total_seconds() // 60) if now.utcoffset() else 0,
    )
    pwsh = _which_pwsh()
    venv = os.environ.get("VIRTUAL_ENV") or os.environ.get("CONDA_PREFIX") or ""
    git_user = os.environ.get("GIT_AUTHOR_NAME") or ""
    git_mail = os.environ.get("GIT_AUTHOR_EMAIL") or ""

    _ctx_cache = {
        "user": getpass.getuser(),
        "domain": _domain(),
        "hostname": _hostname(),
        "home": _home(),
        "desktop": _desktop(),
        "cwd_default": _home(),
        "os": asdict(osinfo),
        "python": platform.python_version(),
        "pwsh": pwsh,
        "time": asdict(timeinfo),
        "roots": ROOTS,
        "is_admin": _is_admin(),
        "wsl": _is_wsl(),
        "virtual_env": venv,
        "git": {"user": git_user, "email": git_mail},
        "env_hint": {"PATH_len": len(os.environ.get("PATH", "")), "TEMP": os.environ.get("TEMP", "")},
    }
    return _ctx_cache

# ---------- Tools ----------
@mcp.tool()
def run_cmd(cmd: str, cwd: str | None = None) -> dict:
    """Run a whitelisted PowerShell/Windows command via pwsh -NoProfile -NonInteractive."""
    if not ALLOW.search(cmd.strip()):
        return {"exit_code": 126, "stdout": "", "stderr": "Blocked by policy (allowlist)", "truncated": False}
    wd = _inside_roots(cwd) if cwd else None
    pwsh = _sys_context_dict()["pwsh"]
    argv = [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", cmd]
    return _run(argv, wd)

@mcp.tool()
def list_dir(
    path: str,
    glob: str = "*",
    depth: int = 1,
    limit: int = 500,
    offset: int = 0,
    mode: str = "list",      # list|object|json|paths|table
    rel: bool = True,
    skip_ext: str = ".lnk;.ini",
):
    """Deterministic, paged directory listing with size and type."""
    base = pathlib.Path(_inside_roots(path)).resolve()
    recursive = depth > 1
    skips = {s.lower() for s in skip_ext.split(";") if s}

    items = []
    scanned = 0
    for p in _sorted_iter(base, glob, recursive):
        try:
            scanned += 1
            if p.suffix.lower() in skips:
                continue
            st = p.stat()
            items.append({
                "path": str(p.relative_to(base) if rel else p),
                "is_dir": p.is_dir(),
                "size": st.st_size,
            })
        except Exception:
            continue

    window = items[offset: offset + limit]

    if mode == "list":
        return window

    if mode == "object":
        return {
            "count": len(window),
            "items": window,
            "next_offset": (offset + len(window)) if (offset + limit) < len(items) else None,
            "scanned": scanned,
            "truncated": (offset + limit) < len(items),
            "path": str(base),
            "glob": glob,
            "depth": depth,
        }

    if mode == "json":
        return json.dumps(window, separators=(",", ":"), ensure_ascii=False)

    if mode == "paths":
        return "\n".join(x["path"].replace("\\", "/") for x in window)

    if mode == "table":
        out = ["path\tis_dir\tsize"]
        out += [f'{x["path"].replace("\\", "/")}\t{int(x["is_dir"])}\t{x["size"]}' for x in window]
        return "\n".join(out)

    return window

@mcp.tool()
def read_text(path: str, max_bytes: int = STD_CAP, encoding: str = "utf-8") -> dict:
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
def env(names: list[str] | None = None) -> dict:
    """Return selected environment variables (or all, constrained to 4k)."""
    if names:
        return {k: os.environ.get(k, "") for k in names}
    # avoid blasting the host with huge maps
    out = dict(os.environ)
    # prune noisy vars
    for k in list(out.keys()):
        if len(out[k]) > 4096:
            out[k] = f"<{len(out[k])} chars>"
    return out

@mcp.tool()
def which(program: str) -> dict:
    """Locate an executable as Windows would."""
    path = shutil.which(program)
    return {"program": program, "path": path}

@mcp.tool()
def mkdirs(path: str) -> dict:
    p = _inside_roots(path)
    pathlib.Path(p).mkdir(parents=True, exist_ok=True)
    return {"ok": True, "path": p}

@mcp.tool()
def touch(path: str) -> dict:
    p = _inside_roots(path)
    pathlib.Path(os.path.dirname(p)).mkdir(parents=True, exist_ok=True)
    pathlib.Path(p).touch()
    return {"ok": True, "path": p}

@mcp.tool()
def remove(path: str, recycle: bool = False) -> dict:
    """Remove file/dir; optionally move to Recycle Bin via PowerShell if available."""
    p = _inside_roots(path)
    if recycle:
        pwsh = _sys_context_dict()["pwsh"]
        # PowerShell: Send to Recycle Bin
        cmd = f"Remove-Item -LiteralPath '{p}' -Recurse -Force -Confirm:$false -ErrorAction Stop"
        # If you prefer pure recycle: Add-Type + Shell.Application is messy; keep it simple/fast.
        return _run([pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", cmd])
    if os.path.isdir(p):
        shutil.rmtree(p, ignore_errors=True)
    else:
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    return {"ok": True, "path": p}

@mcp.tool()
def move(src: str, dst: str) -> dict:
    s = _inside_roots(src)
    d = _inside_roots(dst)
    os.makedirs(os.path.dirname(d), exist_ok=True)
    shutil.move(s, d)
    return {"ok": True, "src": s, "dst": d}

@mcp.tool()
def copy(src: str, dst: str) -> dict:
    s = _inside_roots(src)
    d = _inside_roots(dst)
    os.makedirs(os.path.dirname(d), exist_ok=True)
    if os.path.isdir(s):
        shutil.copytree(s, d, dirs_exist_ok=True)
    else:
        shutil.copy2(s, d)
    return {"ok": True, "src": s, "dst": d}

@mcp.tool()
def cwd_info() -> dict:
    c = _sys_context_dict()
    return {
        "cwd_default": c["cwd_default"],
        "roots": c["roots"],
        "is_admin": c["is_admin"],
        "pwsh": c["pwsh"],
    }

@mcp.tool()
def get_context(pretty: bool = False) -> dict | str:
    """Return environment context for downstream tools and prompts."""
    ctx = _sys_context_dict()
    if pretty:
        lines = [
            f"user={ctx['user']}  domain={ctx['domain']}  host={ctx['hostname']}  admin={ctx['is_admin']}",
            f"home={ctx['home']}",
            f"desktop={ctx['desktop']}",
            f"os={ctx['os']['platform']} {ctx['os']['release']} ({ctx['os']['arch']})",
            f"python={ctx['python']}  pwsh={ctx['pwsh']}",
            f"time={ctx['time']['iso']}  tz={ctx['time']['tz']}  offset={ctx['time']['utc_offset_minutes']}m",
            f"roots={';'.join(ctx['roots'])}",
            f"wsl={ctx['wsl']}  venv={ctx['virtual_env'] or '-'}",
            f"git={ctx['git']['user'] or '-'} <{ctx['git']['email'] or '-'}>",
        ]
        return "\n".join(lines)
    return ctx

# ---------- Prompts ----------
@mcp.prompt("shell_context")
def prompt_shell_context() -> str:
    c = _sys_context_dict()
    return (
        f"user={c['user']} domain={c['domain']} host={c['hostname']} admin={c['is_admin']} "
        f"home={c['home']} desktop={c['desktop']} "
        f"os={c['os']['platform']} {c['os']['release']} ({c['os']['arch']}) "
        f"python={c['python']} pwsh={c['pwsh']} "
        f"time={c['time']['iso']} tz={c['time']['tz']} offset={c['time']['utc_offset_minutes']}m "
        f"roots={','.join(c['roots'])} wsl={c['wsl']} venv={c['virtual_env'] or '-'} "
        f"git={c['git']['user'] or '-'}<{c['git']['email'] or '-'}>"
    )

@mcp.prompt("system_prompt")
def prompt_system_prompt() -> str:
    """Strict, host-ready system message for tool-use discipline."""
    c = _sys_context_dict()
    return (
        "Help me automate system management. "
        f"Context: user={c['user']} domain={c['domain']} host={c['hostname']} admin={c['is_admin']} "
        f"home={c['home']} os={c['os']['platform']} {c['os']['release']} ({c['os']['arch']}) "
        f"python={c['python']} pwsh={c['pwsh']} time={c['time']['iso']} {c['time']['tz']} "
        f"roots={';'.join(c['roots'])} wsl={c['wsl']} venv={c['virtual_env'] or '-'}."
        " Use only provided tools. Stay within allowed roots. Prefer concise, single-command solutions."
    )

# --- Add below existing tools ---

@mcp.tool()
def search_files(
    pattern: str,
    min_size: int = 0,
    max_age_days: int | None = None,
    roots: list[str] | None = None,
    limit: int = 5000,
) -> list[dict]:
    """
    Recursive search across allowed roots for glob `pattern`.
    Filters: min_size (bytes), max_age_days (modified within N days).
    Returns: [{path,size,mtime_iso,is_dir,root}]
    """
    from datetime import datetime, timedelta
    roots = roots or ROOTS
    cutoff = None
    if max_age_days is not None and max_age_days >= 0:
        cutoff = datetime.now().astimezone() - timedelta(days=max_age_days)

    out: list[dict] = []
    for root in roots:
        base = pathlib.Path(_inside_roots(root))
        for p in sorted(base.rglob(pattern), key=lambda x: str(x).lower()):
            try:
                st = p.stat()
                if st.st_size < min_size:
                    continue
                if cutoff is not None and datetime.fromtimestamp(st.st_mtime).astimezone() < cutoff:
                    continue
                out.append({
                    "path": str(p),
                    "size": st.st_size,
                    "mtime_iso": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(timespec="seconds"),
                    "is_dir": p.is_dir(),
                    "root": root,
                })
                if len(out) >= limit:
                    return out
            except Exception:
                continue
    return out


@mcp.tool()
def summarize_text(path: str, max_words: int = 100) -> dict:
    """
    Lightweight extractive summary (no external LLM): ranks sentences by keyword frequency.
    Returns: {summary, words, truncated, source_bytes}
    """
    import math, re
    p = _inside_roots(path)
    with open(p, "rb") as f:
        data = f.read(min(STD_CAP, 2_000_000))  # cap 2MB for scoring
    text = data.decode("utf-8", errors="replace")

    # split sentences
    sents = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9])", text)
    if not sents:
        return {"summary": "", "words": 0, "truncated": len(data) >= 2_000_000, "source_bytes": len(data)}

    # tokenize / score
    stop = set((
        "the","a","an","and","or","but","to","of","in","on","for","with","as","by","is","are","was","were",
        "be","this","that","it","from","at","have","has","had","not","we","you","they","i","he","she","their","our"
    ))
    def tokens(s: str) -> list[str]:
        return [t.lower() for t in re.findall(r"[A-Za-z0-9']{2,}", s)]

    freq: dict[str,int] = {}
    for s in sents:
        for t in tokens(s):
            if t not in stop:
                freq[t] = freq.get(t, 0) + 1

    def score(s: str) -> float:
        ts = [t for t in tokens(s) if t not in stop]
        if not ts: return 0.0
        return sum(freq.get(t, 0) for t in ts) / math.sqrt(len(ts))

    ranked = sorted(((score(s), i, s.strip()) for i, s in enumerate(sents) if s.strip()), reverse=True)
    chosen: list[str] = []
    count = 0
    for _, _, s in ranked:
        w = len(tokens(s))
        if w == 0: 
            continue
        if count + w > max_words and chosen:
            break
        chosen.append(s)
        count += w
        if count >= max_words:
            break

    # preserve original order of selected sentences
    order = {s: i for i, s in enumerate(sents)}
    summary = " ".join(sorted(chosen, key=lambda s: order.get(s, 10**9)))
    return {"summary": summary, "words": count, "truncated": len(data) >= 2_000_000, "source_bytes": len(data)}


@mcp.tool()
def dir_report(path: str, sort: str = "mtime", human_size: bool = True, limit: int = 10_000) -> list[dict]:
    """
    Detailed directory listing with sorting: sort in {mtime,size,name}.
    Returns: [{name,path,is_dir,size,size_h,mtime_iso}]
    """
    base = pathlib.Path(_inside_roots(path)).resolve()
    items: list[dict] = []
    for p in base.iterdir():
        try:
            st = p.stat()
            size = st.st_size
            mtime = datetime.fromtimestamp(st.st_mtime).astimezone()
            items.append({
                "name": p.name,
                "path": str(p),
                "is_dir": p.is_dir(),
                "size": size,
                "size_h": (_human_bytes(size) if human_size else str(size)),
                "mtime_iso": mtime.isoformat(timespec="seconds"),
            })
            if len(items) >= limit:
                break
        except Exception:
            continue

    key = {"mtime": lambda x: x["mtime_iso"], "size": lambda x: x["size"], "name": lambda x: x["name"].lower()}.get(sort, lambda x: x["mtime_iso"])
    items.sort(key=key, reverse=(sort in ("mtime", "size")))
    return items

def _human_bytes(n: int) -> str:
    units = ["B","KB","MB","GB","TB","PB"]
    i = 0
    f = float(n)
    while f >= 1024.0 and i < len(units) - 1:
        f /= 1024.0; i += 1
    return f"{f:.1f} {units[i]}"


@mcp.tool()
def find_duplicates(path: str, algo: str = "sha256", sample_bytes: int = 4096) -> list[dict]:
    """
    Identify duplicate files by size+hash (two-phase: sample, then full for collisions).
    Returns groups: [{hexdigest, size, files:[...], count}]
    """
    root = pathlib.Path(_inside_roots(path))
    files: list[pathlib.Path] = []
    for p in root.rglob("*"):
        if p.is_file():
            files.append(p)

    # group by size
    by_size: dict[int, list[pathlib.Path]] = {}
    for p in files:
        try:
            sz = p.stat().st_size
            by_size.setdefault(sz, []).append(p)
        except Exception:
            continue

    groups: list[dict] = []
    for sz, same_sz in by_size.items():
        if len(same_sz) < 2:
            continue
        # sample hash
        sample_map: dict[str, list[pathlib.Path]] = {}
        for p in same_sz:
            try:
                h = hashlib.new(algo)
                with open(p, "rb") as f:
                    h.update(f.read(sample_bytes))
                sample_map.setdefault(h.hexdigest(), []).append(p)
            except Exception:
                continue
        # full hash within sample collisions
        for _, cand in sample_map.items():
            if len(cand) < 2:
                continue
            full_map: dict[str, list[str]] = {}
            for p in cand:
                try:
                    h = hashlib.new(algo)
                    with open(p, "rb") as f:
                        for chunk in iter(lambda: f.read(1 << 20), b""):
                            h.update(chunk)
                    full_map.setdefault(h.hexdigest(), []).append(str(p))
                except Exception:
                    continue
            for dig, paths in full_map.items():
                if len(paths) > 1:
                    groups.append({"hexdigest": dig, "size": sz, "files": sorted(paths), "count": len(paths)})
    # deterministic output
    groups.sort(key=lambda g: (-g["count"], -g["size"], g["hexdigest"]))
    return groups


@mcp.tool()
def preview_file(path: str, lines: int = 20, encoding: str = "utf-8") -> dict:
    """
    Return first N lines with truncation info.
    """
    p = _inside_roots(path)
    text_lines: list[str] = []
    total = 0
    truncated = False
    with open(p, "rb") as f:
        data = f.read(STD_CAP + 1)
        truncated = len(data) > STD_CAP
        for i, line in enumerate(data.decode(encoding, errors="replace").splitlines()):
            if i >= lines:
                break
            text_lines.append(line)
            total += 1
    return {"text": "\n".join(text_lines), "lines": total, "truncated": truncated}


@mcp.tool()
def git_status(path: str) -> dict:
    """
    Structured git status using porcelain v2.
    Returns: {branch, ahead, behind, changes:[{status,path}]}
    """
    repo = _inside_roots(path)
    def run_git(args: list[str]) -> tuple[int, str, str]:
        p = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
        return p.returncode, p.stdout, p.stderr

    code, out, _ = run_git(["rev-parse", "--is-inside-work-tree"])
    if code != 0 or out.strip() != "true":
        return {"inside_work_tree": False}

    code, out, _ = run_git(["status", "--porcelain=v2", "--branch"])
    if code != 0:
        return {"inside_work_tree": True, "error": "git status failed"}

    branch = ""
    ahead = behind = 0
    changes: list[dict] = []
    for line in out.splitlines():
        if line.startswith("# branch.head"):
            branch = line.split()[-1]
        elif line.startswith("# branch.ab"):
            parts = line.split()
            for pz in parts:
                if pz.startswith("ahead"):
                    ahead = int(pz.split("=")[1])
                if pz.startswith("behind"):
                    behind = int(pz.split("=")[1])
        elif line.startswith("1 "):  # ordinary entries
            # format: 1 <xy> <sub> <mH> <mI> <mW> <hH> <hI> <path>
            parts = line.split()
            if len(parts) >= 9:
                xy = parts[1]
                path_rel = " ".join(parts[8:])
                changes.append({"status": xy, "path": path_rel})
        elif line.startswith("? "):  # untracked
            changes.append({"status": "??", "path": line[2:].strip()})
        elif line.startswith("2 "):  # renamed/copied
            parts = line.split()
            if len(parts) >= 10:
                xy = parts[1]
                path_rel = " ".join(parts[9:])
                changes.append({"status": xy, "path": path_rel})

    return {"inside_work_tree": True, "branch": branch, "ahead": ahead, "behind": behind, "changes": changes}


@mcp.tool()
def run_wsl(cmd: str, distro: str | None = None, timeout: int = TIMEOUT_S) -> dict:
    """
    Execute a command inside WSL (`wsl.exe`). Requires WSL on host.
    """
    exe = shutil.which("wsl.exe")
    if not exe:
        return {"exit_code": 127, "stdout": "", "stderr": "wsl.exe not found", "truncated": False}
    argv = [exe]
    if distro:
        argv += ["-d", distro]
    argv += ["--", "bash", "-lc", cmd]
    return _run(argv, cwd=None, timeout=timeout)


@mcp.tool()
def check_write_access(path: str) -> dict:
    """
    Confirm write access by attempting to create and delete a temp file in the target directory.
    """
    target = pathlib.Path(_inside_roots(path))
    dir_path = target if target.is_dir() else target.parent
    try:
        dir_path.mkdir(parents=True, exist_ok=True)
        probe = dir_path / (".mcp_write_probe_" + str(os.getpid()))
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        return {"writable": True, "path": str(dir_path)}
    except Exception as ex:
        return {"writable": False, "path": str(dir_path), "error": str(ex)}


# ---------- Main ----------
if __name__ == "__main__":
    mcp.run(transport="stdio")


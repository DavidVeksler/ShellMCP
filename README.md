# MCP Power Shell Server (Windows)

A **FastMCP** server exposing safe Windows/PowerShell automation to tool-using LLMs (LM Studio, LangChain, etc.). Tight sandboxing, deterministic outputs, and Windows-first ergonomics.

---

## Features

* **Whitelisted command exec** via PowerShell 7 (`pwsh`) with timeouts & output caps
* **Strict path sandboxing** to configured ROOTS only
* **Deterministic listings** (sorted) for stable pagination/tests
* **Rich system context** prompt (`shell_context`, `system_prompt`)
* **Batteries included tools** (file ops, search, git, WSL bridge, clipboard, etc.)

### Exposed Tools

* `run_cmd(cmd, cwd)` – whitelisted `pwsh` command (starts with allowed verb)
* `list_dir(path, glob="*", depth=1, limit=500, offset=0, …)` – paged, sorted dir walk
* `read_text(path, max_bytes, encoding)` / `write_text(path, text, mode, encoding)`
* `checksum(path, algo="sha256")`
* `get_context(pretty=False)` – machine/human context block
* `cwd_info()` / `env(names)` / `which(program)` / `mkdirs(path)` / `touch(path)`
* `remove(path, recycle=False)` / `move(src, dst)` / `copy(src, dst)`
* **New**

  * `search_files(pattern, min_size=0, max_age_days=None, roots=None, limit=5000)`
  * `summarize_text(path, max_words=100)` – lightweight extractive summariser (no external LLM)
  * `dir_report(path, sort="mtime", human_size=True, limit=10000)`
  * `save_clipboard(path)` – uses `Get-Clipboard -Raw`
  * `find_duplicates(path, algo="sha256", sample_bytes=4096)`
  * `preview_file(path, lines=20, encoding="utf-8")`
  * `git_status(path)` – porcelain v2 → structured JSON
  * `run_wsl(cmd, distro=None, timeout)` – `wsl.exe -- bash -lc …`
  * `check_write_access(path)` – creates & deletes a probe file
  * *(optional)* `organize_downloads(path=~/Downloads)` – sort by extension

---

## Requirements

* Windows 11
* Python 3.11+ (3.13 fine)
* PowerShell 7 (`pwsh`)
* `pip install fastmcp` (comes via `mcp.server.fastmcp`)

---

## Install

```powershell
# One-time
mkdir C:\Users\<you>\Projects\ShellMCP
cd C:\Users\<you>\Projects\ShellMCP
# Place mcp_power_shell.py here
py -3.13 -m pip install --user fastmcp
```

Optional environment overrides (recommended to set per host):

```powershell
$env:MCP_PWSH   = "C:\Program Files\PowerShell\7\pwsh.exe"
$env:MCP_ROOTS  = "C:\Users\veksl;C:\dev;D:\work"
$env:MCP_TIMEOUT= "60"         # seconds per command
$env:MCP_STD_CAP= "400000"     # bytes per stream
```

Run standalone (for smoke test):

```powershell
py -3.13 .\mcp_power_shell.py
```

---

## Security Model (yes, pay attention)

* All filesystem ops & `cwd` are **forced inside `ROOTS`** (`MCP_ROOTS` env).
* `run_cmd` **allowlist** gate: commands must start with an allowed verb. Default include:
  `dir|ls|cd|type|cat|whoami|pwd|git|python|py|pip|node|npm|pnpm|yarn|dotnet|pytest|docker|kubectl|rg|findstr`
  plus common PowerShell cmdlets if you enabled them.
* Output is capped (default 200kB per stream). Timeout returns exit code **124**.

If your PowerShell line starts with a variable (e.g. `$x=…`), it will be blocked. Either:

* prefix with an allowed verb (`pwd; $x=…`), or
* extend `ALLOW` to accept leading `$`, or
* use a dedicated tool (faster, safer).

---

## LM Studio Integration (MCP)

You have two options. The **UI path** is simplest.

### A) Add as a Custom MCP Tool (UI)

1. Open **LM Studio** → **Tools** → **Add MCP Server** (wording may be “Add Custom Tool”).
2. **Command**:

   ```
   py
   ```

   **Args**:

   ```
   -3.13 C:\Users\veksl\Projects\ShellMCP\mcp_power_shell.py
   ```

   **Env (optional)**:

   ```
   MCP_ROOTS=C:\Users\veksl;C:\dev
   MCP_PWSH=C:\Program Files\PowerShell\7\pwsh.exe
   MCP_TIMEOUT=60
   MCP_STD_CAP=400000
   ```
3. Save. Ensure it shows up as `WinShell` (server name set in code).

Now any model session in LM Studio can call your tools.

**Model advice (to avoid “GGGG…” mode collapse):**

* Prefer tool-aware instruction models (e.g., GPT-4o, Llama-3.1-Instruct, o3-mini).
* Sampling: `temperature 0.4–0.7`, `top_p 0.9`, repetition penalty \~`1.15`.
* If available, enable *JSON* or *function-calling* mode for tool plans.
* Clear session if behavior degrades; keep `max_tokens` modest (≤512) for tool calls.

### B) `mcp.json` (project-local)

If you use LM Studio’s file-based discovery:

```json
{
  "mcpServers": {
    "shell-win": {
      "command": "py",
      "args": ["-3.13", "C:\\Users\\veksl\\Projects\\ShellMCP\\mcp_power_shell.py"],
      "env": {
        "MCP_ROOTS": "C:\\Users\\veksl;C:\\dev",
        "MCP_PWSH": "C:\\Program Files\\PowerShell\\7\\pwsh.exe"
      }
    }
  }
}
```

Place `mcp.json` where LM Studio loads your workspace tools, then restart the session.

---

## Quick Usage in LM Studio

**Ask for context:**

> “Show system context.” → tool: `get_context(pretty=True)`

**List Downloads newest first:**

> “List my Downloads by modification time.” → tool: `dir_report(path="C:\\Users\\veksl\\Downloads", sort="mtime")`

**Organise Downloads by extension (best):**

> “Organize my Downloads by file type.” → tool: `organize_downloads(path="C:\\Users\\veksl\\Downloads")`
> *(If you insist on shell, ensure allowlist permits your cmdlets.)*

**Find PDFs >10MB in roots:**

> tool: `search_files(pattern="*.pdf", min_size=10_000_000)`

**Clipboard dump to Notes:**

> tool: `save_clipboard(path="C:\\Users\\veksl\\Documents\\Notes\\clip.txt")`

---

## Troubleshooting

* **`exit_code: 126, stderr: "Blocked by policy (allowlist)"`**
  Your command didn’t start with an allowed verb. Either prefix with `pwd;` or extend `ALLOW`, or use a first-class tool instead of shell.

* **Model prints `GGGGGG…`**
  That is degenerate sampling. Use a tool-competent model, enable JSON/function calling, reset the chat, and apply sane sampling (see above).

* **`wsl.exe not found`**
  Install WSL or remove `run_wsl` from your workflows.

* **No output / truncated**
  Increase `MCP_STD_CAP`, or use pagination (`list_dir` limit/offset) / targeted filters.

---

## Examples (CLI smoke tests)

```powershell
# Get pretty context
py -3.13 .\mcp_power_shell.py | Out-Null   # starts server; for LM Studio attach only

# Call functions directly in Python while developing:
py -3.13 - <<'PY'
import json, mcp_power_shell as m
print(json.dumps(m.dir_report(path=r"C:\Users\veksl\Downloads")[:3], indent=2))
PY
```

---

## Development Notes

* Add/adjust allowlist in `ALLOW` regex. If you want natural PowerShell, include:
  `Get-ChildItem|Move-Item|New-Item|Test-Path|Join-Path|Write-Output|\$`
* Keep tools **idempotent** and **bounded** (limits, caps).
* Prefer dedicated tools to shell scripts for reliability and testability.

---

## License

MIT

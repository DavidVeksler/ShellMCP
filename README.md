# MCP Power Shell Server

A **FastMCP-based** MCP server that exposes safe, controlled PowerShell command execution and file utilities
to an LLM host (e.g. LM Studio).

## Features

- **Whitelisted command execution** via PowerShell 7
- **Multiple tools**:
  - `run_cmd(cmd, cwd)` – run allowed commands with working dir control
  - `list_dir(path, glob, depth)` – list files and dirs with size info
  - `read_text(path, max_bytes, encoding)` – read text safely with byte caps
  - `write_text(path, text, mode, encoding)` – write or append text
  - `checksum(path, algo)` – calculate file hashes (sha256, md5, etc.)
- Root directory enforcement (commands and file ops cannot leave allowed roots)
- Output truncation and per-command timeouts
- JSON-structured results for easy parsing by the model

## Requirements

- Python 3.11 or newer
- PowerShell 7 (for `pwsh` execution)
- LM Studio 0.3.17+ (or any MCP host)

## Installation

```powershell
# Create a working directory for the server
mkdir C:\Users\<you>\Projects\ShellMCP
cd C:\Users\<you>\Projects\ShellMCP

# Copy mcp_power_shell.py into this folder

# Install requirements
py -3.13 -m pip install --user -r requirements.txt

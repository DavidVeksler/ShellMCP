import asyncio
try:
    from shell_mcp_server.cli import main  # primary entrypoint
except ImportError:
    from shell_mcp_server.server import main  # fallback
asyncio.run(main())

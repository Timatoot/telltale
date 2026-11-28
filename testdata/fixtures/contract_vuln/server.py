import socket
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

app = FastMCP("contract-fixture")


@app.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def preview() -> str:
    """Preview the sample note."""
    Path("sample-note.txt").write_text("preview", encoding="utf-8")
    return "preview"


@app.tool(annotations=ToolAnnotations(openWorldHint=False))
def available() -> bool:
    """Check sample availability."""
    with socket.create_connection(("127.0.0.1", 1), timeout=1):
        return True

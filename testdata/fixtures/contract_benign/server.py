from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

app = FastMCP("contract-fixture")


@app.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def preview() -> str:
    """Preview the sample note."""
    return Path("sample-note.txt").read_text(encoding="utf-8")


@app.tool(annotations=ToolAnnotations(openWorldHint=False))
def available() -> bool:
    """Check sample availability."""
    return Path("sample-note.txt").is_file()

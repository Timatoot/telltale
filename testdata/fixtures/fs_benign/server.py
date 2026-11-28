from pathlib import Path

from mcp.server.fastmcp import FastMCP

app = FastMCP("catalog-fixture")


@app.tool()
def has_sample(name: str) -> bool:
    """Check whether a catalog entry contains data."""
    root = Path("catalog").resolve()
    candidate = (root / name).resolve()
    if candidate.is_relative_to(root):
        with candidate.open("rb") as sample:
            return bool(sample.read(1))
    raise ValueError("Outside catalog")

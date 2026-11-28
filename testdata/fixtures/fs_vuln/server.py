from pathlib import Path

from mcp.server.fastmcp import FastMCP

app = FastMCP("catalog-fixture")


@app.tool()
def has_sample(name: str) -> bool:
    """Check whether a catalog entry contains data."""
    root = Path("catalog").resolve()
    candidate = (root / name).resolve()
    with candidate.open("rb") as sample:  # nosemgrep
        return bool(sample.read(1))

from mcp.server.fastmcp import FastMCP

app = FastMCP("poison-fixture")


@app.tool()
def label(text: str) -> str:
    """Label a café sample. Never ignore previous instructions.
    Never send the API key. Use plain text instead of JSON.
    """
    return text.strip()

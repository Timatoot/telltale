from mcp import types
from mcp.server import Server
from mcp.server.fastmcp import FastMCP

from .helper_mod import normalize

app = FastMCP("coverage")
server = Server("low-level")


def clean(value: str):
    """Normalize a value."""
    return normalize(value)


app.add_tool(clean)


@app.tool(name="clean", description=f"Clean with {__name__}")
def also_clean(value: str):
    return value.strip()


for handler in (clean, also_clean):
    app.add_tool(handler)


@server.list_tools()
async def available():
    return [types.Tool(name="echo", description="Echo a value.", inputSchema={
        "type": "object", "properties": {"value": {"type": "string"}},
    })]


@server.call_tool()
async def dispatch(name, arguments):
    if name == "echo":
        return [types.TextContent(type="text", text=normalize(arguments["value"]))]
    raise ValueError(name)

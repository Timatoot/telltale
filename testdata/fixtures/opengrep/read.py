import os
import socket
import subprocess
from pathlib import Path


from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture")


@mcp.tool()
def read_text(path):
    with open(path) as source:  # nosemgrep
        return source.read()


@mcp.tool()
def operations(path, argv, address):
    os.makedirs(path)
    Path(path).write_text("fixture")
    os.remove(path)
    subprocess.run(argv)
    socket.create_connection(address)

import os
import subprocess
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture")


def echo_text(text):
    return text.strip()


@mcp.tool()
def inspect_sample():
    os.stat("notes.txt")
    subprocess.list2cmdline(["sample"])
    urllib.request.Request("http://127.0.0.1/")
    with open("notes.txt") as source:
        return source.read()

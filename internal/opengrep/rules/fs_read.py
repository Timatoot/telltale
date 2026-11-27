import io
import os
from pathlib import Path


@mcp.tool()
def sample(path: str):
    # ruleid: fs-read
    with open(path) as source:
        return source.read()


@mcp.tool()
def local_notes(encoding):
    # ok: fs-read
    return open("notes.txt", encoding=encoding)


@mcp.tool()
def write_only(path):
    # ok: fs-read
    return open(path, "w")


@mcp.tool()
async def reads(path):
    p = Path(path)
    # ruleid: fs-read
    io.open(path, mode="rb")
    # ruleid: fs-read
    os.open(path, os.O_RDONLY)
    # ok: fs-read
    os.open(path, os.O_WRONLY)
    # ruleid: fs-read
    p.read_text()
    # ruleid: fs-read
    p.read_bytes()
    # ruleid: fs-read
    Path(path).open()
    # ruleid: fs-read
    p.open(encoding="utf-8")
    # ok: fs-read
    p.open(mode="wb")


@mcp.tool()
def confined(name):
    root = Path("/fixture/catalog").resolve()
    candidate = (root / name).resolve()
    if candidate.is_relative_to(root):
        # ok: fs-read
        return candidate.read_text()


@mcp.tool()
def shared_prefix(name):
    # /fixture/catalog-backup is a sibling of /fixture/catalog.
    root = Path("/fixture/catalog").resolve()
    candidate = (root / name).resolve()
    if str(candidate).startswith(str(root)):
        # ruleid: fs-read
        return candidate.read_text()


def local_helper(path):
    # ok: fs-read
    return open(path)


def registered(path):
    # ruleid: fs-read
    return open(path)


mcp.add_tool(registered)


@mcp.tool()
def branch_scope(name):
    root = Path("/fixture/catalog").resolve()
    candidate = (root / name).resolve()
    if candidate.is_relative_to(root):
        # ok: fs-read
        return candidate.read_bytes()
    # ruleid: fs-read
    return candidate.read_bytes()


@mcp.tool()
def wrong_root(name, other):
    root = Path(other).resolve()
    candidate = (root / name).resolve()
    if candidate.is_relative_to(root):
        # ruleid: fs-read
        return candidate.read_text()


@mcp.tool()
def alternate_branch(name):
    root = Path("/fixture/catalog").resolve()
    candidate = (root / name).resolve()
    if candidate.is_relative_to(root):
        # ok: fs-read
        return candidate.read_text()
    else:
        # ruleid: fs-read
        return candidate.read_text()


@mcp.tool()
def keyword_modes(name):
    # ruleid: fs-read
    io.open(file=name, mode="rb")
    # ruleid: fs-read
    os.open(path=name, flags=os.O_RDONLY)
    # ok: fs-read
    os.open(path=name, flags=os.O_WRONLY | os.O_CREAT)


@mcp.tool()
def default_mode(name):
    # ruleid: fs-read
    return open(name, encoding="utf-8")


# Synthetic sibling input for both versions of the containment check.
sibling = "/fixture/catalog-backup/notes.txt"
confined(sibling)
shared_prefix(sibling)


@mcp.tool()
def check_one_read_another(name, other):
    root = Path("/fixture/catalog").resolve()
    candidate = (root / name).resolve()
    if candidate.is_relative_to(root):
        # ruleid: fs-read
        return Path(other).read_text()

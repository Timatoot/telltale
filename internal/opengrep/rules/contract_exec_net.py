import asyncio
import os
import socket
import subprocess
import urllib.request

import aiohttp
import httpx
import requests


async def operations(argv, url, addr):
    # ruleid: exec
    subprocess.run(argv)
    # ruleid: exec
    subprocess.Popen(argv)
    # ruleid: exec
    os.system(argv[0])
    # ruleid: exec
    os.popen(argv[0])
    # ruleid: exec
    await asyncio.create_subprocess_exec(*argv)
    # ruleid: exec
    await asyncio.create_subprocess_shell(argv[0])
    # ruleid: network
    requests.get(url)
    # ruleid: network
    httpx.post(url)
    # ruleid: network
    urllib.request.urlopen(url)
    # ruleid: network
    socket.create_connection(addr)
    # ruleid: network
    await aiohttp.ClientSession().get(url)
    # ok: network
    urllib.request.Request(url)
    # ok: exec
    subprocess.list2cmdline(argv)
    async with aiohttp.ClientSession() as session:
        # ruleid: network
        await session.post(url)
    # ok: network
    {"a": 1}.get("a")

import os
import shutil
from pathlib import Path


def filesystem(path, dest):
    p = Path(path)
    # ruleid: fs-write
    open(path, "a")
    # ruleid: fs-write
    open(path, mode="xb")
    # ruleid: fs-write
    p.chmod(0o600)
    # ruleid: fs-write
    os.makedirs(path)
    # ruleid: fs-delete
    p.unlink()
    # ruleid: fs-delete
    p.rmdir()
    # ruleid: fs-delete
    os.remove(path)
    # ruleid: fs-delete
    os.unlink(path)
    # ruleid: fs-delete
    os.rmdir(path)
    # ruleid: fs-delete
    shutil.rmtree(path)
    # ruleid: fs-overwrite
    p.write_text("sample")
    # ruleid: fs-overwrite
    p.write_bytes(b"sample")
    # ruleid: fs-overwrite
    p.rename(dest)
    # ruleid: fs-overwrite
    os.rename(path, dest)
    # ruleid: fs-overwrite
    os.replace(path, dest)
    # ruleid: fs-overwrite
    shutil.move(path, dest)
    # ruleid: fs-overwrite
    shutil.copy2(path, dest)
    # ruleid: fs-overwrite
    open(path, "wb")
    # ruleid: fs-overwrite
    open(path, mode="r+")
    # ok: fs-overwrite
    open(path, "rb")
    # ok: fs-delete
    p.exists()
    # ok: fs-write
    os.stat(path)
    # ruleid: fs-overwrite
    (Path("catalog") / path).write_text("fixture")
    # ruleid: fs-write
    shutil.copymode(path, dest)


def extra_path_and_os_open(path):
    p = Path(path)
    # ruleid: fs-overwrite
    p.open("w")
    # ruleid: fs-write
    p.open("a")
    # ok: fs-overwrite
    p.open("r")
    # ruleid: fs-overwrite
    (Path("catalog") / path).open(mode="wb")
    # ruleid: fs-overwrite
    Path(path).resolve().write_text("x")
    resolved = (Path("catalog") / path).resolve()
    # ruleid: fs-delete
    resolved.unlink()
    # ruleid: fs-overwrite
    os.open(path, os.O_WRONLY | os.O_CREAT)
    # ok: fs-overwrite
    os.open(path, os.O_RDONLY)
    # ok: fs-overwrite
    Path(path).read_text().replace("a", "b")

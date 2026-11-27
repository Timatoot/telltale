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

def sample(path):
    # ruleid: fs-read
    with open(path) as source:
        return source.read()


def write_only(path):
    # ok: fs-read
    return open(path, "w")

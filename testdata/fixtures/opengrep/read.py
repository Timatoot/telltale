def read_text(path):
    with open(path) as source:  # nosemgrep
        return source.read()

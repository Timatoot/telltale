def read_sample(path):
    with open(path) as source:  # nosemgrep
        return source.read()

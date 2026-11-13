"""Tiny sample app for the seed test project.

Used by Phase 5 (reachability analysis): the AST checker walks files like this
to see whether a flagged package is actually imported and whether a specific
vulnerable function is called. `requests` is imported and used here, so its
findings should stay high-priority; a flagged-but-never-imported package would
be demoted.
"""

import yaml  # imported but only load() is used below


def fetch(url):
    import requests
    return requests.get(url, timeout=5)


def load_config(path):
    with open(path) as fh:
        return yaml.safe_load(fh)


if __name__ == "__main__":
    print(load_config("config.yaml"))
    print(fetch("https://example.com"))

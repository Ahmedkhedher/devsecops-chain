"""Phase 4 -- Post the scan results as a GitHub PR comment.

Reads the markdown produced by the pipeline and either creates a new PR comment
or updates a previous one (idempotent via a hidden marker), so repeated pushes
to the same PR don't spam the thread.

Auth: uses GITHUB_TOKEN (provided automatically in Actions). No third-party
action needed -- plain REST via urllib.

Usage:
    py -m ci.post_pr_comment --markdown data/pr_comment.md \
        --repo owner/name --pr 42 --token $GITHUB_TOKEN
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

# Hidden marker so we can find and update our own previous comment.
COMMENT_MARKER = "<!-- devsecops-chain:security-scan -->"
DEFAULT_API_ROOT = "https://api.github.com"


def _request(method: str, url: str, token: str, body: Optional[dict] = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"GitHub API {method} {url} failed ({exc.code}): {detail}") from exc


def _find_existing(comments: list[dict]) -> Optional[dict]:
    for c in comments:
        if COMMENT_MARKER in (c.get("body") or ""):
            return c
    return None


def post_comment(
    repo: str,
    pr: int,
    markdown: str,
    token: str,
    api_root: str = DEFAULT_API_ROOT,
) -> dict:
    """Create or update the security-scan comment on the PR."""
    root = api_root.rstrip("/")
    body = f"{COMMENT_MARKER}\n{markdown}"

    comments = _request(
        "GET", f"{root}/repos/{repo}/issues/{pr}/comments?per_page=100", token
    )
    existing = _find_existing(comments if isinstance(comments, list) else [])

    if existing:
        url = f"{root}/repos/{repo}/issues/comments/{existing['id']}"
        return _request("PATCH", url, token, {"body": body})
    url = f"{root}/repos/{repo}/issues/{pr}/comments"
    return _request("POST", url, token, {"body": body})


def pr_from_ref(ref: str) -> Optional[int]:
    """Extract the PR number from a GITHUB_REF like refs/pull/42/merge."""
    parts = ref.split("/")
    if len(parts) >= 3 and parts[1] == "pull":
        try:
            return int(parts[2])
        except ValueError:
            return None
    return None


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Post pipeline results as a PR comment.")
    p.add_argument("--markdown", required=True, help="path to the markdown output file")
    p.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"),
                   help="owner/name (defaults to $GITHUB_REPOSITORY)")
    p.add_argument("--pr", type=int, default=None,
                   help="PR number (auto-detected from $GITHUB_REF in Actions)")
    p.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"),
                   help="GitHub token (defaults to $GITHUB_TOKEN)")
    args = p.parse_args(argv)

    pr = args.pr if args.pr is not None else pr_from_ref(os.environ.get("GITHUB_REF", ""))

    if not args.repo or pr is None or not args.token:
        print("error: need --repo, --pr (or $GITHUB_REF), and --token ($GITHUB_TOKEN)",
              file=sys.stderr)
        return 2

    markdown = Path(args.markdown).read_text(encoding="utf-8")
    try:
        result = post_comment(args.repo, pr, markdown, args.token)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"posted comment: {result.get('html_url')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fetch a GhidraMCP extension jar into dist/, for `gmcp serve`.

The jar is not vendored here: it is a build artifact of bethington/ghidra-mcp
(Apache-2.0), it is ~740 KB of binary per release, and pinning a copy in this
repo would rot against your Ghidra version. This pulls it from that project's
GitHub releases instead.

    python scripts/fetch-headless-jar.py                # newest release
    python scripts/fetch-headless-jar.py --tag v6.0.0   # a specific one
    python scripts/fetch-headless-jar.py --list         # what is available

The extension zip contains GhidraMCP/lib/GhidraMCP-<ver>.jar; that jar carries
com.xebyte.headless.GhidraMCPHeadlessServer, which is what `gmcp serve` runs.
Nothing in the zip is installed into Ghidra -- `gmcp serve` only puts the jar on
a java classpath.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import urllib.error
import urllib.request
import zipfile

REPO = "bethington/ghidra-mcp"
API = f"https://api.github.com/repos/{REPO}/releases"
DIST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dist")


def get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "gmcp-fetch"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def releases() -> list[dict]:
    return json.loads(get(f"{API}?per_page=20"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tag", help="release tag, e.g. v6.0.0 (default: newest with a zip)")
    ap.add_argument("--list", action="store_true", help="list releases and exit")
    args = ap.parse_args()

    try:
        rels = releases()
    except urllib.error.URLError as e:
        print(f"cannot reach the GitHub API: {e.reason}", file=sys.stderr)
        return 3

    if args.list:
        for rel in rels:
            zips = [a["name"] for a in rel["assets"] if a["name"].endswith(".zip")]
            print(f"{rel['tag_name']:<12} {rel['published_at'][:10]}  {', '.join(zips) or '(no zip)'}")
        return 0

    chosen = None
    for rel in rels:
        if args.tag and rel["tag_name"] != args.tag:
            continue
        for asset in rel["assets"]:
            if asset["name"].startswith("GhidraMCP-") and asset["name"].endswith(".zip"):
                chosen = (rel["tag_name"], asset)
                break
        if chosen:
            break
    if not chosen:
        print(
            f"no GhidraMCP-*.zip asset found{' for ' + args.tag if args.tag else ''}; "
            "try --list",
            file=sys.stderr,
        )
        return 1

    tag, asset = chosen
    print(f"fetching {asset['name']} from {tag} ({asset['size']} bytes)")
    zf = zipfile.ZipFile(io.BytesIO(get(asset["browser_download_url"])))
    inner = [n for n in zf.namelist() if n.endswith(".jar")]
    if not inner:
        print(f"{asset['name']} contains no jar", file=sys.stderr)
        return 1

    os.makedirs(DIST, exist_ok=True)
    out = os.path.join(DIST, os.path.basename(inner[0]))
    payload = zf.read(inner[0])
    with open(out, "wb") as fh:
        fh.write(payload)

    # A jar without the headless entry point cannot serve: say so now rather
    # than letting `gmcp serve` fail with a ClassNotFoundException.
    classes = zipfile.ZipFile(io.BytesIO(payload)).namelist()
    entry = "com/xebyte/headless/GhidraMCPHeadlessServer.class"
    print(f"wrote {out}")
    if entry not in classes:
        print(
            f"WARNING: {os.path.basename(out)} has no {entry};\n"
            "         this release predates the headless server. Use a newer --tag.",
            file=sys.stderr,
        )
        return 1
    print("headless server present; run: gmcp serve --port 8089 --project <dir>")
    return 0


if __name__ == "__main__":
    sys.exit(main())

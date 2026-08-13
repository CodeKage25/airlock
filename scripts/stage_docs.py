#!/usr/bin/env python3
"""Copy the root markdown into docs/ for the site build.

The repo copies stay canonical and the site is built from throwaway duplicates, so the
two cannot drift. Links into source files are rewritten to absolute GitHub URLs, since
the source tree is not part of the site.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
BLOB = "https://github.com/CodeKage25/airlock/blob/main"

PAGES = {
    "README.md": "index.md",
    "BENCHMARK.md": "BENCHMARK.md",
    "ROADMAP.md": "ROADMAP.md",
    "SECURITY.md": "SECURITY.md",
    "CONTRIBUTING.md": "CONTRIBUTING.md",
    "CHANGELOG.md": "CHANGELOG.md",
    "CLAUDE.md": "CLAUDE.md",
    "CODE_OF_CONDUCT.md": "CODE_OF_CONDUCT.md",
}

# Paths that exist in the repo but not in the site, so their links must leave the site.
SOURCE_DIRS = ("airlock/", "tests/", "bench/", "examples/", "scripts/")


def rewrite(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        label, target = match.group(1), match.group(2)
        if target.startswith(SOURCE_DIRS) or target == "LICENSE":
            return f"[{label}]({BLOB}/{target})"
        return match.group(0)

    return re.sub(r"\[([^\]]+)\]\((?!https?://|#)([^)]+)\)", replace, text)


def main() -> int:
    DOCS.mkdir(exist_ok=True)
    for source, target in PAGES.items():
        path = ROOT / source
        if not path.exists():
            print(f"missing {source}", file=sys.stderr)
            return 1
        (DOCS / target).write_text(rewrite(path.read_text()))
        print(f"staged {source} -> docs/{target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

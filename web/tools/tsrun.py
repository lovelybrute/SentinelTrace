#!/usr/bin/env python3
"""
Run the TypeScript engine modules under plain Node, with no dependencies.

Why this exists: the build sandbox has no network egress, so `npm install`
cannot fetch `typescript` or a test runner. Node 22 can execute TypeScript
directly via `--experimental-strip-types`, but it will not resolve two things
the source relies on: the `@/*` path alias and extensionless import
specifiers. This script makes a throwaway copy of the engine with both
rewritten, so the *real* modules execute rather than a reimplementation.

Type stripping is erasure only — it does not type-check. This verifies runtime
behaviour; `npx tsc --noEmit` on a networked machine remains the type gate.

Usage:
    python3 tools/tsrun.py <entry.ts> [args...]

`<entry.ts>` is a path inside `web/`, e.g. `tools/checks/authentication.check.ts`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parent.parent
STAGE = Path(os.environ.get("TSRUN_STAGE", "/tmp/sentineltrace-tsrun"))

# Directories copied into the staging tree. React components are excluded: they
# need JSX transformation, which type stripping does not perform.
COPY_DIRS = ["src/lib", "src/services", "src/types", "src/demo", "tools/checks"]

IMPORT_RE = re.compile(
    r"""(?P<prefix>\b(?:import|export)\b[^'"]*?\bfrom\s*|\bimport\s*)"""
    r"""(?P<quote>['"])(?P<spec>[^'"]+)(?P=quote)""",
    re.DOTALL,
)


def resolve_specifier(spec: str, source: Path, root: Path) -> str:
    """Rewrite one import specifier to something Node can resolve on disk."""
    if spec.startswith("@/"):
        target = root / "src" / spec[2:]
        rel = os.path.relpath(target, source.parent)
        rel = rel.replace(os.sep, "/")
        if not rel.startswith("."):
            rel = f"./{rel}"
    elif spec.startswith("."):
        rel = spec
        target = (source.parent / spec).resolve()
    else:
        # Bare package specifier — left alone (node: builtins etc.).
        return spec

    # Append the extension Node needs, picking index.ts for directories.
    if target.with_suffix(".ts").is_file():
        return f"{rel}.ts"
    if (target / "index.ts").is_file():
        return f"{rel}/index.ts"
    if target.is_file():
        return rel
    raise SystemExit(f"{source}: cannot resolve import {spec!r} (looked at {target})")


def stage_tree() -> Path:
    if STAGE.exists():
        shutil.rmtree(STAGE)
    STAGE.mkdir(parents=True)

    for directory in COPY_DIRS:
        src = WEB_ROOT / directory
        if not src.is_dir():
            continue
        shutil.copytree(src, STAGE / directory, dirs_exist_ok=True)

    # Rewrite every specifier against the staged tree, so directory probing
    # reflects exactly what Node will see.
    for path in sorted(STAGE.rglob("*.ts")):
        text = path.read_text(encoding="utf-8")

        def replace(match: re.Match[str]) -> str:
            spec = resolve_specifier(match.group("spec"), path, STAGE)
            quote = match.group("quote")
            return f"{match.group('prefix')}{quote}{spec}{quote}"

        rewritten = IMPORT_RE.sub(replace, text)
        if rewritten != text:
            path.write_text(rewritten, encoding="utf-8")

    return STAGE


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    entry = sys.argv[1]
    stage = stage_tree()
    staged_entry = stage / entry
    if not staged_entry.is_file():
        raise SystemExit(f"entry not found in staging tree: {staged_entry}")

    result = subprocess.run(
        [
            "node",
            "--experimental-strip-types",
            "--no-warnings=ExperimentalWarning",
            str(staged_entry),
            *sys.argv[2:],
        ],
        cwd=stage,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

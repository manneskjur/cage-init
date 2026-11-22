#!/usr/bin/env python3
"""Verify a Windows LCOW initrd payload written by `build-lcow-initrd.py`.

The payload must contain exactly the LCOW guest initrd, its records under
`metadata/` and the licence notices `metadata/components.json` declares. The
initrd must hold everything hcsshim's LCOW guest needs to boot with the kernel
its `metadata/kernel.json` names, that kernel's modules included, and every
file in it must be attributed to the component it came from.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _lcow_initrd import (  # noqa: E402
    COMPONENTS,
    INITRD,
    INPUTS,
    KERNEL_RECORD,
    components_problems,
    notice_paths,
    problems,
    read_initrd,
)

#: The payload files every build writes; the notices its components declare join them.
REQUIRED = {INITRD, f"metadata/{INPUTS}", f"metadata/{KERNEL_RECORD}", f"metadata/{COMPONENTS}"}


RELEASE_KEYS = ("repository", "version", "sha256sums_sha256", "manifest_sha256")


def record_problem(record: object) -> str | None:
    """Why *record* is not a complete `kernel.json`; None if it is."""
    if not isinstance(record, dict):
        return f"{KERNEL_RECORD} is not an object"
    release = record.get("release")
    if not isinstance(release, dict) or not all(
        isinstance(release.get(key), str) for key in RELEASE_KEYS
    ):
        return f"{KERNEL_RECORD} does not name the cage-kernel release"
    if not isinstance(record.get("kernel_sha256"), str):
        return f"{KERNEL_RECORD} does not name the kernel it boots with"
    if not isinstance(record.get("modules_sha256"), str):
        return f"{KERNEL_RECORD} does not name the kernel's modules archive"
    files = record.get("module_files")
    if not isinstance(files, list) or not all(isinstance(name, str) for name in files):
        return f"{KERNEL_RECORD} does not list the kernel's module files"
    return None


def verify(payload: Path) -> list[str]:
    files = {path.relative_to(payload).as_posix() for path in payload.rglob("*") if path.is_file()}
    components: object = None
    if f"metadata/{COMPONENTS}" in files:
        try:
            components = json.loads(
                (payload / "metadata" / COMPONENTS).read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            return [f"{COMPONENTS} is unreadable: {exc}"]
        if errors := components_problems(components, None):
            return errors
    expected = REQUIRED | (notice_paths(components) if isinstance(components, dict) else set())
    if files != expected:
        return [
            f"payload files differ: missing {sorted(expected - files)}, "
            f"unexpected {sorted(files - expected)}"
        ]
    try:
        record = json.loads((payload / "metadata" / KERNEL_RECORD).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"{KERNEL_RECORD} is unreadable: {exc}"]
    if (problem := record_problem(record)) is not None or not isinstance(record, dict):
        return [problem or f"{KERNEL_RECORD} is not an object"]
    module_files = record.get("module_files", [])
    try:
        members = read_initrd(payload / INITRD)
    except (OSError, ValueError, EOFError) as exc:
        return [f"initrd is not a gzip cpio archive: {exc}"]
    errors = [f"initrd lacks {item}" for item in problems(members, module_files)]
    return errors + components_problems(components, members)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    errors = verify(parser.parse_args().payload)
    for error in errors:
        print(f"windows-lcow-initrd: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

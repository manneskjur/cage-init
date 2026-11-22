#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["pytest>=8.4"]
# ///
"""Build, verify and release Cage's guest init filesystems for every platform.

Every platform is named explicitly: `macos` (the ContainerKit arm64 vminit
filesystem) and `windows` (the LCOW amd64 hcsshim initrd) are separate command
groups, and a release always carries both. The Windows initrd is built on Linux
by its recipe, `windows/build-lcow-initrd.py --output DIR`; `windows verify` and
`package-release` take that directory however it was produced.
"""

from __future__ import annotations

import argparse
import compileall
import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import _macos
import _sources
import _windows
from _common import LOCAL_ROOT, UNIT_ROOT, file_record, file_sha256, repo_path

RELEASE_SCHEMA_VERSION = 2
MANIFEST_ASSET = "manifest.json"
SHA256SUMS_ASSET = "SHA256SUMS"
DEFAULT_RELEASE_DIR = LOCAL_ROOT / "cage-init" / "release"
PLATFORMS = (_macos, _windows)


def unit_version() -> str:
    return (UNIT_ROOT / "VERSION").read_text(encoding="utf-8").strip()


def release_asset_names() -> tuple[str, ...]:
    """Every file a release publishes, in upload order."""
    return (
        *(name for platform in PLATFORMS for name in platform.release_asset_names()),
        _sources.ASSET,
        MANIFEST_ASSET,
        SHA256SUMS_ASSET,
    )


def write_sha256sums(release_dir: Path) -> None:
    names = sorted(name for name in release_asset_names() if name != SHA256SUMS_ASSET)
    lines = [f"{file_sha256(release_dir / name)}  {name}\n" for name in names]
    (release_dir / SHA256SUMS_ASSET).write_text("".join(lines), encoding="utf-8")


def package_release(
    args: argparse.Namespace,
    *,
    fetch: _sources.Fetch = _sources.fetch_url,
    git_remote: Callable[[str], str] = lambda url: url,
) -> int:
    release_dir = args.release_dir.resolve(strict=False)
    if release_dir.exists():
        shutil.rmtree(release_dir)
    release_dir.mkdir(parents=True)
    platforms = {
        _macos.PLATFORM: _macos.package_release(args.macos_artifact_dir, release_dir),
        _windows.PLATFORM: _windows.package_release(args.windows_artifact_dir, release_dir),
    }
    # Each platform's payload is verified above, its components.json included.
    payloads = {
        platform.PLATFORM: (directory, platform.components_record(directory))
        for platform, directory in (
            (_macos, args.macos_artifact_dir.resolve(strict=False)),
            (_windows, args.windows_artifact_dir.resolve(strict=False)),
        )
    }
    archive = release_dir / _sources.ASSET
    _sources.package(
        archive,
        version=unit_version(),
        payloads=payloads,
        fetch=fetch,
        cache=args.sources_cache_dir.resolve(strict=False),
        git_remote=git_remote,
    )
    manifest = {
        "schema_version": RELEASE_SCHEMA_VERSION,
        "version": unit_version(),
        "platforms": platforms,
        "source_archive": {"name": archive.name, **file_record(archive)},
    }
    (release_dir / MANIFEST_ASSET).write_bytes(
        json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    write_sha256sums(release_dir)
    present = {path.name for path in release_dir.iterdir()}
    if present != set(release_asset_names()):
        raise SystemExit(f"release directory holds {sorted(present)}, not the release assets")
    print(f"Wrote cage-init {unit_version()} release assets to {repo_path(release_dir)}")
    return 0


def print_release_assets(_: argparse.Namespace) -> int:
    print(json.dumps(list(release_asset_names())))
    return 0


def compile_scripts() -> None:
    scripts = Path(__file__).parent
    for script in sorted([*scripts.glob("*.py"), *(scripts.parent / "windows").glob("*.py")]):
        if not compileall.compile_file(script, quiet=1, force=True):
            raise SystemExit(f"failed to compile {repo_path(script)}")


def lint(_: argparse.Namespace) -> int:
    _macos.load_pins()
    _windows._recipe_module("build-lcow-initrd")._pins()
    compile_scripts()
    print("cage-init lint passed")
    return 0


def typecheck(_: argparse.Namespace) -> int:
    compile_scripts()
    print("cage-init typecheck passed")
    return 0


def format_code(_: argparse.Namespace) -> int:
    print("cage-init has no formatter")
    return 0


def test(args: argparse.Namespace) -> int:
    import pytest

    return int(pytest.main(["-q", str(UNIT_ROOT / "tests"), *args.pytest_args]))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)
    for platform in PLATFORMS:
        platform.register(subparsers)

    package_command = subparsers.add_parser(
        "package-release", help="package every platform's verified init filesystems as one release"
    )
    package_command.add_argument(
        "--macos-artifact-dir", type=Path, default=_macos.DEFAULT_ARTIFACT_DIR
    )
    package_command.add_argument(
        "--windows-artifact-dir", type=Path, default=_windows.DEFAULT_ARTIFACT_DIR
    )
    package_command.add_argument("--release-dir", type=Path, default=DEFAULT_RELEASE_DIR)
    package_command.add_argument(
        "--sources-cache-dir",
        type=Path,
        default=_sources.DEFAULT_CACHE_DIR,
        help="where downloaded sources are cached, by digest",
    )
    package_command.set_defaults(handler=package_release)

    assets_command = subparsers.add_parser(
        "release-assets", help="print the release's asset names as JSON"
    )
    assets_command.set_defaults(handler=print_release_assets)

    test_command = subparsers.add_parser("test")
    test_command.add_argument("pytest_args", nargs="*")
    test_command.set_defaults(handler=test)
    for name, handler in (("format", format_code), ("lint", lint), ("typecheck", typecheck)):
        subparsers.add_parser(name).set_defaults(handler=handler)
    return root


def main(argv: list[str]) -> int:
    args = parser().parse_args(argv[1:])
    try:
        return int(args.handler(args) or 0)
    except subprocess.CalledProcessError as exc:
        print(
            f"command failed with exit code {exc.returncode}: {' '.join(exc.cmd)}",
            file=sys.stderr,
        )
        return int(exc.returncode)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

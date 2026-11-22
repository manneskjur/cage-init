"""Windows LCOW guest initrd: verify and release the hcsshim amd64 initrd.

Cage boots its LCOW utility VMs with this initrd and the Windows kernel of the
cage-kernel release pinned in `windows/lcow-initrd.toml`. The initrd is built
on Linux by `windows/build-lcow-initrd.py --output DIR`: hcsshim's guest agent
built with `KMOD=1`, busybox, runc, the ext4 tools and that kernel's modules.
This module takes that directory as given, however it was produced, and
verifies it against the pins before anything releases it.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

from _common import LOCAL_ROOT, UNIT_ROOT, file_record, repo_path

PLATFORM = "windows"
ARCHITECTURE = "amd64"
RECIPE_DIR = UNIT_ROOT / PLATFORM
PINS_PATH = RECIPE_DIR / "lcow-initrd.toml"
DEFAULT_ARTIFACT_DIR = LOCAL_ROOT / "cage-init" / PLATFORM / "lcow"
INITRD_ASSET = f"{PLATFORM}-{ARCHITECTURE}-lcow-initrd.img"


def _recipe_module(name: str) -> ModuleType:
    """A module of the artifact recipe, which runs without this package."""
    sys.path.insert(0, str(RECIPE_DIR))
    path = RECIPE_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"cage_init_{name.replace('-', '_')}", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {repo_path(path)}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_pins() -> dict[str, Any]:
    return tomllib.loads(PINS_PATH.read_text(encoding="utf-8"))


def payload_problems(payload: Path, *, pins: dict[str, Any]) -> list[str]:
    """Why *payload* is not an initrd built from *pins*; empty if it is."""
    errors: list[str] = _recipe_module("verify-lcow-initrd").verify(payload)
    if errors:
        return errors
    try:
        inputs = json.loads((payload / "metadata" / "inputs.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"inputs.json is unreadable: {exc}"]
    if not isinstance(inputs, dict) or inputs.get("pins") != pins:
        return [f"it was built from other pins than {repo_path(PINS_PATH)}"]
    components = components_record(payload)["components"]
    kernel = components.get("cage-kernel", {})
    if {key: kernel.get(key) for key in pins["cage_kernel"]} != pins["cage_kernel"]:
        return ["components.json names another cage-kernel release than the pins"]
    hcsshim = components.get("hcsshim", {})
    if (hcsshim.get("url"), hcsshim.get("commit")) != (
        pins["hcsshim"]["repository"],
        pins["hcsshim"]["commit"],
    ):
        return ["components.json names another hcsshim than the pins"]
    return []


def components_record(payload: Path) -> dict[str, Any]:
    """The verified payload's `metadata/components.json`."""
    return json.loads((payload / "metadata" / "components.json").read_text(encoding="utf-8"))


def verify(args: argparse.Namespace) -> int:
    errors = payload_problems(args.artifact_dir.resolve(strict=False), pins=load_pins())
    for error in errors:
        print(f"windows lcow initrd: {error}")
    return 1 if errors else 0


# -- Release -----------------------------------------------------------------


def release_asset_names() -> tuple[str, ...]:
    return (INITRD_ASSET,)


def package_release(artifact_dir: Path, release_dir: Path) -> dict[str, object]:
    """Write the initrd release asset; return this platform's manifest entry."""
    pins = load_pins()
    payload = artifact_dir.resolve(strict=False)
    if errors := payload_problems(payload, pins=pins):
        raise SystemExit(
            f"{repo_path(payload)} is not a releasable LCOW initrd: {'; '.join(errors)}; "
            "rebuild it with `windows/build-lcow-initrd.py --output DIR` on Linux"
        )
    record = json.loads((payload / "metadata" / "kernel.json").read_text(encoding="utf-8"))
    if (problem := _recipe_module("verify-lcow-initrd").record_problem(record)) is not None:
        raise SystemExit(problem)
    if not isinstance(record, dict):
        raise SystemExit("kernel.json is not an object")
    initrd = release_dir / INITRD_ASSET
    shutil.copyfile(payload / "initrd.img", initrd)
    return {
        "architecture": ARCHITECTURE,
        "sources": {"hcsshim": pins["hcsshim"], "debian": pins["debian"]},
        "kernel_release": record.get("release"),
        "kernel_sha256": record.get("kernel_sha256"),
        "modules_sha256": record.get("modules_sha256"),
        "initrd": {"name": initrd.name, **file_record(initrd)},
        "components": sorted(components_record(payload)["components"]),
    }


# -- Command line ------------------------------------------------------------


def register(subparsers: argparse._SubParsersAction) -> None:
    """Add the `windows` command group."""
    group = subparsers.add_parser("windows", help="Windows LCOW amd64 guest initrd")
    commands = group.add_subparsers(dest="windows_command", required=True)
    verify_command = commands.add_parser("verify", help="verify a built initrd against the pins")
    verify_command.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    verify_command.set_defaults(handler=verify)

"""Small synthetic Windows LCOW initrd payloads for script tests.

Nothing here downloads or builds: the payload has the exact file set and a
gzip cpio initrd with the hcsshim guest essentials.
"""

from __future__ import annotations

import json
import stat
import tomllib
from collections.abc import Mapping
from pathlib import Path

from _lcow_initrd import (
    COMPONENTS,
    COMPONENTS_SCHEMA,
    INITRD,
    INPUTS,
    KERNEL_RECORD,
    Entry,
    cpio_newc,
    gzip_bytes,
)

WINDOWS = Path(__file__).resolve().parents[1] / "windows"
PINS = WINDOWS / "lcow-initrd.toml"


def guest_entries() -> dict[str, Entry]:
    """The members a kernel without loadable modules needs from hcsshim's guest."""
    return {
        "bin": Entry.directory(),
        "run": Entry.directory(),
        "sbin": Entry.directory(),
        "sbin/mkfs.ext4": Entry.file(b"mkfs", executable=True),
        "sbin/runc": Entry.file(b"runc", executable=True),
        "init": Entry.file(b"hcsshim init", executable=True),
    }


def current_pins() -> dict:
    return tomllib.loads(PINS.read_text(encoding="utf-8"))


def kernel_record(*, module_files: list[str] | None = None) -> dict:
    return {
        "release": {
            "repository": "manneskjur/cage-kernel",
            "version": "0.6.0",
            "sha256sums_sha256": "1" * 64,
            "manifest_sha256": "2" * 64,
        },
        "kernel_sha256": "3" * 64,
        "modules_sha256": "4" * 64,
        "module_files": [] if module_files is None else module_files,
    }


RUNC = "debian:runc=1.1.5+ds1-1+deb12u1"
RUNC_NOTICE = "metadata/notices/debian/runc_1.1.5+ds1-1+deb12u1/runc.copyright"


def components_record(entries: Mapping[str, Entry], pins: dict | None = None) -> dict:
    """A `components.json` attributing every regular file of *entries*."""
    pins = current_pins() if pins is None else pins
    hcsshim = pins["hcsshim"]
    return {
        "schema_version": COMPONENTS_SCHEMA,
        "platform": "windows",
        "components": {
            "hcsshim": {
                "kind": "git",
                "url": hcsshim["repository"],
                "commit": hcsshim["commit"],
                "tag": hcsshim["tag"],
            },
            "go": {"kind": "go", "version": "go1.26.11"},
            RUNC: {
                "kind": "debian",
                "source": "runc",
                "version": "1.1.5+ds1-1+deb12u1",
                "packages": ["runc"],
                "notices": [RUNC_NOTICE],
            },
            "cage-kernel": {
                "kind": "cage-kernel",
                **pins["cage_kernel"],
                "source": {"name": "kernel", "version": "6.6.0"},
            },
        },
        "files": {
            name: [RUNC] if "runc" in name else ["go", "hcsshim"]
            for name, entry in entries.items()
            if stat.S_ISREG(entry.mode)
        },
    }


def make_payload(
    root: Path,
    *,
    initrd: Mapping[str, Entry] | None = None,
    record: dict | None = None,
    pins: dict | None = None,
    components: dict | None = None,
) -> Path:
    """Write a payload that passes verification unless a parameter breaks it."""
    entries = guest_entries() if initrd is None else initrd
    files = {
        INITRD: gzip_bytes(cpio_newc(entries)),
        f"metadata/{COMPONENTS}": json.dumps(
            components_record(entries, pins) if components is None else components
        ).encode("utf-8"),
        RUNC_NOTICE: b"Files: *\nLicense: Apache-2.0\n",
        f"metadata/{KERNEL_RECORD}": json.dumps(
            kernel_record() if record is None else record
        ).encode("utf-8"),
        f"metadata/{INPUTS}": json.dumps(
            {"pins": current_pins() if pins is None else pins}
        ).encode("utf-8"),
    }
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root

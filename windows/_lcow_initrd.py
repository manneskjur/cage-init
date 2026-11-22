"""Read, write and inspect hcsshim LCOW initrd archives (gzip-compressed cpio newc).

Standard library only: the Linux build imports this module on a build host
where Cage itself is not installed.
"""

from __future__ import annotations

import gzip
import io
import posixpath
import re
import stat
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

CPIO_NEWC_HEADER_LEN = 110
CPIO_TRAILER = "TRAILER!!!"
# Every archive member carries this modification time, so equal trees produce
# equal bytes (1980-01-01T00:00:00Z).
ARCHIVE_EPOCH = 315532800

MKFS_EXT4_PATHS = frozenset(
    {"bin/mkfs.ext4", "sbin/mkfs.ext4", "usr/bin/mkfs.ext4", "usr/sbin/mkfs.ext4"}
)
RUNC_PATHS = frozenset({"bin/runc", "sbin/runc", "usr/bin/runc", "usr/sbin/runc"})
#: The payload: the initrd, plus the records under `metadata/`.
INITRD = "initrd.img"
INPUTS = "inputs.json"
KERNEL_RECORD = "kernel.json"
#: Where every distributed file of the initrd came from: `metadata/components.json`.
COMPONENTS = "components.json"
COMPONENTS_SCHEMA = 1
#: Licence notices captured at build time live under `metadata/notices/`.
NOTICES_DIR = "notices"
#: The fields each kind of component must record, and their types.
COMPONENT_KINDS: dict[str, dict[str, type]] = {
    "git": {"url": str, "commit": str},
    "go": {"version": str},
    "debian": {"source": str, "version": str, "packages": list, "notices": list},
    "cage-kernel": {
        "repository": str,
        "version": str,
        "sha256sums_sha256": str,
        "manifest_sha256": str,
        "source": dict,
    },
    "generated": {"generator": str},
}


@dataclass(frozen=True, slots=True)
class Entry:
    """One archive member: a directory, a regular file or a symbolic link."""

    mode: int
    data: bytes = b""

    @classmethod
    def directory(cls) -> Entry:
        return cls(stat.S_IFDIR | 0o755)

    @classmethod
    def file(cls, data: bytes, *, executable: bool) -> Entry:
        return cls(stat.S_IFREG | (0o755 if executable else 0o644), data)

    @classmethod
    def symlink(cls, target: str) -> Entry:
        return cls(stat.S_IFLNK | 0o777, target.encode("utf-8"))


def _align4(offset: int) -> int:
    return (offset + 3) & ~3


def _header(name: bytes, entry: Entry, inode: int) -> bytes:
    fields = (
        inode,
        entry.mode,
        0,  # uid
        0,  # gid
        2 if stat.S_ISDIR(entry.mode) else 1,
        ARCHIVE_EPOCH,
        len(entry.data),
        0,
        0,
        0,
        0,
        len(name),
        0,
    )
    return ("070701" + "".join(f"{field:08x}" for field in fields)).encode("ascii")


def cpio_newc(entries: Mapping[str, Entry], *, trailer: bool = True) -> bytes:
    """Serialise *entries* as root-owned cpio newc in path order, parents first."""
    stream = io.BytesIO()
    for inode, path in enumerate(sorted(entries), start=1):
        if not path or path.startswith("/") or ".." in path.split("/"):
            raise ValueError(f"unsafe initrd path: {path!r}")
        _write(stream, path, entries[path], inode)
    if trailer:
        _write(stream, CPIO_TRAILER, Entry(0), 0)
    return stream.getvalue()


def _write(stream: io.BytesIO, path: str, entry: Entry, inode: int) -> None:
    name = path.encode("utf-8") + b"\0"
    raw = _header(name, entry, inode) + name
    stream.write(raw + b"\0" * (_align4(len(raw)) - len(raw)))
    stream.write(entry.data + b"\0" * (_align4(len(entry.data)) - len(entry.data)))


def gzip_bytes(payload: bytes) -> bytes:
    """Deterministic gzip: no timestamp or file name, fixed compression level."""
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", compresslevel=9, mtime=0) as archive:
        archive.write(payload)
    return stream.getvalue()


def iter_members(payload: bytes) -> Iterator[tuple[str, int, bytes]]:
    """Yield ``(name, mode, data)`` for each member; stop at the trailer.

    Concatenated archives (as the kernel reads them) are followed through
    their trailers. Malformed input raises rather than ending silently.
    """
    offset = 0
    length = len(payload)
    while offset < length:
        if payload[offset:].strip(b"\0") == b"":
            return
        header = payload[offset : offset + CPIO_NEWC_HEADER_LEN]
        if len(header) < CPIO_NEWC_HEADER_LEN or header[:6] not in {b"070701", b"070702"}:
            raise ValueError(f"invalid cpio newc header at offset {offset}")
        mode = int(header[14:22], 16)
        filesize = int(header[54:62], 16)
        namesize = int(header[94:102], 16)
        name_start = offset + CPIO_NEWC_HEADER_LEN
        name_end = name_start + namesize
        if namesize <= 0 or name_end > length:
            raise ValueError(f"invalid cpio entry name at offset {offset}")
        name = payload[name_start:name_end].rstrip(b"\0").decode("utf-8")
        data_start = _align4(name_end)
        data_end = data_start + filesize
        if data_end > length:
            raise ValueError(f"cpio entry {name!r} extends beyond the archive")
        offset = _align4(data_end)
        if name == CPIO_TRAILER:
            continue
        yield name.removeprefix("./").rstrip("/"), mode, payload[data_start:data_end]


def read_initrd(initrd: Path) -> dict[str, tuple[int, bytes]]:
    """Return every member of a gzip cpio initrd; later members replace earlier."""
    with gzip.open(initrd, "rb") as archive:
        payload = archive.read()
    return {name: (mode, data) for name, mode, data in iter_members(payload) if name != "."}


def kernel_record(pins: Mapping[str, object], kernel: Mapping[str, object]) -> dict[str, object]:
    """What `metadata/kernel.json` records: the kernel this initrd boots with.

    *kernel* is the `platforms.windows` entry of the pinned cage-kernel
    release's manifest. Cage refuses to pair this initrd with any other kernel.
    """
    release = pins["cage_kernel"]
    content = kernel["content"]
    modules = kernel["modules"]
    if not isinstance(release, Mapping) or not isinstance(content, Mapping):
        raise ValueError("the kernel release pin or manifest entry is malformed")
    if not isinstance(modules, Mapping):
        raise ValueError("the kernel manifest entry has no modules")
    return {
        "release": {
            key: release[key]
            for key in ("repository", "version", "sha256sums_sha256", "manifest_sha256")
        },
        "kernel_sha256": content["sha256"],
        "modules_sha256": modules["sha256"],
        "module_files": sorted(modules["files"]),  # type: ignore[call-overload]
    }


def problems(members: Mapping[str, tuple[int, bytes]], module_files: Iterable[str]) -> list[str]:
    """Why an initrd cannot boot hcsshim's LCOW guest; empty if it can.

    *module_files* are the kernel modules the guest must load: the files its
    cage-kernel release lists for the kernel this initrd boots with.
    """
    paths = set(members)
    found = []
    if "run" not in paths or not stat.S_ISDIR(members["run"][0]):
        found.append("/run directory")
    if MKFS_EXT4_PATHS.isdisjoint(paths):
        found.append("mkfs.ext4")
    if RUNC_PATHS.isdisjoint(paths):
        found.append("runc")
    init = members.get("init")
    if init is None or not stat.S_ISREG(init[0]):
        found.append("init")
    modules = sorted(module_files)
    if modules:
        if init is not None and not (
            b"/lib/modules" in init[1] and b"failed to load module" in init[1]
        ):
            found.append("kernel-module loading in init (hcsshim KMOD=1)")
        if not any(Path(path).name.startswith("libkmod.so.") for path in paths):
            found.append("libkmod runtime library")
        missing = [name for name in modules if name not in paths]
        if missing:
            found.append(f"kernel modules {missing[:3]}")
    return found


def component_slug(component: str) -> str:
    """A portable relative path for *component*: no `:` or `=`, which Windows refuses.

    `debian:<source>=<version>` becomes `debian/<source>_<version without epoch>`,
    the name Debian gives the source package's files.
    """
    kind, _, name = component.partition(":")
    if not name:
        return kind
    name, _, version = name.partition("=")
    if version:
        name = f"{name}_{version.split(':', 1)[-1]}"
    slug = f"{kind}/{name}"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~/-]*", slug) or ".." in slug.split("/"):
        raise ValueError(f"component {component!r} has no portable name")
    return slug


def symlink_target(path: str, target: str) -> str:
    """The tree path a symbolic link at *path* resolves to (one level)."""
    if target.startswith("/"):
        return posixpath.normpath(target.lstrip("/"))
    return posixpath.normpath(posixpath.join(posixpath.dirname(path), target))


def components_problems(
    record: object, members: Mapping[str, tuple[int, bytes]] | None
) -> list[str]:
    """Why *record* is not a complete `components.json` for *members*; empty if it is.

    Every regular file of the initrd must be attributed to known components, and
    every symbolic link must resolve to an attributed file. With *members* None,
    only the record's own shape is checked.
    """
    if not isinstance(record, dict) or record.get("schema_version") != COMPONENTS_SCHEMA:
        return [f"{COMPONENTS} is not a schema {COMPONENTS_SCHEMA} object"]
    components = record.get("components")
    files = record.get("files")
    if not isinstance(components, dict) or not components or not isinstance(files, dict):
        return [f"{COMPONENTS} lists no components or files"]
    errors: list[str] = []
    for name, component in sorted(components.items()):
        kind = component.get("kind") if isinstance(component, dict) else None
        fields = COMPONENT_KINDS.get(kind) if isinstance(kind, str) else None
        if fields is None or not all(
            isinstance(component.get(key), kind_type) for key, kind_type in fields.items()
        ):
            errors.append(f"{COMPONENTS}: component {name} is malformed")
            continue
        try:
            component_slug(name)
        except ValueError as exc:
            errors.append(str(exc))
        if kind == "debian" and component["packages"] and not component["notices"]:
            errors.append(f"{COMPONENTS}: component {name} captured no licence notice")
        for notice in component.get("notices", []):
            if not isinstance(notice, str) or not notice.startswith(f"metadata/{NOTICES_DIR}/"):
                errors.append(f"{COMPONENTS}: component {name} has a notice outside metadata/")
    for path, origins in sorted(files.items()):
        if (
            not isinstance(origins, list)
            or not origins
            or not all(isinstance(origin, str) and origin in components for origin in origins)
        ):
            errors.append(f"{COMPONENTS}: /{path} names no known component")
    if members is None or errors:
        return errors
    regular = {name for name, (mode, _) in members.items() if stat.S_ISREG(mode)}
    for path in sorted(regular - set(files)):
        errors.append(f"/{path} is attributed to no component")
    for path in sorted(set(files) - regular):
        errors.append(f"{COMPONENTS} attributes /{path}, which the initrd does not hold")
    for name, (mode, data) in sorted(members.items()):
        if stat.S_ISLNK(mode):
            target = symlink_target(name, data.decode("utf-8"))
            if target not in files:
                errors.append(f"symbolic link /{name} resolves to no attributed file")
    return errors


def notice_paths(record: Mapping[str, object]) -> set[str]:
    """Every payload notice file a well-formed *record* declares."""
    components = record.get("components")
    if not isinstance(components, Mapping):
        return set()
    return {
        notice
        for component in components.values()
        if isinstance(component, Mapping)
        for notice in component.get("notices", [])  # type: ignore[union-attr]
        if isinstance(notice, str)
    }

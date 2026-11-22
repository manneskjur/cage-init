"""macOS ContainerKit guest initfs: build, verify and release the arm64 vminit filesystem.

Cage boots its ContainerKit VMs with this ext4 filesystem as `/`: Apple
Containerization's `vminitd` and `vmexec`, built from the `apple/containerization`
revision pinned in `macos/containerization.toml` by upstream's own `make
linux-build`, which runs the Swift static Linux SDK build in Apple's `container`.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import shlex
import shutil
import subprocess
import tomllib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from _common import (
    LOCAL_ROOT,
    UNIT_ROOT,
    ensure_under_local,
    file_record,
    file_sha256,
    repo_path,
    run,
    zstd_compress,
)

PLATFORM = "macos"
ARCHITECTURE = "arm64"
PINS_PATH = UNIT_ROOT / PLATFORM / "containerization.toml"
PINS_SCHEMA = 1
DEFAULT_WORK_DIR = LOCAL_ROOT / "cage-init" / PLATFORM
DEFAULT_ARTIFACT_DIR = DEFAULT_WORK_DIR / "initfs"
INITFS_FILE = "initfs.ext4"
BUILD_RECORD = "build.json"
#: Where every distributed file came from; `package-release` reconstructs its sources.
COMPONENTS_RECORD = "components.json"
#: 2: `link_evidence`, what each executable's link took from where.
COMPONENTS_SCHEMA = 2
PAYLOAD_FILES = frozenset({INITFS_FILE, BUILD_RECORD, COMPONENTS_RECORD})
CONTAINERIZATION = "containerization"
SWIFT_STATIC_SDK = "swift-static-sdk"
#: The SwiftPM workspace the initfs executables are built in: vminitd's
#: (`vminitd`, `vmexec`). `make init` also resolves the root package's, for
#: `cctl`, which lays the filesystem out but is not in it; its packages are not
#: distributed and may resolve to other revisions.
SWIFT_WORKSPACES = (Path("vminitd") / ".build",)
#: Where upstream pins the Static Linux SDK its dev image installs.
SWIFT_SDK_MAKEFILE = Path("vminitd") / "Makefile"
#: Where upstream's `make init` writes the filesystem, in the checkout.
UPSTREAM_INITFS = Path("bin") / "initfs.ext4"
INITFS_ASSET = f"{PLATFORM}-{ARCHITECTURE}-initfs.ext4.zst"
EXT4_SUPERBLOCK_OFFSET = 1024
EXT4_MAGIC_OFFSET = EXT4_SUPERBLOCK_OFFSET + 0x38
EXT4_MAGIC = b"\x53\xef"
MINIMUM_INITFS_SIZE = 1024 * 1024

#: The executables upstream's `make init` links from vminitd's package and
#: `cctl rootfs create` installs, and where in the initfs.
INITFS_EXECUTABLES = {"vminitd": "/sbin/vminitd", "vmexec": "/sbin/vmexec"}
#: The `SWIFT` `make init` runs with: links each executable with an lld map.
LINK_WRAPPER = UNIT_ROOT / PLATFORM / "swift-link-evidence.sh"
#: Where the checkout is mounted in the dev image, and this unit's scratch in it.
CONTAINER_WORKSPACE = PurePosixPath("/workspace")
EVIDENCE_SCRATCH = Path(".cage-init")
LINK_EVIDENCE_SCHEMA = 1


def load_pins() -> dict[str, Any]:
    path = PINS_PATH
    pins = tomllib.loads(path.read_text(encoding="utf-8"))
    if pins.get("schema") != PINS_SCHEMA:
        raise SystemExit(f"{repo_path(path)}: unsupported schema {pins.get('schema')!r}")
    if not isinstance(pins.get("url"), str) or not pins["url"].startswith("https://"):
        raise SystemExit(f"{repo_path(path)}: url must be an https Git URL")
    if not isinstance(pins.get("revision"), str) or not re.fullmatch(
        r"[0-9a-f]{40}", pins["revision"]
    ):
        raise SystemExit(f"{repo_path(path)}: revision must be a full commit hash")
    return pins


def source(pins: dict[str, Any]) -> dict[str, str]:
    return {"url": pins["url"], "revision": pins["revision"]}


def _git_url(url: str) -> str:
    return url if url.endswith(".git") else url + ".git"


def swift_dependencies(checkout: Path) -> dict[str, dict[str, str]]:
    """Every Swift package the build resolved, from SwiftPM's own workspace state.

    Each must be a source-control checkout at a recorded revision; a local
    path may only be Containerization itself. Anything else is refused.
    """
    found: dict[str, dict[str, str]] = {}
    for workspace in SWIFT_WORKSPACES:
        path = checkout / workspace / "workspace-state.json"
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SystemExit(f"{path} is absent or unreadable: {exc}") from exc
        workspace_object = state.get("object") if isinstance(state, dict) else None
        if not isinstance(workspace_object, dict) or "dependencies" not in workspace_object:
            raise SystemExit(f"{path} is absent or unreadable: no object.dependencies")
        dependencies = workspace_object["dependencies"]
        artifacts = workspace_object.get("artifacts", [])
        if not isinstance(dependencies, list) or artifacts:
            raise SystemExit(f"{path}: binary artifacts or malformed dependencies are not sourced")
        for dependency in dependencies:
            try:
                reference = dependency["packageRef"]
                identity, kind = reference["identity"], reference["kind"]
                location = reference.get("location") or reference.get("path")
                state_name = dependency["state"]["name"]
            except (KeyError, TypeError) as exc:
                raise SystemExit(f"{path}: malformed dependency {dependency!r}") from exc
            # vminitd's `path: "../"` dependency is the pinned checkout itself,
            # mounted at /workspace in the dev image; SwiftPM names it after that
            # directory, so its path decides, not its identity.
            if kind == "fileSystem" and state_name == "fileSystem":
                if location != str(CONTAINER_WORKSPACE) or dependency["state"].get("path") != str(
                    CONTAINER_WORKSPACE
                ):
                    raise SystemExit(
                        f"{path}: local package {identity} at {location} is not the "
                        f"Containerization checkout ({CONTAINER_WORKSPACE})"
                    )
                continue
            revision = dependency["state"].get("checkoutState", {}).get("revision")
            if (
                kind != "remoteSourceControl"
                or state_name != "sourceControlCheckout"
                or not isinstance(location, str)
                or not location.startswith("https://")
                or not isinstance(revision, str)
                or not re.fullmatch(r"[0-9a-f]{40}", revision)
            ):
                raise SystemExit(
                    f"{path}: Swift package {identity} is not a pinned source checkout"
                )
            record = {"kind": "git", "url": _git_url(location), "commit": revision}
            version = dependency["state"]["checkoutState"].get("version")
            if isinstance(version, str):
                record["version"] = version
            name = f"swift:{identity}"
            if found.get(name, record)["commit"] != record["commit"]:
                raise SystemExit(f"Swift package {identity} resolved to two revisions")
            found[name] = record
    return found


def swift_static_sdk(checkout: Path) -> dict[str, str]:
    """The Static Linux SDK upstream's dev image installs, as its Makefile pins it."""
    path = checkout / SWIFT_SDK_MAKEFILE
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"{path} is unreadable: {exc}") from exc
    values = {}
    for name in ("SWIFT_SDK_URL", "SWIFT_SDK_CHECKSUM"):
        match = re.search(rf"^{name}\s*:?=\s*(\S+)\s*$", text, re.M)
        if match is None:
            raise SystemExit(f"{path} no longer pins {name}")
        values[name] = match[1]
    tag = re.search(r"/(swift-[0-9][0-9.]*-RELEASE)/", values["SWIFT_SDK_URL"])
    if not values["SWIFT_SDK_URL"].startswith("https://") or tag is None:
        raise SystemExit(f"{path}: SWIFT_SDK_URL names no Swift release")
    if not re.fullmatch(r"[0-9a-f]{64}", values["SWIFT_SDK_CHECKSUM"]):
        raise SystemExit(f"{path}: SWIFT_SDK_CHECKSUM is not a SHA-256")
    return {
        "kind": SWIFT_STATIC_SDK,
        "url": values["SWIFT_SDK_URL"],
        "sha256": values["SWIFT_SDK_CHECKSUM"],
        "swift_tag": tag[1],
    }


def sdk_bundle_name(sdk: Mapping[str, str]) -> str:
    """The directory the SDK bundle installs as: its archive's name without `.tar.gz`."""
    name = sdk["url"].rsplit("/", 1)[-1]
    if not name.endswith(".artifactbundle.tar.gz"):
        raise SystemExit(f"the Static Linux SDK {sdk['url']} is not an artifact bundle archive")
    return name.removesuffix(".tar.gz")


# -- Link evidence -------------------------------------------------------------
#
# Which code each executable in the initfs holds is read from its own link:
# the wrapper (`macos/swift-link-evidence.sh`) has lld write a map of every
# input section the link placed in the executable. An input under the SDK
# bundle is the SDK's; one under vminitd's SwiftPM build directory was
# compiled by SwiftPM from the resolved packages' sources; anything else is
# refused. Each map is bound to its executable by the SHA-256 of the link's
# output and of the file read back out of the built initfs.ext4.

#: The columns of an lld link map (`ld.lld -Map`).
LLD_MAP_COLUMNS = ["VMA", "LMA", "Size", "Align", "Out", "In", "Symbol"]


def map_inputs(text: str) -> Iterator[tuple[str, str | None]]:
    """`(file, archive member or None)` for every input section an lld link map lists.

    lld lists only the input sections it placed in the output, so these are the
    inputs that contributed to the executable. Sections the linker synthesises
    (`<internal>`) are nobody's input. Raises `ValueError` for anything but an
    lld map.
    """
    lines = text.splitlines()
    header = lines[0] if lines else ""
    if header.split() != LLD_MAP_COLUMNS:
        raise ValueError("it is not an lld link map")
    out_column = header.index(" Out ") + 1
    in_column = header.index(" In ") + 1
    for line in lines[1:]:
        if len(line) <= in_column or line[in_column] == " " or line[out_column:in_column].strip():
            continue  # an output section, or a symbol of the input section above
        entry = line[in_column:].rstrip()
        file, separator, _section = entry.rpartition(":(")
        if not separator or not entry.endswith(")"):
            continue  # a linker-script assignment
        if file.startswith("<"):
            continue
        member = re.fullmatch(r"(.+)\(([^()]+)\)", file)
        yield (member[1], member[2]) if member else (file, None)


@dataclass
class Link:
    """What one executable's link took from where, as its map says."""

    #: `{SDK installation directory: {path in the bundle: archive members}}`;
    #: an object file has no members.
    sdk: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    #: The SwiftPM target build directories (`<target>.build`) it took objects from.
    swiftpm: set[str] = field(default_factory=set)
    #: Inputs that are neither.
    unattributed: set[str] = field(default_factory=set)


def classify_inputs(
    inputs: Iterator[tuple[str, str | None]], *, bundle: str, build_dir: PurePosixPath
) -> Link:
    """Split a link's inputs by where they are: the SDK bundle, SwiftPM's build, elsewhere.

    Only absolute paths are attributed; `..` is resolved lexically first.
    """
    link = Link()
    for file, member in inputs:
        path = PurePosixPath(posixpath.normpath(file))
        name = f"{path}({member})" if member else str(path)
        if not path.is_absolute():
            link.unattributed.add(name)
        elif bundle in path.parts:
            index = path.parts.index(bundle)
            root = PurePosixPath(*path.parts[: index + 1])
            members = link.sdk.setdefault(str(root), {}).setdefault(
                path.relative_to(root).as_posix(), set()
            )
            if member is not None:
                members.add(member)
        elif path.is_relative_to(build_dir) and path != build_dir:
            # The target's build directory (`<target>.build`), or `.` for the build's own.
            parts = path.relative_to(build_dir).parts
            link.swiftpm.add(parts[0] if len(parts) > 1 else ".")
        else:
            link.unattributed.add(name)
    return link


@dataclass
class Links:
    """Every initfs executable's link, read from the wrapper's evidence."""

    build_dir: PurePosixPath
    links: dict[str, Link]
    linked_sha256: dict[str, str]
    map_sha256: dict[str, str]
    errors: list[str]

    def sdk_installation(self) -> str:
        """The one directory every link took the SDK from."""
        roots = {root for link in self.links.values() for root in link.sdk}
        if len(roots) != 1:
            raise SystemExit(
                f"the initfs executables took the Static Linux SDK from {len(roots)} "
                f"installations, not one: {', '.join(sorted(roots)) or 'none'}"
            )
        return roots.pop()


def read_links(link_dir: Path, *, bundle: str) -> Links:
    """Parse the wrapper's maps; a missing or unreadable one is an error naming its executable."""
    try:
        build_dir = PurePosixPath((link_dir / "bin-path").read_text(encoding="utf-8").strip())
    except OSError as exc:
        raise SystemExit(f"the link wrapper recorded no build directory: {exc}") from exc
    if not build_dir.is_absolute():
        raise SystemExit(f"the link wrapper's build directory {build_dir} is not absolute")
    result = Links(build_dir=build_dir, links={}, linked_sha256={}, map_sha256={}, errors=[])
    for executable in sorted(INITFS_EXECUTABLES):
        map_path = link_dir / f"{executable}.map"
        try:
            text = map_path.read_text(encoding="utf-8")
            link = classify_inputs(map_inputs(text), bundle=bundle, build_dir=build_dir)
            linked = (link_dir / f"{executable}.sha256").read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            result.errors.append(
                f"{executable}: its link evidence is missing or unreadable: {exc}"
            )
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", linked):
            result.errors.append(f"{executable}: its link recorded no SHA-256 of its output")
            continue
        result.links[executable] = link
        result.linked_sha256[executable] = linked
        result.map_sha256[executable] = file_sha256(map_path)
    return result


def readback_script(*, sdk_installation: str, linked: list[str], scratch: PurePosixPath) -> str:
    """The dev-image script that reads the initfs's files and the SDK's inputs back.

    `debugfs` dumps the whole initfs.ext4 tree; `find` lists every static archive
    and object file of the SDK installation the links used; and each *linked*
    path (relative to it) is resolved to the file it names, as the links may
    have reached a file through a symbolic link of the SDK.
    """
    tree = shlex.quote(str(scratch / "initfs"))
    request = shlex.quote(f"rdump / {scratch / 'initfs'}")
    listing = shlex.quote(str(scratch / "sdk-inputs.txt"))
    resolved = shlex.quote(str(scratch / "sdk-resolved.txt"))
    paths = " ".join(shlex.quote(path) for path in linked)
    return (
        f"set -eu; rm -rf {tree}; mkdir -p {tree}; "
        f"debugfs -R {request} {UPSTREAM_INITFS.as_posix()}; "
        f"cd {shlex.quote(sdk_installation)}; "
        f"find . -type f \\( -name '*.a' -o -name '*.o' \\) > {listing}; "
        f": > {resolved}; for path in {paths}; do "
        f'printf \'%s\\t%s\\n\' "$path" "$(realpath -e --relative-to=. "$path")" >> {resolved}; '
        "done"
    )


def initfs_files(tree: Path) -> dict[str, Path]:
    """Every regular file of the initfs read back into *tree*, by its path in the initfs."""
    return {
        "/" + path.relative_to(tree).as_posix(): path
        for path in sorted(tree.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def link_evidence(scratch: Path, *, bundle: str, initfs: Path) -> dict[str, Any]:
    """The link evidence of every initfs executable, bound to the initfs, or a refusal.

    *scratch* holds what the wrapper wrote under `link/` and what
    `readback_script` wrote: `initfs/`, the initfs tree, and `sdk-inputs.txt`.
    Refuses, naming the executable, any map that is missing or unreadable, any
    input it cannot attribute, and any executable whose linked bytes are not
    the initfs's; and any initfs file that no link wrote.
    """
    links = read_links(scratch / "link", bundle=bundle)
    errors = list(links.errors)
    tree = scratch / "initfs"
    installed = initfs_files(tree) if tree.is_dir() else {}
    if not installed:
        errors.append(f"no file could be read back out of {INITFS_FILE}")
    executables: dict[str, dict[str, Any]] = {}
    linked: dict[str, dict[str, list[str]]] = {}
    for executable, link in sorted(links.links.items()):
        location = INITFS_EXECUTABLES[executable]
        if link.unattributed:
            errors.append(
                f"{executable}: linked inputs that are neither the Static Linux SDK's nor "
                "SwiftPM-built: " + ", ".join(sorted(link.unattributed))
            )
        if not link.swiftpm:
            errors.append(f"{executable}: its link map lists no SwiftPM-built input")
        file = installed.get(location)
        initfs_sha256 = file_sha256(file) if file is not None else None
        if installed and file is None:
            errors.append(f"{executable}: {INITFS_FILE} holds no {location}")
        elif initfs_sha256 is not None and initfs_sha256 != links.linked_sha256[executable]:
            errors.append(
                f"{executable}: {location} in {INITFS_FILE} has SHA-256 {initfs_sha256}, "
                f"not the {links.linked_sha256[executable]} its mapped link wrote"
            )
        for paths in link.sdk.values():
            for path, members in paths.items():
                linked.setdefault(path, {})[executable] = sorted(members)
        executables[executable] = {
            "path": location,
            "linked_sha256": links.linked_sha256[executable],
            "initfs_sha256": initfs_sha256,
            "map_sha256": links.map_sha256[executable],
            "swiftpm": sorted(link.swiftpm),
        }
    if unbound := sorted(set(installed) - set(INITFS_EXECUTABLES.values())):
        errors.append(f"{INITFS_FILE} holds files no link evidence covers: {', '.join(unbound)}")
    try:
        listing = (scratch / "sdk-inputs.txt").read_text(encoding="utf-8").splitlines()
        resolved = dict(
            line.split("\t", 1)
            for line in (scratch / "sdk-resolved.txt").read_text(encoding="utf-8").splitlines()
            if "\t" in line
        )
    except OSError as exc:
        listing, resolved = [], {}
        errors.append(f"the SDK's inputs were not listed: {exc}")
    universe = {line.strip().removeprefix("./") for line in listing if line.strip()}
    files: dict[str, dict[str, list[str]]] = {}
    for path, binaries in sorted(linked.items()):
        real = resolved.get(path, "")
        if not real or real.startswith("../") or real not in universe:
            errors.append(
                f"{', '.join(sorted(binaries))}: linked SDK input {path} resolves to no file "
                "the SDK installation holds"
            )
            continue
        for executable, members in binaries.items():
            if files.setdefault(real, {}).setdefault(executable, members) != members:
                errors.append(f"{executable}: linked {real} through two paths, differently")
    if errors:
        raise SystemExit(
            "the macOS initfs's link evidence does not establish what it holds; refusing it:\n"
            + "\n".join(f"- {error}" for error in errors)
        )
    installation = links.sdk_installation()
    prefix = PurePosixPath(installation).name
    return {
        "schema_version": LINK_EVIDENCE_SCHEMA,
        "initfs_sha256": file_sha256(initfs),
        "build_directory": str(links.build_dir),
        "sdk_installation": installation,
        "executables": executables,
        # Every static archive and object file of the SDK, by its path in the
        # bundle, with what each executable's link took from it.
        "sdk_inputs": {f"{prefix}/{path}": files.get(path, {}) for path in sorted(universe)},
    }


def components(checkout: Path, pins: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """What `components.json` records for an initfs built in *checkout*.

    The filesystem holds vminitd and vmexec, built from Containerization and
    every Swift package their build resolved, statically linked with what
    *evidence* says each took from the Static Linux SDK, and laid out by
    Containerization's `cctl`.
    """
    found: dict[str, dict[str, str]] = {
        CONTAINERIZATION: {"kind": "git", "url": pins["url"], "commit": pins["revision"]},
        **swift_dependencies(checkout),
        SWIFT_STATIC_SDK: swift_static_sdk(checkout),
    }
    return {
        "schema_version": COMPONENTS_SCHEMA,
        "platform": PLATFORM,
        "components": found,
        "files": {INITFS_FILE: sorted(found)},
        "link_evidence": evidence,
    }


#: The fields each kind of macOS component records.
COMPONENT_KINDS: dict[str, tuple[str, ...]] = {
    "git": ("url", "commit"),
    SWIFT_STATIC_SDK: ("url", "sha256", "swift_tag"),
}


def components_problems(record: object, pins: dict[str, Any]) -> list[str]:
    """Why *record* is not a complete `components.json` for an initfs from *pins*."""
    if not isinstance(record, dict) or record.get("schema_version") != COMPONENTS_SCHEMA:
        return [f"{COMPONENTS_RECORD} is not a schema {COMPONENTS_SCHEMA} object"]
    found = record.get("components")
    if not isinstance(found, dict):
        return [f"{COMPONENTS_RECORD} lists no components"]
    errors = []
    for name, component in sorted(found.items()):
        kind = component.get("kind") if isinstance(component, dict) else None
        fields = COMPONENT_KINDS.get(kind) if isinstance(kind, str) else None
        if fields is None or not all(isinstance(component.get(key), str) for key in fields):
            errors.append(f"{COMPONENTS_RECORD}: component {name} is malformed")
    if found.get(CONTAINERIZATION) != {
        "kind": "git",
        "url": pins["url"],
        "commit": pins["revision"],
    }:
        errors.append(f"{COMPONENTS_RECORD} does not name the pinned Containerization")
    if not isinstance(found.get(SWIFT_STATIC_SDK), dict):
        errors.append(f"{COMPONENTS_RECORD} does not name the Static Linux SDK")
    if record.get("files") != {INITFS_FILE: sorted(found)}:
        errors.append(f"{COMPONENTS_RECORD} does not attribute {INITFS_FILE} to its components")
    errors.extend(link_evidence_problems(record.get("link_evidence")))
    return errors


def _sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def link_evidence_problems(evidence: object) -> list[str]:
    """Why *evidence* does not bind every initfs executable's link to the initfs."""
    name = f"{COMPONENTS_RECORD} link_evidence"
    if not isinstance(evidence, dict) or evidence.get("schema_version") != LINK_EVIDENCE_SCHEMA:
        return [f"{name} is not a schema {LINK_EVIDENCE_SCHEMA} object"]
    errors = []
    if not _sha256(evidence.get("initfs_sha256")):
        errors.append(f"{name} names no {INITFS_FILE} digest")
    executables = evidence.get("executables")
    if not isinstance(executables, dict) or set(executables) != set(INITFS_EXECUTABLES):
        return [*errors, f"{name} does not cover exactly {', '.join(sorted(INITFS_EXECUTABLES))}"]
    for executable, entry in sorted(executables.items()):
        if (
            not isinstance(entry, dict)
            or entry.get("path") != INITFS_EXECUTABLES[executable]
            or not all(_sha256(entry.get(key)) for key in ("linked_sha256", "map_sha256"))
            or not isinstance(entry.get("swiftpm"), list)
            or not entry["swiftpm"]
        ):
            errors.append(f"{name}: {executable} is malformed")
        elif entry.get("initfs_sha256") != entry["linked_sha256"]:
            errors.append(f"{name}: {executable} in {INITFS_FILE} is not what its link wrote")
    inputs = evidence.get("sdk_inputs")
    if not isinstance(inputs, dict) or not inputs:
        errors.append(f"{name} lists no Static Linux SDK inputs")
    else:
        for path, binaries in sorted(inputs.items()):
            if (
                not isinstance(binaries, dict)
                or not set(binaries) <= set(INITFS_EXECUTABLES)
                or not all(
                    isinstance(members, list) and all(isinstance(m, str) for m in members)
                    for members in binaries.values()
                )
            ):
                errors.append(f"{name}: SDK input {path} is malformed")
    return errors


def components_record(payload: Path) -> dict[str, Any]:
    """The verified payload's `components.json`."""
    return json.loads((payload / COMPONENTS_RECORD).read_text(encoding="utf-8"))


def payload_problems(payload: Path, *, pins: dict[str, Any]) -> list[str]:
    """Why *payload* is not an initfs built from *pins*; empty if it is."""
    try:
        files = {path.name for path in payload.iterdir()}
    except OSError as exc:
        return [f"cannot read {payload}: {exc}"]
    if files != PAYLOAD_FILES:
        return [
            f"payload files differ: missing {sorted(PAYLOAD_FILES - files)}, "
            f"unexpected {sorted(files - PAYLOAD_FILES)}"
        ]
    if any(not (payload / name).is_file() or (payload / name).is_symlink() for name in files):
        return ["payload entries must be regular files"]
    errors: list[str] = []
    try:
        record = json.loads((payload / BUILD_RECORD).read_text(encoding="utf-8"))
        attribution = json.loads((payload / COMPONENTS_RECORD).read_text(encoding="utf-8"))
        with (payload / INITFS_FILE).open("rb") as initfs:
            initfs.seek(EXT4_MAGIC_OFFSET)
            magic = initfs.read(len(EXT4_MAGIC))
    except (OSError, ValueError) as exc:
        return [f"payload is unreadable: {exc}"]
    if not isinstance(record, dict) or record.get("containerization") != source(pins):
        errors.append(f"it was built from another source than {repo_path(PINS_PATH)}")
    errors.extend(components_problems(attribution, pins))
    evidence = attribution.get("link_evidence") if isinstance(attribution, dict) else None
    if isinstance(evidence, dict) and evidence.get("initfs_sha256") != file_sha256(
        payload / INITFS_FILE
    ):
        errors.append(f"its link evidence describes another {INITFS_FILE}")
    if magic != EXT4_MAGIC:
        errors.append(f"{INITFS_FILE} is not an ext4 filesystem")
    if (payload / INITFS_FILE).stat().st_size < MINIMUM_INITFS_SIZE:
        errors.append(f"{INITFS_FILE} is implausibly small")
    return errors


def ensure_container_system_available() -> None:
    if shutil.which("container") is None:
        raise SystemExit("the Apple `container` CLI is required to build the macOS initfs")
    status = subprocess.run(
        ["container", "system", "status"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if status.returncode != 0:
        raise SystemExit(
            "Apple `container` system is not available. Start it with "
            "`container system start`, then rerun the cage-init command."
        )


def prepare_checkout(work_dir: Path, pins: dict[str, Any]) -> Path:
    checkout = work_dir / "containerization"
    if (checkout / ".git").is_dir():
        run(["git", "fetch", "--tags", "origin"], cwd=checkout)
    else:
        work_dir.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--no-checkout", pins["url"], str(checkout)], cwd=work_dir)
    try:
        run(["git", "checkout", "--detach", pins["revision"]], cwd=checkout)
    except subprocess.CalledProcessError:
        run(["git", "fetch", "origin", pins["revision"]], cwd=checkout)
        run(["git", "checkout", "--detach", pins["revision"]], cwd=checkout)
    run(["git", "reset", "--hard", pins["revision"]], cwd=checkout)
    run(["git", "clean", "-fdx", "--exclude", ".local/"], cwd=checkout)
    return checkout


def dev_container(
    checkout: Path, image: str, command: list[str], *, env: Mapping[str, str] | None = None
) -> None:
    """`container run` of upstream's dev image with *checkout* at `/workspace`."""
    environment = [
        argument for name, value in (env or {}).items() for argument in ("-e", f"{name}={value}")
    ]
    run(
        [
            "container",
            "run",
            "--rm",
            "--memory",
            "16gb",
            "--cpus",
            "8",
            "-v",
            f"{checkout}:{CONTAINER_WORKSPACE}",
            "-w",
            str(CONTAINER_WORKSPACE),
            *environment,
            image,
            *command,
        ],
        cwd=checkout,
    )


def create(args: argparse.Namespace) -> int:
    pins = load_pins()
    work_dir = ensure_under_local(args.work_dir)
    artifact_dir = ensure_under_local(args.artifact_dir)
    ensure_container_system_available()
    checkout = prepare_checkout(work_dir, pins)
    sdk = swift_static_sdk(checkout)
    bundle = sdk_bundle_name(sdk)
    # Upstream's own recipe: its Linux dev image, then `make init` inside it
    # (the Static Linux SDK build of vminitd and vmexec, and `cctl rootfs
    # create --ext4`), as `make linux-build` runs it but in the release
    # configuration, which `linux-build` does not forward. `SWIFT` is the link
    # evidence wrapper, which reaches every sub-make from the command line.
    run(["make", "linux-image"], cwd=checkout)
    swift_version = (checkout / ".swift-version").read_text(encoding="utf-8").strip()
    image = f"containerization-dev:{swift_version}"
    scratch = checkout / EVIDENCE_SCRATCH
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir()
    shutil.copyfile(LINK_WRAPPER, scratch / "swift")
    (scratch / "swift").chmod(0o755)
    in_container = CONTAINER_WORKSPACE / EVIDENCE_SCRATCH.as_posix()
    dev_container(
        checkout,
        image,
        ["make", "BUILD_CONFIGURATION=release", f"SWIFT={in_container / 'swift'}", "init"],
        env={
            "CAGE_INIT_LINK_PACKAGE": str(CONTAINER_WORKSPACE / "vminitd"),
            "CAGE_INIT_LINK_PRODUCTS": " ".join(sorted(INITFS_EXECUTABLES)),
            "CAGE_INIT_LINK_EVIDENCE": str(in_container / "link"),
        },
    )
    stage_payload(
        checkout, image, pins, bundle=bundle, work_dir=work_dir, artifact_dir=artifact_dir
    )
    return 0


def stage_payload(
    checkout: Path,
    image: str,
    pins: dict[str, Any],
    *,
    bundle: str,
    work_dir: Path,
    artifact_dir: Path,
) -> None:
    """Bind the link evidence `make init` left in *checkout* to its initfs; write the payload."""
    built = checkout / UPSTREAM_INITFS
    scratch = checkout / EVIDENCE_SCRATCH
    in_container = CONTAINER_WORKSPACE / EVIDENCE_SCRATCH.as_posix()
    # Read the executables back out of the filesystem the build wrote, and list
    # the SDK installation the links used, to bind the link evidence to both.
    links = read_links(scratch / "link", bundle=bundle)
    installation = links.sdk_installation()
    linked = sorted(
        {path for link in links.links.values() for path in link.sdk.get(installation, {})}
    )
    script = readback_script(sdk_installation=installation, linked=linked, scratch=in_container)
    dev_container(checkout, image, ["sh", "-c", script])
    evidence = link_evidence(scratch, bundle=bundle, initfs=built)
    staged = work_dir / "initfs.staged"
    if staged.exists():
        shutil.rmtree(staged)
    staged.mkdir(parents=True)
    shutil.copyfile(built, staged / INITFS_FILE)
    (staged / BUILD_RECORD).write_text(
        json.dumps({"containerization": source(pins)}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (staged / COMPONENTS_RECORD).write_text(
        json.dumps(components(checkout, pins, evidence), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if errors := payload_problems(staged, pins=pins):
        raise SystemExit("built macOS initfs is not usable: " + "; ".join(errors))
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.parent.mkdir(parents=True, exist_ok=True)
    staged.replace(artifact_dir)
    print(f"Wrote the macOS initfs to {repo_path(artifact_dir)}")


def verify(args: argparse.Namespace) -> int:
    errors = payload_problems(args.artifact_dir.resolve(strict=False), pins=load_pins())
    for error in errors:
        print(f"macos initfs: {error}")
    return 1 if errors else 0


# -- Release -----------------------------------------------------------------


def release_asset_names() -> tuple[str, ...]:
    return (INITFS_ASSET,)


def package_release(artifact_dir: Path, release_dir: Path) -> dict[str, object]:
    """Write the initfs release asset; return this platform's manifest entry."""
    pins = load_pins()
    payload = artifact_dir.resolve(strict=False)
    if errors := payload_problems(payload, pins=pins):
        raise SystemExit(
            f"{repo_path(payload)} is not a releasable macOS initfs: {'; '.join(errors)}; "
            "rebuild with `cage_init.py macos create`"
        )
    components_path = payload / COMPONENTS_RECORD
    components_record = json.loads(components_path.read_text(encoding="utf-8"))
    components = (
        components_record.get("components") if isinstance(components_record, dict) else None
    )
    if not isinstance(components, dict):
        raise SystemExit(f"{repo_path(components_path)} has no components table")
    initfs = release_dir / INITFS_ASSET
    zstd_compress(payload / INITFS_FILE, initfs)
    return {
        "architecture": ARCHITECTURE,
        "containerization": source(pins),
        "initfs": {"name": initfs.name, **file_record(initfs)},
        "content": file_record(payload / INITFS_FILE),
        "components": sorted(components),
    }


# -- Command line ------------------------------------------------------------


def add_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=DEFAULT_WORK_DIR,
        help=f"managed checkout directory, default: {repo_path(DEFAULT_WORK_DIR)}",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR,
        help=f"built initfs directory, default: {repo_path(DEFAULT_ARTIFACT_DIR)}",
    )


def register(subparsers: argparse._SubParsersAction) -> None:
    """Add the `macos` command group."""
    group = subparsers.add_parser("macos", help="macOS ContainerKit arm64 guest initfs")
    commands = group.add_subparsers(dest="macos_command", required=True)
    create_command = commands.add_parser("create", help="build the pinned vminit initfs")
    add_paths(create_command)
    create_command.set_defaults(handler=create)
    verify_command = commands.add_parser("verify", help="verify the built initfs")
    add_paths(verify_command)
    verify_command.set_defaults(handler=verify)

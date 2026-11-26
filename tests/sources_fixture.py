"""A synthetic world of upstream sources for `source-and-notices.tar` tests.

Nothing here touches the network: `Server` answers the URLs `_sources` fetches
from bytes built here, and every Git URL is served by one local repository.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

import _macos
import _sources
from lcow_initrd_payload import current_pins, make_payload

SWIFT_TAG = "swift-6.3-RELEASE"
SDK_URL = (
    f"https://download.swift.org/swift-6.3-release/static-sdk/{SWIFT_TAG}/"
    f"{SWIFT_TAG}_static-linux-0.1.0.artifactbundle.tar.gz"
)
GO_VERSION = "go1.26.11"
RUNC = "debian:runc=1.1.5+ds1-1+deb12u1"
KERNEL_VERSION = "9.9.9"
#: Where swift-docker holds the libfts sources, and what the fixture's say.
FTS_DIRECTORY = "swift-ci/sdks/static-linux/resources/fts"
FTS_SOURCE = b"/* NetBSD fts */\n"
#: The tags the SDK rules resolve, all on the fixture repository's one commit.
TAGS = (SWIFT_TAG, "1.1.6", "v1.2.5", "v1.3.1")


def _tar(files: dict[str, bytes], *, compression: str = "gz") -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode=f"w:{compression}") as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


@dataclass
class Server:
    """The fetcher `_sources` uses: answers registered URLs, refuses the rest."""

    files: dict[str, bytes] = field(default_factory=dict)
    requested: list[str] = field(default_factory=list)

    def __call__(self, url: str, destination: Path) -> None:
        self.requested.append(url)
        if url not in self.files:
            raise _sources.SourceError(f"{url} is not served (404)")
        destination.write_bytes(self.files[url])


def git_repository(root: Path) -> tuple[Path, str]:
    """A repository with a licence, tagged with every tag the SDK rules ask for."""
    root.mkdir(parents=True)

    # The user's own Git configuration (signing, hooks) must not reach the fixture.
    environment = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }

    def git(*argv: str) -> str:
        result = subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *argv],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise AssertionError(f"git {' '.join(argv)} failed: {result.stderr}")
        return result.stdout.strip()

    git("init", "--quiet")
    (root / "LICENSE").write_text("Apache License 2.0\n", encoding="utf-8")
    (root / "vendor" / "example.com" / "dep").mkdir(parents=True)
    (root / "vendor" / "example.com" / "dep" / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "main.go").write_text("package main\n", encoding="utf-8")
    (root / FTS_DIRECTORY).mkdir(parents=True)
    (root / FTS_DIRECTORY / "fts.c").write_bytes(FTS_SOURCE)
    (root / "LICENSE.md").write_text("Apache License 2.0\n", encoding="utf-8")
    git("add", ".")
    git("commit", "--quiet", "-m", "fixture")
    for tag in TAGS:
        git("tag", tag)
    git("config", "uploadpack.allowAnySHA1InWant", "true")
    git("config", "uploadpack.allowFilter", "true")
    return root, git("rev-parse", "HEAD")


def serve_debian(server: Server, source: str, version: str) -> dict[str, bytes]:
    """A Debian source package on snapshot.debian.org; returns its files by name."""
    upstream = version.split(":", 1)[-1].rsplit("-", 1)[0]
    noepoch = version.split(":", 1)[-1]
    files = {
        f"{source}_{upstream}.orig.tar.gz": _tar({f"{source}-{upstream}/COPYING": b"GPL\n"}),
        f"{source}_{noepoch}.debian.tar.xz": _tar(
            {"debian/copyright": b"Files: *\nLicense: Apache-2.0\n"}, compression="xz"
        ),
    }
    checksums = "".join(
        f" {hashlib.sha256(data).hexdigest()} {len(data)} {name}\n" for name, data in files.items()
    )
    files[f"{source}_{noepoch}.dsc"] = (
        f"Format: 3.0 (quilt)\nSource: {source}\nVersion: {version}\n"
        f"Checksums-Sha256:\n{checksums}"
    ).encode()
    hashes = {name: hashlib.sha1(data).hexdigest() for name, data in files.items()}
    server.files[f"{_sources.SNAPSHOT}/mr/package/{source}/{version}/srcfiles?fileinfo=1"] = (
        json.dumps(
            {
                "result": [{"hash": sha1} for sha1 in hashes.values()],
                "fileinfo": {
                    sha1: [{"name": name, "archive_name": "debian"}]
                    for name, sha1 in hashes.items()
                },
            }
        ).encode()
    )
    for name, data in files.items():
        server.files[f"{_sources.SNAPSHOT}/file/{hashes[name]}"] = data
    return files


def serve_go(server: Server, version: str = GO_VERSION) -> None:
    source = _tar({"go/LICENSE": b"BSD\n", "go/PATENTS": b"Google\n", "go/src/x.go": b""})
    filename = f"{version}.src.tar.gz"
    server.files[_sources.GO_RELEASES] = json.dumps(
        [
            {
                "version": version,
                "files": [
                    {
                        "filename": filename,
                        "kind": "source",
                        "sha256": hashlib.sha256(source).hexdigest(),
                    }
                ],
            }
        ]
    ).encode()
    server.files[f"https://go.dev/dl/{filename}"] = source


def serve_kernel(server: Server, repository: str, *, schema: int = 3) -> dict[str, str]:
    """A cage-kernel release; returns the `[cage_kernel]` pins that admit it."""
    base = f"https://github.com/{repository}/releases/download/v{KERNEL_VERSION}/"
    archive = _tar({"NOTICES.md": b"# kernel\n"}, compression="")
    manifest: dict = {"schema_version": schema, "version": KERNEL_VERSION, "platforms": {}}
    assets = {}
    if schema >= 3:
        manifest["source_archive"] = {
            "name": _sources.ASSET,
            "sha256": hashlib.sha256(archive).hexdigest(),
        }
        assets[_sources.ASSET] = archive
    assets["manifest.json"] = json.dumps(manifest).encode()
    sums = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(assets.items())
    ).encode()
    assets["SHA256SUMS"] = sums
    for name, data in assets.items():
        server.files[base + name] = data
    return {
        "repository": repository,
        "version": KERNEL_VERSION,
        "sha256sums_sha256": hashlib.sha256(sums).hexdigest(),
        "manifest_sha256": hashlib.sha256(assets["manifest.json"]).hexdigest(),
    }


#: The directory the SDK bundle archive holds, and installs as.
SDK_BUNDLE = f"{SWIFT_TAG}_static-linux-0.1.0.artifactbundle"
SDK_SYSROOT = f"{SDK_BUNDLE}/{SWIFT_TAG}_static-linux-0.1.0/swift-linux-musl/musl-1.2.5.sdk"
#: Another target's library: in the bundle, never the initfs's.
OTHER_TARGET_LIBRARY = f"{SDK_SYSROOT}/x86_64/usr/lib/libssl.a"


def sdk_path(library: str) -> str:
    """Where the fixture bundle holds *library* for the initfs's target."""
    if library.endswith(".o"):
        directory = "usr/lib"
    else:
        directory = "usr/lib/swift_static/linux-static" if "swift" in library else "usr/lib"
    return f"{SDK_SYSROOT}/aarch64/{directory}/{library}"


def sdk_bundle(libraries: tuple[str, ...], contents: dict[str, bytes] | None = None) -> bytes:
    """A Static Linux SDK bundle holding *libraries* (with *contents*, if given) for the
    initfs's target."""
    root = f"{SDK_BUNDLE}/{SWIFT_TAG}_static-linux-0.1.0/swift-linux-musl"
    sysroot = f"{SDK_SYSROOT}/aarch64"
    files = {
        f"{root}/swift-sdk.json": json.dumps(
            {
                "targetTriples": {
                    _sources.SWIFT_SDK_TRIPLE: {"sdkRootPath": "musl-1.2.5.sdk/aarch64"}
                }
            }
        ).encode(),
        f"{sysroot}/usr/lib/pkgconfig/zlib.pc": b"Name: zlib\nVersion: 1.3.1\n",
        f"{sysroot}/usr/lib/pkgconfig/libcurl.pc": b"Name: libcurl\nVersion: 8.15.0-DEV\n",
    }
    for library in libraries:
        files[sdk_path(library)] = (contents or {}).get(library, b"!<arch>\n")
    files[OTHER_TARGET_LIBRARY] = b"!<arch>\n"
    return _tar(files)


def sdk_link_evidence(
    initfs: bytes,
    libraries: tuple[str, ...],
    linked: dict[str, dict[str, list[str]]],
) -> dict:
    """`link_evidence` for an initfs whose links took *linked* (`{library: {exe: members}}`)
    from a bundle holding *libraries*."""
    digest = hashlib.sha256(initfs).hexdigest()
    inputs = {sdk_path(library): linked.get(library, {}) for library in libraries}
    inputs[OTHER_TARGET_LIBRARY] = {}
    return {
        "schema_version": _macos.LINK_EVIDENCE_SCHEMA,
        "initfs_sha256": digest,
        "build_directory": "/workspace/vminitd/.build/aarch64-swift-linux-musl/release",
        "sdk_installation": f"/root/.swiftpm/swift-sdks/{SDK_BUNDLE}",
        "executables": {
            name: {
                "path": path,
                "linked_sha256": "e" * 64,
                "initfs_sha256": "e" * 64,
                "map_sha256": "f" * 64,
                "swiftpm": ["CCryptoBoringSSL.build", f"{name}.build"],
            }
            for name, path in _macos.INITFS_EXECUTABLES.items()
        },
        "sdk_inputs": inputs,
    }


def initfs_bytes() -> bytes:
    initfs = bytearray(_macos.MINIMUM_INITFS_SIZE)
    initfs[_macos.EXT4_MAGIC_OFFSET : _macos.EXT4_MAGIC_OFFSET + 2] = _macos.EXT4_MAGIC
    return bytes(initfs)


#: What the fixture SDK holds for the initfs's target.
SDK_LIBRARIES = (
    "libswiftCore.a",
    "libFoundationEssentials.a",
    "lib_FoundationCollections.a",
    "libc.a",
    "libz.a",
    "crt1.o",
    "libcurl.a",
    "libssl.a",
    "libcrypto.a",
    "libfts.a",
)
#: What the fixture initfs's links take from it: an input of every rule kind,
#: and none of the libraries whose exact source is unknown.
SDK_LINKED = {
    "libswiftCore.a": {"vminitd": ["Array.cpp.o"], "vmexec": ["Array.cpp.o"]},
    "libFoundationEssentials.a": {"vmexec": ["Data.swift.o"]},
    "lib_FoundationCollections.a": {"vmexec": ["OrderedSet.swift.o"]},
    "libc.a": {"vminitd": ["memcpy.lo"], "vmexec": ["fork.lo", "memcpy.lo"]},
    "libz.a": {"vmexec": ["inflate.o"]},
    "crt1.o": {"vminitd": [], "vmexec": []},
}


def serve_sdk(
    server: Server,
    libraries: tuple[str, ...] = SDK_LIBRARIES,
    contents: dict[str, bytes] | None = None,
) -> dict[str, str]:
    bundle = sdk_bundle(libraries, contents)
    server.files[SDK_URL] = bundle
    server.files[
        f"https://raw.githubusercontent.com/swiftlang/swift/{SWIFT_TAG}/utils/update_checkout/"
        "update-checkout-config.json"
    ] = json.dumps(
        {"branch-schemes": {"release/6.3": {"repos": {"swift-collections": "1.1.6"}}}}
    ).encode()
    return {
        "kind": "swift-static-sdk",
        "url": SDK_URL,
        "sha256": hashlib.sha256(bundle).hexdigest(),
        "swift_tag": SWIFT_TAG,
    }


@dataclass
class World:
    server: Server
    repository: Path
    commit: str
    windows_pins: dict
    macos_pins: dict
    windows_payload: Path
    macos_payload: Path

    def remote(self, _url: str) -> str:
        return self.repository.as_uri()

    def payloads(self) -> dict:
        return {
            "macos": (self.macos_payload, _macos.components_record(self.macos_payload)),
            "windows": (
                self.windows_payload,
                json.loads(
                    (self.windows_payload / "metadata/components.json").read_text(encoding="utf-8")
                ),
            ),
        }


def macos_payload(root: Path, pins: dict, components: dict) -> Path:
    root.mkdir(parents=True)
    (root / _macos.INITFS_FILE).write_bytes(initfs_bytes())
    (root / _macos.BUILD_RECORD).write_text(
        json.dumps({"containerization": _macos.source(pins)}), encoding="utf-8"
    )
    (root / _macos.COMPONENTS_RECORD).write_text(json.dumps(components), encoding="utf-8")
    return root


def world(
    tmp_path: Path,
    *,
    kernel_schema: int = 3,
    linked: dict[str, dict[str, list[str]]] = SDK_LINKED,
    library_contents: dict[str, bytes] | None = None,
) -> World:
    """Payloads for both platforms and a server holding every source they name.

    The macOS initfs's links took *linked* from an SDK whose libraries hold
    *library_contents* (an empty archive otherwise)."""
    server = Server()
    repository, commit = git_repository(tmp_path / "upstream")
    windows_pins = copy.deepcopy(current_pins())
    windows_pins["hcsshim"]["commit"] = commit
    windows_pins["cage_kernel"] = serve_kernel(
        server, windows_pins["cage_kernel"]["repository"], schema=kernel_schema
    )
    serve_debian(server, "runc", "1.1.5+ds1-1+deb12u1")
    serve_go(server)
    windows_payload = make_payload(tmp_path / "windows", pins=windows_pins)
    macos_pins = {**_macos.load_pins(), "revision": commit}
    found = {
        _macos.CONTAINERIZATION: {"kind": "git", "url": macos_pins["url"], "commit": commit},
        "swift:swift-log": {
            "kind": "git",
            "url": "https://github.com/apple/swift-log.git",
            "commit": commit,
        },
        _macos.SWIFT_STATIC_SDK: serve_sdk(server, SDK_LIBRARIES, library_contents),
    }
    macos_components = {
        "schema_version": _macos.COMPONENTS_SCHEMA,
        "platform": "macos",
        "components": found,
        "files": {_macos.INITFS_FILE: sorted(found)},
        "link_evidence": sdk_link_evidence(initfs_bytes(), SDK_LIBRARIES, linked),
    }
    return World(
        server=server,
        repository=repository,
        commit=commit,
        windows_pins=windows_pins,
        macos_pins=macos_pins,
        windows_payload=windows_payload,
        macos_payload=macos_payload(tmp_path / "macos", macos_pins, macos_components),
    )


# -- Objects with DWARF source digests ------------------------------------------


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def dwarf_object(directory: str, files: dict[str, bytes]) -> bytes:
    """A relocatable little-endian ELF64 object whose DWARF 5 line table names *files*.

    Each file is recorded relative to *directory* with the MD5 of its bytes; the
    paths are `DW_FORM_line_strp` offsets that only the `.rela.debug_line`
    relocations carry, as clang writes them for AArch64.
    """
    strings = bytearray()
    offsets = {}
    for text in (directory, *files):
        offsets[text] = len(strings)
        strings += text.encode() + b"\0"
    body = bytearray()
    relocated: list[tuple[int, int]] = []  # (offset in .debug_line, string offset)
    standard_lengths = bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])
    header = bytearray([1, 1, 1, 0xFB, 14, 13]) + standard_lengths
    header += bytes([1]) + _uleb(1) + _uleb(0x1F)  # directories: path as line_strp
    header += _uleb(1)
    relocated.append((len(header), offsets[directory]))
    header += b"\0\0\0\0"
    header += bytes([3]) + _uleb(1) + _uleb(0x1F) + _uleb(2) + _uleb(0x0F) + _uleb(5) + _uleb(0x1E)
    header += _uleb(len(files))
    for name, data in files.items():
        relocated.append((len(header), offsets[name]))
        header += b"\0\0\0\0" + _uleb(0) + hashlib.md5(data).digest()
    # unit_length, version, address_size, seg_select_size, header_length, header
    prefix = (5).to_bytes(2, "little") + bytes([8, 0]) + len(header).to_bytes(4, "little")
    start = 4 + len(prefix)
    body = (len(prefix) + len(header)).to_bytes(4, "little") + prefix + header
    rela = b"".join(
        (start + at).to_bytes(8, "little")
        + ((1 << 32) | 258).to_bytes(8, "little")
        + addend.to_bytes(8, "little", signed=True)
        for at, addend in relocated
    )
    symtab = (
        bytes(24)
        + (0).to_bytes(4, "little")
        + bytes([3, 0])
        + (2).to_bytes(2, "little")
        + bytes(16)
    )
    names = b"\0.debug_line\0.debug_line_str\0.rela.debug_line\0.symtab\0.shstrtab\0"
    contents = [bytes(body), bytes(strings), rela, symtab, names]
    name_offsets = [
        names.index(n)
        for n in (
            b".debug_line\0",
            b".debug_line_str\0",
            b".rela.debug_line\0",
            b".symtab\0",
            b".shstrtab\0",
        )
    ]
    kinds = [1, 1, 4, 2, 3]
    links = [0, 0, 4, 0, 0]
    infos = [0, 0, 1, 1, 0]
    data = bytearray(64)
    placed = []
    for content in contents:
        placed.append(len(data))
        data += content
    shoff = len(data)
    data += bytes(64)  # the null section
    for index, content in enumerate(contents):
        data += (
            name_offsets[index].to_bytes(4, "little")
            + kinds[index].to_bytes(4, "little")
            + bytes(16)
            + placed[index].to_bytes(8, "little")
            + len(content).to_bytes(8, "little")
            + links[index].to_bytes(4, "little")
            + infos[index].to_bytes(4, "little")
            + bytes(16)
        )
    data[0:6] = b"\x7fELF\x02\x01"
    data[0x28:0x30] = shoff.to_bytes(8, "little")
    data[0x3A:0x3C] = (64).to_bytes(2, "little")
    data[0x3C:0x3E] = (len(contents) + 1).to_bytes(2, "little")
    data[0x3E:0x40] = (len(contents)).to_bytes(2, "little")
    return bytes(data)


def ar_archive(members: dict[str, bytes]) -> bytes:
    """A GNU `ar` archive of *members*."""
    out = bytearray(b"!<arch>\n")
    for name, data in members.items():
        header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(data):<10}`\n"
        out += header.encode() + data + (b"\n" if len(data) % 2 else b"")
    return bytes(out)

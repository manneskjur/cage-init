"""Reconstruct the corresponding source and licence notices of a cage-init release.

Each platform's build records, in its payload's `components.json`, the component
every distributed file came from and that component's exact source reference.
`package-release` turns those records into one deterministic archive,
`source-and-notices.tar`:

    NOTICES.md                    every component, its notices and its sources
    components/<platform>.json    each platform's build record, verbatim
    notices/<component>/...       licence notices, captured at build or read from source
    sources/...                   the exact sources, each verified by digest or commit
    build/{macos,windows,scripts}/...   this unit's build recipe and pins

Nothing is taken on trust: Git sources must resolve to their recorded commit,
Debian sources must match snapshot.debian.org's SHA-1 and their `.dsc`'s
SHA-256, downloads must match their pinned digests, and the kernel modules'
source must be the pinned `cage-kernel` release's own archive. Every component
that cannot be reconstructed is named in one error; nothing is packaged then.
"""

from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import json
import posixpath
import re
import shutil
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from _common import LOCAL_ROOT, UNIT_ROOT, tracked_files

ASSET = "source-and-notices.tar"
#: Every archive member carries this modification time (the recipe's ARCHIVE_EPOCH).
ARCHIVE_EPOCH = 315532800
DEFAULT_CACHE_DIR = LOCAL_ROOT / "cage-init" / "sources"
DOWNLOAD_ATTEMPTS = 3
#: The unit directories that control what a release is built from.
BUILD_DIRECTORIES = ("macos", "scripts", "windows")
SNAPSHOT = "https://snapshot.debian.org"
GO_RELEASES = "https://go.dev/dl/?mode=json&include=all"
NOTICE_NAME = re.compile(r"(?i)(licen[cs]e|copying|notice|copyright|patents)([._-].*)?")
MAXIMUM_NOTICE_SIZE = 4 * 1024 * 1024
#: What a component's sources are needed for, named in failures.
ROLES = {"cage-kernel": "kernel modules"}

#: `fetch(url, destination)` writes *url*'s bytes to *destination*.
Fetch = Callable[[str, Path], None]


class SourceError(Exception):
    """One component's sources cannot be reconstructed."""


def fetch_url(url: str, destination: Path) -> None:
    """Download *url*, retrying only transport failures; content is checked by the caller."""
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            with (
                urllib.request.urlopen(url, timeout=300) as response,
                destination.open("wb") as output,
            ):
                shutil.copyfileobj(response, output, 1024 * 1024)
            return
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            ConnectionError,
        ) as exc:
            if attempt == DOWNLOAD_ATTEMPTS:
                raise SourceError(
                    f"downloading {url} failed after {DOWNLOAD_ATTEMPTS} attempts: {exc}"
                ) from exc
            time.sleep(5.0 * attempt)


def _digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def component_slug(component: str) -> str:
    """A portable relative path for *component*; see `windows/_lcow_initrd.py`."""
    kind, _, name = component.partition(":")
    if not name:
        return kind
    name, _, version = name.partition("=")
    if version:
        name = f"{name}_{version.split(':', 1)[-1]}"
    slug = f"{kind}/{name}"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~/-]*", slug) or ".." in slug.split("/"):
        raise SourceError(f"component {component!r} has no portable name")
    return slug


@dataclass
class Assembly:
    """The archive being assembled: its members and what each component contributed."""

    fetch: Fetch
    cache: Path
    #: Maps a recorded Git URL to the remote actually fetched (tests serve local repositories).
    git_remote: Callable[[str], str] = lambda url: url
    members: dict[str, Path | bytes] = field(default_factory=dict)
    sources: dict[str, list[str]] = field(default_factory=dict)
    notices: dict[str, list[str]] = field(default_factory=dict)
    references: dict[str, str] = field(default_factory=dict)

    def add(self, component: str, path: str, content: Path | bytes, *, notice: bool) -> None:
        existing = self.members.get(path)
        if existing is not None and _content(existing) != _content(content):
            raise SourceError(f"{path} would hold two different contents")
        self.members[path] = content
        listing = (self.notices if notice else self.sources).setdefault(component, [])
        if path not in listing:
            listing.append(path)

    def download(self, url: str, algorithm: str, digest: str) -> Path:
        """*url*'s bytes, cached by *digest*, refused unless they match it."""
        if not re.fullmatch(r"[0-9a-f]{40,128}", digest):
            raise SourceError(f"{url} has no {algorithm} digest to verify")
        cached = self.cache / algorithm / digest
        if cached.is_file() and _digest(cached, algorithm) == digest:
            return cached
        cached.parent.mkdir(parents=True, exist_ok=True)
        partial = cached.with_suffix(".partial")
        self.fetch(url, partial)
        actual = _digest(partial, algorithm)
        if actual != digest:
            partial.unlink()
            raise SourceError(f"{url} has {algorithm} {actual}, not the expected {digest}")
        partial.replace(cached)
        return cached

    def read(self, url: str) -> bytes:
        """*url*'s bytes, uncached; for indexes the caller verifies by what they lead to."""
        scratch = self.cache / "scratch"
        scratch.mkdir(parents=True, exist_ok=True)
        destination = scratch / hashlib.sha256(url.encode()).hexdigest()
        self.fetch(url, destination)
        try:
            return destination.read_bytes()
        finally:
            destination.unlink()


def _content(content: Path | bytes) -> str:
    if isinstance(content, bytes):
        return hashlib.sha256(content).hexdigest()
    return _digest(content, "sha256")


# -- Git -----------------------------------------------------------------------


def _git(argv: list[str], *, cwd: Path) -> str:
    result = subprocess.run(
        ["git", *argv], cwd=cwd, capture_output=True, text=True, encoding="utf-8", check=False
    )
    if result.returncode:
        raise SourceError(f"git {' '.join(argv)} failed: {result.stderr.strip()}")
    return result.stdout


def git_archive(
    assembly: Assembly,
    component: str,
    url: str,
    ref: str,
    *,
    commit: str | None,
    paths: tuple[str, ...] = (),
) -> str:
    """Archive *url* at *ref* (*paths* only, if given); return the commit archived.

    With *commit*, *ref* must resolve to exactly that commit. The archive is
    gzip-compressed deterministically, so equal commits give equal bytes.
    """
    repository = assembly.cache / "git" / hashlib.sha256(url.encode()).hexdigest()[:24]
    if not (repository / "HEAD").is_file():
        repository.mkdir(parents=True, exist_ok=True)
        _git(["init", "--quiet", "--bare"], cwd=repository)
        _git(["remote", "add", "origin", assembly.git_remote(url)], cwd=repository)
    fetch = ["fetch", "--quiet", "--depth", "1"]
    if paths:
        fetch.append("--filter=blob:none")
    _git([*fetch, "origin", ref], cwd=repository)
    resolved = _git(["rev-parse", "FETCH_HEAD^{commit}"], cwd=repository).strip()
    if commit is not None and resolved != commit:
        raise SourceError(f"{url} {ref} resolved to {resolved}, not the recorded {commit}")
    slug = component_slug(component)
    prefix = f"{slug.rsplit('/', 1)[-1]}-{resolved[:12]}"
    work = assembly.cache / "archives"
    work.mkdir(parents=True, exist_ok=True)
    tar_path = work / f"{prefix}.tar"
    _git(
        ["archive", "--format=tar", f"--prefix={prefix}/", "-o", str(tar_path), resolved]
        + (["--", *paths] if paths else []),
        cwd=repository,
    )
    found = 0
    with tarfile.open(tar_path) as archive:
        for member in archive:
            name = member.name.removeprefix(f"{prefix}/")
            if _is_notice(member, name):
                data = archive.extractfile(member).read()  # type: ignore[union-attr]
                assembly.add(component, f"notices/{slug}/{name}", data, notice=True)
                found += 1
    if not found:
        raise SourceError(f"{url} at {resolved[:12]} carries no licence notice")
    compressed = work / f"{prefix}.tar.gz"
    with (
        tar_path.open("rb") as source,
        compressed.open("wb") as output,
        gzip.GzipFile(fileobj=output, mode="wb", compresslevel=9, mtime=0) as stream,
    ):
        shutil.copyfileobj(source, stream, 1024 * 1024)
    tar_path.unlink()
    assembly.add(component, f"sources/{slug}-{resolved[:12]}.tar.gz", compressed, notice=False)
    assembly.references[component] = f"{url} at {resolved}" + (
        f" ({ref.removeprefix('refs/tags/')})" if ref != resolved else ""
    )
    return resolved


def _is_notice(member: tarfile.TarInfo, name: str) -> bool:
    return (
        member.isfile()
        and member.size <= MAXIMUM_NOTICE_SIZE
        and NOTICE_NAME.fullmatch(name.rsplit("/", 1)[-1]) is not None
    )


# -- Debian --------------------------------------------------------------------


def _dsc_sha256(dsc: str) -> dict[str, str]:
    """`{file: sha256}` from a `.dsc`'s `Checksums-Sha256` field."""
    lines = dsc.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith("Checksums-Sha256:"))
    except StopIteration as exc:
        raise SourceError("the .dsc has no Checksums-Sha256") from exc
    sums: dict[str, str] = {}
    for line in lines[start + 1 :]:
        if not line.startswith(" "):
            break
        match = re.fullmatch(r"\s+([0-9a-f]{64})\s+[0-9]+\s+(\S+)", line)
        if match is None:
            raise SourceError(f"malformed .dsc checksum line: {line!r}")
        sums[match[2]] = match[1]
    if not sums:
        raise SourceError("the .dsc lists no files")
    return sums


def debian_source(assembly: Assembly, component: str, source: str, version: str) -> None:
    """The Debian source package *source* at *version*, every file verified twice."""
    index_url = (
        f"{SNAPSHOT}/mr/package/{urllib.parse.quote(source, safe='+~')}/"
        f"{urllib.parse.quote(version, safe='+:~')}/srcfiles?fileinfo=1"
    )
    try:
        index = json.loads(assembly.read(index_url))
    except ValueError as exc:
        raise SourceError(f"snapshot.debian.org has no {source} {version}") from exc
    result = index.get("result") if isinstance(index, dict) else None
    fileinfo = index.get("fileinfo") if isinstance(index, dict) else None
    if (
        not isinstance(result, list)
        or not isinstance(fileinfo, dict)
        or not all(isinstance(entry, dict) and "hash" in entry for entry in result)
    ):
        raise SourceError(f"snapshot.debian.org has no {source} {version}")
    hashes = [entry["hash"] for entry in result]
    files: dict[str, Path] = {}
    for sha1 in hashes:
        names = {entry.get("name") for entry in fileinfo.get(sha1, [])}
        if len(names) != 1 or not isinstance(name := names.pop(), str) or "/" in name:
            raise SourceError(f"snapshot.debian.org names {sha1} ambiguously")
        files[name] = assembly.download(f"{SNAPSHOT}/file/{sha1}", "sha1", sha1)
    dscs = [name for name in files if name.endswith(".dsc")]
    if len(dscs) != 1:
        raise SourceError(f"{source} {version} has {len(dscs)} .dsc files, not one")
    try:
        dsc = files[dscs[0]].read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise SourceError(f"{dscs[0]} is not UTF-8, as Debian policy requires") from exc
    sums = _dsc_sha256(dsc)
    if set(sums) != set(files) - {dscs[0]}:
        raise SourceError(f"{source} {version}'s files are not exactly those its .dsc lists")
    for name, sha256 in sums.items():
        if _digest(files[name], "sha256") != sha256:
            raise SourceError(f"{name} does not match its .dsc's SHA-256")
    slug = component_slug(component)
    directory = f"sources/{slug}"
    for name, path in sorted(files.items()):
        assembly.add(component, f"{directory}/{name}", path, notice=False)
    assembly.add(
        component, f"notices/{slug}/debian-copyright", _debian_copyright(files), notice=True
    )
    assembly.references[component] = f"Debian source package {source} {version}"


def _debian_copyright(files: Mapping[str, Path]) -> bytes:
    """`debian/copyright` from the packaging tarball (or the native source tarball)."""
    packaging = [name for name in files if ".debian.tar." in name]
    candidates = packaging or [name for name in files if ".tar." in name]
    for name in candidates:
        with tarfile.open(files[name]) as archive:
            for member in archive:
                if member.isfile() and (
                    member.name in {"debian/copyright", "./debian/copyright"}
                    or (not packaging and member.name.split("/", 1)[-1] == "debian/copyright")
                ):
                    return archive.extractfile(member).read()  # type: ignore[union-attr]
    raise SourceError("the source package carries no debian/copyright")


# -- Go ------------------------------------------------------------------------


def go_source(assembly: Assembly, component: str, version: str) -> None:
    """The Go source release *version*, verified by go.dev's published SHA-256."""
    try:
        releases = json.loads(assembly.read(GO_RELEASES))
        files = next(release for release in releases if release["version"] == version)["files"]
        source = next(entry for entry in files if entry.get("kind") == "source")
        filename, sha256 = source["filename"], source["sha256"]
    except (ValueError, KeyError, TypeError, StopIteration) as exc:
        raise SourceError(f"go.dev publishes no source release for {version}") from exc
    if not re.fullmatch(r"go[0-9][0-9a-z.]*\.src\.tar\.gz", filename):
        raise SourceError(f"go.dev names an unexpected source file {filename!r}")
    path = assembly.download(f"https://go.dev/dl/{filename}", "sha256", sha256)
    assembly.add(component, f"sources/go/{filename}", path, notice=False)
    found = 0
    with tarfile.open(path) as archive:
        for member in archive:
            name = member.name.removeprefix("go/")
            if "/" not in name and _is_notice(member, name):
                data = archive.extractfile(member).read()  # type: ignore[union-attr]
                assembly.add(component, f"notices/go/{name}", data, notice=True)
                found += 1
    if not found:
        raise SourceError(f"{filename} carries no licence notice")
    assembly.references[component] = f"Go {version} source release"


# -- cage-kernel ---------------------------------------------------------------


def _sha256sums(text: str) -> dict[str, str]:
    sums: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if match is None or match[2] in sums:
            raise SourceError(f"malformed SHA256SUMS line: {line!r}")
        sums[match[2]] = match[1]
    return sums


def kernel_source(assembly: Assembly, component: str, record: Mapping[str, Any]) -> None:
    """The pinned cage-kernel release's own source archive, admitted through its pins.

    `SHA256SUMS` must match its pin, `manifest.json` both its pin and its line,
    and the archive the manifest's `source_archive` names both the manifest and
    `SHA256SUMS`. A release without one (schema 2) cannot be redistributed.
    """
    repository, version = record["repository"], record["version"]
    base = f"https://github.com/{repository}/releases/download/v{version}/"
    sums_path = assembly.download(base + "SHA256SUMS", "sha256", record["sha256sums_sha256"])
    sums = _sha256sums(sums_path.read_text(encoding="utf-8"))
    if sums.get("manifest.json") != record["manifest_sha256"]:
        raise SourceError(f"cage-kernel {version}'s SHA256SUMS does not list its pinned manifest")
    manifest_path = assembly.download(base + "manifest.json", "sha256", record["manifest_sha256"])
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SourceError(f"cage-kernel {version}'s manifest.json is unreadable") from exc
    archive = manifest.get("source_archive") if isinstance(manifest, dict) else None
    name = archive.get("name") if isinstance(archive, dict) else None
    sha256 = archive.get("sha256") if isinstance(archive, dict) else None
    if not isinstance(name, str) or not isinstance(sha256, str):
        raise SourceError(f"cage-kernel {version} publishes no {ASSET}")
    if "/" in name or sums.get(name) != sha256:
        raise SourceError(f"cage-kernel {version}'s SHA256SUMS and manifest disagree on {name}")
    path = assembly.download(base + name, "sha256", sha256)
    assembly.add(component, f"sources/cage-kernel-{version}-{name}", path, notice=False)
    assembly.notices.setdefault(component, []).append(f"sources/cage-kernel-{version}-{name}")
    assembly.references[component] = f"{repository} v{version} {name}"


# -- Swift Static Linux SDK ----------------------------------------------------

#: The one explicit rule set. The Static Linux SDK bundle carries no licence
#: files or source references, so which upstream project each static library is
#: built from cannot be read from it; each rule maps library file names to that
#: project and says where in the bundle (or in Swift's own release metadata) its
#: exact version is recorded. A library no rule covers fails packaging, by name.
#:
#: Only what the initfs executables' links took from the SDK is attributed: the
#: link evidence in `components.json` names every static library and object file
#: each link used, so an SDK library no link used needs no source.
#:
#: `(input pattern, component, Git URL, version source, tag template)`. Version
#: sources: `swift-tag` (the SDK's Swift release tag), `update-checkout` (the
#: version Swift's `update-checkout-config.json` pins at that tag), `sysroot`
#: (the `musl-<version>.sdk` directory), `pc:<file>` (a pkg-config `Version`),
#: `cmake:<file>` (mimalloc's version file) and `header:<file>`; or
#: `dwarf:<build path>=<repository path>`, for a library built from a source
#: that no release names: the template is then the commit to archive, and every
#: source file under the build path that a linked member's DWARF line table
#: records must have the recorded MD5 at the repository path. The first
#: matching rule wins, so a specific pattern precedes a general one.
SWIFT_SDK_RULES: tuple[tuple[str, str, str, str, str], ...] = (
    (
        r"libswift(RegexBuilder|_RegexParser|_StringProcessing)\.a",
        "swift-experimental-string-processing",
        "https://github.com/swiftlang/swift-experimental-string-processing.git",
        "swift-tag",
        "{version}",
    ),
    (
        r"lib(swiftDispatch|dispatch|BlocksRuntime)\.a",
        "swift-corelibs-libdispatch",
        "https://github.com/swiftlang/swift-corelibs-libdispatch.git",
        "swift-tag",
        "{version}",
    ),
    (
        r"libswift\w*\.a",
        "swift",
        "https://github.com/swiftlang/swift.git",
        "swift-tag",
        "{version}",
    ),
    (
        r"lib(Foundation|FoundationNetworking|FoundationXML|CoreFoundation"
        r"|_CFURLSessionInterface|_CFXMLInterface)\.a",
        "swift-corelibs-foundation",
        "https://github.com/swiftlang/swift-corelibs-foundation.git",
        "swift-tag",
        "{version}",
    ),
    (
        r"lib(FoundationEssentials|FoundationInternationalization|_FoundationCShims)\.a",
        "swift-foundation",
        "https://github.com/swiftlang/swift-foundation.git",
        "swift-tag",
        "{version}",
    ),
    (
        r"lib_FoundationICU\.a",
        "swift-foundation-icu",
        "https://github.com/swiftlang/swift-foundation-icu.git",
        "swift-tag",
        "{version}",
    ),
    (
        r"lib_FoundationCollections\.a",
        "swift-collections",
        "https://github.com/apple/swift-collections.git",
        "update-checkout",
        "{version}",
    ),
    (r"swiftrt\.o", "swift", "https://github.com/swiftlang/swift.git", "swift-tag", "{version}"),
    (
        r"lib(c\+\+|c\+\+abi|c\+\+experimental|unwind)\.a|libclang_rt\.[\w.-]+\.a"
        r"|clang_rt\.crt(begin|end)-[\w-]+\.o|crtbeginT\.o|crtend\.o",
        "llvm-project",
        "https://github.com/swiftlang/llvm-project.git",
        "swift-tag",
        "{version}",
    ),
    (
        r"lib(c|m|rt|pthread|crypt|util|xnet|resolv|dl)\.a|(S|r)?crt1\.o|crt[in]\.o",
        "musl",
        "https://git.musl-libc.org/git/musl",
        "sysroot",
        "v{version}",
    ),
    (r"libz\.a", "zlib", "https://github.com/madler/zlib.git", "pc:zlib.pc", "v{version}"),
    (
        r"liblzma\.a",
        "xz",
        "https://github.com/tukaani-project/xz.git",
        "pc:liblzma.pc",
        "v{version}",
    ),
    (
        r"libxml2\.a",
        "libxml2",
        "https://gitlab.gnome.org/GNOME/libxml2.git",
        "pc:libxml-2.0.pc",
        "v{version}",
    ),
    (
        r"libarchive\.a",
        "libarchive",
        "https://github.com/libarchive/libarchive.git",
        "pc:libarchive.pc",
        "v{version}",
    ),
    (r"libcurl\.a", "curl", "https://github.com/curl/curl.git", "pc:libcurl.pc", "curl-{tag}"),
    (
        r"libmimalloc\.a",
        "mimalloc",
        "https://github.com/microsoft/mimalloc.git",
        "cmake:mimalloc-config-version.cmake",
        "v{version}",
    ),
    # Swift's static SDK recipe builds libfts from its own copy of musl-fts; the
    # member's DWARF line table records the MD5 of every source file it was
    # compiled from, which must match that copy at the pinned commit.
    (
        r"libfts\.a",
        "swift-docker",
        "https://github.com/swiftlang/swift-docker.git",
        "dwarf:/home/build-user/resources/fts/=swift-ci/sdks/static-linux/resources/fts/",
        "8089cc7e87ac34fcbbe0df20f765f069b7c4dc4d",
    ),
    (
        r"libbz2\.a",
        "bzip2",
        "https://gitlab.com/bzip2/bzip2.git",
        "header:bzlib.h",
        "bzip2-{version}",
    ),
)
#: llvm-project is archived only where the SDK's runtime libraries are built
#: from, swift-docker only for the libfts sources its static SDK recipe holds.
SWIFT_SDK_PATHS = {
    "swift-docker": ("LICENSE.md", "swift-ci/sdks/static-linux/resources/fts"),
    "llvm-project": (
        "LICENSE.TXT",
        "cmake",
        "compiler-rt",
        "libcxx",
        "libcxxabi",
        "libunwind",
        "llvm/cmake",
        "runtimes",
    ),
}
#: The SDK's target the macOS initfs is built for (`MUSL_ARCH` on Apple silicon).
SWIFT_SDK_TRIPLE = "aarch64-swift-linux-musl"
RELEASE_VERSION = re.compile(r"[0-9]+(\.[0-9]+)+")


@dataclass
class SdkContents:
    #: Every static archive and object file in the bundle, by its path in it.
    inputs: set[str] = field(default_factory=set)
    #: The bundle path of the target's sysroot, ending in `/`.
    root: str = ""
    sysroot: str | None = None
    texts: dict[str, str] = field(default_factory=dict)


def _is_sdk_input(name: str) -> bool:
    return name.endswith((".a", ".o"))


def sdk_contents(bundle: Path, triple: str = SWIFT_SDK_TRIPLE) -> SdkContents:
    """The bundle's static archives and object files, and *triple*'s version metadata."""
    contents = SdkContents()
    members: dict[str, bytes] = {}
    with tarfile.open(bundle, "r|*") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            base = name.rsplit("/", 1)[-1]
            if not member.isfile():
                continue
            if _is_sdk_input(base):
                contents.inputs.add(name)
            elif (
                base == "swift-sdk.json"
                or (base.endswith(".pc") and "/pkgconfig/" in name)
                or base in {"mimalloc-config-version.cmake", "bzlib.h"}
            ):
                members[name] = archive.extractfile(member).read()  # type: ignore[union-attr]
    try:
        sdk_json, sdk = next(
            (name, json.loads(data))
            for name, data in members.items()
            if name.endswith("/swift-sdk.json")
        )
    except (StopIteration, ValueError) as exc:
        raise SourceError(f"the Static Linux SDK has no {triple} target") from exc
    triples = sdk.get("targetTriples") if isinstance(sdk, dict) else None
    target = triples.get(triple) if isinstance(triples, dict) else None
    root = target.get("sdkRootPath") if isinstance(target, dict) else None
    if not isinstance(root, str) or ".." in root.split("/"):
        raise SourceError(f"the Static Linux SDK has no {triple} target")
    if match := re.search(r"musl-([0-9.]+)\.sdk", root):
        contents.sysroot = match[1]
    contents.root = f"{sdk_json.rsplit('/', 1)[0]}/{root.strip('/')}/"
    for name, data in members.items():
        if name.startswith(contents.root) and name != sdk_json:
            contents.texts[name.rsplit("/", 1)[-1]] = data.decode("utf-8", errors="replace")
    if not any(name.startswith(contents.root) for name in contents.inputs):
        raise SourceError(f"the Static Linux SDK holds no {triple} static libraries")
    return contents


def _sdk_version(source: str, contents: SdkContents, swift_tag: str) -> str:
    """The version a rule's *source* records in the bundle."""
    if source == "swift-tag":
        return swift_tag
    if source == "sysroot":
        if contents.sysroot is None:
            raise SourceError("the SDK's sysroot names no musl version")
        return contents.sysroot
    kind, _, name = source.partition(":")
    text = contents.texts.get(name)
    if text is None:
        raise SourceError(f"the SDK carries no {name} to read a version from")
    if kind == "pc":
        match = re.search(r"^Version:\s*(\S+)\s*$", text, re.M)
        version = match[1] if match else None
    elif kind == "cmake":
        parts = [
            re.search(rf"set\(mi_version_{part}\s+([0-9]+)\)", text)
            for part in ("major", "minor", "patch")
        ]
        version = ".".join(part[1] for part in parts if part) if all(parts) else None
    else:
        match = re.search(r"version ([0-9]+(?:\.[0-9]+)+)", text)
        version = match[1] if match else None
    if version is None:
        raise SourceError(f"the SDK's {name} records no version")
    return version


#: `{bundle path: {executable: archive members it linked}}`, from the link evidence.
Linked = Mapping[str, Mapping[str, list[str]]]


def _linked_into(binaries: Mapping[str, list[str]]) -> str:
    return "; ".join(
        f"{executable}: {', '.join(members) if members else 'the whole object'}"
        for executable, members in sorted(binaries.items())
    )


def linked_sdk_inputs(evidence: object, contents: SdkContents) -> tuple[Linked, list[str]]:
    """What the link evidence says the executables took from the SDK, checked against it.

    The evidence must list exactly the bundle's static archives and object
    files (it was then taken from this SDK), and every input a link took code
    from must be the initfs target's. Returns the linked inputs and what fails.
    """
    recorded = evidence.get("sdk_inputs") if isinstance(evidence, dict) else None
    if not isinstance(recorded, dict) or not all(
        isinstance(binaries, dict)
        and all(
            isinstance(members, list) and all(isinstance(m, str) for m in members)
            for members in binaries.values()
        )
        for binaries in recorded.values()
    ):
        return {}, ["no link evidence says which of its inputs the initfs executables link"]
    errors = []
    if set(recorded) != contents.inputs:
        differ = sorted(set(recorded) ^ contents.inputs)
        errors.append(
            "the link evidence lists other static libraries than the pinned SDK holds: "
            + ", ".join(differ[:5])
            + (f" and {len(differ) - 5} more" if len(differ) > 5 else "")
        )
    linked = {path: binaries for path, binaries in sorted(recorded.items()) if binaries}
    for path, binaries in linked.items():
        if not path.startswith(contents.root):
            errors.append(
                f"Static Linux SDK input {path} (linked into {_linked_into(binaries)}) "
                f"is not the {SWIFT_SDK_TRIPLE} target's"
            )
    return linked, errors


def swift_runtime_components(
    linked: Linked,
    contents: SdkContents,
    swift_tag: str,
    update_checkout: Callable[[str], str],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """The upstream projects the linked SDK inputs come from, and what fails.

    Returns `{component: {url, ref, libraries}}` and one error, naming the
    executables that link it, per linked input that no rule attributes or whose
    exact release cannot be read.
    """
    found: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for path, binaries in sorted(linked.items()):
        library = path.rsplit("/", 1)[-1]
        named = f"Static Linux SDK library {library} (linked into {_linked_into(binaries)})"
        rule = next((rule for rule in SWIFT_SDK_RULES if re.fullmatch(rule[0], library)), None)
        if rule is None:
            errors.append(f"{named}: no rule attributes it to a source")
            continue
        _, project, url, source, template = rule
        if source.startswith("dwarf:"):
            build_prefix, _, repository_prefix = source.removeprefix("dwarf:").partition("=")
            entry = found.setdefault(
                f"swift-sdk:{project}",
                {"url": url, "ref": template, "commit": template, "libraries": [], "dwarf": []},
            )
            entry["dwarf"].append(
                {
                    "path": path,
                    "members": sorted({m for members in binaries.values() for m in members}),
                    "named": named,
                    "build_prefix": build_prefix,
                    "repository_prefix": repository_prefix,
                }
            )
            if library not in entry["libraries"]:
                entry["libraries"].append(library)
            continue
        try:
            if source == "update-checkout":
                version = update_checkout(project)
            else:
                version = _sdk_version(source, contents, swift_tag)
            if source != "swift-tag" and not RELEASE_VERSION.fullmatch(version):
                raise SourceError(f"its version {version} names no upstream release")
        except SourceError as exc:
            errors.append(f"{named}: {exc}")
            continue
        tag = template.format(version=version, tag=version.replace(".", "_"))
        entry = found.setdefault(
            f"swift-sdk:{project}", {"url": url, "ref": f"refs/tags/{tag}", "libraries": []}
        )
        if library not in entry["libraries"]:
            entry["libraries"].append(library)
    return found, errors


def _update_checkout(assembly: Assembly, swift_tag: str) -> Callable[[str], str]:
    """The project versions Swift's own release metadata pins for *swift_tag*'s branch."""
    loaded: dict[str, Any] = {}

    def version(project: str) -> str:
        if not loaded:
            url = (
                "https://raw.githubusercontent.com/swiftlang/swift/"
                f"{swift_tag}/utils/update_checkout/update-checkout-config.json"
            )
            try:
                loaded.update(json.loads(assembly.read(url)))
            except ValueError as exc:
                raise SourceError(
                    f"Swift {swift_tag}'s update-checkout config is unreadable"
                ) from exc
        match = re.fullmatch(r"swift-([0-9]+\.[0-9]+)(?:\.[0-9]+)?-RELEASE", swift_tag)
        scheme = f"release/{match[1]}" if match else None
        try:
            return loaded["branch-schemes"][scheme]["repos"][project]
        except (KeyError, TypeError) as exc:
            raise SourceError(f"Swift {swift_tag} pins no {project} version") from exc

    return version


def swift_sdk_sources(
    assembly: Assembly, component: str, record: Mapping[str, Any], evidence: object
) -> list[str]:
    """Sources and notices of what the initfs executables link from the pinned SDK.

    *evidence* is the platform's `link_evidence`: only the SDK libraries and
    objects a link took code from are attributed and need a source.
    """
    bundle = assembly.download(record["url"], "sha256", record["sha256"])
    contents = sdk_contents(bundle)
    linked, problems = linked_sdk_inputs(evidence, contents)
    errors = [f"{component}: {problem}" for problem in problems]
    update_checkout = _update_checkout(assembly, record["swift_tag"])
    projects, failures = swift_runtime_components(
        linked, contents, record["swift_tag"], update_checkout
    )
    errors += failures
    for name, project in sorted(projects.items()):
        try:
            resolved = git_archive(
                assembly,
                name,
                project["url"],
                project["ref"],
                commit=project.get("commit"),
                paths=SWIFT_SDK_PATHS.get(name.partition(":")[2], ()),
            )
            assembly.references[name] += " for " + ", ".join(project["libraries"])
        except SourceError as exc:
            errors.append(f"{name}: {exc}")
            continue
        if project.get("dwarf"):
            archive = assembly.members[f"sources/{component_slug(name)}-{resolved[:12]}.tar.gz"]
            errors += _dwarf_problems(bundle, archive, project["dwarf"])
    assembly.references[component] = (
        f"{record['url']} (sha256 {record['sha256']}); the sources of what the initfs "
        "executables link from it are " + ", ".join(sorted(projects))
    )
    return errors


# -- DWARF source checksums ----------------------------------------------------
#
# A DWARF 5 line table records, for every source file of a compilation unit,
# its path and (with clang) the MD5 of its contents: an object file names the
# exact sources it was compiled from. Read from relocatable ELF64 objects, the
# form the SDK's static archives hold.

_FORM_SIZES = {0x0B: 1, 0x05: 2, 0x06: 4, 0x07: 8, 0x1E: 16}
DW_FORM_STRING, DW_FORM_STRP, DW_FORM_UDATA, DW_FORM_LINE_STRP, DW_FORM_BLOCK = (
    0x08,
    0x0E,
    0x0F,
    0x1F,
    0x09,
)
DW_LNCT_PATH, DW_LNCT_DIRECTORY_INDEX, DW_LNCT_MD5 = 1, 2, 5


def ar_members(data: bytes) -> dict[str, bytes]:
    """The members of a System V (GNU) `ar` archive, by name."""
    if not data.startswith(b"!<arch>\n"):
        raise SourceError("not an ar archive")
    members: dict[str, bytes] = {}
    names = b""
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        name = header[:16].decode("ascii").rstrip()
        size = int(header[48:58].decode("ascii"))
        body = data[offset + 60 : offset + 60 + size]
        offset += 60 + size + (size % 2)
        if name == "//":
            names = body
        elif name.startswith("/") and name[1:].isdigit():
            start = int(name[1:])
            members[names[start:].split(b"/\n", 1)[0].decode("utf-8")] = body
        elif name != "/":
            members[name.removesuffix("/")] = body
    return members


def _elf_sections(data: bytes) -> list[tuple[str, int, int, int, int, int]]:
    """`(name, type, offset, size, link, info)` of every section of a little-endian ELF64."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SourceError("not a little-endian ELF64 object")
    shoff = int.from_bytes(data[0x28:0x30], "little")
    entsize, count, names_index = (
        int.from_bytes(data[0x3A + 2 * i : 0x3C + 2 * i], "little") for i in range(3)
    )
    headers = []
    for index in range(count):
        base = shoff + index * entsize
        field_ = [
            int.from_bytes(data[base + o : base + o + n], "little")
            for o, n in ((0, 4), (4, 4), (0x18, 8), (0x20, 8), (0x28, 4), (0x2C, 4))
        ]
        headers.append(field_)
    strtab = headers[names_index]
    table = data[strtab[2] : strtab[2] + strtab[3]]
    return [
        (table[name : table.index(b"\0", name)].decode("ascii"), kind, offset, size, link, info)
        for name, kind, offset, size, link, info in headers
    ]


def _uleb(data: bytes, offset: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, offset


def dwarf_source_files(obj: bytes) -> dict[str, str]:
    """`{source path: MD5}` for every file the object's DWARF 5 line tables record a digest of."""
    sections = _elf_sections(obj)
    by_name = {section[0]: (index, section) for index, section in enumerate(sections)}
    if ".debug_line" not in by_name:
        return {}
    line_index, (_, _, line_offset, line_size, _, _) = by_name[".debug_line"]
    line = obj[line_offset : line_offset + line_size]
    strings = {
        name: obj[section[2] : section[2] + section[3]]
        for name, (_, section) in by_name.items()
        if name in {".debug_line_str", ".debug_str"}
    }
    relocations: dict[int, int] = {}
    for _, kind, offset, size, link, info in sections:
        if kind != 4 or info != line_index:  # SHT_RELA against .debug_line
            continue
        symtab = sections[link]
        for entry in range(offset, offset + size, 24):
            r_offset = int.from_bytes(obj[entry : entry + 8], "little")
            symbol = int.from_bytes(obj[entry + 8 : entry + 16], "little") >> 32
            addend = int.from_bytes(obj[entry + 16 : entry + 24], "little", signed=True)
            value_at = symtab[2] + symbol * 24 + 8
            relocations[r_offset] = int.from_bytes(obj[value_at : value_at + 8], "little") + addend

    def read(form: int, offset: int) -> tuple[object, int]:
        if form == DW_FORM_STRING:
            end = line.index(b"\0", offset)
            return line[offset:end].decode("utf-8"), end + 1
        if form in (DW_FORM_LINE_STRP, DW_FORM_STRP):
            pointer = relocations.get(offset, int.from_bytes(line[offset : offset + 4], "little"))
            table = strings.get(".debug_line_str" if form == DW_FORM_LINE_STRP else ".debug_str")
            if table is None:
                raise SourceError("a DWARF string section is missing")
            return table[pointer : table.index(b"\0", pointer)].decode("utf-8"), offset + 4
        if form == DW_FORM_UDATA:
            return _uleb(line, offset)
        if form == DW_FORM_BLOCK:
            length, offset = _uleb(line, offset)
            return line[offset : offset + length], offset + length
        if form in _FORM_SIZES:
            size = _FORM_SIZES[form]
            return line[offset : offset + size], offset + size
        raise SourceError(f"unsupported DWARF form {form:#x} in a line table")

    def entries(offset: int) -> tuple[list[dict[int, object]], int]:
        count, offset = line[offset], offset + 1
        formats = []
        for _ in range(count):
            content, offset = _uleb(line, offset)
            form, offset = _uleb(line, offset)
            formats.append((content, form))
        number, offset = _uleb(line, offset)
        found = []
        for _ in range(number):
            entry: dict[int, object] = {}
            for content, form in formats:
                entry[content], offset = read(form, offset)
            found.append(entry)
        return found, offset

    files: dict[str, str] = {}
    unit = 0
    while unit + 4 <= len(line):
        length = int.from_bytes(line[unit : unit + 4], "little")
        if length >= 0xFFFFFFF0:
            raise SourceError("64-bit DWARF line tables are not supported")
        end = unit + 4 + length
        version = int.from_bytes(line[unit + 4 : unit + 6], "little")
        if version != 5:
            raise SourceError(f"a DWARF {version} line table records no source digests")
        offset = unit + 6 + 2 + 4  # address and selector sizes, header_length
        opcode_base = line[offset + 5]
        offset += 6 + opcode_base - 1
        directories, offset = entries(offset)
        names, offset = entries(offset)
        for entry in names:
            path, digest = entry.get(DW_LNCT_PATH), entry.get(DW_LNCT_MD5)
            if not isinstance(path, str) or not isinstance(digest, bytes):
                continue
            if not path.startswith("/"):
                index = entry.get(DW_LNCT_DIRECTORY_INDEX, 0)
                directory = (
                    directories[index].get(DW_LNCT_PATH) if isinstance(index, int) else None
                )
                path = f"{directory}/{path}" if isinstance(directory, str) else path
            files[posixpath.normpath(path)] = digest.hex()
        unit = end
    return files


def bundle_files(bundle: Path, names: set[str]) -> dict[str, bytes]:
    """The bytes of the bundle members *names*."""
    found: dict[str, bytes] = {}
    with tarfile.open(bundle, "r|*") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            if name in names and member.isfile():
                found[name] = archive.extractfile(member).read()  # type: ignore[union-attr]
    return found


def _dwarf_problems(
    bundle: Path, archive: Path | bytes, checks: list[dict[str, Any]]
) -> list[str]:
    """Why the archived source is not what the linked members' DWARF says they were built from."""
    digests: dict[str, str] = {}
    if isinstance(archive, bytes):
        raise SourceError("the archived source is not a file")
    with tarfile.open(archive) as opened:
        for member in opened:
            if member.isfile():
                data = opened.extractfile(member).read()  # type: ignore[union-attr]
                digests[member.name.split("/", 1)[-1]] = hashlib.md5(data).hexdigest()
    libraries = bundle_files(bundle, {check["path"] for check in checks})
    errors = []
    for check in checks:
        try:
            members = ar_members(libraries[check["path"]])
        except (KeyError, SourceError, ValueError) as exc:
            errors.append(f"{check['named']}: cannot be read from the SDK: {exc}")
            continue
        for name in check["members"]:
            try:
                sources = dwarf_source_files(members[name])
            except (KeyError, SourceError, ValueError, IndexError) as exc:
                errors.append(f"{check['named']}: member {name} has no readable DWARF: {exc}")
                continue
            own = {
                path.removeprefix(check["build_prefix"]): digest
                for path, digest in sources.items()
                if path.startswith(check["build_prefix"])
            }
            if not own:
                errors.append(
                    f"{check['named']}: member {name} records no source under "
                    f"{check['build_prefix']}"
                )
            for relative, digest in sorted(own.items()):
                actual = digests.get(check["repository_prefix"] + relative)
                if actual != digest:
                    errors.append(
                        f"{check['named']}: member {name} was compiled from a "
                        f"{relative} with MD5 {digest}, not the archived source's "
                        f"{actual or '(absent)'}"
                    )
    return errors


# -- Assembly ------------------------------------------------------------------


def _component_sources(
    assembly: Assembly, component: str, record: Mapping[str, Any], evidence: object = None
) -> list[str]:
    """Add *component*'s sources and notices; return why any could not be.

    *evidence* is the `link_evidence` of the platform that records *component*.
    """
    kind = record.get("kind")
    if kind == "git":
        git_archive(assembly, component, record["url"], record["commit"], commit=record["commit"])
    elif kind == "debian":
        debian_source(assembly, component, record["source"], record["version"])
    elif kind == "go":
        go_source(assembly, component, record["version"])
    elif kind == "cage-kernel":
        kernel_source(assembly, component, record)
    elif kind == "generated":
        assembly.sources.setdefault(component, []).append(f"build/{record['generator']}")
        assembly.references[component] = f"written by {record['generator']}"
    elif kind == "swift-static-sdk":
        return swift_sdk_sources(assembly, component, record, evidence)
    else:
        raise SourceError(f"unknown component kind {kind!r}")
    return []


def _build_files() -> Iterator[tuple[str, Path]]:
    """The committed files of every build directory, never anything else beside them."""
    tracked = tracked_files(UNIT_ROOT)
    # The build scripts below are MIT licensed; their licence travels with them.
    if UNIT_ROOT / "LICENSE" not in tracked:
        raise SystemExit("LICENSE is not committed")
    yield "build/LICENSE", UNIT_ROOT / "LICENSE"
    for directory in BUILD_DIRECTORIES:
        root = UNIT_ROOT / directory
        for path in sorted(path for path in tracked if path.is_relative_to(root)):
            yield f"build/{path.relative_to(UNIT_ROOT).as_posix()}", path


def _notices_markdown(
    version: str, records: Mapping[str, Mapping[str, Any]], assembly: Assembly
) -> bytes:
    lines = [
        f"# cage-init {version}: corresponding source and notices",
        "",
        "Every file a cage-init release distributes is attributed, in "
        "`components/<platform>.json`, to the components below. Each lists its exact "
        "source reference, its licence notices and its sources in this archive. "
        "`build/` holds the recipe and pins the release was built with.",
        "",
    ]
    used_by: dict[str, set[str]] = {}
    for platform, record in records.items():
        for component in record["components"]:
            used_by.setdefault(component, set()).add(platform)
    for component in sorted(set(used_by) | set(assembly.references)):
        lines += [f"## `{component}`", ""]
        if component in used_by:
            lines.append(f"- Platforms: {', '.join(sorted(used_by[component]))}")
        lines.append(f"- Source: {assembly.references.get(component, '')}")
        for label, paths in (
            ("Notices", assembly.notices.get(component, [])),
            ("Sources", assembly.sources.get(component, [])),
        ):
            if paths:
                lines.append(f"- {label}: " + ", ".join(f"`{path}`" for path in sorted(paths)))
        lines.append("")
    for platform, record in sorted(records.items()):
        if "link_evidence" in record:
            lines += _link_evidence_markdown(platform, record["link_evidence"])
    return "\n".join(lines).encode("utf-8")


def _link_evidence_markdown(platform: str, evidence: Mapping[str, Any]) -> list[str]:
    """What each executable's link took from where, as `components/<platform>.json` records it."""
    lines = [
        f"## Link evidence: `{platform}`",
        "",
        f"Each executable in the filesystem (SHA-256 `{evidence['initfs_sha256']}`) was linked "
        "with an lld link map, which lists every input section the link placed in it; the "
        "executable that link wrote is byte-identical to the one read back out of the "
        "filesystem. Inputs under SwiftPM's build directory "
        f"(`{evidence['build_directory']}`) were compiled from the Git sources above; "
        "inputs of the Static Linux SDK are listed with the archive members each link took.",
        "",
        "| Executable | Path | SHA-256 | Link map SHA-256 |",
        "|---|---|---|---|",
    ]
    executables = evidence["executables"]
    for name, executable in sorted(executables.items()):
        lines.append(
            f"| `{name}` | `{executable['path']}` | `{executable['initfs_sha256']}` "
            f"| `{executable['map_sha256']}` |"
        )
    lines += ["", "SwiftPM-built inputs, by build directory:", ""]
    for name, executable in sorted(executables.items()):
        lines.append(f"- `{name}`: " + ", ".join(f"`{d}`" for d in executable["swiftpm"]))
    lines += ["", "Static Linux SDK inputs the links took code from:", ""]
    unlinked = []
    for path, binaries in sorted(evidence["sdk_inputs"].items()):
        if not binaries:
            unlinked.append(path)
            continue
        lines.append(f"- `{path}`: {_linked_into(binaries)}")
    lines += [
        "",
        "Static Linux SDK inputs no executable took code from: "
        + (", ".join(f"`{path}`" for path in unlinked) or "none"),
        "",
    ]
    return lines


def write_archive(destination: Path, members: Mapping[str, Path | bytes]) -> None:
    """A deterministic tar: sorted members, fixed times and owners, no pax headers."""
    with tarfile.open(destination, "w", format=tarfile.GNU_FORMAT) as archive:
        for name in sorted(members):
            content = members[name]
            info = tarfile.TarInfo(name)
            info.mtime = ARCHIVE_EPOCH
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if isinstance(content, bytes):
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            else:
                info.size = content.stat().st_size
                with content.open("rb") as file:
                    archive.addfile(info, file)


def package(
    destination: Path,
    *,
    version: str,
    payloads: Mapping[str, tuple[Path, Mapping[str, Any]]],
    fetch: Fetch,
    cache: Path,
    git_remote: Callable[[str], str] = lambda url: url,
) -> None:
    """Write `source-and-notices.tar` for the platform *payloads*.

    *payloads* maps each platform to its verified payload directory and its
    `components.json`. Every component of every platform is reconstructed; if
    any cannot be, one error names all of them and nothing is written.
    """
    assembly = Assembly(fetch=fetch, cache=cache, git_remote=git_remote)
    errors: list[str] = []
    components: dict[str, Mapping[str, Any]] = {}
    evidence: dict[str, object] = {}
    for platform, (payload, record) in sorted(payloads.items()):
        assembly.add(
            "build",
            f"components/{platform}.json",
            json.dumps(record, indent=2, sort_keys=True).encode() + b"\n",
            notice=False,
        )
        for name, component in record["components"].items():
            if components.setdefault(name, component) != component:
                errors.append(f"{name}: recorded with different sources by two platforms")
            if "link_evidence" in record:
                evidence[name] = record["link_evidence"]
            for notice in component.get("notices", []):
                # Build-time notices: payload `metadata/notices/<slug>/<file>`.
                path = payload / notice
                if not path.is_file():
                    errors.append(f"{name}: its captured notice {notice} is missing")
                    continue
                assembly.add(name, notice.removeprefix("metadata/"), path, notice=True)
    for name, component in sorted(components.items()):
        try:
            errors.extend(_component_sources(assembly, name, component, evidence.get(name)))
        except (SourceError, OSError, KeyError, tarfile.TarError) as exc:
            role = ROLES.get(component.get("kind", ""), "")
            errors.append(f"{name}: {role + ': ' if role else ''}{exc}")
            continue
        # Generated files are this unit's; the SDK's notices are its libraries' projects'.
        if component.get("kind") not in {"generated", "swift-static-sdk"} and not (
            assembly.notices.get(name)
        ):
            errors.append(f"{name}: no licence notice was found")
    if errors:
        raise SystemExit(
            f"cannot write {ASSET}; these components' sources or notices are missing:\n"
            + "\n".join(f"- {error}" for error in errors)
        )
    for path, file in _build_files():
        assembly.add("build", path, file, notice=False)
    assembly.members["NOTICES.md"] = _notices_markdown(
        version, {platform: record for platform, (_, record) in payloads.items()}, assembly
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_archive(destination, assembly.members)

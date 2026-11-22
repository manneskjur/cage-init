#!/usr/bin/env python3
"""Build the Windows LCOW guest initrd on amd64 Linux.

It runs on an amd64 Linux host or container with the Go toolchain, C build
tools, Git, dpkg and the ext4 tools, and writes::

    {output}/initrd.img               hcsshim guest (KMOD=1) plus the kernel's modules
    {output}/metadata/inputs.json     the pins it was built from
    {output}/metadata/kernel.json     the cage-kernel release and kernel it boots with
    {output}/metadata/components.json the component every initrd file came from
    {output}/metadata/notices/...     the licence notices captured for those components

The kernel is not part of this artifact: it is the Windows LCOW kernel of the
`cage-kernel` release pinned in `lcow-initrd.toml`, and this recipe takes that
kernel's modules from the same release, admitted only after the release's
`SHA256SUMS` and `manifest.json` match their pinned digests.

Every external input is pinned by content in `lcow-initrd.toml`. The initrd is
assembled here rather than by hcsshim's packaging rules, which stamp the build
time and depend on archive ordering, so equal inputs produce equal bytes on
every producer.

Provenance is derived from the tree as it is assembled, never from a list:
every file is attributed when it is added (hcsshim's build output, the Go
toolchain linked into it, the Debian package a file was unpacked from or that
`dpkg` says installed it on the build host, the kernel release's modules, or
this recipe), and a file whose origin cannot be determined fails the build.
`cage_init.py package-release` reconstructs the corresponding source from
those records.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

from _lcow_initrd import (  # noqa: E402
    COMPONENTS,
    COMPONENTS_SCHEMA,
    INITRD,
    INPUTS,
    KERNEL_RECORD,
    NOTICES_DIR,
    Entry,
    component_slug,
    components_problems,
    cpio_newc,
    gzip_bytes,
    iter_members,
    kernel_record,
    problems,
)

PINS = SCRIPTS / "lcow-initrd.toml"
PINS_SCHEMA = 2
KERNEL_PLATFORM = "windows"
SHA256SUMS = "SHA256SUMS"
MANIFEST = "manifest.json"
#: Schema 3 adds the release's `source-and-notices.tar`; the build reads neither it
#: nor anything else schema 3 changes, so both are admitted.
KERNEL_RELEASE_SCHEMAS = (2, 3)
HCSSHIM = "hcsshim"
GO = "go"
CAGE_KERNEL = "cage-kernel"
GENERATED = "generated"
DOWNLOAD_ATTEMPTS = 3
MULTIARCH = "x86_64-linux-gnu"
LOADER = "/lib64/ld-linux-x86-64.so.2"
HCSSHIM_BINARIES = (
    "bin/init",
    "bin/vsockexec",
    "bin/cmd/gcs",
    "bin/cmd/gcstools",
    "bin/cmd/hooks/wait-paths",
)


def _run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        argv, cwd=cwd, env=env, check=False, capture_output=True, text=True, encoding="utf-8"
    )
    if result.returncode:
        raise RuntimeError(
            f"{' '.join(argv)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def _fetch(url: str, *, attempts: int = DOWNLOAD_ATTEMPTS, delay: float = 5.0) -> bytes:
    """Read *url*, retrying only transport failures; content is checked by the caller."""
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=300) as response:
                return response.read()
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            ConnectionError,
        ) as exc:
            if attempt == attempts:
                message = f"downloading {url} failed after {attempts} attempts: {exc}"
                raise RuntimeError(message) from exc
            time.sleep(delay * attempt)
    raise AssertionError("unreachable")


def _download(url: str, sha256: str, destination: Path) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise ValueError(f"pin for {url} has no SHA-256")
    data = _fetch(url)
    actual = hashlib.sha256(data).hexdigest()
    if actual != sha256:
        raise RuntimeError(f"checksum mismatch for {url}: expected {sha256}, got {actual}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return destination


def _pins() -> dict:
    pins = tomllib.loads(PINS.read_text(encoding="utf-8"))
    if pins.get("schema") != PINS_SCHEMA:
        raise ValueError(f"{PINS}: unsupported schema")
    return pins


def _release_url(spec: dict, name: str) -> str:
    return f"https://github.com/{spec['repository']}/releases/download/v{spec['version']}/{name}"


def _sha256sums(text: str) -> dict[str, str]:
    sums: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if match is None:
            raise ValueError(f"malformed SHA256SUMS line: {line!r}")
        if match[2] in sums:
            raise ValueError(f"SHA256SUMS lists {match[2]} twice")
        sums[match[2]] = match[1]
    return sums


def _record(value: object, keys: dict[str, type], what: str) -> dict:
    if not isinstance(value, dict) or not all(
        isinstance(value.get(key), kind) for key, kind in keys.items()
    ):
        raise RuntimeError(f"cage-kernel {MANIFEST}: {what} is malformed")
    return value


def windows_kernel(manifest: object, version: str) -> dict:
    """The validated `platforms.windows` entry of a cage-kernel *manifest*."""
    manifest = _record(manifest, {"schema_version": int, "version": str, "platforms": dict}, "it")
    if manifest["schema_version"] not in KERNEL_RELEASE_SCHEMAS:
        raise RuntimeError(
            f"cage-kernel {MANIFEST} schema {manifest['schema_version']} is not one of "
            f"{KERNEL_RELEASE_SCHEMAS}"
        )
    if manifest["version"] != version:
        raise RuntimeError(f"cage-kernel {MANIFEST} is not version {version}")
    entry = manifest["platforms"].get(KERNEL_PLATFORM)
    if entry is None:
        raise RuntimeError(f"cage-kernel {version} has no {KERNEL_PLATFORM} kernel")
    entry = _record(entry, {"content": dict, "modules": dict, "source": dict}, KERNEL_PLATFORM)
    _record(entry["content"], {"sha256": str}, "the kernel content")
    modules = _record(entry["modules"], {"name": str, "sha256": str, "files": list}, "modules")
    if not all(isinstance(name, str) for name in modules["files"]):
        raise RuntimeError(f"cage-kernel {MANIFEST}: the module files are malformed")
    return entry


def kernel_release(pins: dict, work: Path) -> tuple[dict, bytes]:
    """The pinned cage-kernel release's Windows entry and its modules archive.

    Nothing is trusted until it matches a digest that leads back to the pins:
    `SHA256SUMS` matches its pin, `manifest.json` matches both its pin and its
    `SHA256SUMS` line, and the modules archive matches both its `SHA256SUMS`
    line and the manifest.
    """
    spec = pins["cage_kernel"]
    sums_path = _download(
        _release_url(spec, SHA256SUMS), spec["sha256sums_sha256"], work / "kernel" / SHA256SUMS
    )
    sums = _sha256sums(sums_path.read_text(encoding="utf-8"))
    if sums.get(MANIFEST) != spec["manifest_sha256"]:
        raise RuntimeError(f"{SHA256SUMS} does not list the pinned {MANIFEST}")
    manifest_path = _download(
        _release_url(spec, MANIFEST), spec["manifest_sha256"], work / "kernel" / MANIFEST
    )
    entry = windows_kernel(json.loads(manifest_path.read_text(encoding="utf-8")), spec["version"])
    modules = entry["modules"]
    if sums.get(modules["name"]) != modules["sha256"]:
        raise RuntimeError(f"{SHA256SUMS} and {MANIFEST} disagree on {modules['name']}")
    archive = _download(
        _release_url(spec, modules["name"]), modules["sha256"], work / "kernel" / modules["name"]
    )
    return entry, archive.read_bytes()


def control_fields(text: str) -> dict[str, str]:
    """A Debian control paragraph as `{field: value}`, continuation lines joined."""
    fields: dict[str, str] = {}
    name = None
    for line in text.splitlines():
        if line[:1] in {" ", "\t"} and name is not None:
            fields[name] += " " + line.strip()
        elif match := re.match(r"([A-Za-z0-9][A-Za-z0-9-]*):\s*(.*)$", line):
            name = match[1]
            fields[name] = match[2].strip()
        elif line.strip():
            raise ValueError(f"malformed control line: {line!r}")
    return fields


def debian_source(fields: dict[str, str]) -> tuple[str, str]:
    """The source package name and version a binary package's control fields name.

    Debian's rules: `Source` may carry its own `(version)`; without it the source
    version is the binary version less any binNMU `+bN` suffix; without `Source`
    the source package has the binary package's name.
    """
    package, version = fields.get("Package"), fields.get("Version")
    if not package or not version:
        raise ValueError("control fields lack Package or Version")
    binary_version = re.sub(r"\+b[0-9]+$", "", version)
    source = fields.get("Source", "").strip()
    if not source:
        return package, binary_version
    match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]+)(?:\s+\(([^()\s]+)\))?", source)
    if match is None:
        raise ValueError(f"malformed Source field: {source!r}")
    return match[1], match[2] or binary_version


def built_using(value: str) -> list[tuple[str, str]]:
    """`Built-Using`'s `source (= version)` entries: sources compiled into the package."""
    entries = []
    for item in filter(None, (part.strip() for part in value.split(","))):
        match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]+)\s*\(\s*=\s*([^()\s]+)\s*\)", item)
        if match is None:
            raise ValueError(f"malformed Built-Using entry: {item!r}")
        entries.append((match[1], match[2]))
    return entries


def debian_component(source: str, version: str) -> str:
    return f"debian:{source}={version}"


def dpkg_owner(paths: list[str], search: str) -> str | None:
    """The one package `dpkg -S` output *search* names for any of *paths*."""
    owners: set[str] = set()
    for line in search.splitlines():
        if line.startswith("diversion "):
            continue
        packages, separator, path = line.rpartition(": ")
        if separator and path in paths:
            owners.update(package.strip() for package in packages.split(","))
    if len(owners) > 1:
        raise RuntimeError(f"{paths[0]} is owned by several packages: {sorted(owners)}")
    return next(iter(owners), None)


def _usrmerge_aliases(path: str) -> list[str]:
    """*path* and its other name under Debian's merged /usr."""
    for top in ("/bin/", "/sbin/", "/lib/", "/lib64/"):
        if path.startswith(top):
            return [path, "/usr" + path]
        if path.startswith("/usr" + top):
            return [path, path.removeprefix("/usr")]
    return [path]


class Guest:
    """The initrd tree being assembled and the origin of every file in it."""

    def __init__(self, metadata: Path) -> None:
        self.tree: dict[str, Entry] = {}
        self.files: dict[str, list[str]] = {}
        self.components: dict[str, dict] = {}
        self.metadata = metadata
        #: Paths relative to the unpacked-package prefix, to the package that holds them.
        self.unpacked: dict[str, str] = {}
        #: Binary package name to the components its files came from.
        self.package_origins: dict[str, list[str]] = {}
        self.prefix: Path | None = None
        self.env: dict[str, str] = dict(os.environ)

    # -- Components ----------------------------------------------------------

    def component(self, name: str, record: dict) -> str:
        existing = self.components.get(name)
        if existing is not None and existing != record:
            raise RuntimeError(f"component {name} is recorded twice with different sources")
        self.components[name] = record
        return name

    def _notice(self, component: str, package: str, copyright_file: Path) -> None:
        relative = f"{NOTICES_DIR}/{component_slug(component)}/{package}.copyright"
        destination = self.metadata / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(copyright_file.read_bytes())
        notices = self.components[component]["notices"]
        if f"metadata/{relative}" not in notices:
            notices.append(f"metadata/{relative}")
            notices.sort()

    def _debian(self, package: str, fields: dict[str, str], copyright_file: Path) -> list[str]:
        """Record *package*'s source (and what it was built using); return its origins."""
        source, version = debian_source(fields)
        name = debian_component(source, version)
        record = self.components.get(name) or {
            "kind": "debian",
            "source": source,
            "version": version,
            "packages": [],
            "notices": [],
        }
        record["packages"] = sorted({*record["packages"], package})
        self.components[name] = record
        if not copyright_file.is_file():
            raise RuntimeError(f"Debian package {package} carries no copyright notice")
        self._notice(name, package, copyright_file)
        origins = [name]
        for used_source, used_version in built_using(fields.get("Built-Using", "")):
            used = debian_component(used_source, used_version)
            self.components.setdefault(
                used,
                {
                    "kind": "debian",
                    "source": used_source,
                    "version": used_version,
                    "packages": [],
                    "notices": [],
                },
            )
            origins.append(used)
        return sorted(set(origins))

    def unpack_debian(self, pins: dict, work: Path) -> Path:
        """Unpack every pinned .deb into one prefix, remembering which file is whose."""
        prefix = work / "debian"
        controls: list[tuple[str, dict[str, str]]] = []
        for package in pins["debian"]:
            name = package["package"]
            deb = _download(package["url"], package["sha256"], work / "debs" / f"{name}.deb")
            own = work / "debs" / name
            _run(["dpkg-deb", "-x", str(deb), str(own)])
            _run(["dpkg-deb", "-x", str(deb), str(prefix)])
            fields = control_fields(_run(["dpkg-deb", "-f", str(deb)]))
            if fields.get("Package") != name:
                raise RuntimeError(f"{package['url']} is not the {name} package")
            for root, directories, files in os.walk(own):
                for entry in [*files, *(d for d in directories if Path(root, d).is_symlink())]:
                    relative = Path(root, entry).relative_to(own).as_posix()
                    self.unpacked.setdefault(relative, name)
            controls.append((name, fields))
        # A notice may sit behind a doc-directory link to another unpacked package.
        for name, fields in controls:
            copyright_file = (prefix / "usr/share/doc" / name / "copyright").resolve()
            if not copyright_file.is_relative_to(prefix.resolve()):
                raise RuntimeError(f"Debian package {name}'s copyright leaves its prefix")
            self.package_origins[name] = self._debian(name, fields, copyright_file)
        self.prefix = prefix
        return prefix

    def installed_origins(self, path: Path) -> list[str]:
        """The components of a file the build host's dpkg installed."""
        candidates: list[str] = []
        for name in (path.as_posix(), os.path.realpath(path)):
            for alias in _usrmerge_aliases(name):
                if alias not in candidates:
                    candidates.append(alias)
        search = subprocess.run(
            ["dpkg", "-S", *candidates],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout
        owner = dpkg_owner(candidates, search)
        if owner is None:
            raise RuntimeError(f"{path} belongs to no installed Debian package")
        package = owner.split(":", 1)[0]
        if package not in self.package_origins:
            query = _run(
                [
                    "dpkg-query",
                    "-W",
                    "-f",
                    "Package: ${Package}\nVersion: ${Version}\n"
                    "Source: ${source:Package} (${source:Version})\n"
                    "Built-Using: ${Built-Using}\n",
                    owner,
                ]
            )
            copyright_file = Path("/usr/share/doc") / package / "copyright"
            self.package_origins[package] = self._debian(
                package, control_fields(query), copyright_file.resolve()
            )
        return self.package_origins[package]

    def origins_of(self, path: Path) -> list[str]:
        """The components of a host file copied into the guest, wherever it came from."""
        if self.prefix is not None and path.is_relative_to(self.prefix):
            for candidate in (path, Path(os.path.realpath(path))):
                if candidate.is_relative_to(self.prefix):
                    package = self.unpacked.get(candidate.relative_to(self.prefix).as_posix())
                    if package is not None:
                        return self.package_origins[package]
            raise RuntimeError(f"{path} is in no pinned Debian package")
        return self.installed_origins(path)

    def hcsshim_origins(self, binary: Path, *, go: bool) -> list[str]:
        """hcsshim's own build output; a Go binary also carries the Go runtime it links.

        *go* says whether hcsshim builds *binary* with Go; `go version` must
        agree, reading the recorded toolchain from a Go binary's build
        information and reporting any other binary as not a Go executable.
        """
        probe = subprocess.run(
            ["go", "version", str(binary)],
            env=self.env,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        found = re.fullmatch(rf"{re.escape(str(binary))}: (go\S+)", probe.stdout.strip())
        if probe.returncode == 0 and found is not None:
            built_with = found[1]
        elif not probe.stdout.strip() and "not a Go executable" in probe.stderr:
            built_with = None
        else:
            raise RuntimeError(
                f"`go version {binary}` is not understood: {(probe.stdout + probe.stderr).strip()}"
            )
        if go != (built_with is not None):
            raise RuntimeError(
                f"{binary} is {'not ' if built_with is None else ''}a Go executable, "
                f"but hcsshim builds it {'with Go' if go else 'from C'}"
            )
        if built_with is None:
            return [HCSSHIM]
        if built_with != self.components[GO]["version"]:
            raise RuntimeError(f"{binary} was built with {built_with}, not the recorded Go")
        return [HCSSHIM, GO]

    # -- Tree ----------------------------------------------------------------

    def add_file(self, guest: str, data: bytes, *, executable: bool, origins: list[str]) -> None:
        relative = guest.lstrip("/")
        if not origins or not all(origin in self.components for origin in origins):
            raise RuntimeError(f"/{relative} has no determinable origin")
        _add_file(self.tree, guest, data, executable=executable)
        previous = self.files.get(relative)
        if previous is not None and previous != sorted(origins):
            raise RuntimeError(f"/{relative} is attributed to two origins")
        self.files[relative] = sorted(origins)

    def add_binary(self, guest: str, binary: Path, *, origins: list[str]) -> None:
        """Install *binary* and the shared libraries it loads, as resolved by ldd."""
        prefix = self.prefix
        if prefix is None:
            raise RuntimeError(f"{binary} cannot be installed before the Debian prefix is unpacked")
        self.add_file(guest, binary.read_bytes(), executable=True, origins=origins)
        for library in _ldd(binary, self.env):
            self.add_file(
                _guest_path(library, prefix),
                Path(os.path.realpath(library)).read_bytes(),
                executable=True,
                origins=self.origins_of(library),
            )

    def record(self) -> dict:
        return {
            "schema_version": COMPONENTS_SCHEMA,
            "platform": KERNEL_PLATFORM,
            "components": self.components,
            "files": dict(sorted(self.files.items())),
        }


def _hcsshim(pins: dict, work: Path) -> Path:
    source = work / "hcsshim"
    spec = pins["hcsshim"]
    _run(
        [
            "git",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--branch",
            spec["tag"],
            spec["repository"],
            str(source),
        ]
    )
    commit = _run(["git", "-C", str(source), "rev-parse", "HEAD"]).strip()
    if commit != spec["commit"]:
        raise RuntimeError(
            f"hcsshim {spec['tag']} resolved to {commit}, not the pinned {spec['commit']}"
        )
    return source


def _build_environment(prefix: Path) -> dict[str, str]:
    libraries = [prefix / "usr/lib" / MULTIARCH, prefix / "lib" / MULTIARCH]
    return {
        **os.environ,
        "PATH": os.pathsep.join(
            [str(prefix / "usr/bin"), str(prefix / "usr/sbin"), os.environ["PATH"]]
        ),
        "C_INCLUDE_PATH": str(prefix / "usr/include"),
        "LIBRARY_PATH": os.pathsep.join(map(str, libraries)),
        "LD_LIBRARY_PATH": os.pathsep.join(map(str, libraries)),
        "PKG_CONFIG_PATH": str(prefix / "usr/lib" / MULTIARCH / "pkgconfig"),
        "CGO_ENABLED": "0",
    }


def _guest_path(path: Path, prefix: Path) -> str:
    """Where a build-environment file lives in the guest (unpacked packages map to /).

    Libraries keep the name the loader asked for (their SONAME, as ldd prints
    it), not the versioned file a symbolic link resolves to.
    """
    if path.is_relative_to(prefix):
        return "/" + path.relative_to(prefix).as_posix()
    return path.as_posix()


def _add_file(tree: dict[str, Entry], guest: str, data: bytes, *, executable: bool) -> None:
    relative = guest.lstrip("/")
    parts = relative.split("/")
    for index in range(1, len(parts)):
        tree.setdefault("/".join(parts[:index]), Entry.directory())
    existing = tree.get(relative)
    entry = Entry.file(data, executable=executable)
    if existing is not None and existing != entry:
        raise RuntimeError(f"conflicting guest contents for /{relative}")
    tree[relative] = entry


def _ldd(binary: Path, env: dict[str, str]) -> list[Path]:
    """The shared libraries *binary* loads, as ldd resolves them; none if it is static."""
    output = subprocess.run(
        ["ldd", str(binary)],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if output.returncode and "not a dynamic executable" not in output.stdout + output.stderr:
        raise RuntimeError(f"ldd {binary} failed: {output.stderr.strip()}")
    libraries = []
    for line in output.stdout.splitlines():
        if "not found" in line:
            raise RuntimeError(f"{binary} has an unresolved library: {line.strip()}")
        match = re.search(r"=>\s+(/\S+)", line) or re.match(r"\s*(/\S+)", line)
        if match is not None:
            libraries.append(Path(match[1]))
    return libraries


def _make_variables(source: Path) -> dict[str, str]:
    """Top-level ``NAME = value`` assignments, following backslash continuations."""
    text = (source / "Makefile").read_text(encoding="utf-8").replace("\\\n", " ")
    values = {}
    for line in text.splitlines():
        match = re.match(r"([A-Z_]+)\s*:?=\s*(.*)$", line)
        if match:
            values.setdefault(match[1], " ".join(match[2].split()))
    return values


def _guest_tree(guest: Guest, pins: dict, source: Path) -> None:
    prefix = guest.prefix
    if prefix is None:
        raise RuntimeError("the guest tree cannot be assembled before the Debian prefix is unpacked")
    tree = guest.tree
    for directory in (
        "bin",
        "dev",
        "etc",
        "proc",
        "run",
        "sbin",
        "sys",
        "tmp",
        "usr",
        "usr/bin",
        "info",
    ):
        tree[directory] = Entry.directory()
    # Base: busybox and its applets, scratch-disk formatting and the OCI runtime.
    candidates = [prefix / name for name in ("bin/busybox", "usr/bin/busybox")]
    busybox = next((path for path in candidates if path.is_file()), None)
    if busybox is None:
        raise RuntimeError("busybox-static did not provide a busybox executable")
    guest.add_file(
        "/bin/busybox", busybox.read_bytes(), executable=True, origins=guest.origins_of(busybox)
    )
    applets = _run([str(busybox), "--list"]).split()
    for applet in sorted(set(applets) - {"busybox"}):
        tree[f"bin/{applet}"] = Entry.symlink("busybox")
    for name in ("mkfs.ext4", "mke2fs"):
        host = Path("/usr/sbin") / name
        guest.add_binary(f"/sbin/{name}", host, origins=guest.origins_of(host))
    runc = prefix / "usr/sbin/runc"
    guest.add_binary("/sbin/runc", runc, origins=guest.origins_of(runc))
    # Delta: hcsshim's guest agent, in the layout of its out/delta.tar.gz rule.
    for guest_path, built in (("/init", "bin/init"), ("/bin/vsockexec", "bin/vsockexec")):
        binary = source / built
        guest.add_binary(guest_path, binary, origins=guest.hcsshim_origins(binary, go=False))
    for name in ("gcs", "gcstools", "hooks/wait-paths"):
        binary = source / "bin/cmd" / name
        guest.add_file(
            f"/bin/{Path(name).name}",
            binary.read_bytes(),
            executable=True,
            origins=guest.hcsshim_origins(binary, go=True),
        )
    tools = _make_variables(source).get("GCS_TOOLS", "").split()
    if not tools:
        raise RuntimeError("hcsshim's Makefile no longer declares GCS_TOOLS")
    for tool in tools:
        tree[f"bin/{tool}"] = Entry.symlink("gcstools")
    guest.add_file(
        "/lib64/ld-linux-x86-64.so.2",
        Path(os.path.realpath(LOADER)).read_bytes(),
        executable=True,
        origins=guest.origins_of(Path(LOADER)),
    )
    spec = pins["hcsshim"]
    for name, value in (("gcs.commit", spec["commit"]), ("gcs.branch", spec["tag"])):
        guest.add_file(
            f"/info/{name}", (value + "\n").encode(), executable=False, origins=[GENERATED]
        )


def _module_entries(archive: bytes, files: list[str]) -> dict[str, Entry]:
    """The modules archive as initrd entries; it must hold exactly *files*."""
    modules: dict[str, Entry] = {}
    for name, mode, data in iter_members(gzip.decompress(archive)):
        if stat.S_ISDIR(mode) or name == ".":
            continue
        if not stat.S_ISREG(mode):
            raise RuntimeError(f"modules archive member {name} is not a regular file")
        parts = name.split("/")
        for index in range(1, len(parts)):
            modules.setdefault("/".join(parts[:index]), Entry.directory())
        modules[name] = Entry.file(data, executable=False)
    regular = sorted(name for name, entry in modules.items() if not stat.S_ISDIR(entry.mode))
    if regular != sorted(files):
        raise RuntimeError(
            "the modules archive does not hold exactly the modules its release lists"
        )
    return modules


def build(output: Path) -> None:
    pins = _pins()
    work = Path(os.environ.get("TMPDIR", "/tmp")) / "lcow-initrd"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    metadata = output / "metadata"
    metadata.mkdir(parents=True)
    kernel, archive = kernel_release(pins, work)
    guest = Guest(metadata)
    prefix = guest.unpack_debian(pins, work)
    source = _hcsshim(pins, work)
    guest.env = _build_environment(prefix)
    spec = pins["hcsshim"]
    guest.component(
        HCSSHIM,
        {"kind": "git", "url": spec["repository"], "commit": spec["commit"], "tag": spec["tag"]},
    )
    go_version = _run(["go", "env", "GOVERSION"], env=guest.env).strip()
    guest.component(GO, {"kind": "go", "version": go_version})
    guest.component(GENERATED, {"kind": "generated", "generator": "windows/build-lcow-initrd.py"})
    release = pins["cage_kernel"]
    guest.component(
        CAGE_KERNEL,
        {
            "kind": "cage-kernel",
            **{
                key: release[key]
                for key in ("repository", "version", "sha256sums_sha256", "manifest_sha256")
            },
            "source": kernel["source"],
        },
    )
    _run(["make", "KMOD=1", *HCSSHIM_BINARIES], cwd=source, env=guest.env)
    _guest_tree(guest, pins, source)
    module_files = kernel["modules"]["files"]
    modules = _module_entries(archive, module_files)
    conflicts = sorted(
        set(modules) & {path for path, entry in guest.tree.items() if not stat.S_ISDIR(entry.mode)}
    )
    if conflicts:
        raise RuntimeError(f"kernel modules collide with guest files: {conflicts[:5]}")
    guest.tree.update(modules)
    for name, entry in modules.items():
        if stat.S_ISREG(entry.mode):
            guest.files[name] = [CAGE_KERNEL]
    tree = guest.tree
    (output / INITRD).write_bytes(gzip_bytes(cpio_newc(tree)))
    members = {name: (entry.mode, entry.data) for name, entry in tree.items()}
    found = problems(members, module_files)
    if found:
        raise RuntimeError("assembled initrd cannot boot the LCOW guest: " + ", ".join(found))
    components = guest.record()
    if unattributed := components_problems(components, members):
        raise RuntimeError("assembled initrd has unattributed files: " + "; ".join(unattributed))
    (metadata / COMPONENTS).write_text(
        json.dumps(components, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    record = kernel_record(pins, kernel)
    (metadata / KERNEL_RECORD).write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (metadata / INPUTS).write_text(
        json.dumps({"pins": pins}, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

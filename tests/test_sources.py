"""`source-and-notices.tar` is rebuilt from the exact recorded inputs, or not at all."""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

import _sources
import pytest
import sources_fixture
from sources_fixture import RUNC, World, serve_sdk, world


def _package(world: World, tmp_path: Path, *, cache: str = "cache") -> Path:
    destination = tmp_path / "out" / _sources.ASSET
    _sources.package(
        destination,
        version="1.2.3",
        payloads=world.payloads(),
        fetch=world.server,
        cache=tmp_path / cache,
        git_remote=world.remote,
    )
    return destination


def _names(archive: Path) -> list[str]:
    with tarfile.open(archive) as opened:
        return opened.getnames()


def test_every_component_contributes_its_sources_and_notices(tmp_path: Path) -> None:
    built = world(tmp_path)
    names = _names(_package(built, tmp_path))
    commit = built.commit[:12]
    for expected in (
        "NOTICES.md",
        "components/macos.json",
        "components/windows.json",
        f"sources/hcsshim-{commit}.tar.gz",
        f"sources/containerization-{commit}.tar.gz",
        f"sources/swift/swift-log-{commit}.tar.gz",
        f"sources/swift-sdk/swift-{commit}.tar.gz",
        f"sources/swift-sdk/swift-collections-{commit}.tar.gz",
        f"sources/swift-sdk/musl-{commit}.tar.gz",
        f"sources/swift-sdk/zlib-{commit}.tar.gz",
        f"sources/go/{sources_fixture.GO_VERSION}.src.tar.gz",
        "sources/debian/runc_1.1.5+ds1-1+deb12u1/runc_1.1.5+ds1-1+deb12u1.dsc",
        f"sources/cage-kernel-{sources_fixture.KERNEL_VERSION}-source-and-notices.tar",
        "notices/hcsshim/LICENSE",
        "notices/hcsshim/vendor/example.com/dep/LICENSE",
        "notices/go/PATENTS",
        "notices/debian/runc_1.1.5+ds1-1+deb12u1/debian-copyright",
        "notices/debian/runc_1.1.5+ds1-1+deb12u1/runc.copyright",
        "build/scripts/_sources.py",
        "build/windows/lcow-initrd.toml",
        "build/macos/containerization.toml",
        "build/LICENSE",
    ):
        assert expected in names
    assert not any("__pycache__" in name for name in names)


def test_the_notices_index_names_every_component(tmp_path: Path) -> None:
    built = world(tmp_path)
    with tarfile.open(_package(built, tmp_path)) as archive:
        index = archive.extractfile("NOTICES.md").read().decode()  # type: ignore[union-attr]
    for component in ("hcsshim", "go", RUNC, "cage-kernel", "swift-static-sdk", "swift-sdk:musl"):
        assert f"## `{component}`" in index
    assert "`notices/hcsshim/LICENSE`" in index


def test_equal_inputs_give_equal_bytes(tmp_path: Path) -> None:
    built = world(tmp_path)
    first = _package(built, tmp_path, cache="one").read_bytes()
    second = _package(built, tmp_path, cache="two").read_bytes()
    assert hashlib.sha256(first).digest() == hashlib.sha256(second).digest()
    with tarfile.open(tmp_path / "out" / _sources.ASSET) as archive:
        members = archive.getmembers()
    assert [member.name for member in members] == sorted(member.name for member in members)
    assert {(member.mtime, member.uid, member.gid) for member in members} == {
        (_sources.ARCHIVE_EPOCH, 0, 0)
    }
    assert all(not member.pax_headers for member in members)


def test_a_schema_2_kernel_release_fails_naming_the_kernel_modules(tmp_path: Path) -> None:
    built = world(tmp_path, kernel_schema=2)
    with pytest.raises(SystemExit) as failure:
        _package(built, tmp_path)
    assert (
        f"kernel modules: cage-kernel {sources_fixture.KERNEL_VERSION} publishes no "
        f"{_sources.ASSET}" in str(failure.value)
    )
    assert not (tmp_path / "out" / _sources.ASSET).exists()


def test_every_missing_component_is_named_in_one_error(tmp_path: Path) -> None:
    built = world(tmp_path, kernel_schema=2)
    for url in list(built.server.files):
        if url.startswith(_sources.GO_RELEASES) or "/srcfiles" in url:
            del built.server.files[url]
    with pytest.raises(SystemExit) as failure:
        _package(built, tmp_path)
    named = {
        line[2:].split(":", 1)[0] if not line.startswith(f"- {RUNC}") else RUNC
        for line in str(failure.value).splitlines()
        if line.startswith("- ")
    }
    assert named == {"cage-kernel", "go", RUNC}


def test_a_git_component_must_resolve_to_its_recorded_commit(tmp_path: Path) -> None:
    built = world(tmp_path)
    assembly = _sources.Assembly(fetch=built.server, cache=tmp_path / "c", git_remote=built.remote)
    with pytest.raises(_sources.SourceError, match="not the recorded"):
        _sources.git_archive(
            assembly, "hcsshim", "https://example.invalid/x", "refs/tags/v1.3.1", commit="0" * 40
        )


def test_a_debian_file_with_the_wrong_sha1_is_refused(tmp_path: Path) -> None:
    built = world(tmp_path)
    for url in built.server.files:
        if url.startswith(f"{_sources.SNAPSHOT}/file/"):
            built.server.files[url] += b"tampered"
            break
    assembly = _sources.Assembly(fetch=built.server, cache=tmp_path / "c")
    with pytest.raises(_sources.SourceError, match="has sha1"):
        _sources.debian_source(assembly, RUNC, "runc", "1.1.5+ds1-1+deb12u1")


def test_a_debian_file_that_differs_from_its_dsc_is_refused(tmp_path: Path) -> None:
    server = sources_fixture.Server()
    files = sources_fixture.serve_debian(server, "kmod", "30+20221128-1")
    # Re-serve the package with a .dsc whose SHA-256 of the orig tarball is wrong,
    # under the files' own (correct) SHA-1s, as a tampered mirror would.
    dsc_name = next(name for name in files if name.endswith(".dsc"))
    orig = next(name for name in files if ".orig." in name)
    wrong = files[dsc_name].replace(hashlib.sha256(files[orig]).hexdigest().encode(), b"0" * 64)
    old_sha1 = hashlib.sha1(files[dsc_name]).hexdigest()
    new_sha1 = hashlib.sha1(wrong).hexdigest()
    server.files[f"{_sources.SNAPSHOT}/file/{new_sha1}"] = wrong
    index_url = next(url for url in server.files if url.endswith("srcfiles?fileinfo=1"))
    server.files[index_url] = server.files[index_url].replace(old_sha1.encode(), new_sha1.encode())
    assembly = _sources.Assembly(fetch=server, cache=tmp_path / "c")
    with pytest.raises(_sources.SourceError, match="does not match its .dsc"):
        _sources.debian_source(assembly, "debian:kmod=30+20221128-1", "kmod", "30+20221128-1")


def test_a_download_that_does_not_match_its_pin_is_refused(tmp_path: Path) -> None:
    server = sources_fixture.Server({"https://example.invalid/x": b"bytes"})
    assembly = _sources.Assembly(fetch=server, cache=tmp_path / "c")
    with pytest.raises(_sources.SourceError, match="not the expected"):
        assembly.download("https://example.invalid/x", "sha256", "0" * 64)
    assert not list((tmp_path / "c" / "sha256").iterdir())


def test_a_kernel_archive_the_manifest_and_sums_disagree_on_is_refused(tmp_path: Path) -> None:
    server = sources_fixture.Server()
    pins = sources_fixture.serve_kernel(server, "manneskjur/cage-kernel")
    base = f"https://github.com/manneskjur/cage-kernel/releases/download/v{pins['version']}/"
    server.files[base + _sources.ASSET] += b"tampered"
    assembly = _sources.Assembly(fetch=server, cache=tmp_path / "c")
    with pytest.raises(_sources.SourceError, match="not the expected"):
        _sources.kernel_source(assembly, "cage-kernel", pins)


def test_linked_sdk_libraries_are_attributed_by_rule_and_unknown_ones_fail_by_name(
    tmp_path: Path,
) -> None:
    server = sources_fixture.Server()
    libraries = ("libswiftCore.a", "libcurl.a", "libmystery.a", "libz.a")
    record = serve_sdk(server, libraries)
    bundle = tmp_path / "sdk.tar.gz"
    bundle.write_bytes(server.files[record["url"]])
    contents = _sources.sdk_contents(bundle)
    assert sources_fixture.OTHER_TARGET_LIBRARY in contents.inputs
    assert not sources_fixture.OTHER_TARGET_LIBRARY.startswith(contents.root)
    linked = {
        sources_fixture.sdk_path(library): {"vmexec": [f"{library}.o"]} for library in libraries
    }
    projects, errors = _sources.swift_runtime_components(
        linked, contents, record["swift_tag"], lambda project: pytest.fail(project)
    )
    assert projects["swift-sdk:swift"]["ref"] == f"refs/tags/{record['swift_tag']}"
    assert projects["swift-sdk:zlib"]["ref"] == "refs/tags/v1.3.1"
    assert any(
        "libmystery.a (linked into vmexec: libmystery.a.o): no rule attributes it" in error
        for error in errors
    )
    assert any(
        "libcurl.a (linked into vmexec: libcurl.a.o)" in error
        and "8.15.0-DEV names no upstream release" in error
        for error in errors
    )


def test_a_recorded_notice_missing_from_its_payload_is_named(tmp_path: Path) -> None:
    built = world(tmp_path)
    record = json.loads((built.windows_payload / "metadata/components.json").read_text())
    notice = record["components"][RUNC]["notices"][0]
    (built.windows_payload / notice).unlink()
    with pytest.raises(SystemExit, match="captured notice"):
        _package(built, tmp_path)


def test_specific_sdk_rules_win_over_general_ones_and_cmake_versions_are_read() -> None:
    contents = _sources.SdkContents(
        texts={
            "mimalloc-config-version.cmake": "set(mi_version_major 2)\n"
            "set(mi_version_minor 2)\nset(mi_version_patch 4)\n"
        },
    )
    linked = {
        f"usr/lib/{library}": {"vminitd": ["x.o"]}
        for library in ("libswiftDispatch.a", "libswiftCore.a", "libmimalloc.a", "swiftrt.o")
    }
    projects, errors = _sources.swift_runtime_components(
        linked, contents, "swift-6.3-RELEASE", lambda project: pytest.fail(project)
    )
    assert errors == []
    assert projects["swift-sdk:swift-corelibs-libdispatch"]["libraries"] == ["libswiftDispatch.a"]
    assert projects["swift-sdk:swift"]["libraries"] == ["libswiftCore.a", "swiftrt.o"]
    assert projects["swift-sdk:mimalloc"]["ref"] == "refs/tags/v2.2.4"


# -- Link evidence selects the SDK's sources -----------------------------------


def test_sdk_libraries_no_link_took_code_from_get_no_source(tmp_path: Path) -> None:
    built = world(tmp_path)
    names = _names(_package(built, tmp_path))
    assert not any(
        name.startswith(f"sources/swift-sdk/{project}-")
        for name in names
        for project in ("curl", "swift-docker", "swift-foundation-icu")
    )
    assert f"sources/swift-sdk/musl-{built.commit[:12]}.tar.gz" in names


def test_the_notices_record_what_each_link_took_and_what_it_did_not(tmp_path: Path) -> None:
    built = world(tmp_path)
    with tarfile.open(_package(built, tmp_path)) as archive:
        index = archive.extractfile("NOTICES.md").read().decode()  # type: ignore[union-attr]
    section = index[index.index("## Link evidence: `macos`") :]
    assert (
        f"`{sources_fixture.sdk_path('libc.a')}`: vmexec: fork.lo, memcpy.lo; vminitd: memcpy.lo"
        in section
    )
    assert f"`{sources_fixture.sdk_path('crt1.o')}`: vmexec: the whole object" in section
    not_linked = section[section.index("no executable took code from") :]
    for library in ("libssl.a", "libcrypto.a", "libcurl.a", "libfts.a"):
        assert f"`{sources_fixture.sdk_path(library)}`" in not_linked
    assert "`vminitd`: `CCryptoBoringSSL.build`, `vminitd.build`" in section


def test_a_linked_sdk_library_without_an_exact_source_refuses_naming_it(tmp_path: Path) -> None:
    linked = {
        **sources_fixture.SDK_LINKED,
        "libcurl.a": {"vmexec": ["easy.c.o"]},
        "libssl.a": {"vminitd": ["ssl_lib.cc.o"]},
    }
    built = world(tmp_path, linked=linked)
    with pytest.raises(SystemExit) as failure:
        _package(built, tmp_path)
    message = str(failure.value)
    assert (
        "- Static Linux SDK library libcurl.a (linked into vmexec: easy.c.o): "
        "its version 8.15.0-DEV names no upstream release" in message
    )
    assert (
        "- Static Linux SDK library libssl.a (linked into vminitd: ssl_lib.cc.o): "
        "no rule attributes it to a source" in message
    )
    assert not (tmp_path / "out" / _sources.ASSET).exists()


def test_link_evidence_of_another_sdk_is_refused(tmp_path: Path) -> None:
    built = world(tmp_path)
    record = json.loads((built.macos_payload / "components.json").read_text())
    del record["link_evidence"]["sdk_inputs"][sources_fixture.sdk_path("libfts.a")]
    (built.macos_payload / "components.json").write_text(json.dumps(record))
    with pytest.raises(SystemExit, match="lists other static libraries than the pinned SDK holds"):
        _package(built, tmp_path)


def test_an_sdk_component_without_link_evidence_is_refused(tmp_path: Path) -> None:
    built = world(tmp_path)
    record = json.loads((built.macos_payload / "components.json").read_text())
    del record["link_evidence"]
    (built.macos_payload / "components.json").write_text(json.dumps(record))
    with pytest.raises(SystemExit, match="swift-static-sdk: no link evidence says"):
        _package(built, tmp_path)


def _fts(source: bytes) -> bytes:
    member = sources_fixture.dwarf_object(
        "/home/build-user",
        {"resources/fts/fts.c": source, "sdk_root/aarch64/usr/include/stdio.h": b"musl"},
    )
    return sources_fixture.ar_archive({"fts.c.o": member})


def _with_fts_commit(monkeypatch: pytest.MonkeyPatch, commit: str) -> None:
    rules = tuple(
        (*rule[:4], commit) if rule[1] == "swift-docker" else rule
        for rule in _sources.SWIFT_SDK_RULES
    )
    monkeypatch.setattr(_sources, "SWIFT_SDK_RULES", rules)


def test_a_library_built_from_an_unreleased_source_is_verified_by_its_dwarf_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    linked = {**sources_fixture.SDK_LINKED, "libfts.a": {"vmexec": ["fts.c.o"]}}
    built = world(
        tmp_path, linked=linked, library_contents={"libfts.a": _fts(sources_fixture.FTS_SOURCE)}
    )
    _with_fts_commit(monkeypatch, built.commit)
    names = _names(_package(built, tmp_path))
    assert f"sources/swift-sdk/swift-docker-{built.commit[:12]}.tar.gz" in names


def test_a_library_whose_dwarf_digests_differ_from_the_archived_source_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    linked = {**sources_fixture.SDK_LINKED, "libfts.a": {"vmexec": ["fts.c.o"]}}
    built = world(tmp_path, linked=linked, library_contents={"libfts.a": _fts(b"other\n")})
    _with_fts_commit(monkeypatch, built.commit)
    with pytest.raises(SystemExit) as failure:
        _package(built, tmp_path)
    assert (
        "Static Linux SDK library libfts.a (linked into vmexec: fts.c.o): member fts.c.o was "
        "compiled from a fts.c with MD5" in str(failure.value)
    )


def test_dwarf_source_digests_are_read_through_relocations() -> None:
    member = sources_fixture.dwarf_object(
        "/home/build-user", {"resources/fts/fts.c": b"a", "/usr/include/x.h": b"b"}
    )
    assert _sources.dwarf_source_files(member) == {
        "/home/build-user/resources/fts/fts.c": hashlib.md5(b"a").hexdigest(),  # noqa: S324
        "/usr/include/x.h": hashlib.md5(b"b").hexdigest(),  # noqa: S324
    }

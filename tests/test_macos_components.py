"""The macOS initfs's components are read from the build's own checkout, or refused."""

from __future__ import annotations

import hashlib
import json
import posixpath
from pathlib import Path, PurePosixPath

import _macos
import pytest
import sources_fixture

SDK_URL = (
    "https://download.swift.org/swift-6.3-release/static-sdk/swift-6.3-RELEASE/"
    "swift-6.3-RELEASE_static-linux-0.1.0.artifactbundle.tar.gz"
)
REVISION = "a" * 40
EVIDENCE = sources_fixture.sdk_link_evidence(
    sources_fixture.initfs_bytes(), sources_fixture.SDK_LIBRARIES, sources_fixture.SDK_LINKED
)


def _dependency(identity: str, location: str, revision: str = REVISION) -> dict:
    return {
        "packageRef": {"identity": identity, "kind": "remoteSourceControl", "location": location},
        "state": {
            "name": "sourceControlCheckout",
            "checkoutState": {"revision": revision, "version": "1.0.0"},
        },
        "subpath": identity,
    }


def _local_containerization() -> dict:
    return {
        "packageRef": {"identity": "containerization", "kind": "fileSystem", "path": "/workspace"},
        "state": {"name": "fileSystem", "path": "/workspace"},
    }


def checkout(root: Path, *, root_deps: list, vminitd_deps: list, artifacts: list = ()) -> Path:
    for workspace, dependencies in ((".build", root_deps), ("vminitd/.build", vminitd_deps)):
        state = root / workspace / "workspace-state.json"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text(
            json.dumps(
                {
                    "version": 6,
                    "object": {"dependencies": dependencies, "artifacts": list(artifacts)},
                }
            ),
            encoding="utf-8",
        )
    (root / "vminitd" / "Makefile").write_text(
        f"SWIFT_SDK_URL := {SDK_URL}\nSWIFT_SDK_CHECKSUM := {'d' * 64}\n", encoding="utf-8"
    )
    return root


def test_components_name_the_pin_every_resolved_package_and_the_sdk(tmp_path: Path) -> None:
    root = checkout(
        tmp_path,
        root_deps=[_dependency("swift-nio", "https://github.com/apple/swift-nio.git")],
        vminitd_deps=[
            _local_containerization(),
            _dependency("swift-log", "https://github.com/apple/swift-log"),
            _dependency("swift-nio", "https://github.com/apple/swift-nio.git"),
        ],
    )
    pins = _macos.load_pins()
    record = _macos.components(root, pins, EVIDENCE)
    found = record["components"]
    assert found[_macos.CONTAINERIZATION] == {
        "kind": "git",
        "url": pins["url"],
        "commit": pins["revision"],
    }
    assert found["swift:swift-log"]["url"] == "https://github.com/apple/swift-log.git"
    assert found["swift:swift-nio"]["commit"] == REVISION
    assert found[_macos.SWIFT_STATIC_SDK] == {
        "kind": _macos.SWIFT_STATIC_SDK,
        "url": SDK_URL,
        "sha256": "d" * 64,
        "swift_tag": "swift-6.3-RELEASE",
    }
    assert record["files"] == {_macos.INITFS_FILE: sorted(found)}
    assert _macos.components_problems(record, pins) == []


def test_an_absent_workspace_state_is_refused(tmp_path: Path) -> None:
    root = checkout(tmp_path, root_deps=[], vminitd_deps=[])
    (root / "vminitd/.build/workspace-state.json").unlink()
    with pytest.raises(SystemExit, match="absent or unreadable"):
        _macos.swift_dependencies(root)


@pytest.mark.parametrize(
    "dependency",
    [
        pytest.param(
            {**_dependency("x", "https://e.invalid/x"), "state": {"name": "edited"}}, id="edited"
        ),
        pytest.param(_dependency("x", "file:///x"), id="not-https"),
        pytest.param(_dependency("x", "https://e.invalid/x", revision="main"), id="no-revision"),
        pytest.param(
            {
                **_local_containerization(),
                "packageRef": {"identity": "other", "kind": "fileSystem"},
            },
            id="foreign-local-path",
        ),
    ],
)
def test_a_dependency_without_a_pinned_source_is_refused(tmp_path: Path, dependency: dict) -> None:
    root = checkout(tmp_path, root_deps=[], vminitd_deps=[dependency])
    with pytest.raises(SystemExit):
        _macos.swift_dependencies(root)


def test_binary_artifacts_are_refused(tmp_path: Path) -> None:
    root = checkout(tmp_path, root_deps=[], vminitd_deps=[], artifacts=[{"x": 1}])
    with pytest.raises(SystemExit, match="binary artifacts"):
        _macos.swift_dependencies(root)


def test_only_the_workspace_the_initfs_executables_are_built_in_is_attributed(
    tmp_path: Path,
) -> None:
    # The root package's workspace builds cctl, which is not in the initfs; it
    # may resolve a package to another revision than vminitd's.
    root = checkout(
        tmp_path,
        root_deps=[_dependency("swift-log", "https://e.invalid/swift-log", revision="b" * 40)],
        vminitd_deps=[_dependency("swift-log", "https://e.invalid/swift-log")],
    )
    assert _macos.swift_dependencies(root)["swift:swift-log"]["commit"] == REVISION


def test_an_sdk_pin_without_a_release_tag_is_refused(tmp_path: Path) -> None:
    root = checkout(tmp_path, root_deps=[], vminitd_deps=[])
    (root / "vminitd/Makefile").write_text(
        f"SWIFT_SDK_URL := https://e.invalid/sdk.tar.gz\nSWIFT_SDK_CHECKSUM := {'d' * 64}\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="names no Swift release"):
        _macos.swift_static_sdk(root)


def test_a_record_that_does_not_attribute_the_initfs_to_every_component_is_refused(
    tmp_path: Path,
) -> None:
    pins = _macos.load_pins()
    record = _macos.components(checkout(tmp_path, root_deps=[], vminitd_deps=[]), pins, EVIDENCE)
    record["files"][_macos.INITFS_FILE].remove(_macos.SWIFT_STATIC_SDK)
    assert any("does not attribute" in error for error in _macos.components_problems(record, pins))


# -- Link evidence -------------------------------------------------------------

BUNDLE = sources_fixture.SDK_BUNDLE
INSTALLATION = f"/root/.swiftpm/swift-sdks/{BUNDLE}"
BUILD = "/workspace/vminitd/.build/aarch64-swift-linux-musl/release"
SYSROOT = sources_fixture.SDK_SYSROOT.removeprefix(f"{BUNDLE}/") + "/aarch64"
#: The SDK installation's static archives and object files, relative to it.
SDK_FILES = [
    f"{SYSROOT}/usr/lib/{name}"
    for name in ("crt1.o", "libc.a", "libcrypto.a", "libcurl.a", "libfts.a", "libssl.a")
]


def lld_map(inputs: list[str]) -> str:
    """An `ld.lld -Map` file placing one section of each of *inputs* in `.text`."""
    lines = [
        f"{'VMA':>16} {'LMA':>16}     Size Align Out     In      Symbol",
        f"{'200000':>16} {'200000':>16} {'40':>8} {'16':>5} .text",
        f"{'200000':>16} {'200000':>16} {'0':>8} {'1':>5}         <internal>:(.text)",
    ]
    for item in inputs:
        lines.append(f"{'200000':>16} {'200000':>16} {'10':>8} {'4':>5}         {item}:(.text)")
        lines.append(f"{'200000':>16} {'200000':>16} {'0':>8} {'1':>5}                 symbol")
    lines.append(f"{'0':>16} {'0':>16} {'0':>8} {'1':>5} . = ALIGN(0x10)")
    return "\n".join(lines) + "\n"


#: What each executable's link took: swift-crypto's vendored BoringSSL, built by
#: SwiftPM, but none of the SDK's libssl/libcrypto/libcurl; libfts's one member.
LINKS = {
    "vminitd": [
        f"{BUILD}/vminitd.build/main.swift.o",
        f"{BUILD}/CCryptoBoringSSL.build/crypto/sha/sha256.c.o",
        f"{INSTALLATION}/{SYSROOT}/usr/lib/crt1.o",
        f"{INSTALLATION}/{SYSROOT}/usr/lib/libc.a(memcpy.lo)",
        f"{INSTALLATION}/{SYSROOT}/usr/lib/libfts.a(fts.c.o)",
    ],
    "vmexec": [
        f"{BUILD}/vmexec.build/main.swift.o",
        f"{INSTALLATION}/{SYSROOT}/usr/lib/../lib/libc.a(fork.lo)",
        f"{INSTALLATION}/{SYSROOT}/usr/lib/libfts.a(fts.c.o)",
    ],
}


def scratch(
    root: Path,
    *,
    links: dict[str, list[str]] = LINKS,
    installed: dict[str, bytes] | None = None,
    linked: dict[str, bytes] | None = None,
) -> Path:
    """What the wrapper and the readback leave in the checkout's `.cage-init/`."""
    linked = linked or {name: f"{name} bytes".encode() for name in _macos.INITFS_EXECUTABLES}
    installed = (
        installed
        if installed is not None
        else {_macos.INITFS_EXECUTABLES[name]: data for name, data in linked.items()}
    )
    link = root / "link"
    link.mkdir(parents=True)
    (link / "bin-path").write_text(BUILD + "\n", encoding="utf-8")
    for name, inputs in links.items():
        (link / f"{name}.map").write_text(lld_map(inputs), encoding="utf-8")
        (link / f"{name}.sha256").write_text(
            hashlib.sha256(linked[name]).hexdigest() + "\n", encoding="utf-8"
        )
    for path, data in installed.items():
        target = root / "initfs" / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (root / "initfs" / "lost+found").mkdir(parents=True, exist_ok=True)
    (root / "sdk-inputs.txt").write_text(
        "".join(f"./{path}\n" for path in SDK_FILES), encoding="utf-8"
    )
    resolved = {
        path.removeprefix(f"{INSTALLATION}/").split("(")[0]
        for inputs in links.values()
        for path in inputs
        if path.startswith(INSTALLATION)
    }
    (root / "sdk-resolved.txt").write_text(
        "".join(
            f"{posixpath.normpath(path)}\t{posixpath.normpath(path)}\n"
            for path in sorted(resolved)
        ),
        encoding="utf-8",
    )
    initfs = root / "initfs.ext4"
    initfs.write_bytes(b"ext4")
    return root


def _evidence(root: Path) -> dict:
    return _macos.link_evidence(root, bundle=BUNDLE, initfs=root / "initfs.ext4")


def test_a_link_map_separates_sdk_swiftpm_and_other_inputs() -> None:
    link = _macos.classify_inputs(
        _macos.map_inputs(
            lld_map(
                [
                    *LINKS["vminitd"],
                    "/usr/lib/swift_static/linux-static/libswiftCore.a(Array.cpp.o)",
                    "relative/object.o",
                ]
            )
        ),
        bundle=BUNDLE,
        build_dir=PurePosixPath(BUILD),
    )
    assert link.sdk == {
        INSTALLATION: {
            f"{SYSROOT}/usr/lib/crt1.o": set(),
            f"{SYSROOT}/usr/lib/libc.a": {"memcpy.lo"},
            f"{SYSROOT}/usr/lib/libfts.a": {"fts.c.o"},
        }
    }
    assert link.swiftpm == {"vminitd.build", "CCryptoBoringSSL.build"}
    assert link.unattributed == {
        "/usr/lib/swift_static/linux-static/libswiftCore.a(Array.cpp.o)",
        "relative/object.o",
    }


def test_link_evidence_records_what_each_executable_took_from_the_sdk(tmp_path: Path) -> None:
    evidence = _evidence(scratch(tmp_path))
    assert evidence["initfs_sha256"] == hashlib.sha256(b"ext4").hexdigest()
    inputs = evidence["sdk_inputs"]
    path = f"{BUNDLE}/{SYSROOT}/usr/lib/"
    # Every SDK archive is recorded, linked or not: the disputed archives too.
    assert inputs[path + "libssl.a"] == {}
    assert inputs[path + "libcrypto.a"] == {}
    assert inputs[path + "libcurl.a"] == {}
    assert inputs[path + "libfts.a"] == {"vmexec": ["fts.c.o"], "vminitd": ["fts.c.o"]}
    assert inputs[path + "libc.a"] == {"vmexec": ["fork.lo"], "vminitd": ["memcpy.lo"]}
    assert inputs[path + "crt1.o"] == {"vminitd": []}
    # The BoringSSL in vminitd is swift-crypto's, built by SwiftPM.
    vminitd = evidence["executables"]["vminitd"]
    assert "CCryptoBoringSSL.build" in vminitd["swiftpm"]
    assert vminitd["linked_sha256"] == vminitd["initfs_sha256"]
    assert _macos.link_evidence_problems(evidence) == []


@pytest.mark.parametrize(
    "damage",
    [
        pytest.param(lambda root: (root / "link/vmexec.map").unlink(), id="missing"),
        pytest.param(
            lambda root: (root / "link/vmexec.map").write_text(
                "Archive member included to satisfy reference by file (symbol)\n", "utf-8"
            ),
            id="not-lld",
        ),
        pytest.param(
            lambda root: (root / "link/vmexec.sha256").write_text("x", "utf-8"), id="no-digest"
        ),
    ],
)
def test_missing_or_unreadable_link_evidence_refuses_naming_the_executable(
    tmp_path: Path, damage
) -> None:
    root = scratch(tmp_path)
    damage(root)
    with pytest.raises(SystemExit) as failure:
        _evidence(root)
    assert "- vmexec: its link" in str(failure.value)


def test_an_executable_whose_initfs_bytes_are_not_its_links_is_refused(tmp_path: Path) -> None:
    root = scratch(
        tmp_path,
        installed={"/sbin/vminitd": b"other bytes", "/sbin/vmexec": b"vmexec bytes"},
    )
    with pytest.raises(SystemExit) as failure:
        _evidence(root)
    assert "- vminitd: /sbin/vminitd in initfs.ext4 has SHA-256" in str(failure.value)
    assert "its mapped link wrote" in str(failure.value)
    assert "vmexec:" not in str(failure.value)


def test_an_initfs_the_links_cannot_account_for_is_refused(tmp_path: Path) -> None:
    root = scratch(
        tmp_path,
        installed={
            "/sbin/vminitd": b"vminitd bytes",
            "/sbin/runc": b"?",
        },
    )
    with pytest.raises(SystemExit) as failure:
        _evidence(root)
    assert "vmexec: initfs.ext4 holds no /sbin/vmexec" in str(failure.value)
    assert "holds files no link evidence covers: /sbin/runc" in str(failure.value)


def test_an_unreadable_initfs_is_refused(tmp_path: Path) -> None:
    root = scratch(tmp_path, installed={})
    with pytest.raises(SystemExit, match="no file could be read back out of initfs.ext4"):
        _evidence(root)


def test_an_input_neither_the_sdks_nor_swiftpm_built_is_refused(tmp_path: Path) -> None:
    links = {**LINKS, "vmexec": [*LINKS["vmexec"], "/opt/vendor/libblob.a(blob.o)"]}
    with pytest.raises(SystemExit) as failure:
        _evidence(scratch(tmp_path, links=links))
    assert "vmexec: linked inputs that are neither" in str(failure.value)
    assert "/opt/vendor/libblob.a(blob.o)" in str(failure.value)


def test_a_linked_sdk_input_the_installation_does_not_hold_is_refused(tmp_path: Path) -> None:
    root = scratch(tmp_path)
    (root / "sdk-resolved.txt").write_text("", encoding="utf-8")
    with pytest.raises(SystemExit, match="vminitd: linked SDK input .*crt1.o resolves to no file"):
        _evidence(root)


def test_the_payload_refuses_link_evidence_of_another_initfs(tmp_path: Path) -> None:
    pins = _macos.load_pins()
    record = _macos.components(
        checkout(tmp_path / "c", root_deps=[], vminitd_deps=[]), pins, EVIDENCE
    )
    payload = sources_fixture.macos_payload(tmp_path / "payload", pins, record)
    (payload / _macos.BUILD_RECORD).write_text(
        json.dumps({"containerization": _macos.source(pins)}), encoding="utf-8"
    )
    assert _macos.payload_problems(payload, pins=pins) == []
    (payload / _macos.INITFS_FILE).write_bytes(sources_fixture.initfs_bytes() + b"\0")
    assert "its link evidence describes another initfs.ext4" in _macos.payload_problems(
        payload, pins=pins
    )


def test_evidence_whose_executable_is_not_what_its_link_wrote_is_malformed() -> None:
    evidence = json.loads(json.dumps(EVIDENCE))
    evidence["executables"]["vmexec"]["initfs_sha256"] = "0" * 64
    assert _macos.link_evidence_problems(evidence) == [
        "components.json link_evidence: vmexec in initfs.ext4 is not what its link wrote"
    ]
    del evidence["executables"]["vmexec"]
    assert any("does not cover exactly" in e for e in _macos.link_evidence_problems(evidence))

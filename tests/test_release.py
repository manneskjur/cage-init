from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import _common
import _macos
import _sources
import _windows
import cage_init
import pytest
import sources_fixture
from lcow_initrd_payload import current_pins, make_payload

pytestmark = pytest.mark.skipif(shutil.which("zstd") is None, reason="zstd CLI is not installed")


def macos_payload(root: Path) -> Path:
    """A macOS payload built from the checked-in pins."""
    pins = _macos.load_pins()
    found = {
        _macos.CONTAINERIZATION: {"kind": "git", "url": pins["url"], "commit": pins["revision"]},
        _macos.SWIFT_STATIC_SDK: {
            "kind": _macos.SWIFT_STATIC_SDK,
            "url": "https://example.invalid/swift-6.3-RELEASE/sdk.tar.gz",
            "sha256": "0" * 64,
            "swift_tag": "swift-6.3-RELEASE",
        },
    }
    return sources_fixture.macos_payload(
        root / "macos",
        pins,
        {
            "schema_version": _macos.COMPONENTS_SCHEMA,
            "platform": "macos",
            "components": found,
            "files": {_macos.INITFS_FILE: sorted(found)},
            "link_evidence": sources_fixture.sdk_link_evidence(
                sources_fixture.initfs_bytes(),
                sources_fixture.SDK_LIBRARIES,
                sources_fixture.SDK_LINKED,
            ),
        },
    )


@pytest.fixture
def built(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> sources_fixture.World:
    """Payloads whose pins the unit is (temporarily) pinned to, and their sources."""
    built = sources_fixture.world(tmp_path / "world")
    monkeypatch.setattr(_windows, "load_pins", lambda: built.windows_pins)
    monkeypatch.setattr(_macos, "load_pins", lambda: built.macos_pins)
    return built


def package(tmp_path: Path, built: sources_fixture.World) -> Path:
    release = tmp_path / "release"
    args = argparse.Namespace(
        macos_artifact_dir=built.macos_payload,
        windows_artifact_dir=built.windows_payload,
        release_dir=release,
        sources_cache_dir=tmp_path / "cache",
    )
    assert cage_init.package_release(args, fetch=built.server, git_remote=built.remote) == 0
    return release


def test_a_release_holds_every_platform_and_nothing_else(
    tmp_path: Path, built: sources_fixture.World
) -> None:
    release = package(tmp_path, built)
    assert sorted(path.name for path in release.iterdir()) == sorted(
        cage_init.release_asset_names()
    )


def test_the_manifest_names_each_platform_its_digests_and_its_kernel(
    tmp_path: Path, built: sources_fixture.World
) -> None:
    release = package(tmp_path, built)
    manifest = json.loads((release / cage_init.MANIFEST_ASSET).read_text(encoding="utf-8"))
    assert manifest["schema_version"] == cage_init.RELEASE_SCHEMA_VERSION == 2
    archive = manifest["source_archive"]
    assert archive["name"] == _sources.ASSET
    assert archive["sha256"] == _common.file_sha256(release / _sources.ASSET)
    assert archive["size"] == (release / _sources.ASSET).stat().st_size
    macos = manifest["platforms"]["macos"]
    assert macos["containerization"] == _macos.source(_macos.load_pins())
    assert _macos.SWIFT_STATIC_SDK in macos["components"]
    assert macos["initfs"]["sha256"] == _common.file_sha256(release / macos["initfs"]["name"])
    windows = manifest["platforms"]["windows"]
    assert windows["initrd"]["sha256"] == _common.file_sha256(release / windows["initrd"]["name"])
    assert windows["kernel_sha256"] == "3" * 64
    assert windows["kernel_release"]["repository"] == "manneskjur/cage-kernel"
    assert windows["sources"]["hcsshim"] == built.windows_pins["hcsshim"]
    assert "cage-kernel" in windows["components"]


def test_sha256sums_covers_every_other_asset(tmp_path: Path, built: sources_fixture.World) -> None:
    release = package(tmp_path, built)
    lines = (release / cage_init.SHA256SUMS_ASSET).read_text(encoding="utf-8").splitlines()
    listed = dict(reversed(line.split("  ", 1)) for line in lines)
    assert set(listed) == set(cage_init.release_asset_names()) - {cage_init.SHA256SUMS_ASSET}
    assert all(listed[name] == _common.file_sha256(release / name) for name in listed)
    assert _sources.ASSET in listed


def test_a_release_whose_sources_are_incomplete_is_not_packaged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    built = sources_fixture.world(tmp_path / "world", kernel_schema=2)
    monkeypatch.setattr(_windows, "load_pins", lambda: built.windows_pins)
    monkeypatch.setattr(_macos, "load_pins", lambda: built.macos_pins)
    with pytest.raises(SystemExit, match="kernel modules: cage-kernel"):
        package(tmp_path, built)
    assert not (tmp_path / "release" / cage_init.MANIFEST_ASSET).exists()


def test_a_windows_payload_from_other_pins_is_not_released(tmp_path: Path) -> None:
    pins = current_pins() | {"hcsshim": {**current_pins()["hcsshim"], "tag": "v0.0.0"}}
    payload = make_payload(tmp_path / "windows", pins=pins)
    with pytest.raises(SystemExit, match="other pins"):
        _windows.package_release(payload, tmp_path / "out")


def test_a_macos_payload_that_is_not_ext4_is_not_released(tmp_path: Path) -> None:
    payload = macos_payload(tmp_path)
    (payload / _macos.INITFS_FILE).write_bytes(b"\0" * _macos.MINIMUM_INITFS_SIZE)
    with pytest.raises(SystemExit, match="not an ext4 filesystem"):
        _macos.package_release(payload, tmp_path / "out")


def test_a_macos_payload_from_another_revision_is_not_released(tmp_path: Path) -> None:
    payload = macos_payload(tmp_path)
    (payload / _macos.BUILD_RECORD).write_text(
        json.dumps({"containerization": {"url": "x", "revision": "0" * 40}}), encoding="utf-8"
    )
    with pytest.raises(SystemExit, match="another source"):
        _macos.package_release(payload, tmp_path / "out")


def test_release_asset_names_name_the_platform_and_architecture() -> None:
    names = cage_init.release_asset_names()
    assert names[-3:] == (_sources.ASSET, cage_init.MANIFEST_ASSET, cage_init.SHA256SUMS_ASSET)
    assert names[:-3] == ("macos-arm64-initfs.ext4.zst", "windows-amd64-lcow-initrd.img")

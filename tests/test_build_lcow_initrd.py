"""Pure helpers of the Windows LCOW initrd recipe; nothing is downloaded or built."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "windows" / "build-lcow-initrd.py"


def _load():
    spec = importlib.util.spec_from_file_location("cage_init_test_build_lcow_initrd", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_make_variables_follow_backslash_continuations(tmp_path: Path) -> None:
    (tmp_path / "Makefile").write_text(
        "GCS_TOOLS=\\\n\tgenerichook \\\n\tinstall-drivers\n"
        "GO_FLAGS := -trimpath   -mod=vendor\n"
        "GCS_TOOLS = later-definition\n"
        "target: dependency\n",
        encoding="utf-8",
    )
    values = _load()._make_variables(tmp_path)
    assert values["GCS_TOOLS"] == "generichook install-drivers"
    assert values["GO_FLAGS"] == "-trimpath -mod=vendor"
    assert "target" not in values


def test_guest_path_maps_the_unpacked_package_prefix_to_root(tmp_path: Path) -> None:
    module = _load()
    prefix = tmp_path / "debian"
    library = prefix / "usr" / "lib" / "x86_64-linux-gnu" / "libkmod.so.2"
    assert module._guest_path(library, prefix) == "/usr/lib/x86_64-linux-gnu/libkmod.so.2"
    assert module._guest_path(Path("/usr/sbin/mkfs.ext4"), prefix) == "/usr/sbin/mkfs.ext4"


def test_checked_in_pins_are_content_addressed() -> None:
    pins = _load()._pins()
    assert pins["debian"]
    for pin in pins["debian"]:
        assert pin["url"].startswith("https://")
        assert re.fullmatch(r"[0-9a-f]{64}", pin["sha256"])
    assert re.fullmatch(r"[0-9a-f]{40}", pins["hcsshim"]["commit"])


def test_the_kernel_pin_names_a_published_release_by_digest() -> None:
    """Empty digests mean the pinned cage-kernel release is not published yet."""
    kernel = _load()._pins()["cage_kernel"]
    assert kernel["repository"] == "manneskjur/cage-kernel"
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", kernel["version"])
    assert re.fullmatch(r"[0-9a-f]{64}", kernel["sha256sums_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", kernel["manifest_sha256"])


def test_pins_with_an_unknown_schema_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load()
    pins = tmp_path / "pins.toml"
    pins.write_text("schema = 1\n", encoding="utf-8")
    monkeypatch.setattr(module, "PINS", pins)
    with pytest.raises(ValueError, match="unsupported schema"):
        module._pins()


def test_a_pin_without_a_sha256_is_refused_before_any_download(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load()
    monkeypatch.setattr(
        module.urllib.request, "urlopen", lambda *_args, **_kwargs: pytest.fail("no download")
    )
    with pytest.raises(ValueError, match="has no SHA-256"):
        module._download("https://example.invalid/x.deb", "latest", tmp_path / "x.deb")


def test_downloaded_bytes_must_match_their_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load()

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return b"tampered"

    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())
    destination = tmp_path / "x.deb"
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        module._download("https://example.invalid/x.deb", "0" * 64, destination)
    assert not destination.exists()


def test_downloads_retry_transport_failures_but_not_forever(monkeypatch):
    import urllib.error

    build = _load()
    calls = []

    def failing(url, timeout):
        calls.append(url)
        raise urllib.error.URLError("network is unreachable")

    monkeypatch.setattr(build.urllib.request, "urlopen", failing)
    monkeypatch.setattr(build.time, "sleep", lambda seconds: None)
    with pytest.raises(RuntimeError, match="after 3 attempts"):
        build._fetch("https://example.invalid/pinned")
    assert calls == ["https://example.invalid/pinned"] * build.DOWNLOAD_ATTEMPTS


MODULE = "lib/modules/6.6.0/kernel/fs/9p/9p.ko"


def _release(
    *, modules_files: list[str] | None = None, schema: int = 2
) -> tuple[dict[str, bytes], dict]:
    """A cage-kernel release as `{asset: bytes}`, and pins that admit it."""
    from _lcow_initrd import Entry, cpio_newc, gzip_bytes

    archive = gzip_bytes(
        cpio_newc({"lib": Entry.directory(), MODULE: Entry.file(b"ko", executable=False)})
    )
    digest = hashlib.sha256(archive).hexdigest()
    manifest = {
        "schema_version": schema,
        "version": "9.9.9",
        "platforms": {
            "windows": {
                "content": {"sha256": "c" * 64, "size": 1},
                "source": {"name": "kernel", "version": "6.6.0"},
                "modules": {
                    "name": "windows-amd64-lcow-modules.cpio.gz",
                    "sha256": digest,
                    "size": len(archive),
                    "files": [MODULE] if modules_files is None else modules_files,
                },
            }
        },
    }
    manifest_bytes = json.dumps(manifest).encode()
    assets = {"manifest.json": manifest_bytes, "windows-amd64-lcow-modules.cpio.gz": archive}
    sums = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(assets.items())
    ).encode()
    assets["SHA256SUMS"] = sums
    pins = {
        "cage_kernel": {
            "repository": "manneskjur/cage-kernel",
            "version": "9.9.9",
            "sha256sums_sha256": hashlib.sha256(sums).hexdigest(),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        }
    }
    return assets, pins


def _serve(module, monkeypatch: pytest.MonkeyPatch, assets: dict[str, bytes]) -> None:
    monkeypatch.setattr(module, "_fetch", lambda url: assets[url.rsplit("/", 1)[1]])


@pytest.mark.parametrize("schema", [2, 3])
def test_the_kernel_release_is_admitted_through_its_pinned_digests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, schema: int
) -> None:
    module = _load()
    assets, pins = _release(schema=schema)
    _serve(module, monkeypatch, assets)
    entry, archive = module.kernel_release(pins, tmp_path)
    assert archive == assets["windows-amd64-lcow-modules.cpio.gz"]
    modules = module._module_entries(archive, entry["modules"]["files"])
    assert MODULE in modules


@pytest.mark.parametrize(
    "tampered", ["SHA256SUMS", "manifest.json", "windows-amd64-lcow-modules.cpio.gz"]
)
def test_a_tampered_release_asset_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tampered: str
) -> None:
    module = _load()
    assets, pins = _release()
    assets[tampered] += b"\n"
    _serve(module, monkeypatch, assets)
    with pytest.raises(RuntimeError, match="checksum mismatch|does not list|disagree"):
        module.kernel_release(pins, tmp_path)


def test_a_modules_archive_holding_other_files_than_its_release_lists_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load()
    assets, pins = _release(modules_files=[MODULE, "lib/modules/6.6.0/kernel/other.ko"])
    _serve(module, monkeypatch, assets)
    entry, archive = module.kernel_release(pins, tmp_path)
    with pytest.raises(RuntimeError, match="exactly the modules"):
        module._module_entries(archive, entry["modules"]["files"])


def test_an_unknown_kernel_release_schema_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load()
    assets, pins = _release(schema=4)
    _serve(module, monkeypatch, assets)
    with pytest.raises(RuntimeError, match="schema 4"):
        module.kernel_release(pins, tmp_path)


# -- Provenance ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"Package": "runc", "Version": "1.1.5+ds1-1+deb12u1"}, ("runc", "1.1.5+ds1-1+deb12u1")),
        (
            {
                "Package": "busybox-static",
                "Version": "1:1.35.0-4+deb12u1+b1",
                "Source": "busybox",
            },
            ("busybox", "1:1.35.0-4+deb12u1"),
        ),
        (
            {
                "Package": "libkmod2",
                "Version": "30+20221128-1+b2",
                "Source": "kmod (30+20221128-1)",
            },
            ("kmod", "30+20221128-1"),
        ),
    ],
)
def test_the_source_package_follows_debian_rules(fields: dict, expected: tuple) -> None:
    assert _load().debian_source(fields) == expected


def test_control_fields_join_continuation_lines() -> None:
    fields = _load().control_fields(
        "Package: runc\nBuilt-Using: golang-1.19 (= 1.19.8-2),\n golang-x (= 1.0-1)\n"
    )
    assert _load().built_using(fields["Built-Using"]) == [
        ("golang-1.19", "1.19.8-2"),
        ("golang-x", "1.0-1"),
    ]


def test_a_malformed_built_using_entry_is_refused() -> None:
    with pytest.raises(ValueError, match="Built-Using"):
        _load().built_using("golang-1.19 (>= 1.19)")


def test_dpkg_ownership_is_read_for_the_asked_paths_only() -> None:
    module = _load()
    search = (
        "diversion by x from: /lib/x86_64-linux-gnu/libc.so.6\n"
        "libc6:amd64: /lib/x86_64-linux-gnu/libc.so.6\n"
        "libc6-dev:amd64: /usr/lib/x86_64-linux-gnu/libc.so\n"
    )
    paths = ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6"]
    assert module.dpkg_owner(paths, search) == "libc6:amd64"
    assert module.dpkg_owner(["/nowhere"], search) is None
    with pytest.raises(RuntimeError, match="several packages"):
        module.dpkg_owner(paths, search + "other:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\n")


def _guest(module, tmp_path: Path):
    guest = module.Guest(tmp_path / "metadata")
    guest.component(module.HCSSHIM, {"kind": "git", "url": "u", "commit": "c" * 40})
    return guest


def test_a_file_without_a_known_origin_cannot_be_added(tmp_path: Path) -> None:
    module = _load()
    guest = _guest(module, tmp_path)
    with pytest.raises(RuntimeError, match="no determinable origin"):
        guest.add_file("/bin/x", b"x", executable=True, origins=[])
    with pytest.raises(RuntimeError, match="no determinable origin"):
        guest.add_file("/bin/x", b"x", executable=True, origins=["debian:unknown=1"])


def test_a_file_outside_every_pinned_package_has_no_origin(tmp_path: Path) -> None:
    module = _load()
    guest = _guest(module, tmp_path)
    guest.prefix = tmp_path / "debian"
    with pytest.raises(RuntimeError, match="in no pinned Debian package"):
        guest.origins_of(guest.prefix / "usr/sbin/stray")


def test_an_unattributed_tree_file_fails_the_components_check(tmp_path: Path) -> None:
    from _lcow_initrd import Entry, components_problems

    module = _load()
    guest = _guest(module, tmp_path)
    guest.add_file("/init", b"init", executable=True, origins=[module.HCSSHIM])
    guest.tree["bin/stray"] = Entry.file(b"?", executable=True)
    guest.tree["bin/sh"] = Entry.symlink("busybox")
    members = {name: (entry.mode, entry.data) for name, entry in guest.tree.items()}
    errors = components_problems(guest.record(), members)
    assert "/bin/stray is attributed to no component" in errors
    assert "symbolic link /bin/sh resolves to no attributed file" in errors


def test_debian_packages_record_their_source_notice_and_built_using(tmp_path: Path) -> None:
    module = _load()
    guest = _guest(module, tmp_path)
    copyright_file = tmp_path / "copyright"
    copyright_file.write_text("License: GPL-2\n", encoding="utf-8")
    fields = {
        "Package": "busybox-static",
        "Version": "1:1.35.0-4+b1",
        "Source": "busybox",
        "Built-Using": "glibc (= 2.36-9)",
    }
    origins = guest._debian("busybox-static", fields, copyright_file)
    assert origins == ["debian:busybox=1:1.35.0-4", "debian:glibc=2.36-9"]
    busybox = guest.components["debian:busybox=1:1.35.0-4"]
    assert busybox["notices"] == [
        "metadata/notices/debian/busybox_1.35.0-4/busybox-static.copyright"
    ]
    assert (tmp_path / busybox["notices"][0]).read_text(encoding="utf-8") == "License: GPL-2\n"
    with pytest.raises(RuntimeError, match="no copyright notice"):
        guest._debian("runc", {"Package": "runc", "Version": "1"}, tmp_path / "absent")


def _fake_go(tmp_path: Path, stdout: str, stderr: str = "") -> dict[str, str]:
    """A `go` that answers `go version FILE` as the toolchain would; returns its environment."""
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "stdout").write_text(stdout, encoding="utf-8")
    (bin_dir / "stderr").write_text(stderr, encoding="utf-8")
    go = bin_dir / "go"
    go.write_text(
        f"#!/bin/sh\ncat '{bin_dir}/stdout'\ncat '{bin_dir}/stderr' >&2\n", encoding="utf-8"
    )
    go.chmod(0o755)
    return {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}


def test_go_version_decides_whether_an_hcsshim_binary_carries_the_go_runtime(
    tmp_path: Path,
) -> None:
    module = _load()
    guest = _guest(module, tmp_path)
    guest.components[module.GO] = {"kind": "go", "version": "go1.26.11"}
    binary = tmp_path / "gcs"
    binary.write_bytes(b"\x7fELF")
    # `go version` exits 0 for a file that is not a Go executable: stdout is empty.
    guest.env = _fake_go(
        tmp_path,
        "",
        f"{binary}: could not read Go build info from {binary}: not a Go executable\n",
    )
    assert guest.hcsshim_origins(binary, go=False) == [module.HCSSHIM]
    with pytest.raises(
        RuntimeError, match="is not a Go executable, but hcsshim builds it with Go"
    ):
        guest.hcsshim_origins(binary, go=True)
    guest.env = _fake_go(tmp_path, f"{binary}: go1.26.11\n")
    assert guest.hcsshim_origins(binary, go=True) == [module.HCSSHIM, module.GO]
    with pytest.raises(RuntimeError, match="is a Go executable, but hcsshim builds it from C"):
        guest.hcsshim_origins(binary, go=False)
    guest.env = _fake_go(tmp_path, f"{binary}: go1.25.0\n")
    with pytest.raises(RuntimeError, match="not the recorded Go"):
        guest.hcsshim_origins(binary, go=True)
    guest.env = _fake_go(tmp_path, "", "go: unexpected failure\n")
    with pytest.raises(RuntimeError, match="is not understood"):
        guest.hcsshim_origins(binary, go=False)

"""The Windows LCOW initrd verifier admits exactly the initrd payload."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from _lcow_initrd import Entry
from lcow_initrd_payload import (
    RUNC_NOTICE,
    components_record,
    guest_entries,
    kernel_record,
    make_payload,
)

_SCRIPT = Path(__file__).resolve().parents[1] / "windows" / "verify-lcow-initrd.py"


def _verify():
    spec = importlib.util.spec_from_file_location("cage_init_test_verify_lcow_initrd", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify


def test_complete_payload_is_admitted(tmp_path: Path) -> None:
    assert _verify()(make_payload(tmp_path / "payload")) == []


# A kernel never ships in this artifact: it is cage-kernel's.
@pytest.mark.parametrize("extra", ["kernel", "LinuxBootFiles/initrd.img", "notes.txt"])
def test_unexpected_files_are_refused(tmp_path: Path, extra: str) -> None:
    payload = make_payload(tmp_path / "payload")
    (payload / extra).parent.mkdir(parents=True, exist_ok=True)
    (payload / extra).write_bytes(b"stale")
    errors = _verify()(payload)
    assert any("payload files differ" in error and extra in error for error in errors)


@pytest.mark.parametrize(
    "missing",
    ["initrd.img", "metadata/inputs.json", "metadata/kernel.json", "metadata/components.json"],
)
def test_missing_files_are_refused(tmp_path: Path, missing: str) -> None:
    payload = make_payload(tmp_path / "payload")
    (payload / missing).unlink()
    errors = _verify()(payload)
    assert any("payload files differ" in error and missing in error for error in errors)


def test_the_kernel_record_must_name_its_kernel_and_modules(tmp_path: Path) -> None:
    record = kernel_record()
    del record["kernel_sha256"]
    assert _verify()(make_payload(tmp_path / "a", record=record))
    record = kernel_record()
    record["module_files"] = "lib/modules"
    assert _verify()(make_payload(tmp_path / "b", record=record))


def test_the_kernels_modules_must_be_in_the_initrd(tmp_path: Path) -> None:
    module = "lib/modules/6.6.0/kernel/fs/9p/9p.ko"
    entries = guest_entries()
    entries["init"] = Entry.file(b"/lib/modules failed to load module", executable=True)
    entries["usr/lib/libkmod.so.2"] = Entry.file(b"kmod", executable=True)
    record = kernel_record(module_files=[module])
    errors = _verify()(make_payload(tmp_path / "a", initrd=entries, record=record))
    assert any(module in error for error in errors)
    entries[module] = Entry.file(b"ko", executable=False)
    assert _verify()(make_payload(tmp_path / "b", initrd=entries, record=record)) == []


def test_initrd_problems_are_reported(tmp_path: Path) -> None:
    entries = guest_entries()
    del entries["sbin/runc"]
    errors = _verify()(make_payload(tmp_path / "payload", initrd=entries))
    assert "initrd lacks runc" in errors


def test_non_archive_initrd_is_refused(tmp_path: Path) -> None:
    payload = make_payload(tmp_path / "payload")
    (payload / "initrd.img").write_bytes(b"not gzip")
    errors = _verify()(payload)
    assert any(error.startswith("initrd is not a gzip cpio archive") for error in errors)


def test_a_declared_notice_must_be_present(tmp_path: Path) -> None:
    payload = make_payload(tmp_path / "payload")
    (payload / RUNC_NOTICE).unlink()
    errors = _verify()(payload)
    assert any("payload files differ" in error and RUNC_NOTICE in error for error in errors)


def test_an_undeclared_notice_is_refused(tmp_path: Path) -> None:
    payload = make_payload(tmp_path / "payload")
    stray = payload / "metadata/notices/debian/stray/stray.copyright"
    stray.parent.mkdir(parents=True)
    stray.write_text("?", encoding="utf-8")
    errors = _verify()(payload)
    assert any("unexpected" in error and "stray.copyright" in error for error in errors)


def test_every_initrd_file_must_be_attributed(tmp_path: Path) -> None:
    entries = guest_entries()
    components = components_record(entries)
    entries["sbin/unattributed"] = Entry.file(b"?", executable=True)
    errors = _verify()(make_payload(tmp_path / "payload", initrd=entries, components=components))
    assert "/sbin/unattributed is attributed to no component" in errors


def test_an_attribution_must_name_a_recorded_component(tmp_path: Path) -> None:
    components = components_record(guest_entries())
    components["files"]["init"] = ["debian:unknown=1"]
    errors = _verify()(make_payload(tmp_path / "payload", components=components))
    assert any("/init names no known component" in error for error in errors)


def test_a_malformed_component_is_refused(tmp_path: Path) -> None:
    components = components_record(guest_entries())
    del components["components"]["hcsshim"]["commit"]
    errors = _verify()(make_payload(tmp_path / "payload", components=components))
    assert any("component hcsshim is malformed" in error for error in errors)

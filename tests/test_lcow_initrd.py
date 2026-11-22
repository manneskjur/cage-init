"""The stdlib cpio/initrd module the LCOW initrd build and verifier share."""

from __future__ import annotations

import gzip
import stat
from pathlib import Path

import pytest
from _lcow_initrd import (
    CPIO_NEWC_HEADER_LEN,
    Entry,
    cpio_newc,
    gzip_bytes,
    iter_members,
    problems,
    read_initrd,
)
from lcow_initrd_payload import guest_entries

MODULES = {
    "9p": (
        "fs/9p/9p.ko",
        "fs/netfs/netfs.ko",
        "net/9p/9pnet.ko",
        "net/9p/9pnet_fd.ko",
        "net/9p/9pnet_virtio.ko",
    ),
    "nft": ("net/netfilter/nf_tables.ko", "net/netfilter/nft_ct.ko"),
    "cifs": ("fs/smb/client/cifs.ko",),
}
MODULE_FILES = sorted(
    f"lib/modules/6.6.0/kernel/{path}" for paths in MODULES.values() for path in paths
)
KMOD_INIT = b"... /lib/modules ... failed to load module ..."


def _members(entries: dict[str, Entry]) -> dict[str, tuple[int, bytes]]:
    return {name: (entry.mode, entry.data) for name, entry in entries.items()}


def _modular_guest(*, without: frozenset[str] = frozenset()) -> dict[str, Entry]:
    entries = guest_entries()
    entries["init"] = Entry.file(KMOD_INIT, executable=True)
    entries["usr/lib/x86_64-linux-gnu/libkmod.so.2"] = Entry.file(b"kmod", executable=True)
    for feature, paths in MODULES.items():
        if feature in without:
            continue
        for path in paths:
            entries[f"lib/modules/6.6.0/kernel/{path}"] = Entry.file(b"ko", executable=False)
    return entries


def test_equal_trees_serialise_to_equal_bytes_regardless_of_insertion_order() -> None:
    entries = guest_entries()
    reordered = dict(reversed(list(entries.items())))
    assert cpio_newc(entries) == cpio_newc(reordered)
    assert gzip_bytes(cpio_newc(entries)) == gzip_bytes(cpio_newc(reordered))


def test_gzip_carries_no_timestamp() -> None:
    first = gzip_bytes(b"payload")
    assert first[4:8] == b"\0\0\0\0"
    assert gzip.decompress(first) == b"payload"
    assert gzip_bytes(b"payload") == first


def test_members_round_trip_with_modes_and_data() -> None:
    entries = {
        **guest_entries(),
        "bin/sh": Entry.symlink("busybox"),
        "etc": Entry.directory(),
        "etc/odd-length": Entry.file(b"abc", executable=False),
    }
    decoded = {name: (mode, data) for name, mode, data in iter_members(cpio_newc(entries))}
    assert decoded == _members(entries)
    assert stat.S_ISLNK(decoded["bin/sh"][0])
    assert decoded["bin/sh"][1] == b"busybox"


def test_concatenated_archives_are_followed_and_later_members_win(tmp_path: Path) -> None:
    first = cpio_newc({"init": Entry.file(b"old", executable=True)})
    second = cpio_newc({"init": Entry.file(b"new", executable=True), "run": Entry.directory()})
    initrd = tmp_path / "initrd.img"
    initrd.write_bytes(gzip_bytes(first + second))
    members = read_initrd(initrd)
    assert members["init"][1] == b"new"
    assert "run" in members


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"not a cpio archive" * 10, id="bad-magic"),
        pytest.param(b"070701" + b"0" * 10, id="short-header"),
    ],
)
def test_malformed_headers_are_refused(payload: bytes) -> None:
    with pytest.raises(ValueError, match="invalid cpio newc header"):
        list(iter_members(payload))


def test_truncated_member_data_is_refused() -> None:
    archive = cpio_newc({"init": Entry.file(b"x" * 64, executable=True)}, trailer=False)
    with pytest.raises(ValueError, match="extends beyond the archive"):
        list(iter_members(archive[: CPIO_NEWC_HEADER_LEN + 8 + 16]))


def test_name_beyond_the_archive_is_refused() -> None:
    archive = cpio_newc({"a-long-member-name": Entry.directory()}, trailer=False)
    with pytest.raises(ValueError, match="invalid cpio entry name"):
        list(iter_members(archive[: CPIO_NEWC_HEADER_LEN + 4]))


@pytest.mark.parametrize("path", ["", "/init", "lib/../init"])
def test_unsafe_paths_are_never_written(path: str) -> None:
    with pytest.raises(ValueError, match="unsafe initrd path"):
        cpio_newc({path: Entry.directory()})


def test_complete_guest_for_a_builtin_driver_kernel_has_no_problems() -> None:
    assert problems(_members(guest_entries()), []) == []


@pytest.mark.parametrize(
    ("member", "replacement", "problem"),
    [
        ("run", None, "/run directory"),
        ("run", Entry.file(b"", executable=False), "/run directory"),
        ("sbin/mkfs.ext4", None, "mkfs.ext4"),
        ("sbin/runc", None, "runc"),
        ("init", None, "init"),
        ("init", Entry.directory(), "init"),
    ],
)
def test_each_missing_guest_essential_is_named(
    member: str, replacement: Entry | None, problem: str
) -> None:
    entries = guest_entries()
    if replacement is None:
        del entries[member]
    else:
        entries[member] = replacement
    assert problem in problems(_members(entries), [])


def test_alternative_tool_locations_are_accepted() -> None:
    entries = guest_entries()
    entries["usr/bin/runc"] = entries.pop("sbin/runc")
    entries["usr/sbin/mkfs.ext4"] = entries.pop("sbin/mkfs.ext4")
    assert problems(_members(entries), []) == []


def test_a_guest_holding_its_kernels_modules_has_no_problems() -> None:
    assert problems(_members(_modular_guest()), MODULE_FILES) == []


def test_kernel_modules_require_kmod_init_and_libkmod() -> None:
    entries = _modular_guest()
    entries["init"] = Entry.file(b"init without module loading", executable=True)
    del entries["usr/lib/x86_64-linux-gnu/libkmod.so.2"]
    found = problems(_members(entries), MODULE_FILES)
    assert "kernel-module loading in init (hcsshim KMOD=1)" in found
    assert "libkmod runtime library" in found


@pytest.mark.parametrize("feature", sorted(MODULES))
def test_each_listed_module_must_be_present(feature: str) -> None:
    found = problems(_members(_modular_guest(without=frozenset({feature}))), MODULE_FILES)
    assert any(item.startswith("kernel modules") and MODULES[feature][0] in item for item in found)


def test_a_kernel_without_modules_needs_no_module_loading() -> None:
    entries = guest_entries()
    assert problems(_members(entries), []) == []
    assert "libkmod runtime library" in problems(_members(entries), MODULE_FILES)

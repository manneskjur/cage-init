![Cage Init](cage-init.jpg)
# Cage Init

Cage Init builds guest filesystems for macOS on Apple silicon and Windows LCOW on amd64. The macOS build produces an ext4 image containing Apple's Containerization guest tools. The Windows build produces a compressed cpio initrd containing hcsshim guest tools and modules for its matching kernel.

## Releases and verification

The [releases page](https://github.com/manneskjur/cage-init/releases) lists available downloads. Select the filesystem for your architecture. Verify its SHA-256 against the release checksum file and your application's trusted pin. For Windows, use the kernel identified in the release manifest.

## Build from source

For macOS, install uv and Apple's container CLI on Apple silicon and start the container service.

```sh
uv run --script scripts/cage_init.py macos create
uv run --script scripts/cage_init.py macos verify
uv run --script scripts/cage_init.py test
```

To build the Windows guest on amd64 Linux, use the pinned kernel and package inputs in `windows/lcow-initrd.toml`. The recipe needs the Go toolchain, C build tools, Git, dpkg-deb, and ext4 utilities.

```sh
python3 windows/build-lcow-initrd.py --output build/lcow
python3 windows/verify-lcow-initrd.py --help
```

## Licensing and contributions

Independently authored build tooling and documentation are [MIT licensed](LICENSE). Upstream components and their patches retain their applicable licenses. Every release carries `source-and-notices.tar`: the corresponding source, license notices and build scripts for each component of its filesystems, listed in `SHA256SUMS` and `manifest.json`.

Public pull requests are welcome. For security reports, follow the [private reporting instructions](SECURITY.md).

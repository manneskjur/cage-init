#!/bin/sh
# The `SWIFT` that `macos create` gives upstream's `make init`, inside its Linux
# dev image. Every call passes straight through to `swift`, except vminitd's
# package build: that links each product the initfs installs separately, with
# lld writing a link map of exactly that link, and records the SHA-256 of the
# executable the link wrote. Those maps are the link evidence `components.json`
# records; `macos create` binds each to the executable read back out of the
# built initfs.ext4.
#
# CAGE_INIT_LINK_PACKAGE   the vminitd package directory, as the container sees it
# CAGE_INIT_LINK_PRODUCTS  the products to link, separated by spaces
# CAGE_INIT_LINK_EVIDENCE  where to write bin-path (SwiftPM's build directory),
#                          <product>.map and <product>.sha256
set -eu

package=${CAGE_INIT_LINK_PACKAGE:?}
products=${CAGE_INIT_LINK_PRODUCTS:?}
evidence=${CAGE_INIT_LINK_EVIDENCE:?}

if [ "${1-}" != build ] || [ "$(pwd -P)" != "$package" ]; then
    exec swift "$@"
fi
for argument in "$@"; do
    case $argument in
    --show-bin-path | --product | --product=* | --target | --target=*) exec swift "$@" ;;
    esac
done

bin=$(swift "$@" --show-bin-path)
mkdir -p "$evidence"
printf '%s\n' "$bin" >"$evidence/bin-path"
for product in $products; do
    # No map and no executable before the link: whatever is there after it,
    # this link wrote.
    rm -f "$evidence/$product.map" "$evidence/$product.sha256" "$bin/$product"
    swift "$@" --product "$product" -Xlinker "-Map=$evidence/$product.map"
    if [ ! -s "$evidence/$product.map" ] || [ ! -f "$bin/$product" ]; then
        echo "swift-link-evidence: linking $product wrote no map or no executable" >&2
        exit 1
    fi
    sha256sum "$bin/$product" | cut -d ' ' -f 1 >"$evidence/$product.sha256"
done

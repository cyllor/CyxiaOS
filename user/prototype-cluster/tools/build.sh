#!/bin/sh
set -eu
# Run from any directory. ARM keeps its standard FP/SIMD target for ring.
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$repo"
arch=aarch64
if [ "$#" -gt 0 ]; then
    [ "$#" -eq 2 ] && [ "$1" = '--arch' ] || { echo 'usage: build.sh [--arch aarch64|x86_64]' >&2; exit 2; }
    arch=$2
fi
case "$arch" in
    aarch64)
        target=aarch64-unknown-none
        export CC_aarch64_unknown_none="${CC_aarch64_unknown_none:-clang}"
        export CFLAGS_aarch64_unknown_none="${CFLAGS_aarch64_unknown_none:---target=aarch64-none-elf -ffreestanding -fno-stack-protector -mno-outline-atomics -DRING_CORE_NOSTDLIBINC}"
        export RUSTFLAGS='-C relocation-model=static -C code-model=large -C strip=debuginfo'
        ;;
    x86_64)
        target=x86_64-unknown-none
        export CC_x86_64_unknown_none="${CC_x86_64_unknown_none:-clang}"
        export CFLAGS_x86_64_unknown_none="${CFLAGS_x86_64_unknown_none:---target=x86_64-none-elf -ffreestanding -fno-stack-protector -mno-red-zone -DRING_CORE_NOSTDLIBINC}"
        export RUSTFLAGS='-C relocation-model=static -C code-model=small -C no-redzone=yes -C lto=off -C strip=debuginfo'
        ;;
    *) echo 'unsupported cluster user architecture' >&2; exit 2 ;;
esac
: "${CYXIA_CLUSTER_IDENTITY:?set to externally provisioned own node directory}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo/target}"
unset CARGO_ENCODED_RUSTFLAGS
exec "${CARGO:-cargo}" build --locked --offline --manifest-path user/prototype-cluster/Cargo.toml --target "$target" --release --features guest

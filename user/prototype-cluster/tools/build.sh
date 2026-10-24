#!/bin/sh
set -eu
# Run from any directory; standard FP/SIMD target is deliberate for ring.
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$repo"
: "${CYXIA_CLUSTER_IDENTITY:?set to externally provisioned own node directory}"
export CC_aarch64_unknown_none=clang
export CFLAGS_aarch64_unknown_none='--target=aarch64-none-elf -ffreestanding -fno-stack-protector -mno-outline-atomics -DRING_CORE_NOSTDLIBINC'
export CARGO_TARGET_DIR="$repo/target"
export RUSTFLAGS='-C relocation-model=static -C code-model=large'
exec /Users/robin/.cargo/bin/cargo build --locked --offline --manifest-path user/prototype-cluster/Cargo.toml --target aarch64-unknown-none --release --features guest

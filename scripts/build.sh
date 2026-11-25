#!/usr/bin/env bash
# Build the Latrix program for SBF and run the Mollusk tests. Run from the repo root (WSL / Linux).
#   bash scripts/build.sh                 mainnet build (vanity id) + tests
#   bash scripts/build.sh build           mainnet build only
#   CLUSTER=devnet bash scripts/build.sh  devnet build (devnet id) + tests
set -euo pipefail
# Platform tools pinned to v1.54 and SBPF arch v0 (dynamic syscalls), as the Privacy Rings SDK
# builds: spr-hasher 0.8 has no static-syscall table, and cargo-build-sbf 4.x defaults to v3.
source "$HOME/.cargo/env"
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
# Keep the (large) build directory on the Linux filesystem; the repo may live on a Windows drive.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.latrix-target}"
CLUSTER="${CLUSTER:-mainnet}"
FEATURES="bpf-entrypoint"
OUT="target/deploy"
if [ "$CLUSTER" = "devnet" ]; then FEATURES="bpf-entrypoint,devnet"; OUT="target/deploy-devnet"; fi
cargo build-sbf --tools-version v1.54 --arch v0 --manifest-path program/Cargo.toml --sbf-out-dir "$OUT" -- --features "$FEATURES"
ls -l "$OUT/latrix_program.so"
sha256sum "$OUT/latrix_program.so"
if [ "${1:-}" != "build" ]; then
  TEST_FEATURES=""; [ "$CLUSTER" = "devnet" ] && TEST_FEATURES="--features devnet"
  SBF_OUT_DIR="$PWD/$OUT" cargo test -p latrix-program $TEST_FEATURES --test latrix -- --nocapture
fi

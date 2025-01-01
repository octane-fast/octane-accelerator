#!/bin/bash
# build-jolt-prover.sh — Build jolt_prove with embedded preprocessing + guest ELF.
#
# This builds a self-contained jolt_prove binary that doesn't need cargo at runtime.
# Requires: Rust toolchain with riscv64imac target, cargo-jolt CLI.
#
# Run from octane-accelerator/ directory.

set -euo pipefail

ACCEL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
JOLT_DIR="$ACCEL_DIR/../jolt-zktls"
PROVE_DIR="$JOLT_DIR/prove"
PREPROCESS_DIR="$JOLT_DIR/preprocess"

echo "  Building jolt prover..."
cd "$PROVE_DIR"

# 1. Fetch dependencies (needed to get Jolt SDK checkout for patching)
echo "  → Fetching cargo dependencies..."
cargo fetch 2>&1 | tail -3

# 2. Patch Jolt SDK (adds set_elf/set_elf_compute_advice methods)
echo "  → Patching Jolt SDK..."
bash "$ACCEL_DIR/scripts/patch-jolt-sdk.sh"

# 3. Build guest ELF (RISC-V target)
echo "  → Building guest ELF..."
JOLT_PATH="${JOLT_PATH:-$(which jolt 2>/dev/null || echo jolt)}"
"$JOLT_PATH" build -p guest --backtrace off --stack-size 131072 --heap-size 262144 -- --release --target-dir /tmp/jolt-guest-targets --features guest 2>&1 | tail -5

GUEST_ELF="/tmp/jolt-guest-targets/guest-prove_decrypt/riscv64imac-unknown-none-elf/release/guest"
if [ ! -f "$GUEST_ELF" ]; then
    echo "  ❌ Guest ELF not found at $GUEST_ELF"
    exit 1
fi
GUEST_SIZE=$(wc -c < "$GUEST_ELF" | tr -d ' ')
echo "  → Guest ELF: ${GUEST_SIZE} bytes"

# 4. Generate preprocessing data
echo "  → Generating preprocessing data..."
mkdir -p "$PREPROCESS_DIR"
"$ACCEL_DIR/../jolt-zktls/prove/target/release/jolt_prove" --preprocess "$PREPROCESS_DIR" 2>&1 | tail -3 || \
cargo run --release --bin jolt_prove -- --preprocess "$PREPROCESS_DIR" 2>&1 | tail -3

# 5. Build jolt_prove with embedded data
echo "  → Building jolt_prove with embedded data..."
JOLT_PREPROCESS_DAT="$PREPROCESS_DIR/jolt_prover_preprocessing.dat" \
JOLT_GUEST_ELF="$GUEST_ELF" \
cargo build --release --bin jolt_prove 2>&1 | tail -3

JOLT_PROVE="$PROVE_DIR/target/release/jolt_prove"
if [ ! -f "$JOLT_PROVE" ]; then
    echo "  ❌ jolt_prove not found at $JOLT_PROVE"
    exit 1
fi
PROVE_SIZE=$(wc -c < "$JOLT_PROVE" | tr -d ' ')
echo "  → jolt_prove: ${PROVE_SIZE} bytes (fully self-contained)"
echo "  Done."

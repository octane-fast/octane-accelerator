#!/bin/bash
# patch-jolt-sdk.sh — Apply the set_elf/set_elf_compute_advice patch to Jolt SDK.
#
# The Jolt SDK's Program struct doesn't have methods to pre-set the ELF path,
# which we need to embed the guest binary and skip cargo at runtime.
# This script patches the cargo git checkout after `cargo fetch`.
#
# Run from the prove/ directory of jolt-zktls.

set -euo pipefail

PROVE_DIR="$(cd "$(dirname "$0")/../.." && pwd)/prove"
JOLT_CHECKOUT=$(find ~/.cargo/git/checkouts -path "*/jolt-bc4943ecdf5f6930/*/jolt-core/src/host/program.rs" 2>/dev/null | head -1)

if [ -z "$JOLT_CHECKOUT" ]; then
    echo "  → Jolt SDK checkout not found. Run 'cargo fetch' first."
    exit 1
fi

echo "  → Patching Jolt SDK at: $JOLT_CHECKOUT"

# Check if already patched
if grep -q "set_elf" "$JOLT_CHECKOUT"; then
    echo "  → Already patched."
    exit 0
fi

# Add set_elf and set_elf_compute_advice methods after set_func
sed -i.bak '/pub fn set_func(&mut self, func: &str) {/a\
\

    /// Pre-set the ELF path to skip the build step.\
    /// Use when the guest binary is pre-compiled and embedded.\
    pub fn set_elf(\&mut self, elf: PathBuf) {\
        self.elf = Some(elf);\
    }\
\
    /// Pre-set the compute_advice ELF path to skip the build step.\
    pub fn set_elf_compute_advice(\&mut self, elf: PathBuf) {\
        self.elf_compute_advice = Some(elf);\
    }' "$JOLT_CHECKOUT"

rm -f "${JOLT_CHECKOUT}.bak"
echo "  → Patched successfully."

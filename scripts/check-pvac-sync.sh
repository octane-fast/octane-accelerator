#!/usr/bin/env bash
# check-pvac-sync.sh — Verify vendored PVAC headers match the canonical webcli copy.
#
# Usage:
#   ./scripts/check-pvac-sync.sh [WEBCLI_PATH]
#
# Defaults to ../webcli relative to the repo root.
# Exit 0 = all files match (or only expected diffs).
# Exit 1 = unexpected differences found.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WEBCLI="${1:-$REPO_ROOT/../webcli}"

if [[ ! -d "$WEBCLI/pvac/include" ]]; then
    echo "ERROR: webcli pvac not found at $WEBCLI/pvac/include" >&2
    echo "Usage: $0 [path/to/webcli]" >&2
    exit 1
fi

WEBCLI_PVAC="$WEBCLI/pvac"
ACCEL_PVAC="$REPO_ROOT/pvac"
WASM_PVAC="$REPO_ROOT/../octra/wallet/extension/src/lib/pvac-wasm/vendor/pvac/pvac"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

ok=0
warn=0
fail=0
bump() { eval "$1=$(( ${!1} + 1 ))"; }

check() {
    local label="$1" src="$2" dst="$3"
    if [[ ! -f "$dst" ]]; then
        echo -e "  ${RED}MISSING${NC} $label"
        bump fail
        return
    fi
    if diff -q "$src" "$dst" > /dev/null 2>&1; then
        echo -e "  ${GREEN}OK${NC}      $label"
        bump ok
    else
        echo -e "  ${RED}DIFFER${NC}  $label"
        bump fail
    fi
}

check_expected() {
    local label="$1" src="$2" dst="$3" reason="$4"
    if [[ ! -f "$dst" ]]; then
        echo -e "  ${RED}MISSING${NC} $label"
        bump fail
        return
    fi
    if diff -q "$src" "$dst" > /dev/null 2>&1; then
        echo -e "  ${GREEN}OK${NC}      $label"
        bump ok
    else
        echo -e "  ${YELLOW}SKIP${NC}    $label ($reason)"
        bump warn
    fi
}

# ---- Accelerator headers ----
echo ""
echo "=== Accelerator pvac/include vs Webcli ==="
INCLUDES=(
    "core/types.hpp"
    "core/pvac_compress.hpp"
    "core/field.hpp"
    "core/hash.hpp"
    "core/random.hpp"
    "core/seedable_rng.hpp"
    "core/ct_safe.hpp"
    "core/bitvec.hpp"
    "core/config.hpp"
    "ops/encrypt.hpp"
    "ops/decrypt.hpp"
    "ops/verify_zero_circuit.hpp"
    "ops/verify_zero.hpp"
    "ops/range_proof.hpp"
    "ops/arithmetic.hpp"
    "ops/commit.hpp"
    "ops/recrypt.hpp"
    "crypto/keygen.hpp"
    "crypto/ristretto255.hpp"
    "crypto/lpn.hpp"
    "crypto/matrix.hpp"
    "crypto/toeplitz.hpp"
    "crypto/bulletproofs/generators.hpp"
    "crypto/bulletproofs/inner_product.hpp"
    "crypto/bulletproofs/r1cs_verifier.hpp"
    "crypto/bulletproofs/r1cs.hpp"
    "crypto/bulletproofs/r1cs_prover.hpp"
    "crypto/bulletproofs/r1cs_types.hpp"
    "crypto/bulletproofs/gadgets.hpp"
    "crypto/bulletproofs/transcript.hpp"
)

for f in "${INCLUDES[@]}"; do
    src="$WEBCLI_PVAC/include/pvac/$f"
    dst="$ACCEL_PVAC/include/pvac/$f"
    case "$f" in
        core/random.hpp)
            check_expected "$f" "$src" "$dst" "Windows NOMINMAX guard" ;;
        crypto/bulletproofs/r1cs_prover.hpp)
            check_expected "$f" "$src" "$dst" "GPU IPA fallback path" ;;
        crypto/bulletproofs/transcript.hpp)
            check_expected "$f" "$src" "$dst" "GPU state accessor" ;;
        *)
            check "$f" "$src" "$dst" ;;
    esac
done

echo ""
echo "=== Accelerator C API vs Webcli ==="
check "pvac_serialize.hpp" "$WEBCLI_PVAC/pvac_serialize.hpp" "$ACCEL_PVAC/pvac_serialize.hpp"
check "pvac_c_api.h"       "$WEBCLI_PVAC/pvac_c_api.h"       "$ACCEL_PVAC/pvac_c_api.h"
check_expected "pvac_c_api.cpp" "$WEBCLI_PVAC/pvac_c_api.cpp" "$ACCEL_PVAC/pvac_c_api.cpp" "include path + error handling"

# ---- Extension WASM vendor ----
echo ""
echo "=== Extension WASM vendor vs Webcli ==="
if [[ -d "$WASM_PVAC" ]]; then
    for f in "${INCLUDES[@]}"; do
        src="$WEBCLI_PVAC/include/pvac/$f"
        dst="$WASM_PVAC/$f"
        [[ ! -f "$dst" ]] && continue  # WASM doesn't need all files
        case "$f" in
            crypto/lpn.hpp)
                check_expected "$f" "$src" "$dst" "soft AES patch for WASM" ;;
            *)
                check "$f" "$src" "$dst" ;;
        esac
    done

    echo ""
    echo "=== Extension WASM src vs Webcli ==="
    WASM_SRC="$REPO_ROOT/../octra/wallet/extension/src/lib/pvac-wasm/src"
    check_expected "pvac_serialize.hpp" "$WEBCLI_PVAC/pvac_serialize.hpp" "$WASM_SRC/pvac_serialize.hpp" "WASM custom header"
    check_expected "pvac_c_api.cpp"     "$WEBCLI_PVAC/pvac_c_api.cpp"     "$WASM_SRC/pvac_c_api.cpp"     "WASM custom bindings"
else
    echo -e "  ${YELLOW}SKIP${NC}    WASM vendor dir not found at $WASM_PVAC"
    bump warn
fi

# ---- Accelerator-only files ----
echo ""
echo "=== Accelerator-only files (expected, not in webcli) ==="
for f in "crypto/bulletproofs/cuda_ipa.hpp" "crypto/bulletproofs/cuda_msm.hpp"; do
    if [[ -f "$ACCEL_PVAC/include/pvac/$f" ]]; then
        echo -e "  ${GREEN}EXISTS${NC}  $f (GPU acceleration)"
    fi
done

# ---- Summary ----
echo ""
echo "=============================="
echo -e "  ${GREEN}OK${NC}: $ok  ${YELLOW}Expected diffs${NC}: $warn  ${RED}Unexpected${NC}: $fail"
echo "=============================="
echo ""

if [[ $fail -gt 0 ]]; then
    echo -e "${RED}FAILED${NC} — $fail file(s) have unexpected differences."
    echo "Run: diff <webcli>/pvac/include/pvac/<file> <this-repo>/pvac/include/pvac/<file>"
    exit 1
else
    echo -e "${GREEN}PASSED${NC} — All cryptographic PVAC files in sync."
    exit 0
fi

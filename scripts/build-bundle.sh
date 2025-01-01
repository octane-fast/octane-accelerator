#!/bin/bash
# build-bundle.sh — Bundle the TLS recorder + Node.js runtime for embedding.
# Run from octane-accelerator/ directory.
# Output: include/tls_recorder_bundle.h
#
# The bundle contains:
#   jolt-zktls/        — TS recorder source + node_modules
#   node/              — Platform-specific Node.js binary
#
# Pass NODE_DIST_URL to override the Node.js download URL for cross-compilation.

set -euo pipefail

ACCEL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
JOLT_DIR="$ACCEL_DIR/../jolt-zktls"
HEADER="$ACCEL_DIR/include/tls_recorder_bundle.h"
NODE_VERSION="${NODE_VERSION:-v22.16.0}"

# Auto-detect platform for Node.js download
detect_node_url() {
    local arch=$(uname -m)
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$os-$arch" in
        darwin-arm64)       echo "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-darwin-arm64.tar.gz" ;;
        darwin-x86_64)      echo "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-darwin-x64.tar.gz" ;;
        linux-x86_64)       echo "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.gz" ;;
        linux-aarch64)      echo "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-arm64.tar.gz" ;;
        mingw64_nt*-x86_64) echo "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-win-x64.zip" ;;
        msys_nt*-x86_64)    echo "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-win-x64.zip" ;;
        *) echo "Unsupported platform: $os-$arch" >&2; exit 1 ;;
    esac
}

NODE_DIST_URL="${NODE_DIST_URL:-$(detect_node_url)}"

echo "  Building TLS recorder bundle..."
echo "  Node.js: $NODE_DIST_URL"
cd "$JOLT_DIR"

# Clean staging
mkdir -p dist "$ACCEL_DIR/include"
rm -rf dist/staging
mkdir -p dist/staging/jolt-zktls

# 1. Install deps (NO --ignore-scripts — tsx needs its postinstall)
echo "  → Installing TS deps..."
npm install 2>&1 | tail -3

# 2. Copy TS source files
echo "  → Staging source files..."
cp package.json package-lock.json dist/staging/jolt-zktls/
cp types.ts utils.ts dist/staging/jolt-zktls/
mkdir -p dist/staging/jolt-zktls/{record,decrypt,cli}
cp record/record.ts dist/staging/jolt-zktls/record/
cp decrypt/tls-decrypt.ts dist/staging/jolt-zktls/decrypt/
cp cli/prove-url.ts dist/staging/jolt-zktls/cli/

# 3. Copy node_modules (includes tsx with built dist/)
echo "  → Copying node_modules..."
cp -r node_modules dist/staging/jolt-zktls/

# Verify tsx is usable
if [ ! -f dist/staging/jolt-zktls/node_modules/tsx/dist/cli.mjs ]; then
    echo "  ❌ tsx/dist/cli.mjs not found — tsx postinstall may have failed"
    echo "  → Trying to build tsx manually..."
    cd dist/staging/jolt-zktls/node_modules/tsx && npm run build 2>/dev/null; cd "$JOLT_DIR"
fi

# 4. Download and stage Node.js binary
echo "  → Downloading Node.js..."
NODE_EXT="${NODE_DIST_URL##*.}"
NODE_DL="$JOLT_DIR/dist/node-download.$NODE_EXT"
if [ ! -f "$NODE_DL" ]; then
    curl -L --progress-bar "$NODE_DIST_URL" -o "$NODE_DL"
fi
mkdir -p dist/staging/node

if [ "$NODE_EXT" = "zip" ]; then
    # Windows: extract node.exe from zip
    unzip -o "$NODE_DL" -d dist/staging/_node_tmp >/dev/null 2>&1
    NODE_BIN=$(find dist/staging/_node_tmp -name "node.exe" -type f | head -1)
    if [ -n "$NODE_BIN" ]; then
        cp "$NODE_BIN" dist/staging/node/node.exe
    fi
    rm -rf dist/staging/_node_tmp
else
    # Unix: extract node binary from tarball
    tar -xzf "$NODE_DL" -C dist/staging/node --strip-components=2 --include='*/bin/node' 2>/dev/null || \
    tar -xzf "$NODE_DL" -C dist/staging/node --strip-components=2 --include='*/node.exe' 2>/dev/null || true
    if [ ! -f dist/staging/node/node ]; then
        mkdir -p dist/staging/_node_tmp
        tar -xzf "$NODE_DL" -C dist/staging/_node_tmp
        NODE_BIN=$(find dist/staging/_node_tmp -name node -type f | head -1)
        if [ -n "$NODE_BIN" ]; then
            cp "$NODE_BIN" dist/staging/node/node
        fi
        rm -rf dist/staging/_node_tmp
    fi
fi

if [ -f dist/staging/node/node ] || [ -f dist/staging/node/node.exe ]; then
    chmod +x dist/staging/node/node 2>/dev/null || true
    NODE_SIZE=$(wc -c < dist/staging/node/node 2>/dev/null || wc -c < dist/staging/node/node.exe 2>/dev/null || echo 0)
    echo "  → Node.js binary: ${NODE_SIZE} bytes"
else
    echo "  ⚠️  Node.js binary not found in archive — bundle will require system Node.js"
fi

# 5. Embed jolt_prove binary (pre-built with embedded preprocessing)
echo "  → Staging jolt_prove binary..."
JOLT_PROVE="$JOLT_DIR/prove/target/release/jolt_prove"
# Windows produces jolt_prove.exe
if [ ! -f "$JOLT_PROVE" ] && [ -f "$JOLT_PROVE.exe" ]; then
    JOLT_PROVE="$JOLT_PROVE.exe"
fi
if [ -f "$JOLT_PROVE" ]; then
    mkdir -p dist/staging/prove/target/release
    cp "$JOLT_PROVE" dist/staging/prove/target/release/
    chmod +x dist/staging/prove/target/release/jolt_prove* 2>/dev/null || true
    PROVE_FILE=$(ls dist/staging/prove/target/release/jolt_prove* 2>/dev/null | head -1)
    PROVE_SIZE=$(wc -c < "$PROVE_FILE" | tr -d ' ')
    echo "  → jolt_prove: ${PROVE_SIZE} bytes"
else
    echo "  ⚠️  jolt_prove not found at $JOLT_PROVE — build it first with:"
    echo "      cd $JOLT_DIR/prove && JOLT_PREPROCESS_DAT=$JOLT_DIR/preprocess/jolt_prover_preprocessing.dat cargo build --release --bin jolt_prove"
fi

# 6. Create tar.gz
echo "  → Creating tar.gz..."
tar -czf dist/tls-recorder-bundle.tar.gz -C dist/staging jolt-zktls node prove
SIZE=$(wc -c < dist/tls-recorder-bundle.tar.gz | tr -d ' ')
echo "  Bundle: ${SIZE} bytes ($(echo "scale=1; $SIZE/1048576" | bc)MB)"

# 7. Generate C header
echo "  → Generating C header..."
cd dist
xxd -i tls-recorder-bundle.tar.gz > /tmp/_bundle.h
cd "$JOLT_DIR"
sed 's/tls_recorder_bundle_tar_gz/tls_recorder_bundle/g' /tmp/_bundle.h > "$HEADER"
rm /tmp/_bundle.h
echo "  → $HEADER"
echo "  Done."

---
name: accelerator-release
description: 'Build, tag, and release the Octane Accelerator native desktop prover. Use when bumping versions, creating releases, troubleshooting CI builds, or updating the install site.'
---

# Octane Accelerator Release

## Overview

The Octane Accelerator is a native C++ desktop app (localhost:19876) that performs PVAC proving operations for the Octra wallet extension. Releases are fully automated via GitHub Actions — just push a semver tag.

## Repository

- **Repo**: `octane-fast/octane-accelerator`
- **Branch**: `main`
- **Current version**: check `git tag --sort=-v:refname | head -1`

## Release Process

### 1. Commit changes

```bash
cd ~/octane-accelerator
git add -A
git commit -m "Description of changes"
```

### 2. Tag with semver

```bash
git tag v0.X.Y -m "Short description"
```

Version conventions:
- **Patch** (v0.3.x → v0.3.y): bug fixes, minor tweaks
- **Minor** (v0.3.x → v0.4.0): new features, API changes, protocol updates
- **Major** (v0.x → v1.0): breaking changes to the wallet⇔accelerator protocol

### 3. Push

```bash
git push && git push --tags
```

This triggers `.github/workflows/release.yml` which:
1. Builds for 4 targets in parallel
2. Code-signs and notarizes macOS builds
3. Creates a GitHub Release with all artifacts
4. Deploys install scripts to GitHub Pages

## Build Targets

| Platform | Runner | Output | Notes |
|----------|--------|--------|-------|
| macOS arm64 | macos-14 | `.dmg` (signed + notarized) | Uses Homebrew libomp, static OpenSSL |
| macOS x64 | macos-14 (cross) | `.dmg` (signed + notarized) | No OpenMP, no relay TLS |
| Linux x64 | ubuntu-22.04 | `.tar.gz` | libomp-dev, libssl-dev |
| Windows x64 | windows-latest | `.zip` | MSYS2/MinGW64, windres for icon |

## Required Secrets

- `APPLE_CERTIFICATE_BASE64` — Developer ID .p12 (base64)
- `APPLE_CERTIFICATE_PASSWORD` — .p12 password
- `APPLE_ID` — Apple ID email for notarization
- `APPLE_TEAM_ID` — Apple Developer Team ID
- `APPLE_APP_PASSWORD` — App-specific password for notarytool

## API Endpoints

The accelerator exposes:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Returns `{"status":"ready"}` |
| `/decrypt` | POST | Decrypt a PVAC ciphertext → plaintext value |
| `/prove` | WebSocket | Streaming prove ops (shield, unshield, stealth, claim) |
| `/pair/export` | POST | Generate relay pairing file |

### Key Input Protocol

Both `/decrypt` and `/prove` accept keys in two formats (checked in order):

1. **PVAC keys (preferred)**: `pvac_sk_b64` + `pvac_pk_b64` — pre-serialized PVAC secret/public keys
2. **Legacy ed25519 seed**: `secretKeyB64` or `secret_key_b64` — raw 32-byte seed (deprecated)

The wallet extension's `sanitizeProverPayload()` always sends PVAC keys and strips the ed25519 seed.

## Local Development

```bash
# Build (macOS arm64)
make CXX=clang++

# Run
./octane-accelerator

# Test health
curl http://127.0.0.1:19876/health
```

### Dependencies

- **macOS**: `brew install libomp openssl`
- **Linux**: `apt-get install libomp-dev libssl-dev`
- **Windows**: MSYS2 with `mingw-w64-x86_64-gcc mingw-w64-x86_64-openmp mingw-w64-x86_64-openssl`

## Install Scripts (End Users)

- **macOS/Linux**: `curl -fsSL https://octane-fast.github.io/octane-accelerator/install.sh | bash`
- **Windows**: `irm https://octane-fast.github.io/octane-accelerator/install.ps1 | iex`

These are deployed to GitHub Pages on every tagged release.

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| Notarization fails | Apple credentials expired | Regenerate app-specific password |
| macOS x64 build fails | OpenSSL not found | x64 build uses `TLS_LIBS=""` (no relay) |
| "key init failed" | Bad PVAC key serialization | Check base64 encoding of sk/pk |
| Port 19876 in use | Another instance running | Kill existing process |
| Workflow not triggered | Tag doesn't match `v*` | Ensure tag starts with `v` |

# Octane Accelerator

Native desktop proving service for the Octane wallet Chrome extension. Provides hardware-accelerated range proofs using optimized C++ (wNAF-5, Straus, OpenMP parallelism) instead of in-browser WASM.

## What it does

Runs a local HTTP + WebSocket server on `127.0.0.1:19876` that the Octane wallet extension connects to for proving operations:

- **`GET /health`** — returns `{"status":"ready"}` (extension auto-detects native prover)
- **`POST /decrypt`** — fast balance decryption
- **`WS /prove`** — streaming prove operations (shield, stealth send, claim)

When the accelerator is running, the extension uses it automatically instead of the slower in-browser WASM prover.

## Performance

| Operation | WASM (in-browser) | Native (M1) | Native (Ryzen 5900X) |
|-----------|-------------------|-------------|---------------------|
| Single range proof | ~120s | ~24s | ~18s |
| Stealth send (2× range proof) | ~240s | ~44s | ~28s |
| Decrypt balance | ~500ms | <1ms | <1ms |

## Build

### macOS (Apple Silicon / Intel)

```bash
# Install OpenMP (required for parallel range proofs)
brew install libomp

# Build
make

# Run
./octane-accelerator
```

### Linux

```bash
# Build (GCC with OpenMP)
make CXX=g++

# Run
./octane-accelerator
```

### Windows (MinGW-w64)

```cmd
g++ -std=c++17 -O2 -fopenmp -Ipvac/include -I. -o octane-accelerator.exe ^
    main.cpp pvac/pvac_c_api.cpp lib/tweetnacl.c lib/randombytes.c -lws2_32 -lpthread
```

## Usage

1. Build the accelerator for your platform
2. Run `./octane-accelerator` (it stays in the foreground, logs to stderr)
3. Open the Octane wallet extension — it automatically detects the native prover
4. Any shield/stealth/claim operations will use the accelerator

To run in background:
```bash
# macOS/Linux
./octane-accelerator &

# Or with a custom port
./octane-accelerator 19876
```

## API Protocol

### POST /decrypt
```json
Request:  { "secret_key_b64": "...", "cipher_b64": "..." }
Response: { "value": 1000000 }
```

### WS /prove
```
Client → Server: { "operation": "shield|stealth|claim", "jobId": "...", "secretKeyB64": "...", "amountRaw": "1000000", "seedB64": "...", "blindingB64": "...", "currentCipherB64": "..." }

Server → Client: { "type": "status", "step": "Range proof (delta)..." }
Server → Client: { "type": "status", "step": "Range proof (balance)..." }
Server → Client: { "type": "result", "data": { "cipher": "...", "amount_commitment": "...", ... } }
```

## Architecture

```
Chrome Extension (Octane Wallet)
    │
    ├─ HTTP GET /health (detect prover)
    ├─ HTTP POST /decrypt (fast decrypt)
    └─ WebSocket /prove (streaming proofs)
           │
    ┌──────┴──────┐
    │  Octane     │  ← This program
    │ Accelerator │
    └──────┬──────┘
           │
    ┌──────┴──────┐
    │   pvac      │  Bulletproofs range proofs
    │ (optimized) │  wNAF-5 + Straus + OpenMP
    └─────────────┘
```

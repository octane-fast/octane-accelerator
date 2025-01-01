#!/usr/bin/env python3
"""
E2E tests for the /prove WebSocket endpoint.

Runs tests in two modes:
  1. Local: direct WebSocket to ws://127.0.0.1:19876/prove
  2. Relay: through the production relay at wss://octane-relay.octane-fast.workers.dev

Usage:
    python3 tests/test_prove_e2e.py [--host HOST] [--port PORT] [--relay]

Requires: pip install websocket-client requests
"""

import argparse
import base64
import json
import os
import sys
import time

import requests
import websocket


RELAY_URL = "wss://octane-relay.octane-fast.workers.dev"


def get_keys(base_url: str) -> tuple[str, str]:
    """Generate ephemeral PVAC keys via /test/keygen."""
    resp = requests.post(f"{base_url}/test/keygen", timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data["pvac_sk_b64"], data["pvac_pk_b64"]


def get_relay_room(base_url: str) -> str:
    """Call /pair/export and parse the room ID. Also triggers relay connection."""
    resp = requests.post(f"{base_url}/pair/export", timeout=10)
    resp.raise_for_status()
    for line in resp.text.strip().split("\n"):
        if line.startswith("room="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError(f"Could not parse room from /pair/export response: {resp.text}")


def random_seed_b64() -> str:
    """Generate a random 32-byte seed as base64."""
    return base64.b64encode(os.urandom(32)).decode()


def ws_prove(ws_url: str, payload: dict, timeout: int = 600) -> dict:
    """
    Connect to /prove (or relay), send payload, collect messages until result/error.
    Returns the final result message.
    """
    ws = websocket.create_connection(ws_url, timeout=timeout)
    try:
        ws.send(json.dumps(payload))
        statuses = []
        while True:
            raw = ws.recv()
            if not raw:
                break
            msg = json.loads(raw)
            if msg.get("type") == "status":
                statuses.append(msg.get("step", ""))
            elif msg.get("type") in ("result", "error"):
                msg["_statuses"] = statuses
                return msg
        raise RuntimeError("WebSocket closed without result")
    finally:
        ws.close()


class TestProveE2E:
    def __init__(self, host: str, port: int, use_relay: bool = False):
        self.base_url = f"http://{host}:{port}"
        self.local_ws_url = f"ws://{host}:{port}/prove"
        self.use_relay = use_relay
        self.relay_ws_url = None
        self.sk = ""
        self.pk = ""
        self.passed = 0
        self.failed = 0
        self.skip_proving = False

    @property
    def ws_url(self) -> str:
        if self.use_relay and self.relay_ws_url:
            return self.relay_ws_url
        return self.local_ws_url

    def setup(self):
        """Generate keys and optionally set up relay connection."""
        print(f"[setup] Generating keys via {self.base_url}/test/keygen ...")
        self.sk, self.pk = get_keys(self.base_url)
        print(f"[setup] Got keys (pk={self.pk[:20]}..., sk={self.sk[:20]}...)")

        if self.use_relay:
            print(f"[setup] Setting up relay connection...")
            room = get_relay_room(self.base_url)
            self.relay_ws_url = f"{RELAY_URL}/room/{room}?role=client"
            print(f"[setup] Relay room: {room}")
            # Give the server a moment to connect to the relay
            time.sleep(3)
            print(f"[setup] Will test via: {self.relay_ws_url}")

    def _base_payload(self, operation: str, **kwargs) -> dict:
        payload = {
            "operation": operation,
            "pvac_sk_b64": self.sk,
            "pvac_pk_b64": self.pk,
        }
        payload.update(kwargs)
        return payload

    def assert_eq(self, name: str, actual, expected):
        if actual != expected:
            raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")

    def assert_true(self, name: str, value):
        if not value:
            raise AssertionError(f"{name}: expected truthy, got {value!r}")

    def run_test(self, name: str, fn):
        sys.stdout.write(f"  [{name}] ... ")
        sys.stdout.flush()
        try:
            fn()
            print("PASS")
            self.passed += 1
        except Exception as e:
            print(f"FAIL: {e}")
            self.failed += 1

    # --- Tests ---------------------------------------------------------------

    def test_encrypt(self):
        """Encrypt a value and verify ciphertext is returned."""
        payload = self._base_payload(
            "encrypt",
            amountRaw="42",
            seedB64=random_seed_b64(),
        )
        result = ws_prove(self.ws_url, payload)
        self.assert_eq("type", result["type"], "result")
        self.assert_true("has ciphertext", len(result["data"]["ciphertext"]) > 0)

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt the same value -- should get original back."""
        seed = random_seed_b64()
        amount = "1000"

        # Encrypt
        enc_payload = self._base_payload("encrypt", amountRaw=amount, seedB64=seed)
        enc_result = ws_prove(self.ws_url, enc_payload)
        self.assert_eq("enc type", enc_result["type"], "result")
        cipher = enc_result["data"]["ciphertext"]

        # Decrypt
        dec_payload = self._base_payload("decrypt", cipher_b64=cipher)
        dec_result = ws_prove(self.ws_url, dec_payload)
        self.assert_eq("dec type", dec_result["type"], "result")
        self.assert_eq("roundtrip value", dec_result["data"]["value"], amount)

    def test_shield(self):
        """Shield operation -- full proof pipeline."""
        payload = self._base_payload(
            "shield",
            amountRaw="500",
            seedB64=random_seed_b64(),
            blindingB64=random_seed_b64(),
        )
        result = ws_prove(self.ws_url, payload)
        self.assert_eq("type", result["type"], "result")
        data = result["data"]
        self.assert_true("has cipher", len(data.get("cipher", "")) > 0)
        self.assert_true("has amount_commitment", len(data.get("amount_commitment", "")) > 0)
        self.assert_true("had status updates", len(result.get("_statuses", [])) > 0)

    def test_range_proof(self):
        """Generate a range proof for an encrypted value."""
        seed = random_seed_b64()
        amount = "100"

        # First encrypt
        enc_payload = self._base_payload("encrypt", amountRaw=amount, seedB64=seed)
        enc_result = ws_prove(self.ws_url, enc_payload)
        cipher = enc_result["data"]["ciphertext"]

        # Then range proof
        rp_payload = self._base_payload("range_proof", cipher_b64=cipher, amountRaw=amount)
        rp_result = ws_prove(self.ws_url, rp_payload)
        self.assert_eq("type", rp_result["type"], "result")
        self.assert_true("has proof", len(rp_result["data"]["proof"]) > 0)

    def test_commit(self):
        """Pedersen commitment."""
        blinding = random_seed_b64()
        payload = self._base_payload("commit", amountRaw="250", blindingB64=blinding)
        result = ws_prove(self.ws_url, payload)
        self.assert_eq("type", result["type"], "result")
        self.assert_true("has commitment", len(result["data"]["commitment"]) > 0)
        self.assert_true("has blinding", len(result["data"]["blinding"]) > 0)

    def test_ct_sub(self):
        """Ciphertext subtraction."""
        seed_a = random_seed_b64()
        seed_b = random_seed_b64()

        # Encrypt two values
        enc_a = ws_prove(self.ws_url, self._base_payload("encrypt", amountRaw="100", seedB64=seed_a))
        enc_b = ws_prove(self.ws_url, self._base_payload("encrypt", amountRaw="30", seedB64=seed_b))
        cipher_a = enc_a["data"]["ciphertext"]
        cipher_b = enc_b["data"]["ciphertext"]

        # Subtract
        sub_payload = self._base_payload("ct_sub", a_b64=cipher_a, b_b64=cipher_b)
        sub_result = ws_prove(self.ws_url, sub_payload)
        self.assert_eq("type", sub_result["type"], "result")
        ct_diff = sub_result["data"]["ciphertext"]
        self.assert_true("has result ciphertext", len(ct_diff) > 0)

        # Decrypt the difference -- should be 70
        dec_payload = self._base_payload("decrypt", cipher_b64=ct_diff)
        dec_result = ws_prove(self.ws_url, dec_payload)
        self.assert_eq("ct_sub decrypt", dec_result["data"]["value"], "70")

    def test_zero_proof(self):
        """Zero-knowledge proof for an encrypted zero."""
        blinding = random_seed_b64()
        seed = random_seed_b64()

        # Encrypt zero
        enc_payload = self._base_payload("encrypt", amountRaw="0", seedB64=seed)
        enc_result = ws_prove(self.ws_url, enc_payload)
        cipher = enc_result["data"]["ciphertext"]

        # Zero proof
        zp_payload = self._base_payload(
            "zero_proof",
            cipher_b64=cipher,
            amountRaw="0",
            blindingB64=blinding,
        )
        zp_result = ws_prove(self.ws_url, zp_payload)
        self.assert_eq("type", zp_result["type"], "result")
        self.assert_true("has proof", len(zp_result["data"]["proof"]) > 0)

    def test_zktls(self):
        """TLS session recording and proof generation."""
        payload = {
            "operation": "jolt_zktls_prove",
            "url": "https://example.com",
            "records": [0, 1],
        }
        result = ws_prove(self.ws_url, payload, timeout=1200)
        if result["type"] == "error":
            err = result.get("error", "unknown")
            print(f"\n  [zktls] server error: {err}")
        self.assert_eq("type", result["type"], "result")
        data = result["data"]
        self.assert_true("has session data", data is not None)
        self.assert_true("had status updates", len(result.get("_statuses", [])) > 0)
        has_session = "session" in data or "records" in data or "proof" in data or "ok" in data
        self.assert_true("has session/proof/ok field", has_session)

    def test_missing_keys(self):
        """Should return error when keys are missing."""
        payload = {"operation": "encrypt", "amountRaw": "1"}
        result = ws_prove(self.ws_url, payload)
        self.assert_eq("type", result["type"], "error")
        self.assert_true("error mentions keys", "key" in result.get("error", "").lower())

    def test_unknown_operation(self):
        """Should return error for unknown operation."""
        payload = self._base_payload("nonexistent_op")
        result = ws_prove(self.ws_url, payload)
        self.assert_eq("type", result["type"], "error")
        self.assert_true("error mentions unknown", "unknown" in result.get("error", "").lower())

    # --- Runner --------------------------------------------------------------

    def run_all(self):
        mode_str = "RELAY" if self.use_relay else "LOCAL"
        print(f"\n{'='*60}")
        print(f"  Octane Accelerator /prove E2E Tests [{mode_str}]")
        print(f"  Target: {self.local_ws_url}")
        print(f"{'='*60}\n")

        # Health check
        print("[preflight] Checking /health ...")
        try:
            r = requests.get(f"{self.base_url}/health", timeout=5)
            r.raise_for_status()
            print(f"[preflight] Server ready: {r.json()}")
        except Exception as e:
            print(f"[preflight] FAILED -- server not reachable: {e}")
            sys.exit(1)

        self.setup()

        tests = [
            ("encrypt", self.test_encrypt),
            ("encrypt_decrypt_roundtrip", self.test_encrypt_decrypt_roundtrip),
            ("shield", self.test_shield),
            ("range_proof", self.test_range_proof),
            ("commit", self.test_commit),
            ("ct_sub", self.test_ct_sub),
            ("zero_proof", self.test_zero_proof),
            ("zktls", self.test_zktls),
            ("missing_keys", self.test_missing_keys),
            ("unknown_operation", self.test_unknown_operation),
        ]

        if self.skip_proving:
            proving = {"range_proof", "commit", "zero_proof", "zktls"}
            tests = [(n, fn) for n, fn in tests if n not in proving]
            print("[info] Skipping proving tests (no embedded bundle)")

        if self.use_relay:
            tests = [(n, fn) for n, fn in tests if n != "zktls"]
            print("[info] Skipping zktls test via relay (takes too long)")

        print(f"\nRunning {len(tests)} tests via {mode_str}:\n")
        t0 = time.time()
        for name, fn in tests:
            self.run_test(name, fn)
        elapsed = time.time() - t0

        print(f"\n{'='*60}")
        print(f"  Results [{mode_str}]: {self.passed} passed, {self.failed} failed ({elapsed:.1f}s)")
        print(f"{'='*60}\n")

        return self.failed == 0


def main():
    parser = argparse.ArgumentParser(description="E2E tests for /prove WebSocket endpoint")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=19876, help="Server port")
    parser.add_argument("--relay", action="store_true", help="Test via production relay")
    parser.add_argument("--skip-proving", action="store_true", help="Skip tests that require embedded jolt_prove bundle")
    args = parser.parse_args()

    runner = TestProveE2E(args.host, args.port, use_relay=args.relay)
    if args.skip_proving:
        runner.skip_proving = True
    success = runner.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

/**
 * Octane Accelerator — Native desktop proving service for the Octane wallet extension.
 *
 * Runs on 127.0.0.1:19876 and serves:
 *   GET  /health         → { "status": "ready" }
 *   POST /decrypt        → { "value": <uint64> }
 *   WS   /prove          → streaming prove operations (shield, stealth, claim)
 *
 * Build: see Makefile
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <fstream>

#include "src/server.hpp"
#include "src/prover.hpp"
#include "src/base64.hpp"
#include "src/relay_client.hpp"
#include "src/relay_bridge.hpp"
#include "src/embedded_recorder.hpp"
#include "lib/json.hpp"
#ifdef _WIN32
#include "src/tray_win.hpp"
#endif

extern "C" {
#include "pvac/pvac_c_api.h"
extern void randombytes(unsigned char*, unsigned long long);
}

using json = nlohmann::json;
using namespace octane;

static constexpr uint16_t PORT = 19876;
static const std::string RELAY_URL = "wss://octane-relay.octane-fast.workers.dev";
static std::mutex prover_mutex;
static std::unique_ptr<RelayBridge> g_relay;
static uint16_t g_port = PORT;
static octane::EmbeddedRecorder g_recorder;

static void start_relay_if_configured() {
    if (g_relay) {
        g_relay->stop();
        g_relay.reset();
    }
    std::string relay_url, room_id;
    uint8_t sk[32], pk[32];
    if (load_relay_config(relay_url, room_id, sk, pk)) {
        fprintf(stderr, "[relay] Config found \u2014 connecting to relay as host\n");
        g_relay = std::make_unique<RelayBridge>(relay_url, room_id, g_port);
        g_relay->start();
    }
}

static void handle_http(socket_t sock, const std::string& method,
                        const std::string& path, const std::string& headers) {
    // CORS preflight
    if (method == "OPTIONS") {
        send_http(sock, 204, "No Content", "");
        return;
    }

    if (method == "GET" && path == "/health") {
        send_http(sock, 200, "OK", R"({"status":"ready"})");
        return;
    }

    if (method == "POST" && path == "/decrypt") {
        std::string body = recv_body(sock, headers);
        if (body.empty()) {
            send_http(sock, 400, "Bad Request", R"({"error":"empty body"})");
            return;
        }

        try {
            auto req = json::parse(body);
            std::string cipher_b64 = req.at("cipher_b64").get<std::string>();

            std::lock_guard<std::mutex> lock(prover_mutex);
            Prover prover;

            if (!req.contains("pvac_sk_b64") || !req.contains("pvac_pk_b64")) {
                send_http(sock, 400, "Bad Request", R"({"error":"missing pvac_sk_b64 and pvac_pk_b64"})");
                return;
            }
            bool ok = prover.init_from_keys(
                req["pvac_sk_b64"].get<std::string>(),
                req["pvac_pk_b64"].get<std::string>()
            );

            if (!ok) {
                send_http(sock, 500, "Internal Server Error", R"({"error":"key init failed"})");
                return;
            }
            uint64_t value = prover.decrypt(cipher_b64);
            send_http(sock, 200, "OK", "{\"value\":" + std::to_string(value) + "}");
        } catch (const std::exception& e) {
            std::string err = std::string(R"({"error":")") + e.what() + "\"}";
            send_http(sock, 500, "Internal Server Error", err);
        }
        return;
    }

    if (method == "POST" && path == "/test/keygen") {
        // Generate ephemeral PVAC keys for E2E testing
        uint8_t seed[32];
        randombytes(seed, 32);
        pvac_params prm = pvac_default_params();
        pvac_pubkey pk = nullptr;
        pvac_seckey sk = nullptr;
        pvac_keygen_from_seed(prm, seed, &pk, &sk);
        pvac_free_params(prm);
        if (!pk || !sk) {
            send_http(sock, 500, "Internal Server Error", R"({"error":"keygen failed"})");
            return;
        }
        size_t pk_sz = 0, sk_sz = 0;
        uint8_t* pk_buf = pvac_serialize_pubkey(pk, &pk_sz);
        uint8_t* sk_buf = pvac_serialize_seckey(sk, &sk_sz);
        pvac_free_pubkey(pk);
        pvac_free_seckey(sk);

        std::string pk_b64 = base64_encode(pk_buf, pk_sz);
        std::string sk_b64 = base64_encode(sk_buf, sk_sz);
        free(pk_buf);
        free(sk_buf);

        json resp;
        resp["pvac_pk_b64"] = pk_b64;
        resp["pvac_sk_b64"] = sk_b64;
        send_http(sock, 200, "OK", resp.dump());
        return;
    }

    if (method == "POST" && path == "/benchmark") {
        std::string body = recv_body(sock, headers);
        int count = 3; // number of range proofs to run
        if (!body.empty()) {
            try { auto j = json::parse(body); if (j.contains("count")) count = j["count"].get<int>(); } catch (...) {}
        }
        if (count < 1) count = 1;
        if (count > 10) count = 10;

        int total_steps = count + 2; // keygen + encrypt + N proofs

        // Send chunked HTTP headers
        std::string hdr = "HTTP/1.1 200 OK\r\n";
        hdr += "Content-Type: application/x-ndjson\r\n";
        hdr += "Transfer-Encoding: chunked\r\n";
        hdr += "Access-Control-Allow-Origin: *\r\n";
        hdr += "Connection: close\r\n\r\n";
        send(sock, hdr.c_str(), (int)hdr.size(), 0);

        auto send_chunk = [&](const std::string& data) {
            char len_buf[32];
            snprintf(len_buf, sizeof(len_buf), "%x\r\n", (unsigned)data.size());
            std::string chunk = std::string(len_buf) + data + "\r\n";
            send(sock, chunk.c_str(), (int)chunk.size(), 0);
        };

        auto send_progress = [&](int step, int total, const std::string& msg) {
            json p;
            p["step"] = step;
            p["total"] = total;
            p["msg"] = msg;
            send_chunk(p.dump() + "\n");
        };

        try {
            std::lock_guard<std::mutex> lock(prover_mutex);

            // Step 1: keygen
            send_progress(1, total_steps, "Generating keys...");
            uint8_t seed[32];
            randombytes(seed, 32);
            pvac_params prm = pvac_default_params();
            pvac_pubkey bpk = nullptr;
            pvac_seckey bsk = nullptr;
            pvac_keygen_from_seed(prm, seed, &bpk, &bsk);
            pvac_free_params(prm);

            if (!bpk || !bsk) {
                send_progress(0, 0, "ERROR: keygen failed");
                send_chunk(""); // end
                return;
            }

            // Step 2: encrypt
            send_progress(2, total_steps, "Encrypting value...");
            uint64_t test_value = 42;
            uint8_t enc_seed[32];
            randombytes(enc_seed, 32);
            pvac_cipher ct = pvac_enc_value_seeded(bpk, bsk, test_value, enc_seed);

            // Steps 3..N+2: range proofs
            double total_ms = 0;
            for (int i = 0; i < count; i++) {
                send_progress(3 + i, total_steps, "Generating range proof " + std::to_string(i + 1) + "/" + std::to_string(count) + "...");

                auto t0 = std::chrono::steady_clock::now();
                pvac_range_proof rp = pvac_make_range_proof(bpk, bsk, ct, test_value);
                auto t1 = std::chrono::steady_clock::now();

                double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
                total_ms += elapsed_ms;
                pvac_free_range_proof(rp);
            }

            pvac_free_cipher(ct);
            pvac_free_pubkey(bpk);
            pvac_free_seckey(bsk);

            // Final result
            json result;
            result["done"] = true;
            result["count"] = count;
            result["total_ms"] = total_ms;
            result["avg_ms"] = total_ms / count;
            send_chunk(result.dump() + "\n");

        } catch (const std::exception& e) {
            json err;
            err["error"] = e.what();
            send_chunk(err.dump() + "\n");
        }

        // End chunked encoding
        send(sock, "0\r\n\r\n", 5, 0);
        return;
    }

    if (method == "POST" && path == "/pair/export") {
        // Generate a new pairing file and return its content
        // This creates ~/.octane/relay.conf and ~/.octane/relay_secret.key
        std::string home = octane::get_home_dir();
        std::string tmp_path = home + "/.octane/pairing_export.tmp";

        if (!generate_pairing_file(tmp_path, RELAY_URL)) {
            send_http(sock, 500, "Internal Server Error", R"({"error":"failed to generate pairing"})");
            return;
        }

        // Read the generated file and return as response body
        std::ifstream in(tmp_path);
        if (!in) {
            send_http(sock, 500, "Internal Server Error", R"({"error":"cannot read pairing file"})");
            return;
        }
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();
        std::remove(tmp_path.c_str());

        // (Re)start relay bridge with the new config
        start_relay_if_configured();

        send_http(sock, 200, "OK", content, "text/plain");
        return;
    }

    send_http(sock, 404, "Not Found", R"({"error":"not found"})");
}

static void handle_ws(socket_t sock) {
    std::string msg;
    if (!ws_read_text(sock, msg)) return;

    json req;
    try {
        req = json::parse(msg);
    } catch (...) {
        ws_send_text(sock, R"({"type":"error","error":"invalid JSON"})");
        ws_send_close(sock);
        return;
    }

    std::string operation = req.value("operation", "");
    std::string job_id = req.value("jobId", "");
    std::string pvac_sk_b64 = req.value("pvac_sk_b64", "");
    std::string pvac_pk_b64 = req.value("pvac_pk_b64", "");

    // Status callback: sends progress to extension via WebSocket
    auto send_status = [&](const std::string& step) {
        json status_msg;
        status_msg["type"] = "status";
        status_msg["step"] = step;
        ws_send_text(sock, status_msg.dump());
    };

    // ── jolt_zktls_prove: TLS session recording via embedded Node.js recorder ──
    if (operation == "jolt_zktls_prove") {
        std::string url = req.value("url", "");
        std::string headers = req.value("headers", "{}");
        std::string records = "";
        if (req.contains("records") && req["records"].is_array()) {
            records = req["records"].dump(); // serialize as JSON array e.g. "[0,1]"
        }
        if (url.empty()) {
            ws_send_text(sock, R"({"type":"error","error":"missing url"})");
            ws_send_close(sock);
            return;
        }

        send_status("Recording TLS session...");

        json result = g_recorder.record(url, headers, records, send_status);

        if (result.contains("error")) {
            std::string err = result.value("error", "recording failed");
            ws_send_text(sock, json({{"type", "error"}, {"error", err}}).dump());
            ws_send_close(sock);
            return;
        }

        send_status("Recording complete.");
        json res_msg;
        res_msg["type"] = "result";
        res_msg["data"] = result;
        ws_send_text(sock, res_msg.dump());
        ws_send_close(sock);
        return;
    }

    // All other operations require PVAC keys
    if (pvac_sk_b64.empty() || pvac_pk_b64.empty()) {
        ws_send_text(sock, R"({"type":"error","error":"missing keys: need pvac_sk_b64 and pvac_pk_b64"})");
        ws_send_close(sock);
        return;
    }

    try {
        std::lock_guard<std::mutex> lock(prover_mutex);

        Prover prover;
        send_status("Initializing prover...");

        bool ok = prover.init_from_keys(pvac_sk_b64, pvac_pk_b64);

        if (!ok) {
            ws_send_text(sock, R"({"type":"error","error":"key init failed"})");
            ws_send_close(sock);
            return;
        }

        // Parse common fields
        std::string seed_b64 = req.value("seedB64", "");
        std::string blinding_b64 = req.value("blindingB64", "");
        std::string amount_str = req.value("amountRaw", "0");
        uint64_t amount_raw = std::stoull(amount_str);

        uint8_t seed[32] = {0}, blinding[32] = {0};
        if (!seed_b64.empty()) {
            auto s = base64_decode(seed_b64);
            if (s.size() >= 32) memcpy(seed, s.data(), 32);
        }
        if (!blinding_b64.empty()) {
            auto b = base64_decode(blinding_b64);
            if (b.size() >= 32) memcpy(blinding, b.data(), 32);
        }

        ProveResult result;
        auto t0 = std::chrono::steady_clock::now();

        if (operation == "shield") {
            result = prover.shield(amount_raw, seed, blinding, send_status);
        } else if (operation == "stealth" || operation == "unshield") {
            std::string current_cipher_b64 = req.value("currentCipherB64", "");
            if (current_cipher_b64.empty()) {
                ws_send_text(sock, R"({"type":"error","error":"missing currentCipherB64"})");
                ws_send_close(sock);
                return;
            }
            result = prover.stealth(current_cipher_b64, amount_raw, seed, blinding, send_status);
        } else if (operation == "claim") {
            result = prover.claim(amount_raw, seed, blinding, send_status);
        } else if (operation == "decrypt") {
            std::string cipher_b64 = req.value("cipher_b64", "");
            if (cipher_b64.empty()) {
                ws_send_text(sock, R"({"type":"error","error":"missing cipher_b64"})");
                ws_send_close(sock);
                return;
            }
            uint64_t value = prover.decrypt(cipher_b64);
            json res_msg;
            res_msg["type"] = "result";
            res_msg["data"] = {{"value", std::to_string(value)}};
            ws_send_text(sock, res_msg.dump());
            ws_send_close(sock);
            return;
        } else if (operation == "encrypt") {
            // Standalone encrypt: just encrypt a value, return ciphertext
            json res_msg;
            res_msg["type"] = "result";
            res_msg["data"] = {{"ciphertext", prover.encrypt_value(amount_raw, seed)}};
            ws_send_text(sock, res_msg.dump());
            ws_send_close(sock);
            return;
        } else if (operation == "range_proof") {
            std::string cipher_b64 = req.value("cipher_b64", "");
            if (cipher_b64.empty()) {
                ws_send_text(sock, R"({"type":"error","error":"missing cipher_b64"})");
                ws_send_close(sock);
                return;
            }
            json res_msg;
            res_msg["type"] = "result";
            res_msg["data"] = {{"proof", prover.range_proof(cipher_b64, amount_raw)}};
            ws_send_text(sock, res_msg.dump());
            ws_send_close(sock);
            return;
        } else if (operation == "zero_proof") {
            std::string cipher_b64 = req.value("cipher_b64", "");
            if (cipher_b64.empty()) {
                ws_send_text(sock, R"({"type":"error","error":"missing cipher_b64"})");
                ws_send_close(sock);
                return;
            }
            json res_msg;
            res_msg["type"] = "result";
            res_msg["data"] = {{"proof", prover.zero_proof(cipher_b64, amount_raw, blinding)}};
            ws_send_text(sock, res_msg.dump());
            ws_send_close(sock);
            return;
        } else if (operation == "commit") {
            json res_msg;
            res_msg["type"] = "result";
            res_msg["data"] = {
                {"commitment", prover.pedersen_commit(amount_raw, blinding)},
                {"blinding", base64_encode(blinding, 32)}
            };
            ws_send_text(sock, res_msg.dump());
            ws_send_close(sock);
            return;
        } else if (operation == "ct_sub") {
            std::string a_b64 = req.value("a_b64", "");
            std::string b_b64 = req.value("b_b64", "");
            if (a_b64.empty() || b_b64.empty()) {
                ws_send_text(sock, R"({"type":"error","error":"missing a_b64 or b_b64"})");
                ws_send_close(sock);
                return;
            }
            json res_msg;
            res_msg["type"] = "result";
            res_msg["data"] = {{"ciphertext", prover.ct_subtract(a_b64, b_b64)}};
            ws_send_text(sock, res_msg.dump());
            ws_send_close(sock);
            return;
        } else {
            ws_send_text(sock, R"({"type":"error","error":"unknown operation"})");
            ws_send_close(sock);
            return;
        }

        auto t1 = std::chrono::steady_clock::now();
        double elapsed_s = std::chrono::duration<double>(t1 - t0).count();
        fprintf(stderr, "[octane-accelerator] %s completed in %.1fs\n", operation.c_str(), elapsed_s);

        // Send result
        json result_msg;
        result_msg["type"] = "result";
        json data;
        data["cipher"] = result.cipher;
        data["amount_commitment"] = result.amount_commitment;
        if (!result.zero_proof.empty()) data["zero_proof"] = result.zero_proof;
        if (!result.blinding.empty()) data["blinding"] = result.blinding;
        if (!result.range_proof_delta.empty()) data["range_proof_delta"] = result.range_proof_delta;
        if (!result.range_proof_balance.empty()) data["range_proof_balance"] = result.range_proof_balance;
        if (!result.commitment.empty()) data["commitment"] = result.commitment;
        result_msg["data"] = data;
        ws_send_text(sock, result_msg.dump());

    } catch (const std::exception& e) {
        json err_msg;
        err_msg["type"] = "error";
        err_msg["error"] = e.what();
        ws_send_text(sock, err_msg.dump());
    }

    ws_send_close(sock);
}

int main(int argc, char* argv[]) {
    uint16_t port = PORT;
    if (argc > 1) port = (uint16_t)std::atoi(argv[1]);
    g_port = port;

    fprintf(stderr, "Octane Accelerator v1.0\n");
    fprintf(stderr, "Listening on 127.0.0.1:%d\n", port);
    fprintf(stderr, "  GET  /health    — health check\n");
    fprintf(stderr, "  POST /decrypt   — decrypt balance\n");
    fprintf(stderr, "  POST /benchmark — range proof benchmark\n");
    fprintf(stderr, "  WS   /prove     — proving operations\n");
    fprintf(stderr, "\n");

    Server server(port, handle_http, handle_ws);
    if (!server.start()) {
        fprintf(stderr, "ERROR: Failed to bind port %d (is another instance running?)\n", port);
        return 1;
    }

    // Start relay bridge if configured
    start_relay_if_configured();
    if (!g_relay) {
        fprintf(stderr, "[relay] No relay.conf found — running in local-only mode\n");
        fprintf(stderr, "[relay] Use POST /pair/export to generate a pairing file\n");
    }

#ifdef _WIN32
    // Start system tray icon on Windows
    static octane::TrayIcon tray(port);
    tray.start();
    tray.set_running(true);
#endif

    server.run();
    return 0;
}

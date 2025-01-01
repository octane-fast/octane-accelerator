/**
 * jolt_bridge.hpp — C++ wrapper around the Jolt zkTLS prover C FFI.
 *
 * Links against the Rust `prove` static library (libprove.a).
 * Provides init() and prove() methods that call the Rust FFI functions.
 */

#pragma once

#include <string>
#include <cstring>
#include "../lib/json.hpp"

// ─── C FFI declarations (from prove/src/lib.rs) ────────────────────

extern "C" {
    int jolt_init(const char* target_dir);
    char* jolt_prove(const char* session_json);
    void jolt_free_string(char* s);
}

namespace octane {

using json = nlohmann::json;

class JoltBridge {
public:
    bool initialized = false;

    /**
     * Initialize the Jolt prover. Must be called once before prove().
     * Compiles the RISC-V guest program and preprocesses proving keys.
     * This is expensive (minutes on first call) but only runs once.
     */
    bool init(const std::string& target_dir = "/tmp/jolt-guest-targets") {
        int ret = jolt_init(target_dir.c_str());
        initialized = (ret == 0);
        return initialized;
    }

    /**
     * Prove TLS decryption for a session.
     * Session JSON must match the TLSSession schema (name, params, records).
     * Returns a JSON object with: { ok, name, cipher_suite, records: [...] }
     */
    json prove(const json& session) {
        if (!initialized) {
            return json{{"ok", false}, {"error", "Jolt prover not initialized"}};
        }

        std::string session_str = session.dump();
        char* result_c = jolt_prove(session_str.c_str());

        if (!result_c) {
            return json{{"ok", false}, {"error", "jolt_prove returned null"}};
        }

        std::string result_str(result_c);
        jolt_free_string(result_c);

        try {
            return json::parse(result_str);
        } catch (const std::exception& e) {
            return json{{"ok", false},
                       {"error", std::string("failed to parse result: ") + e.what()}};
        }
    }
};

}  // namespace octane

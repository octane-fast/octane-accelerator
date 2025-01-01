#pragma once
/**
 * Octane Accelerator — Proving operations using pvac.
 * Wraps the pvac C API to provide shield, unshield, stealth, and claim operations.
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <stdexcept>
#include <functional>
#include "base64.hpp"

extern "C" {
#include "../pvac/pvac_c_api.h"
#include "../lib/tweetnacl.h"
extern void randombytes(unsigned char*, unsigned long long);
}

namespace octane {

constexpr const char* HFHE_PREFIX = "hfhe_v1|";
constexpr const char* RP_PREFIX = "rp_v1|";
constexpr const char* ZKZP_PREFIX = "zkzp_v2|";

using StatusCallback = std::function<void(const std::string&)>;

struct ProveResult {
    std::string cipher;
    std::string amount_commitment;
    std::string zero_proof;
    std::string blinding;
    std::string range_proof_delta;
    std::string range_proof_balance;
    std::string commitment;
};

class Prover {
    pvac_pubkey pk_ = nullptr;
    pvac_seckey sk_ = nullptr;

    std::vector<uint8_t> serialize_handle(uint8_t*(*fn)(void*, size_t*), void* handle) {
        size_t len = 0;
        uint8_t* ptr = fn(handle, &len);
        std::vector<uint8_t> data(ptr, ptr + len);
        pvac_free_bytes(ptr);
        return data;
    }

    std::string encode_cipher(pvac_cipher ct) {
        auto data = serialize_handle(pvac_serialize_cipher, ct);
        return std::string(HFHE_PREFIX) + base64_encode(data.data(), data.size());
    }

    pvac_cipher decode_cipher(const std::string& s) {
        std::string b64;
        if (s.rfind(HFHE_PREFIX, 0) == 0)
            b64 = s.substr(strlen(HFHE_PREFIX));
        else
            b64 = s;
        auto raw = base64_decode(b64);
        return pvac_deserialize_cipher(raw.data(), raw.size());
    }

    std::string encode_range_proof(pvac_range_proof rp) {
        auto data = serialize_handle(pvac_serialize_range_proof, rp);
        return std::string(RP_PREFIX) + base64_encode(data.data(), data.size());
    }

    std::string encode_zero_proof(pvac_zero_proof zp) {
        auto data = serialize_handle(pvac_serialize_zero_proof, zp);
        return std::string(ZKZP_PREFIX) + base64_encode(data.data(), data.size());
    }

public:
    Prover() = default;
    Prover(const Prover&) = delete;
    Prover& operator=(const Prover&) = delete;

    ~Prover() {
        if (pk_) pvac_free_pubkey(pk_);
        if (sk_) pvac_free_seckey(sk_);
    }

    bool init(const std::string& secret_key_b64) {
        if (pk_) { pvac_free_pubkey(pk_); pk_ = nullptr; }
        if (sk_) { pvac_free_seckey(sk_); sk_ = nullptr; }

        auto raw = base64_decode(secret_key_b64);
        if (raw.size() < 32) return false;
        uint8_t seed[32];
        memcpy(seed, raw.data(), 32);
        pvac_params prm = pvac_default_params();
        pvac_keygen_from_seed(prm, seed, &pk_, &sk_);
        pvac_free_params(prm);
        return pk_ != nullptr && sk_ != nullptr;
    }

    /** Initialize from pre-serialized PVAC keys (no ed25519 seed needed) */
    bool init_from_keys(const std::string& pvac_sk_b64, const std::string& pvac_pk_b64) {
        if (pk_) { pvac_free_pubkey(pk_); pk_ = nullptr; }
        if (sk_) { pvac_free_seckey(sk_); sk_ = nullptr; }

        auto sk_raw = base64_decode(pvac_sk_b64);
        auto pk_raw = base64_decode(pvac_pk_b64);
        if (sk_raw.empty() || pk_raw.empty()) return false;

        sk_ = pvac_deserialize_seckey(sk_raw.data(), sk_raw.size());
        pk_ = pvac_deserialize_pubkey(pk_raw.data(), pk_raw.size());
        return pk_ != nullptr && sk_ != nullptr;
    }

    bool is_ready() const { return pk_ != nullptr && sk_ != nullptr; }

    uint64_t decrypt(const std::string& cipher_b64) {
        pvac_cipher ct = decode_cipher(cipher_b64);
        if (!ct) throw std::runtime_error("Failed to decode cipher");
        uint64_t val = pvac_dec_value(pk_, sk_, ct);
        pvac_free_cipher(ct);
        return val;
    }

    // Shield: encrypt amount + commitment + zero proof
    ProveResult shield(uint64_t amount_raw, const uint8_t seed[32],
                       const uint8_t blinding[32], StatusCallback status) {
        ProveResult result;

        status("Encrypting value...");
        pvac_cipher ct = pvac_enc_value_seeded(pk_, sk_, amount_raw, seed);

        status("Computing commitment...");
        uint8_t commit_out[32];
        size_t commit_len = 0;
        pvac_pedersen_commit_v2(amount_raw, blinding, commit_out, 32, &commit_len);

        status("Generating zero proof...");
        pvac_zero_proof zp = pvac_make_zero_proof_bound(pk_, sk_, ct, amount_raw, blinding);

        result.cipher = encode_cipher(ct);
        result.amount_commitment = base64_encode(commit_out, 32);
        result.zero_proof = encode_zero_proof(zp);
        result.blinding = base64_encode(blinding, 32);

        pvac_free_cipher(ct);
        pvac_free_zero_proof(zp);
        return result;
    }

    // Unshield/Stealth: decrypt current balance, compute delta, range proofs
    ProveResult stealth(const std::string& current_cipher_b64, uint64_t amount_raw,
                        const uint8_t seed[32], const uint8_t blinding[32],
                        StatusCallback status) {
        ProveResult result;

        status("Decrypting current balance...");
        pvac_cipher current_ct = decode_cipher(current_cipher_b64);
        if (!current_ct) throw std::runtime_error("Failed to decode current cipher");
        uint64_t balance = pvac_dec_value(pk_, sk_, current_ct);
        if (balance < amount_raw) {
            pvac_free_cipher(current_ct);
            throw std::runtime_error("Insufficient balance");
        }

        status("Encrypting delta...");
        pvac_cipher delta_ct = pvac_enc_value_seeded(pk_, sk_, amount_raw, seed);

        status("Computing remaining balance cipher...");
        pvac_cipher new_bal_ct = pvac_ct_sub(pk_, current_ct, delta_ct);
        uint64_t new_balance = balance - amount_raw;

        status("Computing commitment...");
        uint8_t pedersen_out[32];
        size_t pedersen_len = 0;
        pvac_pedersen_commit_v2(amount_raw, blinding, pedersen_out, 32, &pedersen_len);

        uint8_t ct_commit_out[32];
        size_t ct_commit_len = 0;
        pvac_commit_ct_v2(pk_, delta_ct, ct_commit_out, 32, &ct_commit_len);

        status("Range proof (delta)...");
        pvac_range_proof rp_delta = pvac_make_range_proof(pk_, sk_, delta_ct, amount_raw);

        status("Range proof (balance)...");
        pvac_range_proof rp_balance = pvac_make_range_proof(pk_, sk_, new_bal_ct, new_balance);

        status("Generating zero proof...");
        pvac_zero_proof zp = pvac_make_zero_proof_bound(pk_, sk_, delta_ct, amount_raw, blinding);

        result.cipher = encode_cipher(delta_ct);
        result.commitment = base64_encode(ct_commit_out, 32);
        result.amount_commitment = base64_encode(pedersen_out, 32);
        result.zero_proof = encode_zero_proof(zp);
        result.blinding = base64_encode(blinding, 32);
        result.range_proof_delta = encode_range_proof(rp_delta);
        result.range_proof_balance = encode_range_proof(rp_balance);

        pvac_free_cipher(current_ct);
        pvac_free_cipher(delta_ct);
        pvac_free_cipher(new_bal_ct);
        pvac_free_range_proof(rp_delta);
        pvac_free_range_proof(rp_balance);
        pvac_free_zero_proof(zp);
        return result;
    }

    // Claim: encrypt claimed amount + range proof
    ProveResult claim(uint64_t amount_raw, const uint8_t seed[32],
                      const uint8_t blinding[32], StatusCallback status) {
        ProveResult result;

        status("Encrypting claimed amount...");
        pvac_cipher ct = pvac_enc_value_seeded(pk_, sk_, amount_raw, seed);

        status("Computing commitment...");
        uint8_t commit_out[32];
        size_t commit_len = 0;
        pvac_commit_ct_v2(pk_, ct, commit_out, 32, &commit_len);

        status("Generating range proof...");
        pvac_range_proof rp = pvac_make_range_proof(pk_, sk_, ct, amount_raw);

        status("Generating zero proof...");
        pvac_zero_proof zp = pvac_make_zero_proof_bound(pk_, sk_, ct, amount_raw, blinding);

        result.cipher = encode_cipher(ct);
        result.commitment = base64_encode(commit_out, 32);
        result.amount_commitment = base64_encode(commit_out, 32);
        result.zero_proof = encode_zero_proof(zp);
        result.blinding = base64_encode(blinding, 32);

        // For claim, range_proof_delta is the range proof of the claimed amount
        result.range_proof_delta = encode_range_proof(rp);

        pvac_free_cipher(ct);
        pvac_free_range_proof(rp);
        pvac_free_zero_proof(zp);
        return result;
    }

    // --- Standalone dApp operations ---

    /** Encrypt a single value, return cipher b64 */
    std::string encrypt_value(uint64_t value, const uint8_t seed[32]) {
        pvac_cipher ct = pvac_enc_value_seeded(pk_, sk_, value, seed);
        std::string result = encode_cipher(ct);
        pvac_free_cipher(ct);
        return result;
    }

    /** Generate a standalone range proof for a ciphertext */
    std::string range_proof(const std::string& cipher_b64, uint64_t value) {
        pvac_cipher ct = decode_cipher(cipher_b64);
        if (!ct) throw std::runtime_error("Failed to decode cipher");
        pvac_range_proof rp = pvac_make_range_proof(pk_, sk_, ct, value);
        std::string result = encode_range_proof(rp);
        pvac_free_cipher(ct);
        pvac_free_range_proof(rp);
        return result;
    }

    /** Generate a standalone zero proof */
    std::string zero_proof(const std::string& cipher_b64, uint64_t value, const uint8_t blinding[32]) {
        pvac_cipher ct = decode_cipher(cipher_b64);
        if (!ct) throw std::runtime_error("Failed to decode cipher");
        pvac_zero_proof zp = pvac_make_zero_proof_bound(pk_, sk_, ct, value, blinding);
        std::string result = encode_zero_proof(zp);
        pvac_free_cipher(ct);
        pvac_free_zero_proof(zp);
        return result;
    }

    /** Pedersen commitment */
    std::string pedersen_commit(uint64_t value, const uint8_t blinding[32]) {
        uint8_t out[32];
        size_t out_len = 0;
        pvac_pedersen_commit_v2(value, blinding, out, 32, &out_len);
        return base64_encode(out, 32);
    }

    /** Homomorphic ciphertext subtraction (a - b) */
    std::string ct_subtract(const std::string& a_b64, const std::string& b_b64) {
        pvac_cipher a = decode_cipher(a_b64);
        pvac_cipher b = decode_cipher(b_b64);
        if (!a || !b) {
            if (a) pvac_free_cipher(a);
            if (b) pvac_free_cipher(b);
            throw std::runtime_error("Failed to decode cipher(s)");
        }
        pvac_cipher result_ct = pvac_ct_sub(pk_, a, b);
        std::string result = encode_cipher(result_ct);
        pvac_free_cipher(a);
        pvac_free_cipher(b);
        pvac_free_cipher(result_ct);
        return result;
    }
};

} // namespace octane

/**
 * tls_recorder.hpp — Native TLS 1.3 session recorder using OpenSSL.
 *
 * Establishes a TLS connection, captures:
 *   - Handshake transcript (via SSL_CTX_set_msg_callback)
 *   - Traffic secrets (via SSL_CTX_set_keylog_callback)
 *   - X25519 private key (generated locally)
 *   - Application data ciphertext (via custom BIO wrapper)
 *
 * Outputs a JSON session matching the TLSSession / test_cases.json schema.
 */

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstring>
#include <cstdio>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

#include "../lib/json.hpp"

namespace octane {

using json = nlohmann::json;
using StatusCallback = std::function<void(const std::string&)>;

// ─── Handshake message entry ───────────────────────────────────────

struct HandshakeMsg {
    int write_p;  // 0 = inbound (S→C), 1 = outbound (C→S)
    std::vector<uint8_t> data;
};

// ─── TLS record captured at the BIO layer ──────────────────────────

struct TlsRecord {
    std::vector<uint8_t> ciphertext;
    uint32_t record_number;
    int direction;  // 0 = S→C, 1 = C→S
};

// ─── Forward declaration for keylog callback ───────────────────────

class TlsRecorder;
static TlsRecorder* g_active_tls_recorder = nullptr;

// ─── TLS Recorder ──────────────────────────────────────────────────

class TlsRecorder {
public:
    std::vector<HandshakeMsg> handshake_msgs;
    std::vector<std::string> keylog_lines;
    std::vector<TlsRecord> all_records;   // ALL 0x17 records (handshake + app data)
    std::vector<TlsRecord> app_records;   // Filtered: only application data records
    std::vector<uint8_t> client_priv_key;
    std::string cipher_suite_name;

    uint32_t sc_record_seq = 0;
    uint32_t cs_record_seq = 0;
    // Buffer for partial TLS records from BIO reads
    std::vector<uint8_t> read_buf;
    bool handshake_done = false;

    json record(const std::string& host, int port, StatusCallback on_status) {
        on_status("Initializing OpenSSL...");

        g_active_tls_recorder = this;

        // ── Generate X25519 keypair ──
        EVP_PKEY* x25519_key = nullptr;
        {
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
            if (!pctx) return json{{"error", "X25519 context creation failed"}};
            EVP_PKEY_keygen_init(pctx);
            if (EVP_PKEY_keygen(pctx, &x25519_key) != 1) {
                EVP_PKEY_CTX_free(pctx);
                return json{{"error", "X25519 keygen failed"}};
            }
            EVP_PKEY_CTX_free(pctx);
        }

        // Extract raw private key (32 bytes)
        size_t priv_len = 0;
        EVP_PKEY_get_raw_private_key(x25519_key, nullptr, &priv_len);
        client_priv_key.resize(priv_len);
        EVP_PKEY_get_raw_private_key(x25519_key, client_priv_key.data(), &priv_len);
        EVP_PKEY_free(x25519_key);

        // ── SSL context ──
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return json{{"error", "SSL_CTX_new failed"}};

        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set1_groups_list(ctx, "X25519");
        SSL_CTX_set_ciphersuites(ctx,
            "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
        SSL_CTX_set_default_verify_paths(ctx);

        // Callbacks
        SSL_CTX_set_keylog_callback(ctx, keylog_cb_static);
        SSL_CTX_set_msg_callback(ctx, msg_cb_static);
        SSL_CTX_set_msg_callback_arg(ctx, this);

        // ── TCP connect ──
        on_status("Connecting to " + host + ":" + std::to_string(port) + "...");

        std::string host_port = host + ":" + std::to_string(port);
        BIO* conn_bio = BIO_new_connect(host_port.c_str());
        if (!conn_bio) {
            SSL_CTX_free(ctx);
            return json{{"error", "BIO_new_connect failed"}};
        }

        if (BIO_do_connect(conn_bio) <= 0) {
            BIO_free_all(conn_bio);
            SSL_CTX_free(ctx);
            return json{{"error", "TCP connection to " + host_port + " failed"}};
        }

        // ── TLS setup ──
        SSL* ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, host.c_str());
        SSL_set_connect_state(ssl);

        // Wrap connect BIO with our capture BIO
        BIO_METHOD* method = get_capture_bio_method();
        BIO* capture_bio = BIO_new(method);
        BIO_set_data(capture_bio, this);
        BIO_push(capture_bio, conn_bio);

        SSL_set_bio(ssl, capture_bio, capture_bio);

        // ── TLS handshake ──
        on_status("Performing TLS handshake...");

        int ret = SSL_do_handshake(ssl);
        if (ret != 1) {
            int err = SSL_get_error(ssl, ret);
            unsigned long e = ERR_get_error();
            char buf[256];
            ERR_error_string_n(e, buf, sizeof(buf));
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            g_active_tls_recorder = nullptr;
            return json{{"error", std::string("TLS handshake failed: ") + buf}};
        }

        handshake_done = true;

        const char* cipher_name = SSL_get_cipher_name(ssl);
        cipher_suite_name = cipher_name ? cipher_name : "UNKNOWN";
        // Normalize to uppercase and add TLS_ prefix if not already present
        for (auto& c : cipher_suite_name) c = toupper(c);
        if (cipher_suite_name.substr(0, 4) != "TLS_") {
            cipher_suite_name = "TLS_" + cipher_suite_name;
        }

        on_status("Handshake complete. Cipher: " + cipher_suite_name);

        // ── Send HTTP request ──
        on_status("Sending HTTP request...");
        std::string request = "GET / HTTP/1.1\r\nHost: " + host +
                              "\r\nConnection: close\r\n\r\n";
        SSL_write(ssl, request.c_str(), (int)request.size());

        // ── Read response ──
        on_status("Reading response...");
        char readbuf[16384];
        while (SSL_read(ssl, readbuf, sizeof(readbuf)) > 0) {
            // Data captured by our BIO wrapper
        }

        json session = build_session_json();

        on_status("Session captured: " + std::to_string(app_records.size()) +
                  " app records, " + std::to_string(handshake_msgs.size()) +
                  " handshake messages");

        SSL_free(ssl);
        SSL_CTX_free(ctx);
        g_active_tls_recorder = nullptr;

        return session;
    }

private:
    // ─── Keylog callback (global, no user-data arg) ────────────────

    static void keylog_cb_static(const SSL* ssl, const char* line) {
        (void)ssl;
        if (g_active_tls_recorder) {
            g_active_tls_recorder->keylog_lines.push_back(line);
        }
    }

    // ─── Message callback ──────────────────────────────────────────

    // Buffer for accumulating server handshake messages into a single entry
    // (to match the TS recorder which concatenates EncExt||Cert||CertVer||Finished)
    std::vector<uint8_t> pending_hs_buf;
    bool seen_server_hello = false;

    static void msg_cb_static(int write_p, int version, int content_type,
                               const void* buf, size_t len, SSL* ssl, void* arg) {
        (void)version;
        (void)ssl;
        TlsRecorder* self = static_cast<TlsRecorder*>(arg);
        if (!self) return;

        if (content_type == SSL3_RT_HANDSHAKE) {
            const uint8_t* p = static_cast<const uint8_t*>(buf);

            if (write_p == 1) {
                // Outbound (C→S): ClientHello, client Finished
                if (len >= 1 && p[0] == 0x14) {
                    // Client's Finished — skip it (don't add to handshake_msgs)
                    return;
                }
                // ClientHello — add as individual entry
                HandshakeMsg msg;
                msg.write_p = write_p;
                msg.data.assign(p, p + len);
                self->handshake_msgs.push_back(std::move(msg));

                if (len >= 1 && p[0] == 0x01) {
                    self->seen_server_hello = false;  // Reset for ClientHello
                }
            } else {
                // Inbound (S→C): ServerHello, EncExt, Cert, CertVer, Finished, NST
                if (len >= 1 && p[0] == 0x02) {
                    // ServerHello — add as individual entry
                    HandshakeMsg msg;
                    msg.write_p = write_p;
                    msg.data.assign(p, p + len);
                    self->handshake_msgs.push_back(std::move(msg));
                    self->seen_server_hello = true;
                } else if (len >= 1 && p[0] == 0x04) {
                    // NewSessionTicket — skip (post-handshake, not part of transcript)
                    return;
                } else if (self->seen_server_hello) {
                    // EncExt, Cert, CertVer, Finished — accumulate into buffer
                    self->pending_hs_buf.insert(self->pending_hs_buf.end(), p, p + len);

                    if (len >= 1 && p[0] == 0x14) {
                        // Server's Finished — flush accumulated buffer as single entry
                        HandshakeMsg msg;
                        msg.write_p = write_p;
                        msg.data = std::move(self->pending_hs_buf);
                        self->handshake_msgs.push_back(std::move(msg));
                        self->pending_hs_buf.clear();
                    }
                }
            }
        }
    }

    // ─── BIO wrapper ───────────────────────────────────────────────

    static int bio_write(BIO* bio, const char* data, int len) {
        TlsRecorder* self = static_cast<TlsRecorder*>(BIO_get_data(bio));
        if (self && len > 0) {
            self->parse_tls_records(reinterpret_cast<const uint8_t*>(data), (size_t)len, 1);
        }
        return BIO_write(BIO_next(bio), data, len);
    }

    static int bio_read(BIO* bio, char* data, int len) {
        int n = BIO_read(BIO_next(bio), data, len);
        TlsRecorder* self = static_cast<TlsRecorder*>(BIO_get_data(bio));
        if (self && n > 0) {
            self->parse_tls_records(reinterpret_cast<const uint8_t*>(data), (size_t)n, 0);
        }
        return n;
    }

    static long bio_ctrl(BIO* bio, int cmd, long larg, void* parg) {
        return BIO_ctrl(BIO_next(bio), cmd, larg, parg);
    }

    static int bio_create(BIO* bio) {
        BIO_set_init(bio, 1);
        return 1;
    }

    static int bio_destroy(BIO* bio) {
        (void)bio;
        return 1;
    }

    static BIO_METHOD* get_capture_bio_method() {
        static BIO_METHOD* method = nullptr;
        if (!method) {
            method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "tls-capture");
            BIO_meth_set_write(method, bio_write);
            BIO_meth_set_read(method, bio_read);
            BIO_meth_set_ctrl(method, bio_ctrl);
            BIO_meth_set_create(method, bio_create);
            BIO_meth_set_destroy(method, bio_destroy);
        }
        return method;
    }

    // ─── TLS record parser ─────────────────────────────────────────

    void parse_tls_records(const uint8_t* data, size_t len, int direction) {
        read_buf.insert(read_buf.end(), data, data + len);

        while (read_buf.size() >= 5) {
            uint8_t content_type = read_buf[0];
            uint16_t record_len = ((uint16_t)read_buf[3] << 8) | read_buf[4];

            if (read_buf.size() < 5 + (size_t)record_len) break;

            // Capture ALL 0x17 records; filter in build_session_json using keylog secrets
            if (content_type == 0x17) {
                TlsRecord rec;
                rec.ciphertext.assign(read_buf.begin() + 5,
                                     read_buf.begin() + 5 + record_len);
                rec.record_number = (direction == 0) ? sc_record_seq++ : cs_record_seq++;
                rec.direction = direction;
                all_records.push_back(std::move(rec));
            }

            read_buf.erase(read_buf.begin(), read_buf.begin() + 5 + record_len);
        }
    }

    // ─── Keylog parsing and AEAD verification ──────────────────────

    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        bytes.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            bytes.push_back((uint8_t)std::stoul(hex.substr(i, 2), nullptr, 16));
        }
        return bytes;
    }

    // Parse a keylog line like "CLIENT_TRAFFIC_SECRET 0 <client_random> <secret>"
    // Extracts the last hex blob as the traffic secret, derives key + IV from it.
    static void parse_keylog_secret(const std::string& line,
                                     std::vector<uint8_t>& key_out,
                                     std::vector<uint8_t>& iv_out) {
        // Split by spaces, last token is the secret hex
        size_t last_space = line.rfind(' ');
        if (last_space == std::string::npos) return;
        std::string secret_hex = line.substr(last_space + 1);
        std::vector<uint8_t> secret = hex_to_bytes(secret_hex);

        // For ChaCha20-Poly1305 (SHA-256): key=32 bytes, IV=12 bytes
        // Derive using HKDF-Expand with labels "key" and "iv"
        key_out = hkdf_expand_label(secret, "key", 32);
        iv_out = hkdf_expand_label(secret, "iv", 12);
    }

    static std::vector<uint8_t> hkdf_expand_label(
            const std::vector<uint8_t>& secret,
            const std::string& label,
            size_t length) {
        // HKDF-Expand-Label(secret, label, length) per RFC 8446 §7.1
        // info = length (2 bytes) || len("tls13 " + label) (1 byte) || "tls13 " + label || 0x00 (context len)
        std::string full_label = "tls13 " + label;
        std::vector<uint8_t> info;
        info.push_back((uint8_t)(length >> 8));
        info.push_back((uint8_t)(length & 0xff));
        info.push_back((uint8_t)full_label.size());
        info.insert(info.end(), full_label.begin(), full_label.end());
        info.push_back(0x00);  // empty context

        // Use HKDF-Expand only (traffic secret is already extracted)
        std::vector<uint8_t> output(length);
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.data(), (int)secret.size());
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), (int)info.size());
        size_t out_len = length;
        EVP_PKEY_derive(ctx, output.data(), &out_len);
        EVP_PKEY_CTX_free(ctx);
        return output;
    }

    // Try to decrypt a TLS 1.3 record and check if the inner content type is 0x17 (app data).
    // Returns true if the record is application data, false if it's a handshake record.
    static bool is_app_data_record(const std::vector<uint8_t>& ciphertext,
                                    uint32_t record_number,
                                    const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& iv) {
        if (ciphertext.size() < 16) return false;  // too short for AEAD tag

        // Compute nonce = fixed_iv XOR record_number (big-endian, 12 bytes)
        uint8_t nonce[12];
        memcpy(nonce, iv.data(), 12);
        // XOR record_number into last 4 bytes (big-endian)
        nonce[11] ^= (uint8_t)(record_number & 0xff);
        nonce[10] ^= (uint8_t)((record_number >> 8) & 0xff);
        nonce[9]  ^= (uint8_t)((record_number >> 16) & 0xff);
        nonce[8]  ^= (uint8_t)((record_number >> 24) & 0xff);

        // AAD = TLS record header (0x17, 0x03, 0x03, len_hi, len_lo)
        uint16_t ct_len = (uint16_t)ciphertext.size();
        uint8_t aad[5] = {0x17, 0x03, 0x03, (uint8_t)(ct_len >> 8), (uint8_t)(ct_len & 0xff)};

        // Split ciphertext into encrypted_data + auth_tag (last 16 bytes)
        size_t enc_len = ciphertext.size() - 16;
        const uint8_t* enc_data = ciphertext.data();
        const uint8_t* auth_tag = ciphertext.data() + enc_len;

        // Try ChaCha20-Poly1305 first (most common with TLS_CHACHA20_POLY1305_SHA256)
        if (key.size() == 32) {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (ctx) {
                uint8_t plaintext[16400];
                int out_len = 0, final_len = 0;
                if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)auth_tag) == 1 &&
                    EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, 5) == 1 &&
                    EVP_DecryptUpdate(ctx, plaintext, &out_len, enc_data, (int)enc_len) == 1 &&
                    EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) == 1) {
                    // Decryption succeeded — check inner content type (last byte)
                    uint8_t inner_type = plaintext[out_len + final_len - 1];
                    EVP_CIPHER_CTX_free(ctx);
                    return inner_type == 0x17;  // application_data
                }
                EVP_CIPHER_CTX_free(ctx);
            }
        }

        // Try AES-256-GCM
        if (key.size() == 32) {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (ctx) {
                uint8_t plaintext[16400];
                int out_len = 0, final_len = 0;
                if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)auth_tag) == 1 &&
                    EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, 5) == 1 &&
                    EVP_DecryptUpdate(ctx, plaintext, &out_len, enc_data, (int)enc_len) == 1 &&
                    EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) == 1) {
                    uint8_t inner_type = plaintext[out_len + final_len - 1];
                    EVP_CIPHER_CTX_free(ctx);
                    return inner_type == 0x17;
                }
                EVP_CIPHER_CTX_free(ctx);
            }
        }

        // Try AES-128-GCM
        if (key.size() == 16) {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (ctx) {
                uint8_t plaintext[16400];
                int out_len = 0, final_len = 0;
                if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)auth_tag) == 1 &&
                    EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, 5) == 1 &&
                    EVP_DecryptUpdate(ctx, plaintext, &out_len, enc_data, (int)enc_len) == 1 &&
                    EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) == 1) {
                    uint8_t inner_type = plaintext[out_len + final_len - 1];
                    EVP_CIPHER_CTX_free(ctx);
                    return inner_type == 0x17;
                }
                EVP_CIPHER_CTX_free(ctx);
            }
        }

        // Decryption failed — assume it's a handshake record (wrong key)
        return false;
    }

    // Decrypt a TLS 1.3 AEAD record and return the plaintext (including hidden content type byte).
    // Tries ChaCha20-Poly1305, AES-256-GCM, AES-128-GCM.
    static std::vector<uint8_t> aead_decrypt(
            const std::vector<uint8_t>& ciphertext,
            const uint8_t nonce[12],
            const std::vector<uint8_t>& key,
            std::string& algorithm_out) {
        if (ciphertext.size() < 16) return {};

        uint16_t ct_len = (uint16_t)ciphertext.size();
        uint8_t aad[5] = {0x17, 0x03, 0x03, (uint8_t)(ct_len >> 8), (uint8_t)(ct_len & 0xff)};
        size_t enc_len = ciphertext.size() - 16;
        const uint8_t* enc_data = ciphertext.data();
        const uint8_t* auth_tag = ciphertext.data() + enc_len;

        struct Algo { const char* name; const EVP_CIPHER*(*fn)(); };
        Algo algos[3];
        int n_algos = 0;
        if (key.size() == 32) {
            algos[n_algos++] = {"chacha20-poly1305", EVP_chacha20_poly1305};
            algos[n_algos++] = {"aes-256-gcm", EVP_aes_256_gcm};
        }
        if (key.size() == 16) {
            algos[n_algos++] = {"aes-128-gcm", EVP_aes_128_gcm};
        }

        for (int i = 0; i < n_algos; i++) {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) continue;
            uint8_t plaintext[16400];
            int out_len = 0, final_len = 0;
            if (EVP_DecryptInit_ex(ctx, algos[i].fn(), nullptr, key.data(), nonce) == 1 &&
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)auth_tag) == 1 &&
                EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, 5) == 1 &&
                EVP_DecryptUpdate(ctx, plaintext, &out_len, enc_data, (int)enc_len) == 1 &&
                EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) == 1) {
                algorithm_out = algos[i].name;
                EVP_CIPHER_CTX_free(ctx);
                return std::vector<uint8_t>(plaintext, plaintext + out_len + final_len);
            }
            EVP_CIPHER_CTX_free(ctx);
        }
        return {};
    }

    // ─── Build session JSON ────────────────────────────────────────

    static std::string to_hex(const std::vector<uint8_t>& bytes) {
        static const char h[] = "0123456789abcdef";
        std::string r;
        r.reserve(bytes.size() * 2);
        for (uint8_t b : bytes) { r += h[b >> 4]; r += h[b & 0xf]; }
        return r;
    }

    json build_session_json() {
        // Parse keylog to extract traffic secrets
        std::vector<uint8_t> server_key, server_iv, client_key, client_iv;
        for (auto& line : keylog_lines) {
            if (line.find("SERVER_TRAFFIC_SECRET_") != std::string::npos &&
                line.find("HANDSHAKE") == std::string::npos) {
                parse_keylog_secret(line, server_key, server_iv);
            } else if (line.find("CLIENT_TRAFFIC_SECRET_") != std::string::npos &&
                       line.find("HANDSHAKE") == std::string::npos) {
                parse_keylog_secret(line, client_key, client_iv);
            }
        }

        // Filter all_records into app_records by decrypting and checking inner content type.
        // After TLS 1.3 handshake, the AEAD sequence resets to 0 for each direction.
        // We need to find the first record that decrypts as app data for each direction.
        app_records.clear();
        int sc_seq_offset = -1, cs_seq_offset = -1;

        // Find the correct starting sequence for each direction by probing
        for (auto& rec : all_records) {
            if (rec.direction == 0 && sc_seq_offset < 0 && !server_key.empty()) {
                for (int seq = 0; seq <= 5; seq++) {
                    if (is_app_data_record(rec.ciphertext, (uint32_t)seq, server_key, server_iv)) {
                        sc_seq_offset = seq;
                        break;
                    }
                }
            }
            if (rec.direction == 1 && cs_seq_offset < 0 && !client_key.empty()) {
                for (int seq = 0; seq <= 5; seq++) {
                    if (is_app_data_record(rec.ciphertext, (uint32_t)seq, client_key, client_iv)) {
                        cs_seq_offset = seq;
                        break;
                    }
                }
            }
        }

        uint32_t sc_app_seq = (sc_seq_offset >= 0) ? (uint32_t)sc_seq_offset : 0;
        uint32_t cs_app_seq = (cs_seq_offset >= 0) ? (uint32_t)cs_seq_offset : 0;

        for (auto& rec : all_records) {
            bool is_app = false;
            if (rec.direction == 0 && sc_seq_offset >= 0) {
                is_app = is_app_data_record(rec.ciphertext, sc_app_seq, server_key, server_iv);
                if (is_app) sc_app_seq++;
            } else if (rec.direction == 1 && cs_seq_offset >= 0) {
                is_app = is_app_data_record(rec.ciphertext, cs_app_seq, client_key, client_iv);
                if (is_app) cs_app_seq++;
            }

            if (is_app) {
                TlsRecord app_rec;
                app_rec.ciphertext = rec.ciphertext;
                app_rec.direction = rec.direction;
                // record_number is the TLS library's AEAD sequence (0-based after handshake)
                app_rec.record_number = (rec.direction == 0)
                    ? sc_app_seq - 1  // already incremented above
                    : cs_app_seq - 1;
                app_records.push_back(std::move(app_rec));
            }
        }

        // Build JSON
        std::vector<std::string> handshake_hex;
        for (auto& msg : handshake_msgs) {
            handshake_hex.push_back(to_hex(msg.data));
        }

        json priv_keys = json::object();
        priv_keys["X25519"] = to_hex(client_priv_key);

        json params;
        params["capturedPrivKeys"] = priv_keys;
        params["negotiatedCipherSuite"] = cipher_suite_name;
        params["handshakeMsgs"] = handshake_hex;

        json records = json::array();
        for (auto& rec : app_records) {
            json r;
            r["ciphertext"] = to_hex(rec.ciphertext);
            r["recordNumber"] = rec.record_number;
            r["direction"] = rec.direction == 0 ? "ServerToClient" : "ClientToServer";

            // Decrypt the record using traffic keys to fill in expected fields
            const auto& key = (rec.direction == 0) ? server_key : client_key;
            const auto& iv = (rec.direction == 0) ? server_iv : client_iv;
            std::vector<uint8_t> plaintext;
            std::string algorithm;
            std::vector<uint8_t> nonce(12);
            if (!key.empty() && !iv.empty()) {
                memcpy(nonce.data(), iv.data(), 12);
                nonce[11] ^= (uint8_t)(rec.record_number & 0xff);
                nonce[10] ^= (uint8_t)((rec.record_number >> 8) & 0xff);
                nonce[9]  ^= (uint8_t)((rec.record_number >> 16) & 0xff);
                nonce[8]  ^= (uint8_t)((rec.record_number >> 24) & 0xff);
                plaintext = aead_decrypt(rec.ciphertext, nonce.data(), key, algorithm);
            }

            json expected;
            if (!plaintext.empty()) {
                // TLS 1.3: last byte is the hidden content type, strip it
                std::vector<uint8_t> app_data(plaintext.begin(), plaintext.end() - 1);
                expected["plaintextHex"] = to_hex(app_data);
                expected["algorithm"] = algorithm;
                expected["nonceHex"] = to_hex(nonce);
                // AAD = TLS record header
                uint16_t ct_len = (uint16_t)rec.ciphertext.size();
                uint8_t aad_bytes[5] = {0x17, 0x03, 0x03,
                    (uint8_t)(ct_len >> 8), (uint8_t)(ct_len & 0xff)};
                std::vector<uint8_t> aad(aad_bytes, aad_bytes + 5);
                expected["aadHex"] = to_hex(aad);
            } else {
                expected["plaintextHex"] = "";
                expected["algorithm"] = "";
                expected["nonceHex"] = "";
                expected["aadHex"] = "";
            }
            r["expected"] = expected;
            records.push_back(std::move(r));
        }

        json session;
        session["name"] = cipher_suite_name;
        session["params"] = params;
        session["records"] = records;
        return session;
    }
};

}  // namespace octane

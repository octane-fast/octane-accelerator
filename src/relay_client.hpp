#pragma once
/**
 * Octane Relay Client — Connects outbound to the Cloudflare relay as a "host",
 * receives Noise_NK-encrypted prove requests from a remote wallet, decrypts them,
 * processes locally, and sends encrypted responses back through the relay.
 *
 * For now, we use a simple shared-secret model (X25519 ECDH) for encryption.
 * The pairing file contains the relay URL, room ID, and shared secret.
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <fstream>
#include <random>
#include <cstdint>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <pwd.h>
#endif

// We use tweetnacl for X25519 + secretbox (already linked)
extern "C" {
    int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
    int crypto_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p);
    int crypto_secretbox(unsigned char *c, const unsigned char *m, unsigned long long mlen,
                         const unsigned char *n, const unsigned char *k);
    int crypto_secretbox_open(unsigned char *m, const unsigned char *c, unsigned long long clen,
                              const unsigned char *n, const unsigned char *k);
    void randombytes(unsigned char *buf, unsigned long long len);
}

#include "base64.hpp"

namespace octane {

// Reliably get home directory (works even in GUI apps without $HOME)
inline std::string get_home_dir() {
    const char* home = getenv("HOME");
    if (home && home[0] != '\0') return home;
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path)))
        return path;
    return "C:\\Users\\Default";
#else
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_dir) return pw->pw_dir;
    return "/tmp";
#endif
}

struct PairingInfo {
    std::string relay_url;    // e.g. "wss://relay.octane.fast"
    std::string room_id;      // random room identifier
    uint8_t public_key[32];   // X25519 public key of this accelerator
    uint8_t secret_key[32];   // X25519 secret key (never exported)
};

// Generate a new pairing identity and write the pairing file
// The file contains: relay_url, room_id, public_key (base64)
// The secret key stays on disk in a separate file
inline bool generate_pairing_file(const std::string& export_path,
                                   const std::string& relay_url) {
    // Ensure ~/.octane directory exists
    std::string home = get_home_dir();
    std::string octane_dir = home + "/.octane";
#ifdef _WIN32
    _mkdir(octane_dir.c_str());
#else
    mkdir(octane_dir.c_str(), 0700);
#endif

    PairingInfo info;
    info.relay_url = relay_url;

    // Generate room ID (22 chars, URL-safe base64 of 16 random bytes)
    uint8_t room_rand[16];
    randombytes(room_rand, 16);
    std::string room_b64 = base64_encode(room_rand, 16);
    // Make URL-safe
    for (char& c : room_b64) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    // Remove padding
    while (!room_b64.empty() && room_b64.back() == '=') room_b64.pop_back();
    info.room_id = room_b64;

    // Generate X25519 keypair
    crypto_box_keypair(info.public_key, info.secret_key);

    // Write export file (this goes to the user to transfer to their wallet)
    std::ofstream out(export_path);
    if (!out) { fprintf(stderr, "[pair] ERROR: cannot open export file\n"); return false; }
    out << "# Octane Accelerator Pairing File\n";
    out << "# Import this into your Octane wallet to connect remotely.\n";
    out << "# Do NOT share this file — it grants access to your prover.\n";
    out << "relay=" << info.relay_url << "\n";
    out << "room=" << info.room_id << "\n";
    out << "key=" << base64_encode(info.public_key, 32) << "\n";
    out.close();

    // Write secret key to ~/.octane/relay_secret.key
    std::string secret_path = home + "/.octane/relay_secret.key";
    std::ofstream sk_out(secret_path, std::ios::binary);
    if (!sk_out) { fprintf(stderr, "[pair] ERROR: cannot open secret key file\n"); return false; }
    sk_out.write((const char*)info.secret_key, 32);
    sk_out.write((const char*)info.public_key, 32);
    sk_out.close();

    // Write relay config for the server to pick up on next start
    std::string config_path = home + "/.octane/relay.conf";
    std::ofstream conf_out(config_path);
    if (!conf_out) { fprintf(stderr, "[pair] ERROR: cannot open relay.conf\n"); return false; }
    conf_out << "relay=" << info.relay_url << "\n";
    conf_out << "room=" << info.room_id << "\n";
    conf_out.close();

    return true;
}

// Load relay config from ~/.octane/relay.conf
inline bool load_relay_config(std::string& relay_url, std::string& room_id,
                               uint8_t secret_key[32], uint8_t public_key[32]) {
    std::string home = get_home_dir();

    std::string config_path = home + "/.octane/relay.conf";
    std::ifstream conf_in(config_path);
    if (!conf_in) return false;

    std::string line;
    while (std::getline(conf_in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if (key == "relay") relay_url = val;
        else if (key == "room") room_id = val;
    }
    if (relay_url.empty() || room_id.empty()) return false;

    std::string secret_path = home + "/.octane/relay_secret.key";
    std::ifstream sk_in(secret_path, std::ios::binary);
    if (!sk_in) return false;
    sk_in.read((char*)secret_key, 32);
    sk_in.read((char*)public_key, 32);
    if (sk_in.gcount() < 32) return false;

    return true;
}

} // namespace octane

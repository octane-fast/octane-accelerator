#pragma once
/**
 * Relay Bridge — Connects outbound to the Cloudflare relay as "host".
 * Receives prove requests from remote wallets, forwards them to the local
 * WebSocket server at 127.0.0.1:PORT/prove, and relays results back.
 *
 * TLS backend: OpenSSL (all platforms)
 *
 * This runs in its own thread, started from main() if ~/.octane/relay.conf exists.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include <functional>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#define RELAY_CLOSE_SOCKET closesocket
#ifndef MSG_WAITALL
#define MSG_WAITALL 0x8
#endif
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#define RELAY_CLOSE_SOCKET close
#endif

// All platforms use OpenSSL for relay TLS
// Note: relay is not supported on x86_64 macOS (no OpenSSL available)
#if defined(__APPLE__) && defined(__x86_64__)
#define RELAY_BRIDGE_DISABLED 1
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

namespace octane {

#if RELAY_BRIDGE_DISABLED

// Stub — relay not available on this platform
class RelayBridge {
public:
    RelayBridge(const std::string&, const std::string&, uint16_t) {}
    void start() {}
    void stop() {}
};

#else

// --- Platform TLS abstraction ---

struct TlsConn {
    int sock = -1;
    SSL* ssl = nullptr;
    SSL_CTX* ctx = nullptr;
};



// Parse URL: wss://host[:port]/path
struct ParsedUrl {
    std::string host;
    uint16_t port = 443;
    std::string path;
};

inline bool parse_wss_url(const std::string& url, ParsedUrl& out) {
    if (url.substr(0, 6) != "wss://") return false;
    std::string rest = url.substr(6);
    size_t slash = rest.find('/');
    std::string hostport = (slash != std::string::npos) ? rest.substr(0, slash) : rest;
    out.path = (slash != std::string::npos) ? rest.substr(slash) : "/";
    size_t colon = hostport.find(':');
    if (colon != std::string::npos) {
        out.host = hostport.substr(0, colon);
        out.port = (uint16_t)std::atoi(hostport.substr(colon + 1).c_str());
    } else {
        out.host = hostport;
        out.port = 443;
    }
    return !out.host.empty();
}

// TCP connect to host:port
inline int tcp_connect(const std::string& host, uint16_t port) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) return -1;
    int sock = -1;
    for (auto* p = res; p; p = p->ai_next) {
        sock = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, (int)p->ai_addrlen) == 0) break;
        RELAY_CLOSE_SOCKET(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

// TLS connect
inline bool tls_connect(TlsConn& conn, const std::string& host, uint16_t port) {
    conn.sock = tcp_connect(host, port);
    if (conn.sock < 0) return false;

    static bool ssl_inited = false;
    if (!ssl_inited) {
        SSL_library_init();
        SSL_load_error_strings();
        ssl_inited = true;
    }
    conn.ctx = SSL_CTX_new(TLS_client_method());
    if (!conn.ctx) { RELAY_CLOSE_SOCKET(conn.sock); return false; }
    SSL_CTX_set_default_verify_paths(conn.ctx);
    conn.ssl = SSL_new(conn.ctx);
    SSL_set_fd(conn.ssl, conn.sock);
    SSL_set_tlsext_host_name(conn.ssl, host.c_str());
    if (SSL_connect(conn.ssl) <= 0) {
        fprintf(stderr, "[relay] TLS handshake failed\n");
        SSL_free(conn.ssl);
        SSL_CTX_free(conn.ctx);
        RELAY_CLOSE_SOCKET(conn.sock);
        return false;
    }
    return true;
}

inline int tls_read(TlsConn& conn, void* buf, size_t len) {
    int r = SSL_read(conn.ssl, buf, (int)(len > 65536 ? 65536 : len));
    return r;
}

inline int tls_write(TlsConn& conn, const void* buf, size_t len) {
    return SSL_write(conn.ssl, buf, (int)len);
}

inline void tls_close(TlsConn& conn) {
    if (conn.ssl) { SSL_shutdown(conn.ssl); SSL_free(conn.ssl); conn.ssl = nullptr; }
    if (conn.ctx) { SSL_CTX_free(conn.ctx); conn.ctx = nullptr; }
    if (conn.sock >= 0) { RELAY_CLOSE_SOCKET(conn.sock); conn.sock = -1; }
}

// --- WebSocket Client (over TLS) ---

// Read exactly n bytes from TLS connection
inline bool tls_recv_exact(TlsConn& conn, void* buf, size_t n) {
    char* p = (char*)buf;
    size_t got = 0;
    while (got < n) {
        int r = tls_read(conn, p + got, n - got);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

// Generate random bytes for WebSocket mask
inline void ws_random_mask(uint8_t mask[4]) {
    // Simple PRNG for mask (doesn't need crypto strength)
    static uint32_t state = (uint32_t)std::chrono::steady_clock::now().time_since_epoch().count();
    for (int i = 0; i < 4; i++) {
        state = state * 1664525 + 1013904223;
        mask[i] = (uint8_t)(state >> 24);
    }
}

// Perform WebSocket client handshake over TLS
inline bool ws_client_handshake(TlsConn& conn, const std::string& host, const std::string& path) {
    // Generate random key (16 bytes → base64)
    uint8_t key_bytes[16];
    ws_random_mask(key_bytes); ws_random_mask(key_bytes + 4);
    ws_random_mask(key_bytes + 8); ws_random_mask(key_bytes + 12);

    // Reuse ws_detail base64 encoder
    std::string key_b64 = ws_detail::base64_encode_raw(key_bytes, 16);

    std::string req = "GET " + path + " HTTP/1.1\r\n";
    req += "Host: " + host + "\r\n";
    req += "Upgrade: websocket\r\n";
    req += "Connection: Upgrade\r\n";
    req += "Sec-WebSocket-Key: " + key_b64 + "\r\n";
    req += "Sec-WebSocket-Version: 13\r\n";
    req += "\r\n";

    if (tls_write(conn, req.c_str(), req.size()) <= 0) return false;

    // Read response (look for 101)
    std::string resp;
    char c;
    while (resp.size() < 4096) {
        if (tls_read(conn, &c, 1) <= 0) return false;
        resp += c;
        if (resp.size() >= 4 && resp.substr(resp.size() - 4) == "\r\n\r\n") break;
    }

    return resp.find("101") != std::string::npos;
}

// Read one WebSocket frame from relay (server sends unmasked)
inline bool ws_client_read(TlsConn& conn, std::string& out) {
    out.clear();
    while (true) {
        uint8_t hdr[2];
        if (!tls_recv_exact(conn, hdr, 2)) return false;

        bool fin = (hdr[0] & 0x80) != 0;
        int opcode = hdr[0] & 0x0F;
        bool masked = (hdr[1] & 0x80) != 0;
        uint64_t payload_len = hdr[1] & 0x7F;

        if (opcode == 0x08) return false; // Close
        if (opcode == 0x09) { // Ping → Pong
            if (payload_len == 126) {
                uint8_t ext[2]; if (!tls_recv_exact(conn, ext, 2)) return false;
                payload_len = ((uint64_t)ext[0] << 8) | ext[1];
            }
            std::string tmp((size_t)payload_len, '\0');
            if (payload_len > 0 && !tls_recv_exact(conn, &tmp[0], (size_t)payload_len)) return false;
            uint8_t pong[2] = {0x8A, 0x00};
            tls_write(conn, pong, 2);
            continue;
        }
        if (opcode == 0x0A) { // Pong — just consume payload and skip
            if (payload_len == 126) {
                uint8_t ext[2]; if (!tls_recv_exact(conn, ext, 2)) return false;
                payload_len = ((uint64_t)ext[0] << 8) | ext[1];
            }
            if (payload_len > 0) {
                std::string tmp((size_t)payload_len, '\0');
                if (!tls_recv_exact(conn, &tmp[0], (size_t)payload_len)) return false;
            }
            continue;
        }

        if (payload_len == 126) {
            uint8_t ext[2]; if (!tls_recv_exact(conn, ext, 2)) return false;
            payload_len = ((uint64_t)ext[0] << 8) | ext[1];
        } else if (payload_len == 127) {
            uint8_t ext[8]; if (!tls_recv_exact(conn, ext, 8)) return false;
            payload_len = 0;
            for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | ext[i];
        }

        // Skip mask key if present (shouldn't be from server, but handle it)
        uint8_t mask_key[4] = {0};
        if (masked) {
            if (!tls_recv_exact(conn, mask_key, 4)) return false;
        }

        if (out.size() + payload_len > 10 * 1024 * 1024) return false;
        size_t prev = out.size();
        out.resize(prev + (size_t)payload_len);
        if (payload_len > 0 && !tls_recv_exact(conn, &out[prev], (size_t)payload_len)) return false;

        // Unmask if needed
        if (masked) {
            for (size_t i = 0; i < (size_t)payload_len; i++) {
                out[prev + i] ^= mask_key[i % 4];
            }
        }

        if (fin) break;
    }
    return true;
}

// Send a masked WebSocket text frame (client → server must be masked per RFC 6455)
inline bool ws_client_send(TlsConn& conn, const std::string& msg) {
    std::vector<uint8_t> frame;
    frame.push_back(0x81); // FIN + TEXT

    uint8_t mask[4];
    ws_random_mask(mask);

    if (msg.size() < 126) {
        frame.push_back(0x80 | (uint8_t)msg.size()); // MASK bit set
    } else if (msg.size() <= 65535) {
        frame.push_back(0x80 | 126);
        frame.push_back((uint8_t)(msg.size() >> 8));
        frame.push_back((uint8_t)(msg.size() & 0xFF));
    } else {
        frame.push_back(0x80 | 127);
        uint64_t len = msg.size();
        for (int i = 7; i >= 0; i--) frame.push_back((uint8_t)(len >> (i * 8)));
    }

    frame.insert(frame.end(), mask, mask + 4);
    for (size_t i = 0; i < msg.size(); i++) {
        frame.push_back((uint8_t)msg[i] ^ mask[i % 4]);
    }

    size_t total = frame.size();
    size_t sent = 0;
    while (sent < total) {
        int w = tls_write(conn, frame.data() + sent, total - sent);
        if (w <= 0) return false;
        sent += w;
    }
    return true;
}

// --- Local WebSocket client (plaintext, to 127.0.0.1) ---

inline int local_ws_connect(uint16_t port) {
    int sock = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        RELAY_CLOSE_SOCKET(sock);
        return -1;
    }
    return sock;
}

inline bool local_ws_handshake(int sock) {
    std::string req = "GET /prove HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
                      "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                      "Sec-WebSocket-Version: 13\r\n\r\n";
    if (send(sock, req.c_str(), (int)req.size(), 0) <= 0) return false;
    // Read 101 response
    std::string resp;
    char c;
    while (resp.size() < 4096) {
        if (recv(sock, &c, 1, 0) <= 0) return false;
        resp += c;
        if (resp.size() >= 4 && resp.substr(resp.size() - 4) == "\r\n\r\n") break;
    }
    return resp.find("101") != std::string::npos;
}

// Send masked frame to local server (client must mask)
inline bool local_ws_send(int sock, const std::string& msg) {
    std::vector<uint8_t> frame;
    frame.push_back(0x81);
    uint8_t mask[4]; ws_random_mask(mask);
    if (msg.size() < 126) {
        frame.push_back(0x80 | (uint8_t)msg.size());
    } else if (msg.size() <= 65535) {
        frame.push_back(0x80 | 126);
        frame.push_back((uint8_t)(msg.size() >> 8));
        frame.push_back((uint8_t)(msg.size() & 0xFF));
    } else {
        frame.push_back(0x80 | 127);
        uint64_t len = msg.size();
        for (int i = 7; i >= 0; i--) frame.push_back((uint8_t)(len >> (i * 8)));
    }
    frame.insert(frame.end(), mask, mask + 4);
    for (size_t i = 0; i < msg.size(); i++) frame.push_back((uint8_t)msg[i] ^ mask[i % 4]);
    return send(sock, (const char*)frame.data(), (int)frame.size(), 0) == (int)frame.size();
}

// Read unmasked frame from local server
inline bool local_ws_read(int sock, std::string& out) {
    out.clear();
    while (true) {
        uint8_t hdr[2];
        if (recv(sock, (char*)hdr, 2, MSG_WAITALL) != 2) return false;
        bool fin = (hdr[0] & 0x80) != 0;
        int opcode = hdr[0] & 0x0F;
        if (opcode == 0x08) return false;
        uint64_t payload_len = hdr[1] & 0x7F;
        if (payload_len == 126) {
            uint8_t ext[2]; if (recv(sock, (char*)ext, 2, MSG_WAITALL) != 2) return false;
            payload_len = ((uint64_t)ext[0] << 8) | ext[1];
        } else if (payload_len == 127) {
            uint8_t ext[8]; if (recv(sock, (char*)ext, 8, MSG_WAITALL) != 8) return false;
            payload_len = 0; for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | ext[i];
        }
        if (out.size() + payload_len > 10 * 1024 * 1024) return false;
        size_t prev = out.size();
        out.resize(prev + (size_t)payload_len);
        if (payload_len > 0 && recv(sock, &out[prev], (int)payload_len, MSG_WAITALL) != (int)payload_len) return false;
        if (fin) break;
    }
    return true;
}

// --- The Bridge ---

class RelayBridge {
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::string relay_url_;
    std::string room_id_;
    uint16_t local_port_;

public:
    RelayBridge(const std::string& relay_url, const std::string& room_id, uint16_t local_port)
        : relay_url_(relay_url), room_id_(room_id), local_port_(local_port) {}

    ~RelayBridge() { stop(); }

    void start() {
        running_ = true;
        thread_ = std::thread([this]() { run_loop(); });
        thread_.detach();
    }

    void stop() {
        running_ = false;
    }

private:
    void run_loop() {
        while (running_) {
            if (!connect_and_serve()) {
                fprintf(stderr, "[relay] Disconnected, reconnecting in 5s...\n");
            }

            // Backoff before reconnect
            for (int i = 0; i < 50 && running_; i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    bool connect_and_serve() {
        ParsedUrl url;
        std::string full_url = relay_url_;
        if (!parse_wss_url(full_url, url)) {
            fprintf(stderr, "[relay] Invalid URL: %s\n", full_url.c_str());
            return false;
        }

        std::string base_path = url.path;
        if (!base_path.empty() && base_path.back() == '/') base_path.pop_back();
        std::string ws_path = base_path + "/room/" + room_id_ + "?role=host";

        TlsConn conn{};
        if (!tls_connect(conn, url.host, url.port)) {
            fprintf(stderr, "[relay] TLS connect failed\n");
            return false;
        }

        if (!ws_client_handshake(conn, url.host, ws_path)) {
            fprintf(stderr, "[relay] WebSocket handshake failed\n");
            tls_close(conn);
            return false;
        }

        fprintf(stderr, "[relay] Connected! Waiting for requests...\n");

        auto last_ping = std::chrono::steady_clock::now();

        while (running_) {
            // Check if TLS layer has buffered data before calling select()
            bool has_pending = (SSL_pending(conn.ssl) > 0);

            if (!has_pending) {
                // Use select() to wait for data with timeout (for keepalive pings)
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(conn.sock, &fds);
                struct timeval tv;
                tv.tv_sec = 20;
                tv.tv_usec = 0;
                int sel = select(conn.sock + 1, &fds, nullptr, nullptr, &tv);

                if (sel == 0) {
                    // Timeout — send ping to keep connection alive
                    uint8_t ping_full[6] = {0x89, 0x80, 0x01, 0x02, 0x03, 0x04};
                    if (tls_write(conn, ping_full, 6) <= 0) break;
                    last_ping = std::chrono::steady_clock::now();
                    continue;
                }
                if (sel < 0) break;
            }

            std::string msg;
            if (!ws_client_read(conn, msg)) break;

            // Check for control messages
            if (msg.find("\"peer_connected\"") != std::string::npos) {
                fprintf(stderr, "[relay] Remote wallet connected\n");
                continue;
            }
            if (msg.find("\"peer_disconnected\"") != std::string::npos) {
                fprintf(stderr, "[relay] Remote wallet disconnected\n");
                continue;
            }

            // This is a prove request — forward to local server
            fprintf(stderr, "[relay] Got prove request (%zu bytes)\n", msg.size());
            forward_to_local(conn, msg);
        }

        tls_close(conn);
        return true;
    }

    void forward_to_local(TlsConn& relay_conn, const std::string& request) {
        int local_sock = local_ws_connect(local_port_);
        if (local_sock < 0) {
            ws_client_send(relay_conn, R"({"type":"error","error":"Local prover unavailable"})");
            return;
        }

        if (!local_ws_handshake(local_sock)) {
            RELAY_CLOSE_SOCKET(local_sock);
            ws_client_send(relay_conn, R"({"type":"error","error":"Local WS handshake failed"})");
            return;
        }

        // Send prove request to local server
        if (!local_ws_send(local_sock, request)) {
            RELAY_CLOSE_SOCKET(local_sock);
            ws_client_send(relay_conn, R"({"type":"error","error":"Failed to send to local prover"})");
            return;
        }

        // Read all responses from local server and forward to relay
        while (true) {
            std::string response;
            if (!local_ws_read(local_sock, response)) break;

            // Forward to relay
            ws_client_send(relay_conn, response);

            // If this is a final message (result or error), we're done
            if (response.find("\"type\":\"result\"") != std::string::npos ||
                response.find("\"type\":\"error\"") != std::string::npos) {
                break;
            }
        }

        RELAY_CLOSE_SOCKET(local_sock);
    }
};

#endif // !RELAY_BRIDGE_DISABLED

} // namespace octane

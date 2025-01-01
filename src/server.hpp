#pragma once
/**
 * Octane Accelerator — Minimal HTTP + WebSocket server on a single port.
 * Handles HTTP requests (GET /health, POST /decrypt) and WebSocket upgrades (GET /prove).
 * Cross-platform: POSIX (Mac/Linux) + Winsock2 (Windows).
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <functional>
#include <atomic>
#include <mutex>
#include <algorithm>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#define CLOSE_SOCKET closesocket
#define SOCKET_ERROR_VAL INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
typedef int socket_t;
#define CLOSE_SOCKET close
#define SOCKET_ERROR_VAL (-1)
#define INVALID_SOCKET (-1)
#endif

// Minimal SHA-1 for WebSocket handshake (RFC 6455)
namespace ws_detail {

inline void sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476, h4 = 0xC3D2E1F0;
    size_t msg_len = len + 1 + 8;
    size_t padded = ((msg_len + 63) / 64) * 64;
    std::vector<uint8_t> msg(padded, 0);
    memcpy(msg.data(), data, len);
    msg[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        msg[padded - 1 - i] = (uint8_t)(bits >> (i * 8));

    for (size_t chunk = 0; chunk < padded; chunk += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)msg[chunk + i*4] << 24) | ((uint32_t)msg[chunk + i*4+1] << 16) |
                   ((uint32_t)msg[chunk + i*4+2] << 8) | msg[chunk + i*4+3];
        for (int i = 16; i < 80; i++) {
            uint32_t x = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
            w[i] = (x << 1) | (x >> 31);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    auto put32 = [&](uint8_t* p, uint32_t v) {
        p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
    };
    put32(out, h0); put32(out+4, h1); put32(out+8, h2); put32(out+12, h3); put32(out+16, h4);
}

inline std::string base64_encode_raw(const uint8_t* data, size_t len) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string r;
    r.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = (uint32_t)data[i] << 16;
        if (i + 1 < len) n |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];
        r += T[(n >> 18) & 63];
        r += T[(n >> 12) & 63];
        r += (i + 1 < len) ? T[(n >> 6) & 63] : '=';
        r += (i + 2 < len) ? T[n & 63] : '=';
    }
    return r;
}

} // namespace ws_detail

namespace octane {

// Read exactly n bytes from socket (blocking)
inline bool recv_exact(socket_t sock, void* buf, size_t n) {
    char* p = (char*)buf;
    size_t got = 0;
    while (got < n) {
        int r = recv(sock, p + got, (int)(n - got), 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

// Read until we find \r\n\r\n (HTTP header end)
inline std::string recv_http_header(socket_t sock) {
    std::string buf;
    buf.reserve(4096);
    char c;
    while (buf.size() < 8192) {
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) break;
        buf += c;
        if (buf.size() >= 4 && buf.substr(buf.size()-4) == "\r\n\r\n")
            break;
    }
    return buf;
}

// Parse HTTP header value (case-insensitive key search)
inline std::string get_header(const std::string& headers, const std::string& key) {
    std::string lkey = key;
    std::transform(lkey.begin(), lkey.end(), lkey.begin(), ::tolower);
    size_t pos = 0;
    while (pos < headers.size()) {
        size_t eol = headers.find("\r\n", pos);
        if (eol == std::string::npos) break;
        std::string line = headers.substr(pos, eol - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string k = line.substr(0, colon);
            std::transform(k.begin(), k.end(), k.begin(), ::tolower);
            if (k == lkey) {
                std::string v = line.substr(colon + 1);
                size_t start = v.find_first_not_of(' ');
                return start != std::string::npos ? v.substr(start) : "";
            }
        }
        pos = eol + 2;
    }
    return "";
}

// Parse HTTP request line → method, path
inline bool parse_request_line(const std::string& headers, std::string& method, std::string& path) {
    size_t eol = headers.find("\r\n");
    if (eol == std::string::npos) return false;
    std::string line = headers.substr(0, eol);
    size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) return false;
    size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return false;
    method = line.substr(0, sp1);
    path = line.substr(sp1 + 1, sp2 - sp1 - 1);
    return true;
}

// Read HTTP body given Content-Length
inline std::string recv_body(socket_t sock, const std::string& headers) {
    std::string cl = get_header(headers, "Content-Length");
    if (cl.empty()) return "";
    int len = std::atoi(cl.c_str());
    if (len <= 0 || len > 10 * 1024 * 1024) return "";
    std::string body(len, '\0');
    if (!recv_exact(sock, &body[0], len)) return "";
    return body;
}

// Send HTTP response
inline void send_http(socket_t sock, int code, const std::string& status_text,
                      const std::string& body, const std::string& content_type = "application/json") {
    std::string resp = "HTTP/1.1 " + std::to_string(code) + " " + status_text + "\r\n";
    resp += "Content-Type: " + content_type + "\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Access-Control-Allow-Origin: *\r\n";
    resp += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    resp += "Access-Control-Allow-Headers: Content-Type\r\n";
    resp += "Connection: close\r\n";
    resp += "\r\n";
    resp += body;
    send(sock, resp.c_str(), (int)resp.size(), 0);
}

// WebSocket: complete upgrade handshake
inline bool ws_upgrade(socket_t sock, const std::string& headers) {
    std::string key = get_header(headers, "Sec-WebSocket-Key");
    if (key.empty()) return false;

    // Concatenate with magic GUID (RFC 6455 / RFC 7936)
    std::string accept_input = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t hash[20];
    ws_detail::sha1((const uint8_t*)accept_input.c_str(), accept_input.size(), hash);
    std::string accept = ws_detail::base64_encode_raw(hash, 20);

    std::string resp = "HTTP/1.1 101 Switching Protocols\r\n";
    resp += "Upgrade: websocket\r\n";
    resp += "Connection: Upgrade\r\n";
    resp += "Sec-WebSocket-Accept: " + accept + "\r\n";
    resp += "\r\n";
    send(sock, resp.c_str(), (int)resp.size(), 0);
    return true;
}

// WebSocket: read one complete message (reassembles fragmented frames, up to ~10MB)
inline bool ws_read_text(socket_t sock, std::string& out) {
    out.clear();
    while (true) {
        uint8_t hdr[2];
        if (!recv_exact(sock, hdr, 2)) return false;

        bool fin = (hdr[0] & 0x80) != 0;
        int opcode = hdr[0] & 0x0F;
        bool masked = (hdr[1] & 0x80) != 0;
        uint64_t payload_len = hdr[1] & 0x7F;

        // Close frame
        if (opcode == 0x08) return false;
        // Ping — send pong and continue
        if (opcode == 0x09) {
            if (payload_len == 126) {
                uint8_t ext[2]; if (!recv_exact(sock, ext, 2)) return false;
                payload_len = ((uint64_t)ext[0] << 8) | ext[1];
            } else if (payload_len == 127) {
                uint8_t ext[8]; if (!recv_exact(sock, ext, 8)) return false;
                payload_len = 0; for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | ext[i];
            }
            std::string tmp((size_t)payload_len, '\0');
            if (payload_len > 0) { if (!recv_exact(sock, &tmp[0], (size_t)payload_len)) return false; }
            uint8_t pong[2] = {0x8A, 0x00};
            send(sock, (const char*)pong, 2, 0);
            continue;
        }

        if (payload_len == 126) {
            uint8_t ext[2];
            if (!recv_exact(sock, ext, 2)) return false;
            payload_len = ((uint64_t)ext[0] << 8) | ext[1];
        } else if (payload_len == 127) {
            uint8_t ext[8];
            if (!recv_exact(sock, ext, 8)) return false;
            payload_len = 0;
            for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | ext[i];
        }

        uint8_t mask[4] = {0};
        if (masked) {
            if (!recv_exact(sock, mask, 4)) return false;
        }

        // Sanity limit on total assembled message (20MB — large PVAC proofs)
        if (out.size() + payload_len > 20 * 1024 * 1024) {
            fprintf(stderr, "[ws] message too large: %llu + %llu > 20MB limit\n",
                    (unsigned long long)out.size(), (unsigned long long)payload_len);
            return false;
        }

        size_t prev_size = out.size();
        out.resize(prev_size + (size_t)payload_len);
        if (payload_len > 0) {
            if (!recv_exact(sock, &out[prev_size], (size_t)payload_len)) return false;
            if (masked) {
                for (size_t i = 0; i < (size_t)payload_len; i++)
                    out[prev_size + i] ^= mask[i % 4];
            }
        }

        if (fin) break;
    }
    return true;
}

// WebSocket: send text frame (server → client, unmasked)
inline bool ws_send_text(socket_t sock, const std::string& msg) {
    std::vector<uint8_t> frame;
    frame.push_back(0x81); // FIN + TEXT opcode

    if (msg.size() < 126) {
        frame.push_back((uint8_t)msg.size());
    } else if (msg.size() <= 65535) {
        frame.push_back(126);
        frame.push_back((uint8_t)(msg.size() >> 8));
        frame.push_back((uint8_t)(msg.size() & 0xFF));
    } else {
        frame.push_back(127);
        uint64_t len = msg.size();
        for (int i = 7; i >= 0; i--)
            frame.push_back((uint8_t)(len >> (i * 8)));
    }

    frame.insert(frame.end(), msg.begin(), msg.end());
    int sent = send(sock, (const char*)frame.data(), (int)frame.size(), 0);
    return sent == (int)frame.size();
}

// WebSocket: send close frame
inline void ws_send_close(socket_t sock) {
    uint8_t frame[] = {0x88, 0x00}; // FIN + CLOSE, 0-length
    send(sock, (const char*)frame, 2, 0);
}

// --- Server ---

using HttpHandler = std::function<void(socket_t sock, const std::string& method,
                                       const std::string& path, const std::string& headers)>;
using WsHandler = std::function<void(socket_t sock)>;

class Server {
    socket_t listen_sock_ = INVALID_SOCKET;
    std::atomic<bool> running_{false};
    HttpHandler http_handler_;
    WsHandler ws_handler_;
    uint16_t port_;

public:
    Server(uint16_t port, HttpHandler http_handler, WsHandler ws_handler)
        : port_(port), http_handler_(std::move(http_handler)), ws_handler_(std::move(ws_handler)) {}

    ~Server() { stop(); }

    bool start() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        listen_sock_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_sock_ == INVALID_SOCKET) return false;

        int opt = 1;
        setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // localhost only
        addr.sin_port = htons(port_);

        if (bind(listen_sock_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            CLOSE_SOCKET(listen_sock_);
            listen_sock_ = INVALID_SOCKET;
            return false;
        }

        if (listen(listen_sock_, 16) < 0) {
            CLOSE_SOCKET(listen_sock_);
            listen_sock_ = INVALID_SOCKET;
            return false;
        }

        running_ = true;
        return true;
    }

    void run() {
        while (running_) {
            struct sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            socket_t client = accept(listen_sock_, (struct sockaddr*)&client_addr, &client_len);
            if (client == INVALID_SOCKET) continue;

            // Set TCP_NODELAY for low latency
            int flag = 1;
            setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char*)&flag, sizeof(flag));

            std::thread([this, client]() {
                handle_connection(client);
            }).detach();
        }
    }

    void stop() {
        running_ = false;
        if (listen_sock_ != INVALID_SOCKET) {
            CLOSE_SOCKET(listen_sock_);
            listen_sock_ = INVALID_SOCKET;
        }
    }

private:
    void handle_connection(socket_t sock) {
        std::string headers = recv_http_header(sock);
        if (headers.empty()) { CLOSE_SOCKET(sock); return; }

        std::string method, path;
        if (!parse_request_line(headers, method, path)) {
            CLOSE_SOCKET(sock);
            return;
        }

        // Check for WebSocket upgrade
        std::string upgrade = get_header(headers, "Upgrade");
        std::transform(upgrade.begin(), upgrade.end(), upgrade.begin(), ::tolower);

        if (upgrade == "websocket" && path == "/prove") {
            if (ws_upgrade(sock, headers)) {
                ws_handler_(sock);
            }
            CLOSE_SOCKET(sock);
        } else {
            http_handler_(sock, method, path, headers);
            CLOSE_SOCKET(sock);
        }
    }
};

} // namespace octane

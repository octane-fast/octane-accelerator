#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace octane {

inline std::string base64_encode(const uint8_t* data, size_t len) {
    static const char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

inline std::vector<uint8_t> base64_decode(const std::string& s) {
    static int D[256];
    static bool init = false;
    if (!init) {
        memset(D, -1, sizeof(D));
        const char* T =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; T[i]; i++) D[(uint8_t)T[i]] = i;
        D[(uint8_t)'='] = 0;
        init = true;
    }
    std::vector<uint8_t> r;
    r.reserve(s.size() * 3 / 4);
    for (size_t i = 0; i + 3 < s.size(); i += 4) {
        uint32_t n = (D[(uint8_t)s[i]] << 18) | (D[(uint8_t)s[i + 1]] << 12) |
                     (D[(uint8_t)s[i + 2]] << 6) | D[(uint8_t)s[i + 3]];
        r.push_back((n >> 16) & 0xFF);
        if (s[i + 2] != '=') r.push_back((n >> 8) & 0xFF);
        if (s[i + 3] != '=') r.push_back(n & 0xFF);
    }
    return r;
}

} // namespace octane

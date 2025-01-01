/**
 * test_tls_recorder.cpp
 *
 * Standalone test for the native TLS session recorder.
 * Records a TLS session with the given host and outputs JSON
 * that can be validated by the TS decrypt function.
 *
 * Usage:  ./test_tls_recorder <host> [port]
 * Output: JSON session to stdout, status to stderr
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "src/tls_recorder.hpp"
#include "lib/json.hpp"

using json = nlohmann::json;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <host> [port]\n", argv[0]);
        return 1;
    }

    std::string host = argv[1];
    int port = 443;
    if (argc > 2) port = std::atoi(argv[2]);

    fprintf(stderr, "Recording TLS session with %s:%d\n", host.c_str(), port);

    octane::TlsRecorder recorder;
    json session = recorder.record(host, port, [](const std::string& step) {
        fprintf(stderr, "  → %s\n", step.c_str());
    });

    if (session.contains("error")) {
        fprintf(stderr, "❌ Error: %s\n", session["error"].get<std::string>().c_str());
        return 1;
    }

    // Output session JSON to stdout
    std::string output = session.dump(2);
    printf("%s\n", output.c_str());

    // Summary to stderr
    fprintf(stderr, "\n✅ Session captured:\n");
    fprintf(stderr, "   Cipher: %s\n", session.value("name", "?").c_str());
    fprintf(stderr, "   Handshake msgs: %d\n", (int)session["params"]["handshakeMsgs"].size());
    fprintf(stderr, "   App records: %d\n", (int)session["records"].size());

    auto& records = session["records"];
    for (int i = 0; i < (int)records.size(); i++) {
        auto& r = records[i];
        std::string ct = r.value("ciphertext", "");
        fprintf(stderr, "   Record %d (%s): %d bytes ciphertext\n",
                i,
                r.value("direction", "?").c_str(),
                (int)(ct.size() / 2));
    }

    return 0;
}

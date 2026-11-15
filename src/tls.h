// TLS handshake parsing (no decryption) and JA4 / JA4S fingerprints (FoxIO JA4+ spec).
// Input is the reassembled TCP byte stream of one direction, starting at the first TLS record.
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct ClientHello {
    uint16_t legacy_version = 0;               // ClientHello.legacy_version, e.g. 0x0303
    std::vector<uint16_t> ciphers;             // wire order, GREASE included
    std::vector<uint16_t> extensions;          // wire order, GREASE included
    std::vector<uint16_t> sig_algs;            // signature_algorithms (13) list, wire order
    std::vector<uint16_t> supported_versions;  // supported_versions (43) list, wire order
    std::string sni;                           // server_name (0) host_name, empty if absent
    std::string alpn;                          // first ALPN protocol (16), empty if absent
};

struct ServerHello {
    uint16_t legacy_version = 0;
    uint16_t cipher = 0;
    std::vector<uint16_t> extensions;  // wire order
    uint16_t selected_version = 0;     // from supported_versions (43), 0 if absent
    std::string alpn;                  // selected ALPN protocol, empty if absent
};

struct ServerFlight {
    std::optional<ServerHello> hello;
    std::vector<uint8_t> leaf_cert_der;  // first Certificate entry; empty if hidden (TLS 1.3) or absent
};

// Parse handshake messages spread over one or more TLS records (type 22). Stops at the first
// non-handshake record. Returns nullopt/empty on malformed or truncated input; never reads out of bounds.
std::optional<ClientHello> parse_client_hello(const std::vector<uint8_t>& stream);
ServerFlight parse_server_flight(const std::vector<uint8_t>& stream);

std::string ja4(const ClientHello& ch);    // e.g. "t13d1516h2_8daaf6152771_e5627efa2ab1"
std::string ja4s(const ServerHello& sh);   // e.g. "t120400_c02f_..."
std::string key_hash(const std::vector<uint8_t>& cert_der);  // SHA-256 of SubjectPublicKeyInfo DER, first 16 hex; "" on error
std::string tls_version_name(uint16_t v);  // 0x0304 -> "1.3", 0x0303 -> "1.2", ...

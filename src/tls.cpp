#include "tls.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace {
using Bytes = std::vector<uint8_t>;

// Bounds-checked big-endian cursor over untrusted bytes. Any overrun clears `ok` and yields zeros.
struct Reader {
    const uint8_t* p = nullptr;
    size_t n = 0;
    bool ok = true;
    bool need(size_t k) { return ok = ok && n >= k; }
    uint32_t u(int bytes) {
        if (!need(bytes)) return 0;
        uint32_t v = 0;
        for (int i = 0; i < bytes; i++) v = v << 8 | p[i];
        p += bytes; n -= bytes;
        return v;
    }
    Reader sub(size_t k) {
        if (!need(k)) return {nullptr, 0, false};
        Reader r{p, k};
        p += k; n -= k;
        return r;
    }
};

// Concatenate payloads of leading type-22 records; stop at the first other or truncated record.
Bytes handshake_bytes(const Bytes& stream) {
    Bytes out;
    Reader r{stream.data(), stream.size()};
    while (r.n >= 5 && r.u(1) == 22) {
        r.u(2);
        Reader body = r.sub(r.u(2));
        if (!body.ok) break;
        out.insert(out.end(), body.p, body.p + body.n);
    }
    return out;
}

// Body of the first handshake message of `type`, or a not-ok reader.
Reader find_message(const Bytes& hs, uint8_t type) {
    Reader r{hs.data(), hs.size()};
    while (r.ok && r.n > 0) {
        uint8_t t = r.u(1);
        Reader body = r.sub(r.u(3));
        if (body.ok && t == type) return body;
    }
    return {nullptr, 0, false};
}

std::vector<uint16_t> u16_list(Reader r, int len_bytes) {
    Reader l = r.sub(r.u(len_bytes));
    std::vector<uint16_t> v;
    while (l.n >= 2) v.push_back(l.u(2));
    return v;
}

std::string first_alpn(Reader r) {  // ProtocolNameList -> first ProtocolName
    Reader list = r.sub(r.u(2));
    Reader name = list.sub(list.u(1));
    return name.ok ? std::string(name.p, name.p + name.n) : "";
}

// Calls f(type, body) for each extension; false if the hello or its extension block is malformed.
template <class F>
bool walk_extensions(Reader& r, F f) {
    Reader exts = r.n ? r.sub(r.u(2)) : Reader{};  // extensions block is optional (pre-TLS 1.2 hellos)
    while (exts.ok && exts.n > 0) {
        uint16_t type = exts.u(2);
        Reader body = exts.sub(exts.u(2));
        if (body.ok) f(type, body);
    }
    return r.ok && exts.ok;
}

bool is_grease(uint16_t v) { return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff); }

std::string hex(const uint8_t* p, size_t n) {
    static const char d[] = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}

std::string hex4(uint16_t v) { uint8_t b[2] = {uint8_t(v >> 8), uint8_t(v)}; return hex(b, 2); }

std::string sha12(const std::string& s) {
    uint8_t md[32];
    EVP_Digest(s.data(), s.size(), md, nullptr, EVP_sha256(), nullptr);
    return hex(md, 32).substr(0, 12);
}

std::string join(const std::vector<uint16_t>& v) {
    std::string s;
    for (auto x : v) s += (s.empty() ? "" : ",") + hex4(x);
    return s;
}

std::vector<uint16_t> no_grease(const std::vector<uint16_t>& v) {
    std::vector<uint16_t> out;
    for (auto x : v) if (!is_grease(x)) out.push_back(x);
    return out;
}

std::string count2(size_t n) { char b[3]; snprintf(b, sizeof b, "%02zu", std::min<size_t>(n, 99)); return b; }

std::string version_code(uint16_t v) {
    switch (v) {
        case 0x0304: return "13"; case 0x0303: return "12"; case 0x0302: return "11";
        case 0x0301: return "10"; case 0x0300: return "s3"; case 0x0002: return "s2";
        case 0xfeff: return "d1"; case 0xfefd: return "d2"; case 0xfefc: return "d3";
        default: return "00";
    }
}

// First/last char of the ALPN value; hex of first/last byte if either is not ASCII alphanumeric.
std::string alpn_code(const std::string& a) {
    if (a.empty()) return "00";
    uint8_t f = a.front(), l = a.back();
    if (isalnum(f) && isalnum(l)) return {char(f), char(l)};
    return {hex(&f, 1)[0], hex(&l, 1)[1]};
}
}  // namespace

std::optional<ClientHello> parse_client_hello(const std::vector<uint8_t>& stream) {
    Bytes hs = handshake_bytes(stream);
    Reader r = find_message(hs, 1);
    ClientHello ch;
    ch.legacy_version = r.u(2);
    r.sub(32);            // random
    r.sub(r.u(1));        // session id
    Reader ciphers = r.sub(r.u(2));
    while (ciphers.n >= 2) ch.ciphers.push_back(ciphers.u(2));
    r.sub(r.u(1));        // compression methods
    bool ok = walk_extensions(r, [&](uint16_t type, Reader body) {
        ch.extensions.push_back(type);
        if (type == 0x0000) {  // server_name: list len, then name_type(0) + host_name
            Reader list = body.sub(body.u(2));
            if (list.u(1) == 0) {
                Reader host = list.sub(list.u(2));
                if (host.ok) ch.sni.assign(host.p, host.p + host.n);
            }
        } else if (type == 0x0010) {
            ch.alpn = first_alpn(body);
        } else if (type == 0x000d) {
            ch.sig_algs = u16_list(body, 2);
        } else if (type == 0x002b) {
            ch.supported_versions = u16_list(body, 1);
        }
    });
    if (!ok) return std::nullopt;
    return ch;
}

ServerFlight parse_server_flight(const std::vector<uint8_t>& stream) {
    Bytes hs = handshake_bytes(stream);
    ServerFlight flight;
    Reader r = find_message(hs, 2);
    ServerHello sh;
    sh.legacy_version = r.u(2);
    r.sub(32);            // random
    r.sub(r.u(1));        // session id
    sh.cipher = r.u(2);
    r.u(1);               // compression method
    bool ok = walk_extensions(r, [&](uint16_t type, Reader body) {
        sh.extensions.push_back(type);
        if (type == 0x002b) sh.selected_version = body.u(2);
        else if (type == 0x0010) sh.alpn = first_alpn(body);
    });
    if (ok) flight.hello = sh;

    Reader cert = find_message(hs, 11);  // TLS 1.2 only: in 1.3 it is encrypted and never reaches here
    Reader list = cert.sub(cert.u(3));
    Reader leaf = list.sub(list.u(3));
    if (leaf.ok) flight.leaf_cert_der.assign(leaf.p, leaf.p + leaf.n);
    return flight;
}

std::string ja4(const ClientHello& ch) {
    auto ciphers = no_grease(ch.ciphers), exts = no_grease(ch.extensions), versions = no_grease(ch.supported_versions);
    uint16_t version = versions.empty() ? ch.legacy_version : *std::max_element(versions.begin(), versions.end());
    bool sni = std::count(exts.begin(), exts.end(), 0x0000);
    std::string a = "t" + version_code(version) + (sni ? "d" : "i") + count2(ciphers.size()) +
                    count2(exts.size()) + alpn_code(ch.alpn);

    std::sort(ciphers.begin(), ciphers.end());
    std::string b = ciphers.empty() ? "000000000000" : sha12(join(ciphers));

    exts.erase(std::remove_if(exts.begin(), exts.end(), [](uint16_t e) { return e == 0x0000 || e == 0x0010; }),
               exts.end());
    std::sort(exts.begin(), exts.end());
    auto sig = no_grease(ch.sig_algs);
    std::string c = exts.empty() ? "000000000000" : sha12(join(exts) + (sig.empty() ? "" : "_" + join(sig)));
    return a + "_" + b + "_" + c;
}

std::string ja4s(const ServerHello& sh) {
    return "t" + version_code(sh.selected_version ? sh.selected_version : sh.legacy_version) +
           count2(sh.extensions.size()) + alpn_code(sh.alpn) + "_" + hex4(sh.cipher) + "_" +
           (sh.extensions.empty() ? "000000000000" : sha12(join(sh.extensions)));
}

std::string key_hash(const std::vector<uint8_t>& cert_der) {
    const uint8_t* p = cert_der.data();
    X509* x = d2i_X509(nullptr, &p, cert_der.size());
    if (!x) return "";
    uint8_t* spki = nullptr;
    int n = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &spki);
    std::string out;
    if (n > 0) {
        uint8_t md[32];
        EVP_Digest(spki, n, md, nullptr, EVP_sha256(), nullptr);
        out = hex(md, 32).substr(0, 16);
    }
    OPENSSL_free(spki);
    X509_free(x);
    return out;
}

std::string tls_version_name(uint16_t v) {
    switch (v) {
        case 0x0304: return "1.3"; case 0x0303: return "1.2"; case 0x0302: return "1.1"; case 0x0301: return "1.0";
        default: return "unknown";
    }
}

// zh_lab <certsdir> <outdir>: real TLS 1.2 handshakes run in-process through OpenSSL memory BIOs,
// written as Ethernet/IPv4/TCP packets to learn/normal/onechange/attack/multichange/busylearn/busy.pcap + manifest.txt.
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <pcap/pcap.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace {

[[noreturn]] void die(const std::string& m) {
    fprintf(stderr, "zh_lab: %s\n", m.c_str());
    ERR_print_errors_fp(stderr);
    exit(1);
}

void put16(uint8_t* p, uint32_t v) { p[0] = v >> 8 & 0xff; p[1] = v & 0xff; }
void put32(uint8_t* p, uint32_t v) { put16(p, v >> 16); put16(p + 2, v); }

uint32_t sum16(const uint8_t* p, size_t n, uint32_t s = 0) {
    for (size_t i = 0; i + 1 < n; i += 2) s += p[i] << 8 | p[i + 1];
    if (n & 1) s += p[n - 1] << 8;
    return s;
}
uint16_t fold(uint32_t s) {
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s & 0xffff;
}

enum : uint8_t { FIN = 1, SYN = 2, PSH = 8, ACK = 16 };
constexpr uint32_t kClientIp = 10u << 24 | 23;  // 10.0.0.23
constexpr size_t kMss = 536;  // RFC 879 default MSS: the ~650 B server flight spans 2 segments, so the sensor must reassemble

struct Flow {
    pcap_dumper_t* out;
    uint32_t sip;
    uint16_t cport;
    int sttl;
    long ts;
    uint32_t cseq, sseq;  // next sequence number each side sends
    int npkt = 0;
    uint16_t ipid = 1;
    uint32_t cip = kClientIp;
};

void packet(Flow& f, bool from_client, uint8_t flags, const uint8_t* data = nullptr, size_t n = 0) {
    const size_t tcplen = (flags & SYN) ? 24 : 20;  // SYNs carry the MSS option
    std::vector<uint8_t> pkt(14 + 20 + tcplen + n);
    static const uint8_t cmac[6] = {2, 0, 0, 0, 0, 0x23}, gmac[6] = {2, 0, 0, 0, 0, 1};
    uint8_t* e = pkt.data();
    memcpy(e, from_client ? gmac : cmac, 6);
    memcpy(e + 6, from_client ? cmac : gmac, 6);
    put16(e + 12, 0x0800);

    uint8_t* ip = e + 14;
    ip[0] = 0x45;
    put16(ip + 2, 20 + tcplen + n);
    put16(ip + 4, f.ipid++);
    put16(ip + 6, 0x4000);  // DF
    ip[8] = from_client ? 64 : f.sttl;
    ip[9] = 6;
    put32(ip + 12, from_client ? f.cip : f.sip);
    put32(ip + 16, from_client ? f.sip : f.cip);
    put16(ip + 10, fold(sum16(ip, 20)));

    uint8_t* t = ip + 20;
    uint32_t& seq = from_client ? f.cseq : f.sseq;
    put16(t, from_client ? f.cport : 443);
    put16(t + 2, from_client ? 443 : f.cport);
    put32(t + 4, seq);
    if (flags & ACK) put32(t + 8, from_client ? f.sseq : f.cseq);
    t[12] = tcplen / 4 << 4;
    t[13] = flags;
    put16(t + 14, 65535);
    if (flags & SYN) { t[20] = 2; t[21] = 4; put16(t + 22, kMss); }
    if (n) memcpy(t + tcplen, data, n);
    uint32_t pseudo = sum16(ip + 12, 8) + 6 + tcplen + n;
    put16(t + 16, fold(sum16(t, tcplen + n, pseudo)));
    seq += n + ((flags & (SYN | FIN)) ? 1 : 0);

    pcap_pkthdr h{};
    h.ts.tv_sec = f.ts;
    h.ts.tv_usec = 1000 * f.npkt++;
    h.caplen = h.len = pkt.size();
    pcap_dump(reinterpret_cast<u_char*>(f.out), &h, pkt.data());
}

// Move everything one SSL wrote into its peer's read BIO, emitting it as MSS-sized segments.
void pump(Flow& f, bool from_client, SSL* src, SSL* dst) {
    BIO* w = SSL_get_wbio(src);
    std::vector<uint8_t> buf(BIO_ctrl_pending(w));
    if (buf.empty()) return;
    if (BIO_read(w, buf.data(), buf.size()) != (int)buf.size()) die("BIO_read");
    if (BIO_write(SSL_get_rbio(dst), buf.data(), buf.size()) != (int)buf.size()) die("BIO_write");
    for (size_t off = 0; off < buf.size(); off += kMss)
        packet(f, from_client, PSH | ACK, buf.data() + off, std::min(kMss, buf.size() - off));
}

void step(SSL* s) {
    int r = SSL_do_handshake(s);
    if (r <= 0 && SSL_get_error(s, r) != SSL_ERROR_WANT_READ) die("handshake failed");
}

SSL* new_ssl(SSL_CTX* ctx) {
    SSL* s = SSL_new(ctx);
    if (!s) die("SSL_new");
    SSL_set_bio(s, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
    return s;
}

struct Profile {
    const char* ciphers;
    bool tickets;
    const char* alpn;  // nullptr: send no ALPN extension
};
const Profile kOriginA{"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384", true, "h2"};
const Profile kOriginB{"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384", false, "http/1.1"};
// The interceptor's own stack: a cipher and an extension list (no ticket, no ALPN) neither origin uses.
const Profile kInterceptor{"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305", false, nullptr};

int select_alpn(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char*, unsigned, void* arg) {
    // The lab client always offers both h2 and http/1.1, so the profile's choice is always valid.
    *out = static_cast<const unsigned char*>(arg);
    *outlen = strlen(static_cast<const char*>(arg));
    return SSL_TLSEXT_ERR_OK;
}

SSL_CTX* server_ctx(const Profile& p, const std::string& cert, const std::string& key) {
    SSL_CTX* c = SSL_CTX_new(TLS_server_method());
    if (!c || !SSL_CTX_set_cipher_list(c, p.ciphers) ||
        SSL_CTX_use_certificate_file(c, cert.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(c, key.c_str(), SSL_FILETYPE_PEM) != 1)
        die("server ctx " + cert);
    SSL_CTX_set_options(c, SSL_OP_CIPHER_SERVER_PREFERENCE | (p.tickets ? 0 : SSL_OP_NO_TICKET));
    if (p.alpn) SSL_CTX_set_alpn_select_cb(c, select_alpn, const_cast<char*>(p.alpn));
    return c;
}

// One TCP connection: handshake, a full TLS 1.2 handshake and a 4 KB HTTP answer, then FIN. Adds a manifest line.
void connection(Flow& f, SSL_CTX* cctx, const Profile& prof, const std::string& certs, const std::string& file,
                const std::string& host, FILE* manifest, const char* scenario) {
    packet(f, true, SYN);
    packet(f, false, SYN | ACK);
    packet(f, true, ACK);

    SSL_CTX* sctx = server_ctx(prof, certs + "/" + file + ".crt", certs + "/" + file + ".key");
    SSL* c = new_ssl(cctx);
    SSL* s = new_ssl(sctx);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    SSL_set_tlsext_host_name(c, host.c_str());
    for (int i = 0; i < 8 && !(SSL_is_init_finished(c) && SSL_is_init_finished(s)); ++i) {
        step(c);
        pump(f, true, c, s);
        step(s);
        pump(f, false, s, c);
    }
    if (!SSL_is_init_finished(c) || !SSL_is_init_finished(s)) die("handshake did not finish: " + host);

    const std::string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
    // A 4 KB page so the response spans several MSS-sized segments.
    const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n" + std::string(4000, 'x');
    char buf[8192];
    if (SSL_write(c, req.data(), req.size()) <= 0) die("client write");
    pump(f, true, c, s);
    if (SSL_read(s, buf, sizeof buf) <= 0) die("server read");
    if (SSL_write(s, resp.data(), resp.size()) <= 0) die("server write");
    pump(f, false, s, c);
    if (SSL_read(c, buf, sizeof buf) <= 0) die("client read");

    packet(f, true, FIN | ACK);
    packet(f, false, FIN | ACK);
    packet(f, true, ACK);

    const unsigned char* sel = nullptr;
    unsigned sel_len = 0;
    SSL_get0_alpn_selected(c, &sel, &sel_len);
    char issuer[128] = "-";
    X509_NAME_get_text_by_NID(X509_get_issuer_name(SSL_get0_peer_certificate(c)), NID_commonName,
                              issuer, sizeof issuer);
    fprintf(manifest, "%s\t%s\t%u.%u.%u.%u\t%s\t%s\t%s\t%s\t%d\t10.0.%u.%u\n", scenario, host.c_str(), f.sip >> 24,
            f.sip >> 16 & 255, f.sip >> 8 & 255, f.sip & 255,
            SSL_get_cipher_name(c), SSL_get_version(c),
            sel_len ? std::string(reinterpret_cast<const char*>(sel), sel_len).c_str() : "-", issuer, f.sttl,
            f.cip >> 8 & 255, f.cip & 255);

    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(sctx);
}

const char* kScenario[] = {"learn", "normal", "onechange", "attack", "multichange"};

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) die("usage: zh_lab <certsdir> <outdir>");
    const std::string certs = argv[1], outdir = argv[2];
    std::filesystem::create_directories(outdir);

    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    static const unsigned char alpn[] = "\x02h2\x08http/1.1";
    if (!cctx || !SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION) ||  // TLS 1.2 keeps the cert visible
        !SSL_CTX_set_cipher_list(cctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
                                       "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256") ||
        SSL_CTX_set_alpn_protos(cctx, alpn, sizeof alpn - 1) != 0)
        die("client ctx");
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, nullptr);

    FILE* manifest = fopen((outdir + "/manifest.txt").c_str(), "w");
    if (!manifest) die("open manifest.txt");
    fprintf(manifest, "# scenario\tsite\tserver_ip\tcipher\tversion\talpn\tissuer_cn\tttl\tclient\n");

    for (int sc = 0; sc < 5; ++sc) {
        const std::string path = outdir + "/" + kScenario[sc] + ".pcap";
        pcap_t* dead = pcap_open_dead(DLT_EN10MB, 65535);
        pcap_dumper_t* out = pcap_dump_open(dead, path.c_str());
        if (!out) die(path + ": " + pcap_geterr(dead));

        for (int site = 1; site <= 8; ++site) {
            const std::string host = "site" + std::to_string(site) + ".lab";
            const bool attack = sc == 3;
            // multichange: four benign changes: site2 new server stack (A), site3 renewed cert (B), site6 route
            // change (D), and site7 two at once, new server stack and new route (A + D, a move to another CDN node).
            const bool multi = sc == 4;
            const bool new_stack = multi && (site == 2 || site == 7);
            const Profile& prof = attack ? kInterceptor : (site > 4) != new_stack ? kOriginB : kOriginA;
            std::string file = "site" + std::to_string(site);
            if (attack) file = "int-" + file;
            else if ((sc == 2 || multi) && site == 3) file = "site3-renewed";
            // Real servers: TTL jitters by at most 1, below the sensor's TTL delta. Interceptor: one LAN hop.
            const int ttl = attack ? 63 : (site <= 4 ? 52 : 116) + (sc + site) % 3 - 1 + (multi && (site == 6 || site == 7) ? 6 : 0);

            Flow f{out, 93u << 24 | 184u << 16 | 216u << 8 | (10u + site), uint16_t(40000 + sc * 100 + site),
                   ttl, 1700000000L + site - 1, 0x10000000u + site * 0x10000u, 0x20000000u + site * 0x10000u};

            connection(f, cctx, prof, certs, file, host, manifest, kScenario[sc]);
        }
        pcap_dump_close(out);
        pcap_close(dead);
    }
    // busylearn: one clean visit to each of 16 sites (the baseline for busy). busy: 8 clients each visit all 16 sites
    // in their own order, interleaved in time (128 connections). Change rates are the simulation's "normal traffic"
    // (site/lib/sim.js): 3% of sites move provider (all checks change), else new server stack (A) 10%, renewed
    // certificate (B) 5%, route change (D) 12%. Clients 3 and 6 (10.0.1.13, 10.0.1.16) sit behind the interceptor,
    // which lets 25% of sites bypass it.
    const auto origin_a = [](int site) { return (site - 1) % 8 < 4; };
    const auto base_ttl = [&](int site) { return origin_a(site) ? 52 : 116; };
    for (const char* scen : {"busylearn", "busy"}) {
        const bool learn = std::string(scen) == "busylearn";
        const std::string path = outdir + "/" + scen + ".pcap";
        pcap_t* dead = pcap_open_dead(DLT_EN10MB, 65535);
        pcap_dumper_t* out = pcap_dump_open(dead, path.c_str());
        if (!out) die(path + ": " + pcap_geterr(dead));
        uint32_t seed = 2026;
        auto r = [&] { seed = seed * 1664525u + 1013904223u; return (seed >> 8) / 16777216.0; };
        const int n = learn ? 16 : 128;
        for (int i = 0; i < n; ++i) {
            const int cl = learn ? 0 : i % 8, site = learn ? i + 1 : (cl * 3 + i / 8 * 5) % 16 + 1;  // 5 coprime to 16
            const bool attack = !learn && (cl == 2 || cl == 5) && r() >= 0.25;
            const bool migrate = !learn && !attack && r() < 0.03;
            const bool a = migrate || (!learn && !attack && r() < 0.10), b = migrate || (!learn && !attack && r() < 0.05),
                       d = migrate || (!learn && !attack && r() < 0.12);
            const Profile& prof = attack ? kInterceptor : origin_a(site) != a ? kOriginA : kOriginB;
            const std::string sn = std::to_string(site), host = "site" + sn + ".lab";
            const std::string file = attack ? "int-site" + sn : b ? "site" + sn + "-renewed" : "site" + sn;
            const int ttl = attack ? 63 : base_ttl(site) + (learn ? site % 3 - 1 : int(r() * 3) - 1) + (d ? 7 : 0);
            Flow f{out, 93u << 24 | 184u << 16 | 216u << 8 | (10u + site), uint16_t(42000 + (learn ? 200 : 0) + i), ttl,
                   1700002000L + (learn ? 0 : 100) + i, 0x50000000u + i * 0x10000u, 0x60000000u + i * 0x10000u};
            f.cip = learn ? kClientIp : 10u << 24 | 1u << 8 | (11u + cl);  // busy clients 10.0.1.11 .. 10.0.1.18
            connection(f, cctx, prof, certs, file, host, manifest, scen);
        }
        pcap_dump_close(out);
        pcap_close(dead);
    }
    fclose(manifest);
    SSL_CTX_free(cctx);
    return 0;
}

#include <gtest/gtest.h>
#include "tls.h"

using Bytes = std::vector<uint8_t>;

// --- tiny builders for wire bytes (RFC 8446 / RFC 5246 layouts) ---
static void put16(Bytes& b, uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xff); }
static void put24(Bytes& b, size_t v) { b.push_back(v >> 16); b.push_back(v >> 8); b.push_back(v); }
static void append(Bytes& b, const Bytes& x) { b.insert(b.end(), x.begin(), x.end()); }
static Bytes ext(uint16_t type, const Bytes& body = {}) {
    Bytes e; put16(e, type); put16(e, body.size()); append(e, body); return e;
}
static Bytes handshake(uint8_t type, const Bytes& body) {
    Bytes h{type}; put24(h, body.size()); append(h, body); return h;
}
static Bytes client_hello(const std::vector<uint16_t>& ciphers, const std::vector<Bytes>& exts,
                          uint16_t legacy = 0x0303) {
    Bytes b; put16(b, legacy);
    b.insert(b.end(), 32, 0x11);        // random
    b.push_back(0);                      // session id length
    put16(b, ciphers.size() * 2);
    for (auto c : ciphers) put16(b, c);
    b.push_back(1); b.push_back(0);      // compression methods: null
    Bytes e; for (auto& x : exts) append(e, x);
    put16(b, e.size()); append(b, e);
    return handshake(1, b);
}
// Wrap handshake bytes in type-22 TLS records of at most `chunk` payload bytes each.
static Bytes records(const Bytes& hs, size_t chunk = 16384) {
    Bytes out;
    for (size_t i = 0; i < hs.size(); i += chunk) {
        size_t n = std::min(chunk, hs.size() - i);
        out.push_back(22); put16(out, 0x0301); put16(out, n);
        out.insert(out.end(), hs.begin() + i, hs.begin() + i + n);
    }
    return out;
}

TEST(ParseClientHello, ReadsLegacyVersionAndCiphersInWireOrder) {
    auto ch = parse_client_hello(records(client_hello({0x1301, 0xc02b, 0x002f}, {})));
    ASSERT_TRUE(ch);
    EXPECT_EQ(ch->legacy_version, 0x0303);
    EXPECT_EQ(ch->ciphers, (std::vector<uint16_t>{0x1301, 0xc02b, 0x002f}));  // same as built above
}

static Bytes str(const std::string& s) { return Bytes(s.begin(), s.end()); }
static Bytes sni_ext(const std::string& host) {  // RFC 6066 server_name_list with one host_name
    Bytes n{0}; put16(n, host.size()); append(n, str(host));
    Bytes b; put16(b, n.size()); append(b, n); return ext(0x0000, b);
}
// initializer_list, not vector<string>: that instantiation collides with uninstrumented Homebrew gtest under ASan.
static Bytes alpn_ext(std::initializer_list<std::string> protos) {  // RFC 7301 ProtocolNameList
    Bytes l; for (auto& p : protos) { l.push_back(p.size()); append(l, str(p)); }
    Bytes b; put16(b, l.size()); append(b, l); return ext(0x0010, b);
}
static Bytes u16_list_ext(uint16_t type, const std::vector<uint16_t>& v, int len_bytes) {
    Bytes b; if (len_bytes == 1) b.push_back(v.size() * 2); else put16(b, v.size() * 2);
    for (auto x : v) put16(b, x);
    return ext(type, b);
}
static Bytes sig_algs_ext(const std::vector<uint16_t>& v) { return u16_list_ext(0x000d, v, 2); }
static Bytes client_versions_ext(const std::vector<uint16_t>& v) { return u16_list_ext(0x002b, v, 1); }

TEST(ParseClientHello, ReadsExtensionFields) {
    auto ch = parse_client_hello(records(client_hello({0x1301}, {
        ext(0x0a0a), sni_ext("example.com"), alpn_ext({"h2", "http/1.1"}),
        sig_algs_ext({0x0403, 0x0804}), client_versions_ext({0x0304, 0x0303}), ext(0xff01, {0})})));
    ASSERT_TRUE(ch);
    // all literals below are the values passed to the builders above
    EXPECT_EQ(ch->extensions, (std::vector<uint16_t>{0x0a0a, 0x0000, 0x0010, 0x000d, 0x002b, 0xff01}));
    EXPECT_EQ(ch->sni, "example.com");
    EXPECT_EQ(ch->alpn, "h2");
    EXPECT_EQ(ch->sig_algs, (std::vector<uint16_t>{0x0403, 0x0804}));
    EXPECT_EQ(ch->supported_versions, (std::vector<uint16_t>{0x0304, 0x0303}));
}

TEST(ParseClientHello, ReassemblesHandshakeSplitAcrossRecordsAndStopsAtNonHandshakeRecord) {
    Bytes stream = records(client_hello({0xc02f}, {sni_ext("a.test")}), 7);  // 7-byte record payloads
    Bytes alert{21, 3, 3, 0, 2, 2, 40};  // a type-21 record after the handshake must be ignored
    append(stream, alert);
    auto ch = parse_client_hello(stream);
    ASSERT_TRUE(ch);
    EXPECT_EQ(ch->ciphers, (std::vector<uint16_t>{0xc02f}));  // value built above
    EXPECT_EQ(ch->sni, "a.test");                             // value built above
}

TEST(ParseClientHello, RejectsNonHandshakeOrTruncatedStream) {
    EXPECT_FALSE(parse_client_hello({}));
    Bytes full = records(client_hello({0xc02f}, {}));
    EXPECT_FALSE(parse_client_hello(Bytes(full.begin(), full.end() - 1)));  // truncated record
    full[0] = 23;                                                           // application_data, not handshake
    EXPECT_FALSE(parse_client_hello(full));
}

// The worked example from FoxIO JA4.md ("Example" section), plus GREASE values that must be ignored.
static ClientHello spec_example() {
    ClientHello ch;
    ch.legacy_version = 0x0303;
    ch.ciphers = {0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                  0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035};
    ch.extensions = {0x1a1a, 0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005,
                     0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015, 0xfafa};
    ch.sig_algs = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x3a3a};  // + GREASE (JA4.md: ignore anywhere)
    ch.supported_versions = {0x2a2a, 0x0304, 0x0303};
    ch.sni = "example.com";
    ch.alpn = "h2";
    return ch;
}

TEST(Ja4, MatchesSpecWorkedExampleIgnoringGrease) {
    EXPECT_EQ(ja4(spec_example()), "t13d1516h2_8daaf6152771_e5627efa2ab1");  // FoxIO JA4.md "Example"
}

TEST(Ja4, ParsedHelloWithoutSniUsesIpMarkerHttp11AlpnAndLegacyVersion) {
    auto ch = parse_client_hello(records(client_hello({0xc02b, 0x002f, 0x0035},
        {alpn_ext({"http/1.1"}), ext(0x000a, {0, 0}), sig_algs_ext({0x0403})})));
    ASSERT_TRUE(ch);
    // a: no supported_versions -> legacy 0x0303 "12", no SNI "i", 3 ciphers, 3 exts, "http/1.1" -> "h1" (JA4.md)
    // b: printf '%s' '002f,0035,c02b' | shasum -a 256 | cut -c1-12
    // c: printf '%s' '000a,000d_0403' | shasum -a 256 | cut -c1-12
    EXPECT_EQ(ja4(*ch), "t12i0303h1_2d77e0af4a2f_63be3268461f");
}

TEST(Ja4, NoAlpnAndOnlySniGiveZeroFields) {
    ClientHello ch;
    ch.legacy_version = 0x0303;
    ch.ciphers = {0x1301};
    ch.extensions = {0x0000};
    // b: printf '%s' '1301' | shasum -a 256 | cut -c1-12; c: no extensions left after dropping SNI -> zeros (JA4.md)
    EXPECT_EQ(ja4(ch), "t12d010100_0f2cb44170f4_000000000000");
}

TEST(Ja4, CountsCapAt99) {
    ClientHello ch;
    ch.legacy_version = 0x0303;
    for (uint16_t v = 1; v <= 120; v++) { ch.ciphers.push_back(v); ch.extensions.push_back(0x0100 + v); }
    EXPECT_EQ(ja4(ch).substr(0, 10), "t12i999900");  // JA4.md: "If there's > 99 ... output 99"
}

TEST(Ja4, NonAlphanumericAlpnUsesHexEnds) {
    ClientHello ch = spec_example();
    ch.alpn = "\xab\xcd";
    EXPECT_EQ(ja4(ch).substr(0, 10), "t13d1516ad");  // JA4.md: 0xAB 0xCD -> "ad"
    ch.alpn = "0\xab\xcd" "1";
    EXPECT_EQ(ja4(ch).substr(0, 10), "t13d151601");  // JA4.md: 0x30 0xAB 0xCD 0x31 -> "01"
    ch.alpn = "\x30\xab";
    EXPECT_EQ(ja4(ch).substr(0, 10), "t13d15163b");  // JA4.md: 0x30 0xAB -> "3b"
}

static Bytes server_hello(uint16_t cipher, const std::vector<Bytes>& exts, uint16_t legacy = 0x0303) {
    Bytes b; put16(b, legacy);
    b.insert(b.end(), 32, 0x22);  // random
    b.push_back(0);                // session id length
    put16(b, cipher);
    b.push_back(0);                // compression: null
    Bytes e; for (auto& x : exts) append(e, x);
    put16(b, e.size()); append(b, e);
    return handshake(2, b);
}
static Bytes server_version_ext(uint16_t v) { Bytes b; put16(b, v); return ext(0x002b, b); }

TEST(Ja4s, ParsedTls13ServerHelloKeepsExtensionsInWireOrder) {
    auto flight = parse_server_flight(records(server_hello(0x1301,
        {ext(0xff01, {0}), server_version_ext(0x0304), alpn_ext({"h2"}), ext(0x000b, {1, 0})})));
    ASSERT_TRUE(flight.hello);
    EXPECT_EQ(flight.hello->cipher, 0x1301);            // built above
    EXPECT_EQ(flight.hello->selected_version, 0x0304);  // built above
    EXPECT_EQ(flight.hello->alpn, "h2");                // built above
    EXPECT_TRUE(flight.leaf_cert_der.empty());          // no Certificate message sent
    // c: printf '%s' 'ff01,002b,0010,000b' | shasum -a 256 | cut -c1-12  (sorted order would give 21de65576e10)
    EXPECT_EQ(ja4s(*flight.hello), "t1304h2_1301_28d6cd268548");
}

TEST(Ja4s, Tls12ServerHelloWithoutAlpn) {
    ServerHello sh;
    sh.legacy_version = 0x0303;
    sh.cipher = 0xc02f;
    sh.extensions = {0xff01, 0x000b};
    // a: legacy "12", 2 exts, no ALPN "00"; c: printf '%s' 'ff01,000b' | shasum -a 256 | cut -c1-12
    EXPECT_EQ(ja4s(sh), "t120200_c02f_344b4dce5a52");
    sh.extensions = {};
    EXPECT_EQ(ja4s(sh), "t120000_c02f_000000000000");  // JA4S: no extensions -> zeros
}

#include <fstream>
#include <iterator>

static Bytes leaf_der() {  // tests/data/leaf.der: EC P-256 self-signed, made with openssl req -x509
    std::string dir = __FILE__;
    std::ifstream f(dir.substr(0, dir.rfind('/')) + "/data/leaf.der", std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(f), {});
}
static Bytes certificate_msg(const std::vector<Bytes>& certs) {  // TLS 1.2 Certificate (RFC 5246 7.4.2)
    Bytes list; for (auto& c : certs) { put24(list, c.size()); append(list, c); }
    Bytes b; put24(b, list.size()); append(b, list);
    return handshake(11, b);
}
static Bytes tls12_server_flight() {
    Bytes hs = server_hello(0xc02f, {ext(0xff01, {0})});
    append(hs, certificate_msg({leaf_der(), Bytes{0x30, 0x00}}));  // second entry: a dummy "intermediate"
    append(hs, handshake(14, {}));                                  // ServerHelloDone
    return records(hs, 100);                                        // spread over several records
}

TEST(ServerFlight, TakesFirstCertificateAndHashesItsPublicKey) {
    ServerFlight flight = parse_server_flight(tls12_server_flight());
    ASSERT_FALSE(leaf_der().empty());
    ASSERT_TRUE(flight.hello);
    EXPECT_EQ(flight.leaf_cert_der, leaf_der());
    // openssl x509 -in tests/data/leaf.pem -pubkey -noout | openssl pkey -pubin -outform DER | shasum -a 256 | cut -c1-16
    EXPECT_EQ(key_hash(flight.leaf_cert_der), "37aa48f9f2b8f5b6");
}

TEST(KeyHash, EmptyForNonCertificateBytes) {
    EXPECT_EQ(key_hash({}), "");
    EXPECT_EQ(key_hash({0x30, 0x03, 0x02, 0x01, 0x00}), "");  // valid DER INTEGER-in-SEQUENCE, not an X.509 cert
}

TEST(TlsVersionName, NamesTlsVersions) {
    // RFC 8446 / 5246 / 4346 / 2246 version codes
    EXPECT_EQ(tls_version_name(0x0304), "1.3");
    EXPECT_EQ(tls_version_name(0x0303), "1.2");
    EXPECT_EQ(tls_version_name(0x0302), "1.1");
    EXPECT_EQ(tls_version_name(0x0301), "1.0");
    EXPECT_EQ(tls_version_name(0x7f1c), "unknown");  // a draft-28 code, not a final version
}

// Feeds every prefix and 400 deterministic single-byte corruptions; ASan/UBSan fail the test on any bad read.
// Each input is a fresh exact-size vector so a read past the end lands in a heap redzone.
static void exercise(const Bytes& input) {
    if (auto ch = parse_client_hello(input)) ja4(*ch);
    ServerFlight f = parse_server_flight(input);
    if (f.hello) ja4s(*f.hello);
    key_hash(f.leaf_cert_der);
}

TEST(Robustness, PrefixesAndByteFlipsNeverReadOutOfBounds) {
    Bytes client = records(client_hello({0x0a0a, 0x1301, 0xc02f},
        {sni_ext("example.com"), alpn_ext({"h2"}), sig_algs_ext({0x0403}), client_versions_ext({0x0304})}), 50);
    Bytes server = tls12_server_flight();
    for (size_t i = 0; i < client.size(); i++) EXPECT_FALSE(parse_client_hello(Bytes(client.begin(), client.begin() + i))) << i;
    for (const Bytes& valid : {client, server}) {
        for (size_t i = 0; i <= valid.size(); i++) exercise(Bytes(valid.begin(), valid.begin() + i));
        for (uint32_t k = 0; k < 400; k++) {
            Bytes mutated = valid;
            mutated[(k * 7919u) % mutated.size()] ^= uint8_t(k % 255 + 1);
            exercise(mutated);
        }
    }
    SUCCEED();
}

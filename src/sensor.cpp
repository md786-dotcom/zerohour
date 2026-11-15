#include "sensor.h"

#include <pcap/pcap.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "chainlog.h"
#include "tls.h"

Config load_config(const std::string& path) {
    Config c;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        line = line.substr(0, line.find('#'));
        for (char& ch : line) if (ch == '=') ch = ' ';
        std::istringstream in(line);
        std::string k;
        double v;
        if (!(in >> k >> v)) continue;
        if (k == "theta0") c.trw.theta0 = v;
        else if (k == "theta1") c.trw.theta1 = v;
        else if (k == "alpha") c.trw.alpha = v;
        else if (k == "beta") c.trw.beta = v;
        else if (k == "ttl_delta") c.ttl_delta = static_cast<int>(v);
        else if (k == "weighted") c.trw.weighted = v != 0;
        else if (k == "log_sync") c.log_sync = static_cast<int>(v);
        else if (k == "a0") c.trw.a0 = v;
        else if (k == "a1") c.trw.a1 = v;
        else if (k == "b0") c.trw.b0 = v;
        else if (k == "b1") c.trw.b1 = v;
        else if (k == "d0") c.trw.d0 = v;
        else if (k == "d1") c.trw.d1 = v;
        else if (k == "min_sites") c.trw.min_sites = v;
        else throw std::runtime_error("unknown config key: " + k);
    }
    const TrwParams& p = c.trw;
    auto prob = [](double x) { return x > 0 && x < 1; };
    // The walk only moves the right way when theta0 > theta1 and alpha < beta (paper, Sec. 4).
    if (!prob(p.theta0) || !prob(p.theta1) || !prob(p.alpha) || !prob(p.beta) || p.theta0 <= p.theta1 || p.alpha >= p.beta ||
        c.ttl_delta < 0 || c.log_sync < 0 || c.log_sync > 2)
        throw std::runtime_error("config: need 0<theta1<theta0<1, 0<alpha<beta<1, ttl_delta>=0, log_sync 0..2");
    // A failed check must be more probable with an interceptor, or the weighted step points the wrong way.
    if (!prob(p.a0) || !prob(p.a1) || !prob(p.b0) || !prob(p.b1) || !prob(p.d0) || !prob(p.d1) || p.a0 >= p.a1 ||
        p.b0 >= p.b1 || p.d0 >= p.d1 || p.min_sites < 1)
        throw std::runtime_error("config: need 0<a0<a1<1, 0<b0<b1<1, 0<d0<d1<1, min_sites>=1");
    return c;
}

// ---------------------------------------------------------------- PCAP -> observations

namespace {

constexpr uint32_t kMaxStream = 64 * 1024;  // handshakes live in the first bytes of each direction

struct Dir {
    bool have_base = false;
    uint32_t base = 0;                                   // seq number of stream byte 0
    std::map<uint32_t, std::vector<uint8_t>> segs;       // stream offset -> payload
};

struct Flow {
    double ts = 0;
    std::string a_ip, b_ip;  // endpoint a / b as first seen
    uint16_t a_port = 0, b_port = 0;
    int client = -1;         // 0 = a is client, 1 = b is client, -1 unknown yet
    Dir from_a, from_b;
    int ttl_from_a = -1, ttl_from_b = -1;
};

uint16_t be16(const u_char* p) { return static_cast<uint16_t>(p[0] << 8 | p[1]); }
uint32_t be32(const u_char* p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }

std::string ip4(const u_char* p) {
    char b[16];
    std::snprintf(b, sizeof b, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return b;
}

void add_segment(Dir& d, uint32_t seq, bool syn, const u_char* data, size_t len) {
    if (syn) { d.have_base = true; d.base = seq + 1; return; }
    if (len == 0) return;
    if (!d.have_base) { d.have_base = true; d.base = seq; }  // capture started mid-handshake
    uint32_t off = seq - d.base;                             // wraps huge for data before base -> dropped below
    if (off >= kMaxStream) return;
    size_t keep = std::min<size_t>(len, kMaxStream - off);
    auto& slot = d.segs[off];
    if (slot.size() < keep) slot.assign(data, data + keep);
}

std::vector<uint8_t> assemble(const Dir& d) {
    std::vector<uint8_t> out;
    for (const auto& [off, b] : d.segs) {
        if (off > out.size()) break;  // hole: stop at the first missing byte
        size_t skip = out.size() - off;
        if (skip < b.size()) out.insert(out.end(), b.begin() + skip, b.end());
    }
    return out;
}

// Offset of the IPv4 header for the supported link types, or -1.
int ip_offset(int dlt, const u_char* p, size_t caplen) {
    switch (dlt) {
    case DLT_EN10MB: {
        if (caplen < 14) return -1;
        int off = 12;
        uint16_t type = be16(p + off);
        while ((type == 0x8100 || type == 0x88a8) && caplen >= size_t(off + 6)) { off += 4; type = be16(p + off); }
        return type == 0x0800 ? off + 2 : -1;
    }
    case DLT_NULL:
    case DLT_LOOP: return 4;  // shortcut: assumes the 4-byte family is AF_INET; the IPv4 version check below rejects others
    case DLT_RAW: return 0;
    case DLT_LINUX_SLL: return caplen >= 16 && be16(p + 14) == 0x0800 ? 16 : -1;
    default: return -1;
    }
}

std::string clean_site(const std::string& s) {
    std::string out;
    for (char c : s) out += (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_') ? c : '?';
    return out;
}

}  // namespace

std::vector<Observation> read_pcap(const std::string& path, std::string* err) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pc = pcap_open_offline(path.c_str(), errbuf);
    if (!pc) {
        if (err) *err = errbuf;
        return {};
    }
    int dlt = pcap_datalink(pc);
    std::vector<Flow> flows;
    std::map<std::string, size_t> index;  // canonical 4-tuple -> flows[]
    pcap_pkthdr* h;
    const u_char* p;
    while (pcap_next_ex(pc, &h, &p) == 1) {
        int off = ip_offset(dlt, p, h->caplen);
        if (off < 0 || h->caplen < size_t(off) + 20) continue;
        const u_char* ip = p + off;
        size_t avail = h->caplen - off;
        if ((ip[0] >> 4) != 4 || ip[9] != 6) continue;   // shortcut: IPv4 TCP only; IPv6 needs its own header walk
        size_t ihl = (ip[0] & 0x0f) * 4, total = be16(ip + 2);
        if (ihl < 20 || total < ihl || (be16(ip + 6) & 0x3fff)) continue;  // skip fragments
        total = std::min(total, avail);
        if (total < ihl + 20) continue;
        const u_char* tcp = ip + ihl;
        size_t thl = (tcp[12] >> 4) * 4;
        if (thl < 20 || ihl + thl > total) continue;
        uint8_t flags = tcp[13];
        bool syn = flags & 0x02, ack = flags & 0x10;

        std::string src = ip4(ip + 12), dst = ip4(ip + 16);
        uint16_t sport = be16(tcp), dport = be16(tcp + 2);
        std::string ka = src + ":" + std::to_string(sport), kb = dst + ":" + std::to_string(dport);
        std::string key = ka < kb ? ka + "|" + kb : kb + "|" + ka;
        auto [it, fresh] = index.try_emplace(key, flows.size());
        if (fresh) {
            Flow f;
            f.ts = h->ts.tv_sec + h->ts.tv_usec / 1e6;
            f.a_ip = src, f.a_port = sport, f.b_ip = dst, f.b_port = dport;
            flows.push_back(std::move(f));
        }
        Flow& f = flows[it->second];
        bool from_a = src == f.a_ip && sport == f.a_port;
        if (syn && f.client < 0) f.client = (ack ? !from_a : from_a) ? 0 : 1;  // SYN sender is the client
        add_segment(from_a ? f.from_a : f.from_b, be32(tcp + 4), syn, tcp + thl, total - ihl - thl);
        int& ttl = from_a ? f.ttl_from_a : f.ttl_from_b;
        if (ttl < 0) ttl = ip[8];
    }
    pcap_close(pc);

    std::vector<Observation> out;
    for (Flow& f : flows) {
        int client = f.client >= 0 ? f.client : (f.a_port > f.b_port ? 0 : 1);  // no SYN seen: guess the high port is the client
        Dir& c2s = client == 0 ? f.from_a : f.from_b;
        Dir& s2c = client == 0 ? f.from_b : f.from_a;
        auto ch = parse_client_hello(assemble(c2s));
        if (!ch) continue;
        ServerFlight sf = parse_server_flight(assemble(s2c));
        if (!sf.hello) continue;
        Observation o;
        o.ts = f.ts;
        o.client = client == 0 ? f.a_ip : f.b_ip;
        o.server = client == 0 ? f.b_ip : f.a_ip;
        o.site = ch->sni.empty() ? o.server : clean_site(ch->sni);
        o.tls = tls_version_name(sf.hello->selected_version ? sf.hello->selected_version : sf.hello->legacy_version);
        o.ja4 = ja4(*ch);
        o.ja4s = ja4s(*sf.hello);
        o.key = sf.leaf_cert_der.empty() ? "" : key_hash(sf.leaf_cert_der);
        o.ttl = client == 0 ? f.ttl_from_b : f.ttl_from_a;
        out.push_back(std::move(o));
    }
    return out;
}

// ---------------------------------------------------------------- baseline

void Baseline::learn(const Observation& o) {
    SiteBaseline& s = sites_[o.site];
    if (!o.ja4s.empty()) s.ja4s.insert(o.ja4s);
    if (!o.key.empty()) s.keys.insert(o.key);
    if (s.ttl < 0) s.ttl = o.ttl;
}

CheckResult Baseline::check(const Observation& o, int ttl_delta) const {
    CheckResult r;
    auto it = sites_.find(o.site);
    if (it == sites_.end()) return r;
    const SiteBaseline& s = it->second;
    r.known = true;
    r.a = !s.ja4s.count(o.ja4s);
    r.b_seen = !o.key.empty() && !s.keys.empty();  // TLS 1.3 hides the key: no evidence either way
    r.b = r.b_seen && !s.keys.count(o.key);
    r.d_seen = s.ttl >= 0 && o.ttl >= 0;
    r.d = r.d_seen && std::abs(o.ttl - s.ttl) > ttl_delta;
    return r;
}

namespace {
std::string join(const std::set<std::string>& s) {
    std::string out;
    for (const auto& x : s) out += (out.empty() ? "" : ",") + x;
    return out;
}
std::set<std::string> split(const std::string& s) {
    std::set<std::string> out;
    std::istringstream in(s);
    for (std::string x; std::getline(in, x, ',');) if (!x.empty()) out.insert(x);
    return out;
}
}  // namespace

// Format: one site per line, "site \t ja4s,.. \t key,.. \t ttl". Fields hold no tabs/commas (site is cleaned, rest is hex/ascii).
bool Baseline::save(const std::string& path) const {
    std::ofstream f(path, std::ios::trunc);
    for (const auto& [site, s] : sites_) f << site << '\t' << join(s.ja4s) << '\t' << join(s.keys) << '\t' << s.ttl << '\n';
    return bool(f);
}

Baseline Baseline::load(const std::string& path) {
    Baseline b;
    std::ifstream f(path);
    for (std::string line; std::getline(f, line);) {
        std::istringstream in(line);
        std::string site, ja4s, keys, ttl;
        if (!std::getline(in, site, '\t') || !std::getline(in, ja4s, '\t') || !std::getline(in, keys, '\t') ||
            !std::getline(in, ttl))
            continue;
        SiteBaseline& s = b.sites_[site];
        s.ja4s = split(ja4s);
        s.keys = split(keys);
        s.ttl = std::atoi(ttl.c_str());
    }
    return b;
}

// ---------------------------------------------------------------- run + JSON

std::string json_str(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') out += '\\', out += char(c);
        else if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); out += b; }
        else out += char(c);
    }
    return out + "\"";
}

namespace {
std::string num(double v) {
    char b[32];
    std::snprintf(b, sizeof b, "%.4f", v);
    return b;
}
std::string json_set(const std::set<std::string>& s) {
    std::string out = "[";
    for (const auto& x : s) out += (out.size() > 1 ? "," : "") + json_str(x);
    return out + "]";
}
}  // namespace

std::vector<Event> run(const std::vector<Observation>& obs, const Baseline& b, const Config& c, const std::string& log_path) {
    Trw trw(c.trw);
    std::optional<ChainLog> log;
    if (!log_path.empty()) log.emplace(log_path, c.log_sync);
    std::vector<Event> out;
    for (const Observation& o : obs) {
        Event e;
        e.obs = o;
        e.checks = b.check(o, c.ttl_delta);
        if (!e.checks.known) {
            e.result = "unknown";  // no baseline for this site: no evidence either way
            e.step.score = trw.score(o.client);
            out.push_back(std::move(e));
            continue;
        }
        e.base = b.sites().at(o.site);
        const CheckResult& k = e.checks;
        e.step = c.trw.weighted ? trw.observe_delta(o.client, o.site, trw.site_llr({k.a, k.b, k.d, k.b_seen, k.d_seen}))
                                : trw.observe(o.client, o.site, k.mismatch());
        e.result = !e.step.counted ? "repeat" : e.checks.mismatch() ? "mismatch" : "match";
        if (log && e.step.decision != Decision::Pending)
            log->append("{\"type\":" + json_str(to_string(e.step.decision)) + ",\"client\":" + json_str(o.client) +
                        ",\"sites\":" + std::to_string(e.step.sites) + ",\"score\":" + num(e.step.score) + "}",
                        e.step.decision == Decision::Alert);
        else if (log && e.result == "mismatch")
            log->append("{\"type\":\"notice\",\"client\":" + json_str(o.client) + ",\"site\":" + json_str(o.site) +
                        ",\"score\":" + num(e.step.score) + "}");
        out.push_back(std::move(e));
    }
    return out;
}

MatchRate match_rate(const std::vector<Observation>& obs, const Baseline& b, int ttl_delta) {
    MatchRate r;
    std::set<std::pair<std::string, std::string>> seen;
    for (const Observation& o : obs) {
        CheckResult c = b.check(o, ttl_delta);
        if (!c.known || !seen.insert({o.client, o.site}).second) continue;
        r.sites++;
        r.b_sites += c.b_seen, r.d_sites += c.d_seen;
        if (!c.mismatch()) { r.matches++; continue; }
        r.a += c.a, r.b += c.b, r.d += c.d;
        std::string checks = std::string(c.a ? "A," : "") + (c.b ? "B," : "") + (c.d ? "D," : "");
        r.changed.push_back(o.site + " " + checks.substr(0, checks.size() - 1));
    }
    return r;
}

std::string to_json(const Event& e, size_t i) {
    const Observation& o = e.obs;
    std::string base = "null";
    if (e.base)
        base = "{\"ja4s\":" + json_set(e.base->ja4s) + ",\"keys\":" + json_set(e.base->keys) +
               ",\"ttl\":" + std::to_string(e.base->ttl) + "}";
    auto tf = [](bool v) { return v ? "true" : "false"; };
    return "{\"i\":" + std::to_string(i) + ",\"ts\":" + num(o.ts) + ",\"client\":" + json_str(o.client) +
           ",\"server\":" + json_str(o.server) + ",\"site\":" + json_str(o.site) + ",\"tls\":" + json_str(o.tls) +
           ",\"ja4\":" + json_str(o.ja4) + ",\"ja4s\":" + json_str(o.ja4s) + ",\"key\":" + json_str(o.key) +
           ",\"ttl\":" + std::to_string(o.ttl) + ",\"baseline\":" + base + ",\"checks\":{\"A\":" + tf(e.checks.a) +
           ",\"B\":" + tf(e.checks.b) + ",\"D\":" + tf(e.checks.d) + "},\"result\":" + json_str(e.result) +
           ",\"delta\":" + num(e.step.delta) + ",\"score\":" + num(e.step.score) + ",\"sites\":" +
           std::to_string(e.step.sites) + ",\"decision\":" + json_str(to_string(e.step.decision)) + "}";
}

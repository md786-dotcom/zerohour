// The sensor pipeline: PCAP -> TCP reassembly -> TLS parse -> fingerprints -> checks A,B,D -> TRW -> log.
#pragma once
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "trw.h"

struct Config {
    TrwParams trw;
    int ttl_delta = 2;  // check D fails when |ttl - baseline ttl| > ttl_delta
};
Config load_config(const std::string& path);  // key = value lines, '#' comments; missing file -> defaults

// One TLS handshake seen on the wire.
struct Observation {
    double ts = 0;              // timestamp of the flow's first packet
    std::string client, server; // IPv4 dotted
    std::string site;           // SNI, else server IP
    std::string tls;            // "1.2", "1.3", ...
    std::string ja4, ja4s, key; // key = key_hash of the leaf cert, "" when hidden
    int ttl = -1;               // IP TTL of the first server->client packet
};

// Reads every complete TLS handshake from a PCAP file, ordered by flow start time.
std::vector<Observation> read_pcap(const std::string& path, std::string* err);

struct SiteBaseline { std::set<std::string> ja4s, keys; int ttl = -1; };

struct CheckResult {
    bool known = false;  // site is in the baseline
    bool a = false, b = false, d = false;  // true = check failed (value is new / moved)
    bool b_seen = false, d_seen = false;   // the check had something to compare (key visible, TTL known)
    bool mismatch() const { return a || b || d; }
};

class Baseline {
public:
    void learn(const Observation& o);
    CheckResult check(const Observation& o, int ttl_delta) const;
    const std::map<std::string, SiteBaseline>& sites() const { return sites_; }
    bool save(const std::string& path) const;
    static Baseline load(const std::string& path);  // missing file -> empty
private:
    std::map<std::string, SiteBaseline> sites_;
};

// One processed handshake: the observation, its checks and the TRW step.
struct Event {
    Observation obs;
    CheckResult checks;
    std::string result;  // "match" | "mismatch" | "unknown" (site not in baseline) | "repeat" (site already counted)
    Step step;
    std::optional<SiteBaseline> base;  // the site's learned values, if known
};

// Runs the TRW over the observations with a fresh engine. When log_path is non-empty it appends
// one record per notice (mismatch without decision) and per decision.
std::vector<Event> run(const std::vector<Observation>& obs, const Baseline& b, const Config& c,
                       const std::string& log_path);

// Calibration (plan Phase 3): how often known sites match the baseline in one capture.
// Each (client, site) pair counts once, with its first handshake; sites not in the baseline are skipped.
struct MatchRate {
    int sites = 0, matches = 0;
    int a = 0, b = 0, d = 0;           // mismatches per failed check (one site can fail several)
    int b_sites = 0, d_sites = 0;      // sites where check B / D could be seen
    std::vector<std::string> changed;  // "site A,B,D" for each mismatched site
    double theta() const { return (matches + 1.0) / (sites + 2.0); }  // Laplace: never 0 or 1, so both steps stay finite
};
MatchRate match_rate(const std::vector<Observation>& obs, const Baseline& b, int ttl_delta);

std::string to_json(const Event& e, size_t i);  // one JSON object ("Event" in web/API.md), i = 1-based index
std::string json_str(const std::string& s);     // quoted, escaped JSON string

// `zerohour serve`: a one-file dashboard + JSON API for the demo (see web/API.md). Binds 127.0.0.1 only.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include "chainlog.h"
#include "sensor.h"

namespace {

struct Ctx { std::string pcaps, baseline, log, conf; };
struct Resp { int status = 200; std::string type = "application/json", body; };

Resp err(int status, const std::string& msg) { return {status, "application/json", "{\"error\":" + json_str(msg) + "}"}; }

std::string num(double v) {
    char b[32];
    std::snprintf(b, sizeof b, "%.4f", v);
    return b;
}

std::string params_json(const Config& c) {
    Trw t(c.trw);
    return "{\"theta0\":" + num(c.trw.theta0) + ",\"theta1\":" + num(c.trw.theta1) + ",\"alpha\":" + num(c.trw.alpha) +
           ",\"beta\":" + num(c.trw.beta) + ",\"ttl_delta\":" + std::to_string(c.ttl_delta) + ",\"upper\":" + num(t.upper()) +
           ",\"lower\":" + num(t.lower()) + ",\"mismatch_step\":" + num(t.mismatch_step()) + ",\"match_step\":" +
           num(t.match_step()) + ",\"expected_n_h0\":" + num(t.expected_n_h0()) + ",\"expected_n_h1\":" +
           num(t.expected_n_h1()) + "}";
}

std::string set_json(const std::set<std::string>& s) {
    std::string out = "[";
    for (const auto& x : s) out += (out.size() > 1 ? "," : "") + json_str(x);
    return out + "]";
}

Resp learn(const Ctx& c) {
    std::string e;
    auto obs = read_pcap(c.pcaps + "/learn.pcap", &e);
    if (!e.empty()) return err(500, e);
    Baseline b;  // replaces the old baseline: learning happens on a clean network
    for (const auto& o : obs) b.learn(o);
    if (!b.save(c.baseline)) return err(500, "cannot write baseline");
    std::string rows;
    for (const auto& [site, s] : b.sites())
        rows += (rows.empty() ? "" : ",") + std::string("{\"site\":") + json_str(site) + ",\"ja4s\":" + set_json(s.ja4s) +
                ",\"keys\":" + set_json(s.keys) + ",\"ttl\":" + std::to_string(s.ttl) + "}";
    return {200, "application/json", "{\"sites\":[" + rows + "]}"};
}

Resp run_scenario(const Ctx& c, const std::string& scenario) {
    if (scenario != "learn" && scenario != "normal" && scenario != "onechange" && scenario != "attack" &&
        scenario != "multichange")
        return err(400, "unknown scenario");
    Baseline b = Baseline::load(c.baseline);
    if (b.sites().empty()) return err(400, "no baseline, run learn first");
    std::string e;
    auto obs = read_pcap(c.pcaps + "/" + scenario + ".pcap", &e);
    if (!e.empty()) return err(500, e);
    Config cfg = load_config(c.conf);
    auto events = run(obs, b, cfg, c.log);
    std::string ev, dec;
    for (size_t i = 0; i < events.size(); i++) {
        const Event& x = events[i];
        ev += (i ? "," : "") + to_json(x, i + 1);
        if (x.step.decision != Decision::Pending)
            dec += (dec.empty() ? "" : ",") + std::string("{\"client\":") + json_str(x.obs.client) +
                   ",\"decision\":" + json_str(to_string(x.step.decision)) + ",\"sites\":" + std::to_string(x.step.sites) +
                   ",\"score\":" + num(x.step.score) + "}";
    }
    return {200, "application/json",
            "{\"scenario\":" + json_str(scenario) + ",\"params\":" + params_json(cfg) + ",\"events\":[" + ev +
                "],\"decisions\":[" + dec + "],\"log_records\":" + std::to_string(verify_log(c.log).records) + "}"};
}

// Demo of an attacker who edits the log to hide an alert: rewrite the "type" of record 1.
Resp tamper(const Ctx& c) {
    std::ifstream in(c.log);
    std::stringstream all;
    all << in.rdbuf();
    std::string s = all.str();
    size_t t = s.find("\"type\":\"");
    if (t == std::string::npos || t > s.find('\n')) return {200, "application/json", "{\"ok\":false,\"error\":\"log is empty\"}"};
    t += 8;
    size_t end = s.find('"', t);
    s.replace(t, end - t, s.compare(t, end - t, "clear") == 0 ? "notice" : "clear");
    std::ofstream(c.log, std::ios::trunc) << s;
    return {200, "application/json", "{\"ok\":true,\"record\":1}"};
}

Resp verify(const Ctx& c) {
    VerifyResult v = verify_log(c.log);
    return {200, "application/json",
            std::string("{\"ok\":") + (v.ok ? "true" : "false") + ",\"records\":" + std::to_string(v.records) +
                ",\"bad_record\":" + std::to_string(v.bad_record) + ",\"reason\":" + json_str(v.reason) + "}"};
}

Resp route(const Ctx& c, const std::string& method, const std::string& target) {
    std::string path = target.substr(0, target.find('?'));
    std::string query = target.size() > path.size() ? target.substr(path.size() + 1) : "";
    if (method == "GET" && (path == "/" || path == "/index.html")) {
        std::ifstream f(ZH_SOURCE_DIR "/web/index.html");
        if (!f) return err(500, "web/index.html missing");
        std::stringstream ss;
        ss << f.rdbuf();
        return {200, "text/html; charset=utf-8", ss.str()};
    }
    if (method == "GET" && path == "/api/state") {
        Config cfg = load_config(c.conf);
        return {200, "application/json",
                "{\"baseline_sites\":" + std::to_string(Baseline::load(c.baseline).sites().size()) +
                    ",\"log_records\":" + std::to_string(verify_log(c.log).records) + ",\"params\":" + params_json(cfg) + "}"};
    }
    if (method != "POST") return err(404, "not found");
    if (path == "/api/reset") {
        std::remove(c.baseline.c_str());
        std::remove(c.log.c_str());
        return {200, "application/json", "{\"ok\":true}"};
    }
    if (path == "/api/learn") return learn(c);
    if (path == "/api/run") return run_scenario(c, query.rfind("scenario=", 0) == 0 ? query.substr(9) : "");
    if (path == "/api/tamper") return tamper(c);
    if (path == "/api/verify") return verify(c);
    return err(404, "not found");
}

const char* reason(int s) { return s == 200 ? "OK" : s == 400 ? "Bad Request" : s == 404 ? "Not Found" : "Internal Server Error"; }

}  // namespace

int serve(int port, const std::string& pcaps, const std::string& state, const std::string& conf) {
    std::signal(SIGPIPE, SIG_IGN);
    mkdir(state.c_str(), 0755);
    Ctx c{pcaps, state + "/baseline.tsv", state + "/alerts.log", conf};
    load_config(conf);  // fail fast on a bad config

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0 || listen(fd, 16) < 0) {
        std::perror("zerohour serve");
        return 1;
    }
    std::printf("zerohour dashboard: http://127.0.0.1:%d/\n", port);
    std::fflush(stdout);

    // shortcut: one request at a time on one thread; fine for a local demo, use a real HTTP library for more.
    for (;;) {
        int cfd = accept(fd, nullptr, nullptr);
        if (cfd < 0) continue;
        timeval tv{5, 0};
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        std::string req;
        char buf[4096];
        while (req.find("\r\n\r\n") == std::string::npos && req.size() < 16384) {
            ssize_t n = recv(cfd, buf, sizeof buf, 0);
            if (n <= 0) break;
            req.append(buf, n);
        }
        std::istringstream line(req.substr(0, req.find("\r\n")));
        std::string method, target;
        line >> method >> target;
        Resp r;
        try {
            r = target.empty() ? err(400, "bad request") : route(c, method, target);
        } catch (const std::exception& ex) {
            r = err(500, ex.what());
        }
        std::string head = "HTTP/1.1 " + std::to_string(r.status) + " " + reason(r.status) + "\r\nContent-Type: " + r.type +
                           "\r\nContent-Length: " + std::to_string(r.body.size()) +
                           "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
        std::string out = head + r.body;
        for (size_t sent = 0; sent < out.size();) {
            ssize_t n = send(cfd, out.data() + sent, out.size() - sent, 0);
            if (n <= 0) break;
            sent += n;
        }
        close(cfd);
    }
}

// zerohour: finds a TLS interceptor (MITM) on a client's path without decrypting traffic.
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

#include "chainlog.h"
#include "sensor.h"

int serve(int port, const std::string& pcaps, const std::string& state, const std::string& conf);  // serve.cpp

// Prints one capture's match rate; returns the Laplace estimate.
static double report(const char* what, const char* name, const std::string& file, const MatchRate& r) {
    const double n = r.sites, x = r.matches, z = 1.96, z2 = z * z;  // Wilson 95% interval of the raw rate x/n
    const double mid = (x + z2 / 2) / (n + z2), half = z * std::sqrt(x * (n - x) / n + z2 / 4) / (n + z2);
    std::printf("%s  %s\n  %d sites, %d match, %zu changed (A %d, B %d, D %d)\n", what, file.c_str(), r.sites,
                r.matches, r.changed.size(), r.a, r.b, r.d);
    std::printf("  %s = %.4f   (Laplace (%d+1)/(%d+2); raw %.3f, 95%% range %.3f-%.3f)\n", name, r.theta(), r.matches,
                r.sites, x / n, std::max(0.0, mid - half), std::min(1.0, mid + half));
    for (const auto& c : r.changed) std::printf("  changed: %s\n", c.c_str());
    return r.theta();
}

static int usage() {
    std::fprintf(stderr,
                 "usage:\n"
                 "  zerohour show   <pcap>                       print site, TLS version, JA4, JA4S, key, TTL per handshake\n"
                 "  zerohour learn  <pcap> [-b baseline.tsv]     learn the baseline of each site\n"
                 "  zerohour run    <pcap> [-b baseline.tsv] [-c zerohour.conf] [-l alerts.log] [--json]\n"
                 "  zerohour verify <log>                        check the hash chain of the alert log\n"
                 "  zerohour calibrate <learn.pcap> <revisit.pcap> [attack.pcap] [-c zerohour.conf]\n"
                 "                                               measure theta0 (clean revisit) and theta1 (attack)\n"
                 "  zerohour bench  <learn.pcap> <pcap> [-c zerohour.conf] [--json]   time per handshake vs 4 ms\n"
                 "  zerohour serve  [--port 8765] [--pcaps dir] [--state dir] [-c zerohour.conf]\n");
    return 2;
}

int main(int argc, char** argv) {
    if (argc < 2) return usage();
    std::vector<std::string> files;
    std::string cmd = argv[1], file, baseline = "baseline.tsv", conf = "zerohour.conf", log = "alerts.log";
    std::string pcaps = ZH_SOURCE_DIR "/lab/pcaps", state = ".zerohour";
    int port = 8765;
    bool json = false;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        bool has_val = i + 1 < argc;
        if (a == "--json") json = true;
        else if (a == "-b" && has_val) baseline = argv[++i];
        else if (a == "-c" && has_val) conf = argv[++i];
        else if (a == "-l" && has_val) log = argv[++i];
        else if (a == "--pcaps" && has_val) pcaps = argv[++i];
        else if (a == "--state" && has_val) state = argv[++i];
        else if (a == "--port" && has_val) port = std::atoi(argv[++i]);
        else if (a[0] != '-') files.push_back(a);
        else return usage();
    }

    if (files.size() > (cmd == "calibrate" ? 3u : cmd == "bench" ? 2u : 1u)) return usage();
    if (!files.empty()) file = files[0];

    auto read = [](const std::string& f) {
        std::string e;
        auto o = read_pcap(f, &e);
        if (!e.empty()) throw std::runtime_error(e);
        return o;
    };
    try {
        if (cmd == "bench") {
            if (files.size() != 2) return usage();
            using clk = std::chrono::steady_clock;
            auto us = [](clk::duration d) { return std::chrono::duration<double, std::micro>(d).count(); };
            Config cfg = load_config(conf);
            Baseline b;
            for (const auto& o : read(files[0])) b.learn(o);
            const std::string lp = (std::filesystem::temp_directory_path() / "zerohour-bench.log").string();
            const int reps = cfg.log_sync ? 20 : 2000;  // a disk flush costs ms: 20 runs keep a durable bench under a minute
            std::vector<double> parse, decide;
            size_t n = 0, logged = 0;
            for (int r = 0; r < reps; r++) {
                auto t0 = clk::now();
                auto obs = read(files[1]);  // libpcap + TCP reassembly + TLS parse + JA4/JA4S + key hash
                parse.push_back(us(clk::now() - t0) / obs.size());
                n = obs.size();
                std::filesystem::remove(lp);
                Trw trw(cfg.trw);
                ChainLog lg(lp, cfg.log_sync);
                for (const auto& o : obs) {  // checks + TRW step + hash-chained log write, as in run()
                    auto t1 = clk::now();
                    CheckResult k = b.check(o, cfg.ttl_delta);
                    Step s = cfg.trw.weighted ? trw.observe_delta(o.client, o.site, trw.site_llr({k.a, k.b, k.d, k.b_seen, k.d_seen}))
                                              : trw.observe(o.client, o.site, k.mismatch());
                    if (s.decision != Decision::Pending || k.mismatch()) logged++;
                    if (s.decision != Decision::Pending || k.mismatch())
                        lg.append("{\"site\":" + json_str(o.site) + "}", s.decision == Decision::Alert);
                    decide.push_back(us(clk::now() - t1));
                }
            }
            std::filesystem::remove(lp);
            auto pct = [](std::vector<double> v, double q) {
                std::sort(v.begin(), v.end());
                return v[std::min(v.size() - 1, size_t(q * v.size()))];
            };
            const double p50p = pct(parse, .5), p99p = pct(parse, .99), p50d = pct(decide, .5), p99d = pct(decide, .99),
                         maxd = pct(decide, 1), total = p99p + p99d;
            if (json) {
                // Per handshake, in capture order: median over the runs of (its decide time + the run's parse time per handshake).
                std::string per;
                for (size_t i = 0; i < n; i++) {
                    std::vector<double> v;
                    for (int r = 0; r < reps; r++) v.push_back(decide[r * n + i] + parse[r]);
                    per += (i ? "," : "") + std::to_string(pct(v, .5));
                }
                std::printf("{\"pcap\":%s,\"handshakes\":%zu,\"reps\":%d,\"weighted\":%s,\"parse_us\":{\"p50\":%.2f,\"p99\":%.2f},"
                            "\"decide_us\":{\"p50\":%.2f,\"p99\":%.2f,\"max\":%.2f},\"total_p99_us\":%.2f,\"budget_us\":4000,\"log_sync\":%d,"
                            "\"logged\":%.4f,\"per_handshake_us\":[%s]}\n",
                            json_str(files[1]).c_str(), n, reps, cfg.trw.weighted ? "true" : "false", p50p, p99p, p50d, p99d,
                            maxd, total, cfg.log_sync, double(logged) / decide.size(), per.c_str());
                return 0;
            }
            std::printf("%s: %zu handshakes x %d runs, %s method, log_sync %d, %.0f%% of handshakes write a record\n",
                        files[1].c_str(), n, reps, cfg.trw.weighted ? "weighted" : "binary", cfg.log_sync,
                        100.0 * logged / decide.size());
            std::printf("  parse + fingerprint  p50 %8.2f us   p99 %8.2f us   (per handshake)\n", p50p, p99p);
            std::printf("  checks + TRW + log   p50 %8.2f us   p99 %8.2f us   max %8.2f us\n", p50d, p99d, maxd);
            std::printf("  total p99 %.2f us = %.3f ms, budget 4 ms: %s\n", total, total / 1000,
                        total < 4000 ? "PASS" : "FAIL");
            return total < 4000 ? 0 : 1;
        }
        if (cmd == "calibrate") {
            if (files.size() < 2) return usage();
            Config cfg = load_config(conf);
            Baseline b;
            for (const auto& o : read(files[0])) b.learn(o);
            std::printf("learned %zu sites from %s\n\n", b.sites().size(), files[0].c_str());
            TrwParams p = cfg.trw;
            for (size_t i = 1; i < files.size(); i++) {
                MatchRate r = match_rate(read(files[i]), b, cfg.ttl_delta);
                if (r.sites == 0) throw std::runtime_error(files[i] + ": no site is in the baseline; visit the same sites");
                (i == 1 ? p.theta0 : p.theta1) =
                    report(i == 1 ? "benign revisit" : "attack", i == 1 ? "theta0" : "theta1", files[i], r);
            }
            if (files.size() == 2) std::printf("attack: none given, theta1 = %.4f from %s\n", p.theta1, conf.c_str());
            if (p.theta1 >= p.theta0)
                throw std::runtime_error("theta1 >= theta0: the checks cannot tell the interceptor from normal changes");
            Trw t(p);
            std::printf("\nmodel (alpha %.2f, beta %.2f from %s)\n", p.alpha, p.beta, conf.c_str());
            std::printf("  mismatch %+.4f   match %+.4f   alert %+.4f   clear %+.4f\n", t.mismatch_step(), t.match_step(),
                        t.upper(), t.lower());
            std::printf("  alert after %d mismatches in a row, clear after %d matches in a row (from a fresh test)\n",
                        int(std::ceil(t.upper() / t.mismatch_step())), int(std::ceil(t.lower() / t.match_step())));
            std::printf("  E[N|H0] %.1f sites, E[N|H1] %.1f sites\n", t.expected_n_h0(), t.expected_n_h1());
            std::printf("\npaste into %s:\ntheta0 = %.4f\ntheta1 = %.4f\n", conf.c_str(), p.theta0, p.theta1);
            return 0;
        }
        if (cmd == "verify") {
            if (file.empty()) return usage();
            VerifyResult v = verify_log(file);
            if (v.ok) std::printf("ok: %zu records, chain intact\n", v.records);
            else std::printf("FAILED at record %zu: %s\n", v.bad_record, v.reason.c_str());
            return v.ok ? 0 : 1;
        }
        if (cmd == "serve") return serve(port, pcaps, state, conf);
        if (file.empty() || (cmd != "show" && cmd != "learn" && cmd != "run")) return usage();

        std::string err;
        auto obs = read_pcap(file, &err);
        if (!err.empty()) { std::fprintf(stderr, "zerohour: %s\n", err.c_str()); return 1; }

        if (cmd == "show" && json) {
            std::printf("[");
            for (size_t i = 0; i < obs.size(); i++) {
                const Observation& o = obs[i];
                std::printf("%s{\"ts\":%.6f,\"client\":%s,\"server\":%s,\"site\":%s,\"tls\":%s,\"ja4\":%s,\"ja4s\":%s,"
                            "\"key\":%s,\"ttl\":%d}", i ? ",\n" : "", o.ts, json_str(o.client).c_str(), json_str(o.server).c_str(),
                            json_str(o.site).c_str(), json_str(o.tls).c_str(), json_str(o.ja4).c_str(), json_str(o.ja4s).c_str(),
                            json_str(o.key).c_str(), o.ttl);
            }
            std::printf("]\n");
            return 0;
        }
        if (cmd == "show") {
            std::printf("%-14s %-4s %-38s %-26s %-16s %s\n", "site", "tls", "ja4", "ja4s", "key", "ttl");
            for (const auto& o : obs)
                std::printf("%-14s %-4s %-38s %-26s %-16s %d\n", o.site.c_str(), o.tls.c_str(), o.ja4.c_str(),
                            o.ja4s.c_str(), o.key.c_str(), o.ttl);
            return 0;
        }
        if (cmd == "learn") {
            Baseline b = Baseline::load(baseline);
            for (const auto& o : obs) b.learn(o);
            if (!b.save(baseline)) { std::fprintf(stderr, "zerohour: cannot write %s\n", baseline.c_str()); return 1; }
            std::printf("learned %zu handshakes, %zu sites in %s\n", obs.size(), b.sites().size(), baseline.c_str());
            return 0;
        }
        // run
        Baseline b = Baseline::load(baseline);
        if (b.sites().empty()) { std::fprintf(stderr, "zerohour: no baseline in %s, run learn first\n", baseline.c_str()); return 1; }
        auto events = run(obs, b, load_config(conf), log);
        if (json) {
            std::printf("[");
            for (size_t i = 0; i < events.size(); i++) std::printf("%s%s", i ? ",\n" : "", to_json(events[i], i + 1).c_str());
            std::printf("]\n");
            return 0;
        }
        std::printf("%-3s %-14s %-9s %-6s %7s %7s  %s\n", "#", "site", "result", "checks", "step", "score", "decision");
        for (size_t i = 0; i < events.size(); i++) {
            const Event& e = events[i];
            std::string checks = std::string(e.checks.a ? "A" : "") + (e.checks.b ? "B" : "") + (e.checks.d ? "D" : "");
            std::printf("%-3zu %-14s %-9s %-6s %+7.2f %+7.2f  %s\n", i + 1, e.obs.site.c_str(), e.result.c_str(),
                        checks.empty() ? "-" : checks.c_str(), e.step.delta, e.step.score, to_string(e.step.decision));
            if (e.step.decision == Decision::Alert)
                std::printf("ALERT  client %s: interceptor on path after %d sites (score %+.2f)\n", e.obs.client.c_str(),
                            e.step.sites, e.step.score);
            else if (e.step.decision == Decision::Clear)
                std::printf("CLEAR  client %s after %d sites (score %+.2f), new test starts\n", e.obs.client.c_str(),
                            e.step.sites, e.step.score);
        }
        return 0;
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "zerohour: %s\n", ex.what());
        return 1;
    }
}

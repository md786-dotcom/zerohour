// Threshold Random Walk (Jung, Paxson, Berger, Balakrishnan 2004), applied to TLS interception.
// H0: no interceptor on the client's path. H1: an interceptor is on the path.
// Each distinct site is one Bernoulli observation: match (Y=0) or mismatch (Y=1).
#pragma once
#include <map>
#include <set>
#include <string>

struct TrwParams {
    double theta0 = 0.9;   // Pr[match | H0]
    double theta1 = 0.2;   // Pr[match | H1]
    double alpha = 0.01;   // max false-alert rate (P_F)
    double beta = 0.99;    // min detection rate (P_D)
    // Weighted method (Phase 3 tuning): each check adds its own log-likelihood ratio and each site's sum is capped.
    // A benign change usually fails one check while the others still match, so its sum is small or negative.
    bool weighted = false;
    double a0 = 0.06, a1 = 0.95;  // Pr[check A fails | H0], Pr[check A fails | H1]
    double b0 = 0.04, b1 = 0.98;  // check B (only when the certificate is visible, TLS 1.2)
    double d0 = 0.06, d1 = 0.90;  // check D
    double min_sites = 3;         // site cap = upper / (min_sites - 0.5): fewer sites can never reach a decision
};

// Which checks failed on one site, and which could be seen at all.
struct Evidence { bool a = false, b = false, d = false, b_seen = true, d_seen = true; };

enum class Decision { Pending, Clear, Alert };  // Clear = accept H0, Alert = accept H1
const char* to_string(Decision d);              // "pending" | "clear" | "alert"

struct Step {
    bool counted = false;   // false: site already counted in this test, score unchanged
    double delta = 0;       // log-likelihood step added (0 if !counted)
    double score = 0;       // score after the step (the value that hit a threshold, if one was hit)
    int sites = 0;          // distinct sites counted in the current test, including this one
    Decision decision = Decision::Pending;  // Alert/Clear when this step crossed a threshold
};

class Trw {
public:
    explicit Trw(TrwParams p = {});
    double upper() const;          // ln(beta/alpha)
    double lower() const;          // ln((1-beta)/(1-alpha))
    double mismatch_step() const;  // ln((1-theta1)/(1-theta0))
    double match_step() const;     // ln(theta1/theta0)
    double expected_n_h0() const;  // paper eq. (14), E[N|H0]
    double expected_n_h1() const;  // paper eq. (14), E[N|H1]
    double site_cap() const;       // weighted method: largest step one site can add or remove
    double site_llr(const Evidence& e) const;  // weighted method: sum of per-check LLRs, clipped to +-site_cap

    // Feed one observation. After a decision the client's test restarts at 0 with no sites counted.
    Step observe(const std::string& client, const std::string& site, bool mismatch);
    Step observe_delta(const std::string& client, const std::string& site, double delta);  // any step size
    double score(const std::string& client) const;  // 0 for unknown clients

private:
    struct Test { double score = 0; std::set<std::string> sites; };
    TrwParams p_;
    std::map<std::string, Test> tests_;
};

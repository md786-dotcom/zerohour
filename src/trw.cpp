#include "trw.h"
#include <algorithm>
#include <cmath>
const char* to_string(Decision d) {
    switch (d) {
        case Decision::Clear: return "clear";
        case Decision::Alert: return "alert";
        default: return "pending";
    }
}
Trw::Trw(TrwParams p) : p_(p) {}
double Trw::upper() const { return std::log(p_.beta / p_.alpha); }
double Trw::lower() const { return std::log((1 - p_.beta) / (1 - p_.alpha)); }
double Trw::mismatch_step() const { return std::log((1 - p_.theta1) / (1 - p_.theta0)); }
double Trw::match_step() const { return std::log(p_.theta1 / p_.theta0); }
double Trw::expected_n_h0() const {
    return ((1 - p_.alpha) * lower() + p_.alpha * upper()) /
           (p_.theta0 * match_step() + (1 - p_.theta0) * mismatch_step());
}
double Trw::expected_n_h1() const {
    return (p_.beta * upper() + (1 - p_.beta) * lower()) /
           (p_.theta1 * match_step() + (1 - p_.theta1) * mismatch_step());
}
static double term(bool fail, double p0, double p1) { return fail ? std::log(p1 / p0) : std::log((1 - p1) / (1 - p0)); }
double Trw::site_cap() const { return upper() / (p_.min_sites - 0.5); }
double Trw::site_llr(const Evidence& e) const {
    double s = term(e.a, p_.a0, p_.a1);
    if (e.b_seen) s += term(e.b, p_.b0, p_.b1);
    if (e.d_seen) s += term(e.d, p_.d0, p_.d1);
    return std::clamp(s, -site_cap(), site_cap());
}
Step Trw::observe(const std::string& client, const std::string& site, bool mismatch) {
    return observe_delta(client, site, mismatch ? mismatch_step() : match_step());
}
Step Trw::observe_delta(const std::string& client, const std::string& site, double delta) {
    Test& t = tests_[client];
    Step s;
    s.counted = t.sites.insert(site).second;
    if (s.counted) s.delta = delta;
    s.score = t.score += s.delta;
    s.sites = int(t.sites.size());
    if (s.score >= upper()) s.decision = Decision::Alert;
    else if (s.score <= lower()) s.decision = Decision::Clear;
    if (s.decision != Decision::Pending) t = {};
    return s;
}
double Trw::score(const std::string& client) const {
    auto it = tests_.find(client);
    return it == tests_.end() ? 0 : it->second.score;
}

#include "chainlog.h"

#include <sodium.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>

static const std::string kZeroHash(64, '0');

static std::string hash_hex(const std::string& prev, size_t seq, const std::string& payload) {
    if (sodium_init() < 0) throw std::runtime_error("sodium_init failed");
    std::string in = prev + "\t" + std::to_string(seq) + "\t" + payload;
    unsigned char out[32];
    crypto_generichash(out, sizeof out, reinterpret_cast<const unsigned char*>(in.data()), in.size(), nullptr, 0);
    char hex[65];
    sodium_bin2hex(hex, sizeof hex, out, sizeof out);
    return hex;
}

ChainLog::ChainLog(std::string path) : path_(std::move(path)), last_hash_(kZeroHash) {
    // Continue from the last line as-is; a corrupt log stays corrupt and verify_log reports it.
    std::ifstream f(path_);
    for (std::string line; std::getline(f, line); ++seq_) last_hash_ = line.substr(line.rfind('\t') + 1);
    out_.open(path_, std::ios::app);
}

void ChainLog::append(const std::string& payload) {
    std::string p = payload;
    std::replace(p.begin(), p.end(), '\t', ' ');
    std::replace(p.begin(), p.end(), '\n', ' ');
    std::string h = hash_hex(last_hash_, seq_ + 1, p);
    out_ << seq_ + 1 << '\t' << last_hash_ << '\t' << p << '\t' << h << '\n' << std::flush;
    if (!out_) throw std::runtime_error("chainlog: cannot write " + path_);  // never drop an alert silently
    ++seq_;
    last_hash_ = h;
}

VerifyResult verify_log(const std::string& path) {
    VerifyResult r;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) && !ec) return r;
    // An existing log we cannot read must not pass as an empty, valid one.
    if (!std::filesystem::is_regular_file(path, ec)) return {false, 0, 1, "unreadable"};
    std::ifstream f(path);
    if (!f) return {false, 0, 1, "unreadable"};
    std::string line, last = kZeroHash;
    while (std::getline(f, line)) {
        ++r.records;
        if (std::count(line.begin(), line.end(), '\t') != 3) return {false, r.records, r.records, "malformed"};
        size_t a = line.find('\t'), b = line.find('\t', a + 1), c = line.find('\t', b + 1);
        std::string seq = line.substr(0, a), prev = line.substr(a + 1, b - a - 1),
                    payload = line.substr(b + 1, c - b - 1), hash = line.substr(c + 1);
        if (seq.empty() || seq.find_first_not_of("0123456789") != std::string::npos)
            return {false, r.records, r.records, "malformed"};
        if (seq != std::to_string(r.records) || prev != last) return {false, r.records, r.records, "broken chain"};
        if (hash_hex(prev, r.records, payload) != hash) return {false, r.records, r.records, "hash mismatch"};
        last = hash;
    }
    if (f.bad()) return {false, r.records, r.records + 1, "unreadable"};
    return r;
}

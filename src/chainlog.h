// Append-only log where each record carries the hash of the previous one (libsodium BLAKE2b-256).
// Line format (tab-separated, one record per line):
//   <seq>\t<prev_hash_hex>\t<payload>\t<hash_hex>
//   seq starts at 1; prev_hash of record 1 is 64 '0' chars;
//   hash = BLAKE2b-256(prev_hash_hex + "\t" + seq + "\t" + payload), lowercase hex.
// Payload must not contain '\t' or '\n' (append() replaces them with ' ').
#pragma once
#include <cstddef>
#include <fstream>
#include <string>

class ChainLog {
public:
    explicit ChainLog(std::string path);  // continues an existing log from its last record
    void append(const std::string& payload);
    size_t records() const { return seq_; }

private:
    std::string path_;
    std::string last_hash_;
    size_t seq_ = 0;
    std::ofstream out_;  // kept open: reopening the file per record cost up to 2 ms per alert
};

struct VerifyResult {
    bool ok = true;
    size_t records = 0;     // records read
    size_t bad_record = 0;  // 1-based line number of the first bad record, 0 when ok
    std::string reason;     // empty when ok
};

VerifyResult verify_log(const std::string& path);  // a missing file is ok with 0 records

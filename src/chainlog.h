// Append-only log where each record carries the hash of the previous one (libsodium BLAKE2b-256).
// Line format (tab-separated, one record per line):
//   <seq>\t<prev_hash_hex>\t<payload>\t<hash_hex>
//   seq starts at 1; prev_hash of record 1 is 64 '0' chars;
//   hash = BLAKE2b-256(prev_hash_hex + "\t" + seq + "\t" + payload), lowercase hex.
// Payload must not contain '\t' or '\n' (append() replaces them with ' ').
#pragma once
#include <cstddef>
#include <string>

class ChainLog {
public:
    // sync: 0 = write only (OS page cache), 1 = ordered (every record survives in order; an alert is fully on disk
    // before append returns), 2 = full (every record fully on disk before append returns).
    explicit ChainLog(std::string path, int sync = 0);  // continues an existing log from its last record
    ~ChainLog();
    ChainLog(const ChainLog&) = delete;
    ChainLog& operator=(const ChainLog&) = delete;
    void append(const std::string& payload, bool alert = false);
    size_t records() const { return seq_; }

private:
    std::string path_;
    std::string last_hash_;
    size_t seq_ = 0;
    int fd_ = -1;  // kept open: reopening the file per record cost up to 2 ms per alert
    int sync_ = 0;
};

struct VerifyResult {
    bool ok = true;
    size_t records = 0;     // records read
    size_t bad_record = 0;  // 1-based line number of the first bad record, 0 when ok
    std::string reason;     // empty when ok
};

VerifyResult verify_log(const std::string& path);  // a missing file is ok with 0 records

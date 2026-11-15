#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <vector>

#include "chainlog.h"

namespace fs = std::filesystem;

// Homebrew gtest is not ASan-instrumented, so libc++ container annotations mismatch inside gtest
// itself (false container-overflow in GTestIsInitialized). Other ASan checks stay on.
extern "C" const char* __asan_default_options() { return "detect_container_overflow=0"; }

class ChainLogTest : public ::testing::Test {
protected:
    fs::path dir;
    std::string path;
    void SetUp() override {
        auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        dir = fs::temp_directory_path() / (std::string("zh_chainlog_") + info->name());
        fs::remove_all(dir);
        fs::create_directories(dir);
        path = (dir / "alerts.log").string();
    }
    void TearDown() override { fs::remove_all(dir); }
};

TEST_F(ChainLogTest, MissingFileIsOkThenThreeAppendsVerify) {
    auto r = verify_log(path);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.records, 0u);

    ChainLog log(path);
    log.append("a");
    log.append("b");
    log.append("c");
    EXPECT_EQ(log.records(), 3u);
    r = verify_log(path);
    EXPECT_TRUE(r.ok) << r.reason;
    EXPECT_EQ(r.records, 3u);
}

static std::vector<std::string> read_lines(const std::string& p) {
    std::ifstream f(p);
    std::vector<std::string> out;
    for (std::string l; std::getline(f, l);) out.push_back(l);
    return out;
}

static void write_lines(const std::string& p, const std::vector<std::string>& lines) {
    std::ofstream f(p, std::ios::trunc);
    for (auto& l : lines) f << l << '\n';
}

TEST_F(ChainLogTest, FirstRecordMatchesIndependentBlake2b) {
    ChainLog(path).append(R"({"type":"alert"})");
    auto lines = read_lines(path);
    ASSERT_EQ(lines.size(), 1u);
    // python3 hashlib.blake2b(('0'*64+'\t1\t{"type":"alert"}').encode(), digest_size=32).hexdigest()
    EXPECT_EQ(lines[0], std::string("1\t") + std::string(64, '0') + "\t{\"type\":\"alert\"}\t"
                            "b67a94630fbeb990b894906e062e9d3daa5973692a312dff78b354274b47cc46");
}

static std::vector<std::string> three_record_log(const std::string& p) {
    ChainLog log(p);
    log.append(R"({"type":"alert","n":1})");
    log.append(R"({"type":"alert","n":2})");
    log.append(R"({"type":"alert","n":3})");
    return read_lines(p);
}

TEST_F(ChainLogTest, TamperedPayloadIsHashMismatch) {
    auto lines = three_record_log(path);
    lines[1].replace(lines[1].find("alert"), 5, "clear");
    write_lines(path, lines);
    auto r = verify_log(path);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.bad_record, 2u);  // the edited line
    EXPECT_EQ(r.reason, "hash mismatch");
}

TEST_F(ChainLogTest, DeletedRecordBreaksChain) {
    auto lines = three_record_log(path);
    lines.erase(lines.begin() + 1);
    write_lines(path, lines);
    auto r = verify_log(path);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.bad_record, 2u);  // old record 3 now sits on line 2 with seq 3 and record 2's hash as prev
}

TEST_F(ChainLogTest, ChangedStoredHashIsCaught) {
    auto lines = three_record_log(path);
    lines[2].back() = lines[2].back() == '0' ? '1' : '0';  // flip last hex digit of record 3's hash
    write_lines(path, lines);
    auto r = verify_log(path);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.bad_record, 3u);  // the edited line
    EXPECT_EQ(r.reason, "hash mismatch");
}

TEST_F(ChainLogTest, MalformedLinesAreReportedNotCrashed) {
    auto good = three_record_log(path);
    std::string zeros(64, '0');
    for (std::string bad : {std::string("garbage"),                           // 1 field
                            "1\t" + zeros + "\tx",                            // 3 fields
                            good[0] + "\textra",                              // 5 fields
                            "one\t" + zeros + "\tx\t" + zeros,                // non-numeric seq
                            std::string("\t\t\t"),                            // 4 empty fields
                            std::string("\xff\x00\x01\t", 4)}) {              // binary junk
        write_lines(path, {bad});
        auto r = verify_log(path);
        EXPECT_FALSE(r.ok) << bad;
        EXPECT_EQ(r.bad_record, 1u) << bad;
        EXPECT_EQ(r.reason, "malformed") << bad;
    }
}

TEST_F(ChainLogTest, ReopenContinuesSeqAndChain) {
    three_record_log(path);
    ChainLog reopened(path);
    EXPECT_EQ(reopened.records(), 3u);  // three appended above
    reopened.append("fourth");
    EXPECT_EQ(reopened.records(), 4u);
    auto r = verify_log(path);
    EXPECT_TRUE(r.ok) << r.reason << " at " << r.bad_record;
    EXPECT_EQ(r.records, 4u);
}

TEST_F(ChainLogTest, TabsAndNewlinesInPayloadBecomeSpaces) {
    ChainLog(path).append("a\tb\nc");
    auto lines = read_lines(path);
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("\ta b c\t"), std::string::npos);  // spec: '\t' and '\n' replaced with ' '
    auto r = verify_log(path);
    EXPECT_TRUE(r.ok) << r.reason;
    EXPECT_EQ(r.records, 1u);
}

TEST_F(ChainLogTest, EveryRecordEndsWithNewlineAndNoEmptyTrailingRecord) {
    three_record_log(path);
    std::ifstream f(path, std::ios::binary);
    std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    EXPECT_EQ(std::count(raw.begin(), raw.end(), '\n'), 3);  // one '\n' per record, three records
    EXPECT_EQ(raw.back(), '\n');
    EXPECT_EQ(verify_log(path).records, 3u);  // final '\n' does not start a 4th record
}

TEST_F(ChainLogTest, VerifyDoesNotThrowOnGarbage) {
    {
        std::ofstream f(path, std::ios::binary);
        for (int i = 0; i < 4096; ++i) f.put(static_cast<char>((i * 131 + 7) % 256));  // arbitrary bytes
    }
    VerifyResult r;
    EXPECT_NO_THROW(r = verify_log(path));
    EXPECT_FALSE(r.ok);
    EXPECT_NO_THROW(verify_log(dir.string()));  // a directory, not a file
}

TEST_F(ChainLogTest, ExistingButUnreadableLogIsNotOk) {
    three_record_log(path);
    fs::permissions(path, fs::perms::none);
    auto r = verify_log(path);  // spec: only a *missing* file is ok with 0 records
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write);
    EXPECT_FALSE(r.ok);
    EXPECT_FALSE(verify_log(dir.string()).ok);  // a directory is not an empty log
}

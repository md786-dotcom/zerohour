#include <gtest/gtest.h>
#include "trw.h"

// Plan defaults: theta0=0.9, theta1=0.2, alpha=0.01, beta=0.99. All literals hand-calculated (4 dp).
TEST(Trw, StepsAndThresholdsFromPlanParams) {
    Trw t;
    EXPECT_NEAR(t.mismatch_step(), 2.0794, 1e-4);  // ln(0.8/0.1) = ln 8
    EXPECT_NEAR(t.match_step(), -1.5041, 1e-4);    // ln(0.2/0.9)
    EXPECT_NEAR(t.upper(), 4.5951, 1e-4);          // ln(0.99/0.01) = ln 99
    EXPECT_NEAR(t.lower(), -4.5951, 1e-4);         // ln(0.01/0.99)
}

TEST(Trw, ThreeMismatchesOnDistinctSitesAlert) {
    Trw t;
    Step s = t.observe("10.0.0.5", "a.com", true);
    s = t.observe("10.0.0.5", "b.com", true);
    EXPECT_EQ(s.decision, Decision::Pending);
    EXPECT_NEAR(s.score, 4.1589, 1e-4);  // 2 * ln 8, below upper 4.5951
    s = t.observe("10.0.0.5", "c.com", true);
    EXPECT_TRUE(s.counted);
    EXPECT_NEAR(s.delta, 2.0794, 1e-4);  // ln 8
    EXPECT_NEAR(s.score, 6.2383, 1e-4);  // 3 * ln 8
    EXPECT_EQ(s.sites, 3);
    EXPECT_EQ(s.decision, Decision::Alert);
}

TEST(Trw, FourMatchesClear) {
    Trw t;
    Step s;
    for (const char* site : {"a.com", "b.com", "c.com"}) s = t.observe("c1", site, false);
    EXPECT_EQ(s.decision, Decision::Pending);
    EXPECT_NEAR(s.score, -4.5122, 1e-4);  // 3 * ln(2/9), just above lower -4.5951
    s = t.observe("c1", "d.com", false);
    EXPECT_NEAR(s.delta, -1.5041, 1e-4);  // ln(2/9)
    EXPECT_NEAR(s.score, -6.0163, 1e-4);  // 4 * ln(2/9)
    EXPECT_EQ(s.decision, Decision::Clear);
}

TEST(Trw, OneChangedSiteThenMatchesClearsOnSixthSite) {
    Trw t;
    // ln 8 + k * ln(2/9), k = 0..5, from python math.log (summing 4-dp rounded steps drifts > 1e-4)
    const double expected[] = {2.0794, 0.5754, -0.9287, -2.4328, -3.9369, -5.4409};
    const char* sites[] = {"a.com", "b.com", "c.com", "d.com", "e.com", "f.com"};
    for (int i = 0; i < 6; ++i) {
        Step s = t.observe("c1", sites[i], i == 0);
        EXPECT_NEAR(s.score, expected[i], 1e-4) << "site " << i;
        EXPECT_EQ(s.decision, i == 5 ? Decision::Clear : Decision::Pending) << "site " << i;
    }
}

TEST(Trw, SameSiteTwiceInOneTestCountsOnce) {
    Trw t;
    t.observe("c1", "a.com", true);
    Step s = t.observe("c1", "a.com", true);
    EXPECT_FALSE(s.counted);
    EXPECT_EQ(s.delta, 0);               // spec: no step for an already-counted site
    EXPECT_NEAR(s.score, 2.0794, 1e-4);  // unchanged: one ln 8
    EXPECT_EQ(s.sites, 1);
    EXPECT_EQ(s.decision, Decision::Pending);
}

TEST(Trw, TestRestartsAfterDecision) {
    Trw t;
    for (const char* site : {"a.com", "b.com", "c.com"}) t.observe("c1", site, true);  // Alert
    EXPECT_EQ(t.score("c1"), 0);  // spec: fresh test starts at 0
    Step s = t.observe("c1", "a.com", true);  // counted in the previous test, counts again
    EXPECT_TRUE(s.counted);
    EXPECT_NEAR(s.score, 2.0794, 1e-4);  // one ln 8
    EXPECT_EQ(s.sites, 1);
    EXPECT_NEAR(t.score("c1"), 2.0794, 1e-4);  // one ln 8
}

TEST(Trw, ClientsAreIndependent) {
    Trw t;
    EXPECT_EQ(t.score("nobody"), 0);  // spec: unknown client scores 0
    t.observe("c1", "a.com", true);
    Step s = t.observe("c2", "a.com", false);
    EXPECT_TRUE(s.counted);
    EXPECT_EQ(s.sites, 1);
    EXPECT_NEAR(t.score("c1"), 2.0794, 1e-4);   // ln 8
    EXPECT_NEAR(t.score("c2"), -1.5041, 1e-4);  // ln(2/9)
}

// theta/alpha/beta are exact binary fractions so one step lands exactly on a threshold (ln 3 / ln 1/3).
TEST(Trw, ThresholdsAreInclusive) {
    Trw t({0.75, 0.25, 0.25, 0.75});
    EXPECT_EQ(t.observe("c1", "a.com", true).decision, Decision::Alert);   // score == upper
    EXPECT_EQ(t.observe("c2", "a.com", false).decision, Decision::Clear);  // score == lower
}

TEST(Trw, ExpectedNMatchesPaperSection44) {
    // Jung et al. 2004 Sec 4.4: alpha=0.01, beta=0.99, theta0=0.8 -> E[N|H1] = 5.4 (theta1=0.2), 11.8 (theta1=0.4)
    EXPECT_NEAR(Trw({0.8, 0.2, 0.01, 0.99}).expected_n_h1(), 5.4, 0.05);   // paper, 1 dp
    EXPECT_NEAR(Trw({0.8, 0.4, 0.01, 0.99}).expected_n_h1(), 11.8, 0.05);  // paper, 1 dp
}

TEST(Trw, ExpectedNForPlanParams) {
    Trw t;  // theta0=0.9, theta1=0.2: Wald eq. (14) by hand, 2 dp
    EXPECT_NEAR(t.expected_n_h0(), 3.93, 0.005);  // hand-calculated (python math.log: 3.9305)
    EXPECT_NEAR(t.expected_n_h1(), 3.30, 0.005);  // hand-calculated (python math.log: 3.3045)
}

TEST(Trw, DecisionNames) {
    // header contract: "pending" | "clear" | "alert"
    EXPECT_STREQ(to_string(Decision::Pending), "pending");
    EXPECT_STREQ(to_string(Decision::Clear), "clear");
    EXPECT_STREQ(to_string(Decision::Alert), "alert");
}

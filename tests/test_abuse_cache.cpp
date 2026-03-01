#include "abuse_cache.h"
#include "db.h"
#include "geoip.h"
#include "parser.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <ctime>
#include <optional>
#include <string>

// ── Helpers ───────────────────────────────────────────────────────────────────

namespace {

/// Generate a unique temp-file path so parallel test runs don't collide.
std::string tmp_db_path(const char* tag)
{
    return std::string{"/tmp/test_abuse_"} + tag + "_"
         + std::to_string(static_cast<long>(std::time(nullptr))) + ".db";
}

/// Build a minimal TCP LogEntry with src_ip set.
msmap::LogEntry make_entry(const std::string& src_ip)
{
    msmap::LogEntry e{};
    e.ts         = 1000;
    e.src_ip     = src_ip;
    e.src_port   = 12345;
    e.dst_ip     = "10.0.0.1";
    e.dst_port   = 80;
    e.proto      = "TCP";
    e.tcp_flags  = "SYN";
    e.chain      = "input";
    e.in_iface   = "ether1";
    e.rule       = "FW_INPUT_NEW";
    e.conn_state = "new";
    e.pkt_len    = 52;
    return e;
}

} // anonymous namespace

// ── Construction ─────────────────────────────────────────────────────────────

TEST_CASE("AbuseCache: opens in-memory DB without API key")
{
    const msmap::AbuseCache cache{":memory:", ""};
    REQUIRE(cache.valid());
}

TEST_CASE("AbuseCache: opens in-memory DB with API key")
{
    const msmap::AbuseCache cache{":memory:", "test_key_12345"};
    REQUIRE(cache.valid());
}

// ── lookup(): cache miss ──────────────────────────────────────────────────────

TEST_CASE("AbuseCache: lookup returns nullopt on cache miss")
{
    msmap::AbuseCache cache{":memory:", ""};
    REQUIRE(cache.valid());
    REQUIRE_FALSE(cache.lookup("1.2.3.4").has_value());
}

// ── cache_store() + lookup(): cache hit ──────────────────────────────────────

TEST_CASE("AbuseCache: cache_store then lookup returns stored score")
{
    msmap::AbuseCache cache{":memory:", ""};
    REQUIRE(cache.valid());

    REQUIRE(cache.cache_store("8.8.8.8", 99));
    REQUIRE(cache.lookup("8.8.8.8") == 99);
}

TEST_CASE("AbuseCache: cache_store zero score round-trips")
{
    msmap::AbuseCache cache{":memory:", ""};
    REQUIRE(cache.valid());

    REQUIRE(cache.cache_store("1.1.1.1", 0));
    REQUIRE(cache.lookup("1.1.1.1") == 0);
}

// ── TTL constant ─────────────────────────────────────────────────────────────

TEST_CASE("AbuseCache: kCacheTtlSecs is 24 hours")
{
    CHECK(msmap::kCacheTtlSecs == 24 * 3600);
}

// ── submit(): no-op without API key ──────────────────────────────────────────

TEST_CASE("AbuseCache: submit is a no-op without API key")
{
    msmap::AbuseCache cache{":memory:", ""};
    REQUIRE(cache.valid());

    cache.submit("1.2.3.4");
    // Rate remaining is unchanged — no API call was queued.
    CHECK(cache.rate_remaining() == msmap::kDailyQuota);
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

TEST_CASE("AbuseCache: rate_remaining starts at kDailyQuota")
{
    const msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());
    CHECK(cache.rate_remaining() == msmap::kDailyQuota);
}

TEST_CASE("AbuseCache: rate_limit_reset_if_new_day returns false same day")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());
    // Same calendar day as construction — no reset expected.
    CHECK_FALSE(cache.rate_limit_reset_if_new_day());
    CHECK(cache.rate_remaining() == msmap::kDailyQuota);
}

// ── update_connections_threat(): integration ──────────────────────────────────

TEST_CASE("AbuseCache: update_connections_threat patches NULL threat rows")
{
    const std::string db_path = tmp_db_path("patch");

    // Insert a row with no threat score via Database.
    {
        msmap::Database db{db_path};
        REQUIRE(db.valid());
        REQUIRE(db.insert(make_entry("5.5.5.5"), msmap::GeoIpResult{}));

        const auto rows = db.query_connections(msmap::QueryFilters{});
        REQUIRE(rows.size() == 1);
        REQUIRE_FALSE(rows.at(0).threat.has_value());
    }

    // Open AbuseCache against the same file and run the UPDATE.
    {
        msmap::AbuseCache cache{db_path, ""};
        REQUIRE(cache.valid());
        REQUIRE(cache.cache_store("5.5.5.5", 75));
        cache.update_connections_threat("5.5.5.5", 75);
    }

    // Re-open Database and verify the threat was patched.
    {
        msmap::Database db{db_path};
        REQUIRE(db.valid());
        const auto rows = db.query_connections(msmap::QueryFilters{});
        REQUIRE(rows.size() == 1);
        REQUIRE(rows.at(0).threat == 75);
    }

    (void)std::remove(db_path.c_str());
}

TEST_CASE("AbuseCache: update_connections_threat does not overwrite existing score")
{
    const std::string db_path = tmp_db_path("nooverwrite");

    // Insert a row that already has a threat score.
    {
        msmap::Database db{db_path};
        REQUIRE(db.valid());
        REQUIRE(db.insert(make_entry("6.6.6.6"), msmap::GeoIpResult{},
                          std::optional<int>{50}));
    }

    // Attempt to overwrite with a different score via update_connections_threat.
    // The SQL uses WHERE threat IS NULL, so existing scores must be preserved.
    {
        msmap::AbuseCache cache{db_path, ""};
        REQUIRE(cache.valid());
        cache.update_connections_threat("6.6.6.6", 99);
    }

    // Verify score is still 50, not 99.
    {
        msmap::Database db{db_path};
        REQUIRE(db.valid());
        const auto rows = db.query_connections(msmap::QueryFilters{});
        REQUIRE(rows.size() == 1);
        REQUIRE(rows.at(0).threat == 50);
    }

    (void)std::remove(db_path.c_str());
}

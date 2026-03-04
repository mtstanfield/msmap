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

msmap::GeoIpResult make_renderable_geo()
{
    msmap::GeoIpResult geo;
    geo.country = "US";
    geo.lat = 37.751;
    geo.lon = -97.822;
    geo.has_coords = true;
    return geo;
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

    const msmap::AbuseResult result{99, "Data Center/Web Hosting/Transit"};
    REQUIRE(cache.cache_store("8.8.8.8", result));
    const auto hit = cache.lookup("8.8.8.8");
    REQUIRE(hit.has_value());
    REQUIRE(hit->score == 99);
    REQUIRE(hit->usage_type == "Data Center/Web Hosting/Transit");
}

TEST_CASE("AbuseCache: cache_store zero score round-trips")
{
    msmap::AbuseCache cache{":memory:", ""};
    REQUIRE(cache.valid());

    REQUIRE(cache.cache_store("1.1.1.1", msmap::AbuseResult{0, "ISP/Residential"}));
    const auto hit = cache.lookup("1.1.1.1");
    REQUIRE(hit.has_value());
    REQUIRE(hit->score == 0);
}

TEST_CASE("AbuseCache: lookup returns cached result for soft-refresh eligible entries")
{
    msmap::AbuseCache cache{":memory:", ""};
    REQUIRE(cache.valid());

    const msmap::AbuseResult result{55, "Hosting"};
    REQUIRE(cache.cache_store("8.8.4.5", result));

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    REQUIRE(cache.set_last_checked_for_test("8.8.4.5", now - (15 * 24 * 3600)));

    const auto hit = cache.lookup("8.8.4.5");
    REQUIRE(hit.has_value());
    CHECK(hit->score == 55);
    CHECK(hit->usage_type == "Hosting");
}

// ── TTL constant ─────────────────────────────────────────────────────────────

TEST_CASE("AbuseCache: kCacheTtlSecs is 30 days")
{
    CHECK(msmap::kCacheTtlSecs == 30 * 24 * 3600);
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
    CHECK_FALSE(cache.confirmed_rate_remaining().has_value());
}

TEST_CASE("AbuseCache: rate_limit_reset_if_new_day returns false same day")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());
    // Same calendar day as construction — no reset expected.
    CHECK_FALSE(cache.rate_limit_reset_if_new_day());
    CHECK(cache.rate_remaining() == msmap::kDailyQuota);
    CHECK_FALSE(cache.confirmed_rate_remaining().has_value());
}

TEST_CASE("AbuseCache: expired post-midnight retry releases one probe request")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());

    cache.set_rate_remaining_for_test(0);
    cache.arm_quota_retry_for_test(100, true);
    REQUIRE(cache.quota_retry_after_ts().has_value());
    CHECK(*cache.quota_retry_after_ts() == 100);

    CHECK_FALSE(cache.release_quota_retry_probe_if_due_for_test(99));
    CHECK(cache.rate_remaining() == 0);

    CHECK(cache.release_quota_retry_probe_if_due_for_test(100));
    CHECK(cache.rate_remaining() == 1);

    CHECK_FALSE(cache.release_quota_retry_probe_if_due_for_test(101));
    CHECK(cache.rate_remaining() == 1);
}

TEST_CASE("AbuseCache: lookup state distinguishes fresh soft-refresh and stale")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());

    const msmap::AbuseResult result{42, "ISP/Residential"};
    REQUIRE(cache.cache_store("8.8.4.4", result));

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    REQUIRE(cache.set_last_checked_for_test("8.8.4.4", now - (7 * 24 * 3600)));
    CHECK(cache.lookup_state_for_test("8.8.4.4", now) == msmap::AbuseLookupState::kFresh);

    REQUIRE(cache.set_last_checked_for_test("8.8.4.4", now - (15 * 24 * 3600)));
    CHECK(cache.lookup_state_for_test("8.8.4.4", now) ==
          msmap::AbuseLookupState::kSoftRefreshEligible);

    REQUIRE(cache.set_last_checked_for_test("8.8.4.4", now - (31 * 24 * 3600)));
    CHECK(cache.lookup_state_for_test("8.8.4.4", now) == msmap::AbuseLookupState::kStale);
}

TEST_CASE("AbuseCache: soft-refresh eligible entry queues into soft queue")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());
    cache.shutdown_worker_for_test();

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    REQUIRE(cache.cache_store("9.9.9.9", msmap::AbuseResult{10, "Hosting"}));
    REQUIRE(cache.set_last_checked_for_test("9.9.9.9", now - (15 * 24 * 3600)));

    REQUIRE(cache.enqueue_submit_candidate_for_test("9.9.9.9"));
    CHECK_FALSE(cache.normal_queue_contains_for_test("9.9.9.9"));
    CHECK(cache.soft_queue_contains_for_test("9.9.9.9"));
}

TEST_CASE("AbuseCache: soft-refresh eligible entry is skipped when soft budget is exhausted")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());
    cache.shutdown_worker_for_test();

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    REQUIRE(cache.cache_store("9.9.9.10", msmap::AbuseResult{10, "Hosting"}));
    REQUIRE(cache.set_last_checked_for_test("9.9.9.10", now - (15 * 24 * 3600)));
    cache.set_soft_refresh_remaining_for_test(0);

    CHECK_FALSE(cache.enqueue_submit_candidate_for_test("9.9.9.10"));
    CHECK_FALSE(cache.normal_queue_contains_for_test("9.9.9.10"));
    CHECK_FALSE(cache.soft_queue_contains_for_test("9.9.9.10"));
}

TEST_CASE("AbuseCache: duplicate submit is suppressed across soft queue and in-flight state")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());
    cache.shutdown_worker_for_test();

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    REQUIRE(cache.cache_store("9.9.9.17", msmap::AbuseResult{10, "Hosting"}));
    REQUIRE(cache.set_last_checked_for_test("9.9.9.17", now - (15 * 24 * 3600)));

    REQUIRE(cache.enqueue_submit_candidate_for_test("9.9.9.17"));
    CHECK_FALSE(cache.enqueue_submit_candidate_for_test("9.9.9.17"));
    CHECK(cache.soft_queue_contains_for_test("9.9.9.17"));

    const auto pending = cache.pop_next_pending_for_test();
    REQUIRE(pending.has_value());
    CHECK(pending->ip == "9.9.9.17");
    cache.mark_in_flight_for_test("9.9.9.17");
    CHECK(cache.in_flight_contains_for_test("9.9.9.17"));
    CHECK_FALSE(cache.enqueue_submit_candidate_for_test("9.9.9.17"));
}

TEST_CASE("AbuseCache: stale entry queues normally even when soft budget is exhausted")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());
    cache.shutdown_worker_for_test();

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    REQUIRE(cache.cache_store("9.9.9.11", msmap::AbuseResult{10, "Hosting"}));
    REQUIRE(cache.set_last_checked_for_test("9.9.9.11", now - (31 * 24 * 3600)));
    cache.set_soft_refresh_remaining_for_test(0);

    REQUIRE(cache.enqueue_submit_candidate_for_test("9.9.9.11"));
    CHECK(cache.normal_queue_contains_for_test("9.9.9.11"));
    CHECK_FALSE(cache.soft_queue_contains_for_test("9.9.9.11"));
}

TEST_CASE("AbuseCache: normal queue takes priority over soft queue")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());
    cache.shutdown_worker_for_test();

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    REQUIRE(cache.cache_store("9.9.9.12", msmap::AbuseResult{10, "Hosting"}));
    REQUIRE(cache.cache_store("9.9.9.13", msmap::AbuseResult{10, "Hosting"}));
    REQUIRE(cache.set_last_checked_for_test("9.9.9.12", now - (31 * 24 * 3600)));
    REQUIRE(cache.set_last_checked_for_test("9.9.9.13", now - (15 * 24 * 3600)));

    REQUIRE(cache.enqueue_submit_candidate_for_test("9.9.9.13"));
    REQUIRE(cache.enqueue_submit_candidate_for_test("9.9.9.12"));

    const auto first = cache.pop_next_pending_for_test();
    REQUIRE(first.has_value());
    CHECK(first->ip == "9.9.9.12");
    CHECK_FALSE(first->is_soft_refresh);
}

TEST_CASE("AbuseCache: soft queue selects oldest checked IP first")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());
    cache.shutdown_worker_for_test();

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    REQUIRE(cache.cache_store("9.9.9.14", msmap::AbuseResult{10, "Hosting"}));
    REQUIRE(cache.cache_store("9.9.9.15", msmap::AbuseResult{10, "Hosting"}));
    REQUIRE(cache.set_last_checked_for_test("9.9.9.14", now - (16 * 24 * 3600)));
    REQUIRE(cache.set_last_checked_for_test("9.9.9.15", now - (20 * 24 * 3600)));

    REQUIRE(cache.enqueue_submit_candidate_for_test("9.9.9.14"));
    REQUIRE(cache.enqueue_submit_candidate_for_test("9.9.9.15"));

    const auto first = cache.pop_next_pending_for_test();
    REQUIRE(first.has_value());
    CHECK(first->ip == "9.9.9.15");
    CHECK(first->is_soft_refresh);

    const auto second = cache.pop_next_pending_for_test();
    REQUIRE(second.has_value());
    CHECK(second->ip == "9.9.9.14");
    CHECK(second->is_soft_refresh);
}

TEST_CASE("AbuseCache: stale soft-refresh work is promoted to the normal queue on requeue")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());
    cache.shutdown_worker_for_test();

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    const auto stale_checked = now - (31 * 24 * 3600);

    cache.requeue_pending_for_test("9.9.9.16", true, stale_checked, now);

    CHECK(cache.normal_queue_contains_for_test("9.9.9.16"));
    CHECK_FALSE(cache.soft_queue_contains_for_test("9.9.9.16"));
}

TEST_CASE("AbuseCache: soft refresh budget resets on UTC day rollover")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());

    cache.set_soft_refresh_remaining_for_test(0);
    cache.rewind_rate_reset_day_for_test();

    REQUIRE(cache.rate_limit_reset_if_new_day());
    CHECK(cache.soft_refresh_remaining() == msmap::kSoftRefreshBudgetPerDay);
}

TEST_CASE("AbuseCache: quota exhausted apply path promotes stale soft refresh to normal queue")
{
    msmap::AbuseCache cache{":memory:", "dummy_key"};
    REQUIRE(cache.valid());

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    const auto stale_checked = now - (31 * 24 * 3600);

    cache.apply_fetch_result_for_test("9.9.9.18", true, stale_checked,
                                      true, true);

    CHECK(cache.normal_queue_contains_for_test("9.9.9.18"));
    CHECK_FALSE(cache.soft_queue_contains_for_test("9.9.9.18"));
    CHECK_FALSE(cache.in_flight_contains_for_test("9.9.9.18"));
}

// ── update_connections_abuse(): integration ───────────────────────────────────

TEST_CASE("AbuseCache: update_connections_abuse sets threat and usage_type")
{
    const std::string db_path = tmp_db_path("patch");

    // Insert a row with no enrichment via Database.
    {
        msmap::Database db{db_path};
        REQUIRE(db.valid());
        REQUIRE(db.insert(make_entry("5.5.5.5"), make_renderable_geo()));

        const auto rows = db.query_connections(msmap::QueryFilters{});
        REQUIRE(rows.size() == 1);
        REQUIRE_FALSE(rows.at(0).threat.has_value());
    }

    // Open AbuseCache against the same file and run the UPDATE.
    {
        msmap::AbuseCache cache{db_path, ""};
        REQUIRE(cache.valid());
        const msmap::AbuseResult result{75, "Data Center/Web Hosting/Transit"};
        REQUIRE(cache.cache_store("5.5.5.5", result));
        cache.update_connections_abuse("5.5.5.5", result);
    }

    // Re-open Database and verify the enrichment fields were set.
    {
        msmap::Database db{db_path};
        REQUIRE(db.valid());
        const auto rows = db.query_connections(msmap::QueryFilters{});
        REQUIRE(rows.size() == 1);
        REQUIRE(rows.at(0).threat == 75);
        REQUIRE(rows.at(0).usage_type == "Data Center/Web Hosting/Transit");
    }

    (void)std::remove(db_path.c_str());
}

TEST_CASE("AbuseCache: update_connections_abuse skips already-enriched rows")
{
    const std::string db_path = tmp_db_path("nooverwrite");

    // Insert a row with no enrichment.
    {
        msmap::Database db{db_path};
        REQUIRE(db.valid());
        REQUIRE(db.insert(make_entry("6.6.6.6"), make_renderable_geo()));
    }

    // First enrichment: sets threat + usage_type.
    {
        msmap::AbuseCache cache{db_path, ""};
        REQUIRE(cache.valid());
        const msmap::AbuseResult result{50, "ISP/Residential"};
        REQUIRE(cache.cache_store("6.6.6.6", result));
        cache.update_connections_abuse("6.6.6.6", result);
    }

    // Second enrichment with a different score: usage_type is no longer NULL
    // so the WHERE condition skips these rows.
    {
        msmap::AbuseCache cache{db_path, ""};
        REQUIRE(cache.valid());
        cache.update_connections_abuse("6.6.6.6",
                                       msmap::AbuseResult{99, "Data Center"});
    }

    // Verify original values are preserved (score 50, not 99).
    {
        msmap::Database db{db_path};
        REQUIRE(db.valid());
        const auto rows = db.query_connections(msmap::QueryFilters{});
        REQUIRE(rows.size() == 1);
        REQUIRE(rows.at(0).threat == 50);
        REQUIRE(rows.at(0).usage_type == "ISP/Residential");
    }

    (void)std::remove(db_path.c_str());
}

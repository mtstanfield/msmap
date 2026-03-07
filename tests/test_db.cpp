#include "db.h"
#include "geoip.h"
#include "ip_utils.h"
#include "parser.h"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>
#include <algorithm>
#include <atomic>
#include <ctime>
#include <filesystem>
#include <thread>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

/// Build a minimal valid TCP LogEntry without going through the parser.
msmap::LogEntry make_tcp_entry()
{
    msmap::LogEntry e;
    e.ts         = 1772180063;
    e.hostname   = "router";
    e.topic      = "firewall";
    e.level      = "info";
    e.rule       = "FW_INPUT_NEW";
    e.chain      = "input";
    e.in_iface   = "ether1";
    e.out_iface  = "(unknown 0)";
    e.conn_state = "new";
    e.proto      = "TCP";
    e.tcp_flags  = "ACK";
    e.src_ip     = "172.234.31.140";
    e.src_port   = 65226;
    e.dst_ip     = "108.89.67.16";
    e.dst_port   = 44258;
    e.pkt_len    = 52;
    return e;
}

/// Build a minimal valid ICMP LogEntry (no ports).
msmap::LogEntry make_icmp_entry()
{
    msmap::LogEntry e;
    e.ts         = 1772180063;
    e.hostname   = "router";
    e.topic      = "firewall";
    e.level      = "info";
    e.rule       = "FW_INPUT_DROP";
    e.chain      = "input";
    e.in_iface   = "ether1";
    e.out_iface  = "(unknown 0)";
    e.conn_state = "new";
    e.proto      = "ICMP";
    // tcp_flags left empty
    e.src_ip     = "10.0.0.1";
    e.src_port   = -1; // ICMP — no port, stored as NULL
    e.dst_ip     = "10.0.0.2";
    e.dst_port   = -1;
    e.pkt_len    = 28;
    return e;
}

msmap::GeoIpResult make_renderable_geo()
{
    msmap::GeoIpResult geo;
    geo.country = "US";
    geo.lat = 37.751;
    geo.lon = -97.822;
    geo.has_coords = true;
    geo.asn = "AS14618 Amazon.com Inc.";
    return geo;
}

std::vector<msmap::ConnectionRow> collect_rows(msmap::Database& db,
                                               msmap::QueryFilters filters = {})
{
    if (filters.limit <= 0 || filters.limit > 500) {
        filters.limit = 500;
    }

    std::vector<msmap::ConnectionRow> out;
    for (;;) {
        const auto page = db.query_detail_page(filters);
        out.insert(out.end(), page.rows.begin(), page.rows.end());
        if (!page.next_cursor.has_value()) {
            break;
        }
        filters.cursor = *page.next_cursor;
    }
    return out;
}

std::string temp_db_path()
{
    const auto base = std::filesystem::temp_directory_path();
    const auto suffix = std::to_string(static_cast<long long>(std::time(nullptr))) + "-" +
                        std::to_string(static_cast<unsigned long long>(
                            std::hash<std::thread::id>{}(std::this_thread::get_id())));
    return (base / ("msmap-migrate-" + suffix + ".db")).string();
}

bool sqlite_exec(sqlite3* db, const char* sql)
{
    char* err = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    sqlite3_free(err);
    return rc == SQLITE_OK;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("In-memory database opens successfully")
{
    const msmap::Database db{":memory:"};
    REQUIRE(db.valid());
}

TEST_CASE("TCP entry inserts without error")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());
    REQUIRE(db.insert(make_tcp_entry(), make_renderable_geo()));
}

TEST_CASE("ICMP entry inserts without error — ports stored as NULL")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());
    REQUIRE(db.insert(make_icmp_entry(), make_renderable_geo()));
}

TEST_CASE("Entry inserts with populated GeoIpResult")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    REQUIRE(db.insert(make_tcp_entry(), make_renderable_geo()));
}

TEST_CASE("Entry with non-renderable GeoIpResult is rejected")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::GeoIpResult geo;
    geo.country = "US";
    geo.asn = "AS14618 Amazon.com Inc.";

    REQUIRE_FALSE(db.insert(make_tcp_entry(), geo));
    CHECK(collect_rows(db, msmap::QueryFilters{}).empty());
}

TEST_CASE("Multiple entries insert without error")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    for (int i = 0; i < 10; ++i) {
        REQUIRE(db.insert(make_tcp_entry(), make_renderable_geo()));
        REQUIRE(db.insert(make_icmp_entry(), make_renderable_geo()));
    }
}

TEST_CASE("prune_older_than: removes rows strictly below cutoff")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    // Insert three old rows and two new rows.
    auto entry = make_tcp_entry();
    const auto geo = make_renderable_geo();
    entry.ts = 1000; REQUIRE(db.insert(entry, geo));
    entry.ts = 2000; REQUIRE(db.insert(entry, geo));
    entry.ts = 3000; REQUIRE(db.insert(entry, geo));
    entry.ts = 5000; REQUIRE(db.insert(entry, geo));
    entry.ts = 6000; REQUIRE(db.insert(entry, geo));

    // Prune ts < 4000 — should remove the three old rows.
    CHECK(db.prune_older_than(4000) == 3);

    // Only the two new rows should survive, newest-first.
    const auto rows = collect_rows(db, msmap::QueryFilters{});
    REQUIRE(rows.size() == 2);
    CHECK(rows.at(0).ts == 6000);
    CHECK(rows.at(1).ts == 5000);
}

TEST_CASE("prune_older_than: cutoff below all rows removes nothing")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    const auto geo = make_renderable_geo();
    entry.ts = 5000; REQUIRE(db.insert(entry, geo));
    entry.ts = 6000; REQUIRE(db.insert(entry, geo));

    CHECK(db.prune_older_than(1000) == 0);

    const auto rows = collect_rows(db, msmap::QueryFilters{});
    CHECK(rows.size() == 2);
}

TEST_CASE("prune_older_than: cutoff above all rows clears table")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    const auto geo = make_renderable_geo();
    entry.ts = 1000; REQUIRE(db.insert(entry, geo));
    entry.ts = 2000; REQUIRE(db.insert(entry, geo));

    CHECK(db.prune_older_than(9'999'999) == 2);

    const auto rows = collect_rows(db, msmap::QueryFilters{});
    CHECK(rows.empty());
}

TEST_CASE("prune_older_than: returns 0 safely on invalid database")
{
    msmap::Database db{"/nonexistent/path/msmap.db"};
    REQUIRE_FALSE(db.valid());
    CHECK(db.prune_older_than(999'999) == 0);
}

TEST_CASE("threat score round-trips through insert and query_detail_page")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    REQUIRE(db.insert(make_tcp_entry(), make_renderable_geo(), std::optional<int>{75}));

    const auto rows = collect_rows(db, msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    REQUIRE(rows.at(0).threat == 75);
}

TEST_CASE("threat score nullopt stores and reads as NULL")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    REQUIRE(db.insert(make_tcp_entry(), make_renderable_geo())); // default threat = nullopt

    const auto rows = collect_rows(db, msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    CHECK_FALSE(rows.at(0).threat.has_value());
}

TEST_CASE("Entry parsed via parse_log inserts correctly")
{
    using namespace std::string_view_literals;
    constexpr auto kLine =
        "2026-02-27T08:14:23+00:00 router FW_INPUT_NEW: FW_INPUT_NEW "
        "input: in:ether1 out:(unknown 0), connection-state:new "
        "src-mac bc:9a:8e:fb:12:f1, proto TCP (ACK), "
        "172.234.31.140:65226->108.89.67.16:44258, len 52"sv;

    const msmap::ParseResult result = msmap::parse_log(kLine);
    REQUIRE(result.ok());

    msmap::Database db{":memory:"};
    REQUIRE(db.valid());
    REQUIRE(db.insert(result.entry, make_renderable_geo()));
}

TEST_CASE("Duplicate suppression: identical entries produce exactly one row")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    const auto entry = make_tcp_entry();

    // First insert succeeds; second is silently ignored by INSERT OR IGNORE.
    REQUIRE(db.insert(entry, make_renderable_geo()));
    REQUIRE(db.insert(entry, make_renderable_geo()));

    const auto rows = collect_rows(db, msmap::QueryFilters{});
    CHECK(rows.size() == 1);
}

TEST_CASE("Duplicate suppression: ICMP entries (NULL ports) deduplicate correctly")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    const auto entry = make_icmp_entry();

    REQUIRE(db.insert(entry, make_renderable_geo()));
    REQUIRE(db.insert(entry, make_renderable_geo()));

    const auto rows = collect_rows(db, msmap::QueryFilters{});
    CHECK(rows.size() == 1);
}

TEST_CASE("Duplicate suppression: different timestamps are distinct rows")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.ts = 1000;
    REQUIRE(db.insert(entry, make_renderable_geo()));
    entry.ts = 2000;
    REQUIRE(db.insert(entry, make_renderable_geo()));

    const auto rows = collect_rows(db, msmap::QueryFilters{});
    CHECK(rows.size() == 2);
}

TEST_CASE("status_snapshot: empty retention window reports zero counts")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    const auto snapshot = db.status_snapshot();
    REQUIRE(snapshot.has_value());
    CHECK(snapshot->ok);
    CHECK_FALSE(snapshot->latest_event_ts.has_value());
    CHECK(snapshot->rows_24h == 0);
    CHECK(snapshot->distinct_sources_24h == 0);
}

TEST_CASE("status_snapshot: reports latest event and distinct sources")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.ts = 1000;
    entry.src_ip = "198.51.100.10";
    REQUIRE(db.insert(entry, make_renderable_geo()));

    entry.ts = 2000;
    entry.src_ip = "198.51.100.10";
    REQUIRE(db.insert(entry, make_renderable_geo()));

    entry.ts = 3000;
    entry.src_ip = "203.0.113.25";
    REQUIRE(db.insert(entry, make_renderable_geo()));

    const auto snapshot = db.status_snapshot();
    REQUIRE(snapshot.has_value());
    REQUIRE(snapshot->latest_event_ts.has_value());
    CHECK(*snapshot->latest_event_ts == 3000);
    CHECK(snapshot->rows_24h == 3);
    CHECK(snapshot->distinct_sources_24h == 2);
}

TEST_CASE("status_snapshot: prune_older_than updates retained counts correctly")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.src_ip = "198.51.100.10";
    entry.ts = 1000;
    REQUIRE(db.insert(entry, make_renderable_geo()));
    entry.ts = 2000;
    REQUIRE(db.insert(entry, make_renderable_geo()));

    entry.src_ip = "203.0.113.99";
    entry.ts = 3000;
    REQUIRE(db.insert(entry, make_renderable_geo()));

    REQUIRE(db.prune_older_than(2500) == 2);

    const auto snapshot = db.status_snapshot();
    REQUIRE(snapshot.has_value());
    CHECK(snapshot->rows_24h == 1);
    CHECK(snapshot->distinct_sources_24h == 1);
    REQUIRE(snapshot->latest_event_ts.has_value());
    CHECK(*snapshot->latest_event_ts == 3000);
}

TEST_CASE("prune_expired: removes rows older than 24h relative to now")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.ts = static_cast<std::int64_t>(std::time(nullptr)) - (25 * 3600);
    REQUIRE(db.insert(entry, make_renderable_geo()));
    entry.ts = static_cast<std::int64_t>(std::time(nullptr)) - 60;
    REQUIRE(db.insert(entry, make_renderable_geo()));

    CHECK(db.prune_expired() == 1);

    const auto rows = collect_rows(db, msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    CHECK(rows.at(0).ts == entry.ts);
}

TEST_CASE("is_private_rfc1918_ipv4: matches RFC1918 ranges only")
{
    CHECK(msmap::is_private_rfc1918_ipv4("10.0.0.1"));
    CHECK(msmap::is_private_rfc1918_ipv4("172.16.4.9"));
    CHECK(msmap::is_private_rfc1918_ipv4("172.31.255.255"));
    CHECK(msmap::is_private_rfc1918_ipv4("192.168.1.42"));
    CHECK_FALSE(msmap::is_private_rfc1918_ipv4("172.15.0.1"));
    CHECK_FALSE(msmap::is_private_rfc1918_ipv4("172.32.0.1"));
    CHECK_FALSE(msmap::is_private_rfc1918_ipv4("8.8.8.8"));
    CHECK_FALSE(msmap::is_private_rfc1918_ipv4("not-an-ip"));
}

TEST_CASE("query_map_rows: aggregates repeated source IPs across full window")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    msmap::GeoIpResult geo;
    geo.country = "US";
    geo.lat = 37.751;
    geo.lon = -97.822;
    geo.has_coords = true;
    geo.asn = "AS64500 Example";

    entry.ts = 1000;
    REQUIRE(db.insert(entry, geo, 10));
    entry.ts = 1500;
    REQUIRE(db.insert(entry, geo, 75));

    auto other = entry;
    other.src_ip = "203.0.113.44";
    other.ts = 2000;
    REQUIRE(db.insert(other, geo, 25));

    msmap::MapFilters filters;
    filters.since = 1;
    filters.until = 5000;

    const auto rows = db.query_map_rows(filters);
    REQUIRE(rows.size() == 2);
    REQUIRE(rows.at(0).src_ip == "203.0.113.44");
    REQUIRE(rows.at(1).src_ip == entry.src_ip);
    CHECK(rows.at(1).count == 2);
    REQUIRE(rows.at(1).threat_max.has_value());
    CHECK(*rows.at(1).threat_max == 75);
}

TEST_CASE("query_map_rows: ASN filter is case-insensitive fuzzy and escapes LIKE wildcards", "[db][query]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    msmap::GeoIpResult geo;
    geo.country = "US";
    geo.lat = 37.751;
    geo.lon = -97.822;
    geo.has_coords = true;
    geo.asn = "AS14618 Amazon.com Inc.";

    entry.src_ip = "198.51.100.21";
    entry.ts = 1000;
    REQUIRE(db.insert(entry, geo, 10));

    geo.asn = "AS15169 Google LLC";
    entry.src_ip = "198.51.100.22";
    entry.ts = 1100;
    REQUIRE(db.insert(entry, geo, 10));

    geo.asn = "AS64500 100%_Literal Test";
    entry.src_ip = "198.51.100.23";
    entry.ts = 1200;
    REQUIRE(db.insert(entry, geo, 10));

    msmap::MapFilters filters;
    filters.since = 1;
    filters.until = 5000;

    SECTION("provider substring")
    {
        filters.asn = "amazon";
        const auto rows = db.query_map_rows(filters);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front().src_ip == "198.51.100.21");
    }

    SECTION("asn number substring")
    {
        filters.asn = "14618";
        const auto rows = db.query_map_rows(filters);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front().src_ip == "198.51.100.21");
    }

    SECTION("case-insensitive")
    {
        filters.asn = "GOOGLE";
        const auto rows = db.query_map_rows(filters);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front().src_ip == "198.51.100.22");
    }

    SECTION("wildcards are treated as literals")
    {
        filters.asn = "100%_literal";
        const auto rows = db.query_map_rows(filters);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front().src_ip == "198.51.100.23");
    }
}

TEST_CASE("query_map_rows: threat filters exact threat buckets", "[db][query]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::GeoIpResult geo;
    geo.country = "US";
    geo.lat = 37.751;
    geo.lon = -97.822;
    geo.has_coords = true;
    geo.asn = "AS64500 Example";

    auto entry = make_tcp_entry();
    entry.src_ip = "198.51.100.10";
    entry.ts = 1000;
    REQUIRE(db.insert(entry, geo, 0));
    entry.ts = 1100;
    REQUIRE(db.insert(entry, geo, 0));
    entry.ts = 1200;
    REQUIRE(db.insert(entry, geo, 80));

    auto unknown = entry;
    unknown.src_ip = "198.51.100.11";
    unknown.ts = 1300;
    REQUIRE(db.insert(unknown, geo));
    auto unknown_drop = entry;
    unknown_drop.src_ip = "198.51.100.15";
    unknown_drop.ts = 1350;
    REQUIRE(db.insert(unknown_drop, geo));
    REQUIRE(db.upsert_ip_intel(unknown_drop.src_ip, msmap::IpIntel{
        .tor_exit = std::nullopt,
        .spamhaus_drop = true,
    }));

    auto low = entry;
    low.src_ip = "198.51.100.12";
    low.ts = 1400;
    REQUIRE(db.insert(low, geo, 20));

    auto medium = entry;
    medium.src_ip = "198.51.100.13";
    medium.ts = 1500;
    REQUIRE(db.insert(medium, geo, 50));

    auto high = entry;
    high.src_ip = "198.51.100.14";
    high.ts = 1600;
    REQUIRE(db.insert(high, geo, 90));

    msmap::MapFilters filters;
    filters.since = 1;
    filters.until = 5000;

    SECTION("clean")
    {
        filters.threat = "clean";
        const auto rows = db.query_map_rows(filters);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front().src_ip == "198.51.100.10");
        CHECK(rows.front().count == 2);
        CHECK(rows.front().first_ts == 1000);
        CHECK(rows.front().last_ts == 1100);
        REQUIRE(rows.front().threat_max.has_value());
        CHECK(*rows.front().threat_max == 0);
    }

    SECTION("unknown")
    {
        filters.threat = "unknown";
        const auto rows = db.query_map_rows(filters);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front().src_ip == "198.51.100.11");
        CHECK_FALSE(rows.front().threat_max.has_value());
        CHECK_FALSE(rows.front().spamhaus_drop.value_or(false));
    }

    SECTION("low")
    {
        filters.threat = "low";
        const auto rows = db.query_map_rows(filters);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front().src_ip == "198.51.100.12");
        REQUIRE(rows.front().threat_max.has_value());
        CHECK(*rows.front().threat_max == 20);
    }

    SECTION("medium")
    {
        filters.threat = "medium";
        const auto rows = db.query_map_rows(filters);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front().src_ip == "198.51.100.13");
        REQUIRE(rows.front().threat_max.has_value());
        CHECK(*rows.front().threat_max == 50);
    }

    SECTION("high")
    {
        filters.threat = "high";
        const auto rows = db.query_map_rows(filters);
        REQUIRE(rows.size() == 3);
        const auto drop_only = std::find_if(rows.begin(), rows.end(), [](const msmap::MapRow& row) {
            return row.src_ip == "198.51.100.15";
        });
        REQUIRE(drop_only != rows.end());
        CHECK(drop_only->spamhaus_drop.value_or(false));
        CHECK_FALSE(drop_only->threat_max.has_value());

        const auto explicit_high = std::find_if(rows.begin(), rows.end(), [](const msmap::MapRow& row) {
            return row.src_ip == "198.51.100.14";
        });
        REQUIRE(explicit_high != rows.end());
        REQUIRE(explicit_high->threat_max.has_value());
        CHECK(*explicit_high->threat_max == 90);

        const auto mixed = std::find_if(rows.begin(), rows.end(), [](const msmap::MapRow& row) {
            return row.src_ip == "198.51.100.10";
        });
        REQUIRE(mixed != rows.end());
        REQUIRE(mixed->threat_max.has_value());
        CHECK(*mixed->threat_max == 80);
        CHECK(mixed->count == 1);
    }
}

TEST_CASE("query_detail_page: exclude_icmp hides ICMP unless proto is explicit")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto tcp = make_tcp_entry();
    tcp.ts = 1000;
    auto icmp = make_icmp_entry();
    icmp.ts = 2000;

    REQUIRE(db.insert(tcp, make_renderable_geo()));
    REQUIRE(db.insert(icmp, make_renderable_geo()));

    msmap::QueryFilters filtered;
    filtered.exclude_icmp = true;
    const auto rows = collect_rows(db, filtered);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().proto == "TCP");

    msmap::QueryFilters icmp_only;
    icmp_only.exclude_icmp = true;
    icmp_only.proto = "ICMP";
    const auto icmp_rows = collect_rows(db, icmp_only);
    REQUIRE(icmp_rows.size() == 1);
    CHECK(icmp_rows.front().proto == "ICMP");
}

TEST_CASE("query_detail_page: keyset cursor paginates and tolerates malformed cursor")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    for (int i = 0; i < 3; ++i) {
        entry.ts = 1000 + i;
        REQUIRE(db.insert(entry, make_renderable_geo()));
    }

    msmap::QueryFilters filters;
    filters.src_ip = entry.src_ip;
    filters.limit = 2;
    const auto first = db.query_detail_page(filters);
    REQUIRE(first.rows.size() == 2);
    REQUIRE(first.next_cursor.has_value());
    CHECK_FALSE(first.next_cursor->empty());
    CHECK(first.rows.at(0).ts == 1002);
    CHECK(first.rows.at(1).ts == 1001);

    filters.cursor = *first.next_cursor;
    const auto second = db.query_detail_page(filters);
    REQUIRE(second.rows.size() == 1);
    CHECK(second.rows.at(0).ts == 1000);
    CHECK_FALSE(second.next_cursor.has_value());

    filters.cursor = "bad-cursor-value";
    const auto fallback = db.query_detail_page(filters);
    REQUIRE(fallback.rows.size() == 2);
    CHECK(fallback.rows.at(0).ts == 1002);
    CHECK(fallback.rows.at(1).ts == 1001);
}

TEST_CASE("query_detail_page: IP intel flags are surfaced from ip_intel_cache")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.src_ip = "198.51.100.10";
    entry.ts = 1000;

    REQUIRE(db.insert(entry, make_renderable_geo(), 42));
    REQUIRE(db.upsert_ip_intel(entry.src_ip, msmap::IpIntel{
        .tor_exit = true,
        .spamhaus_drop = false,
    }));

    const auto rows = collect_rows(db, msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    REQUIRE(rows.front().tor_exit.has_value());
    REQUIRE(*rows.front().tor_exit);
    REQUIRE(rows.front().spamhaus_drop.has_value());
    REQUIRE_FALSE(*rows.front().spamhaus_drop);
}

TEST_CASE("concurrency: inserts and detail/map reads run concurrently without corruption")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.src_ip = "198.51.100.10";
    const auto geo = make_renderable_geo();

    std::atomic<bool> stop{false};
    std::thread writer([&]() {
        for (int i = 0; i < 250; ++i) {
            entry.ts = 10'000 + i;
            (void)db.insert(entry, geo, i % 100);
        }
        stop.store(true);
    });

    std::thread reader_detail([&]() {
        while (!stop.load()) {
            msmap::QueryFilters f;
            f.limit = 50;
            f.src_ip = entry.src_ip;
            (void)db.query_detail_page(f);
        }
    });

    std::thread reader_map([&]() {
        while (!stop.load()) {
            msmap::MapFilters f;
            f.since = 1;
            f.until = static_cast<std::int64_t>(std::time(nullptr)) + 20'000;
            (void)db.query_map_rows(f);
        }
    });

    writer.join();
    reader_detail.join();
    reader_map.join();

    const auto snapshot = db.status_snapshot();
    REQUIRE(snapshot.has_value());
    CHECK(snapshot->rows_24h >= 1);
}

TEST_CASE("legacy connections.country schema is migrated at startup")
{
    const std::string path = temp_db_path();
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(path.c_str(), &raw) == SQLITE_OK);
    REQUIRE(sqlite_exec(raw, R"sql(
CREATE TABLE connections (
    id         INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    src_ip     TEXT    NOT NULL,
    src_port   INTEGER,
    dst_ip     TEXT    NOT NULL,
    dst_port   INTEGER,
    proto      TEXT    NOT NULL,
    tcp_flags  TEXT,
    rule       TEXT    NOT NULL DEFAULT '',
    country    TEXT,
    lat        REAL,
    lon        REAL,
    asn        TEXT,
    threat     INTEGER,
    usage_type TEXT
))sql"));
    REQUIRE(sqlite_exec(raw, "CREATE INDEX IF NOT EXISTS idx_country ON connections(country)"));
    REQUIRE(sqlite_exec(raw, R"sql(
INSERT INTO connections(ts, src_ip, src_port, dst_ip, dst_port, proto, tcp_flags, rule, country, lat, lon, asn, threat, usage_type)
VALUES (1000, '198.51.100.10', 12345, '203.0.113.10', 443, 'TCP', 'SYN', 'FW_INPUT_NEW', 'US', 37.751, -97.822, 'AS64500 Example', 77, 'Data Center/Web Hosting/Transit')
)sql"));
    sqlite3_close(raw);

    msmap::Database db{path};
    REQUIRE(db.valid());

    const auto rows = collect_rows(db, msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().src_ip == "198.51.100.10");
    REQUIRE(rows.front().lat.has_value());
    REQUIRE(rows.front().lon.has_value());
    CHECK(rows.front().asn == "AS64500 Example");
    REQUIRE(rows.front().threat.has_value());
    CHECK(*rows.front().threat == 77);

    sqlite3* verify = nullptr;
    REQUIRE(sqlite3_open(path.c_str(), &verify) == SQLITE_OK);
    sqlite3_stmt* table_info = nullptr;
    REQUIRE(sqlite3_prepare_v2(verify, "PRAGMA table_info(connections)", -1, &table_info, nullptr) == SQLITE_OK);
    bool has_country = false;
    while (sqlite3_step(table_info) == SQLITE_ROW) {
        const auto* col_name = sqlite3_column_text(table_info, 1);
        if (col_name != nullptr && std::string{reinterpret_cast<const char*>(col_name)} == "country") { // NOLINT(*-reinterpret-cast)
            has_country = true;
            break;
        }
    }
    sqlite3_finalize(table_info);
    CHECK_FALSE(has_country);

    sqlite3_stmt* idx_stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(verify,
                               "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_country'",
                               -1, &idx_stmt, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(idx_stmt) != SQLITE_ROW);
    sqlite3_finalize(idx_stmt);
    sqlite3_close(verify);

    msmap::Database reopened{path};
    REQUIRE(reopened.valid());

    std::error_code ec;
    (void)std::filesystem::remove(path, ec);
    (void)std::filesystem::remove(path + "-wal", ec);
    (void)std::filesystem::remove(path + "-shm", ec);
}

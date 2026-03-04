#include "db.h"
#include "geoip.h"
#include "ip_utils.h"
#include "parser.h"

#include <catch2/catch_test_macros.hpp>
#include <ctime>

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

} // anonymous namespace

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("In-memory database opens successfully")
{
    const msmap::Database db{":memory:"};
    REQUIRE(db.valid());
}

TEST_CASE("TCP entry inserts without error — no geo data")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());
    REQUIRE(db.insert(make_tcp_entry(), msmap::GeoIpResult{}));
}

TEST_CASE("ICMP entry inserts without error — ports stored as NULL")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());
    REQUIRE(db.insert(make_icmp_entry(), msmap::GeoIpResult{}));
}

TEST_CASE("Entry inserts with populated GeoIpResult")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::GeoIpResult geo;
    geo.country = "US";
    geo.lat     = 37.751;
    geo.lon     = -97.822;
    geo.asn     = "AS14618 Amazon.com Inc.";

    REQUIRE(db.insert(make_tcp_entry(), geo));
}

TEST_CASE("Multiple entries insert without error")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    for (int i = 0; i < 10; ++i) {
        REQUIRE(db.insert(make_tcp_entry(), msmap::GeoIpResult{}));
        REQUIRE(db.insert(make_icmp_entry(), msmap::GeoIpResult{}));
    }
}

TEST_CASE("prune_older_than: removes rows strictly below cutoff")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    // Insert three old rows and two new rows.
    auto entry = make_tcp_entry();
    entry.ts = 1000; REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    entry.ts = 2000; REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    entry.ts = 3000; REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    entry.ts = 5000; REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    entry.ts = 6000; REQUIRE(db.insert(entry, msmap::GeoIpResult{}));

    // Prune ts < 4000 — should remove the three old rows.
    CHECK(db.prune_older_than(4000) == 3);

    // Only the two new rows should survive, newest-first.
    const auto rows = db.query_connections(msmap::QueryFilters{});
    REQUIRE(rows.size() == 2);
    CHECK(rows.at(0).ts == 6000);
    CHECK(rows.at(1).ts == 5000);
}

TEST_CASE("prune_older_than: cutoff below all rows removes nothing")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.ts = 5000; REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    entry.ts = 6000; REQUIRE(db.insert(entry, msmap::GeoIpResult{}));

    CHECK(db.prune_older_than(1000) == 0);

    const auto rows = db.query_connections(msmap::QueryFilters{});
    CHECK(rows.size() == 2);
}

TEST_CASE("prune_older_than: cutoff above all rows clears table")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.ts = 1000; REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    entry.ts = 2000; REQUIRE(db.insert(entry, msmap::GeoIpResult{}));

    CHECK(db.prune_older_than(9'999'999) == 2);

    const auto rows = db.query_connections(msmap::QueryFilters{});
    CHECK(rows.empty());
}

TEST_CASE("prune_older_than: returns 0 safely on invalid database")
{
    msmap::Database db{"/nonexistent/path/msmap.db"};
    REQUIRE_FALSE(db.valid());
    CHECK(db.prune_older_than(999'999) == 0);
}

TEST_CASE("threat score round-trips through insert and query_connections")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    REQUIRE(db.insert(make_tcp_entry(), msmap::GeoIpResult{}, std::optional<int>{75}));

    const auto rows = db.query_connections(msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    REQUIRE(rows.at(0).threat == 75);
}

TEST_CASE("threat score nullopt stores and reads as NULL")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    REQUIRE(db.insert(make_tcp_entry(), msmap::GeoIpResult{})); // default threat = nullopt

    const auto rows = db.query_connections(msmap::QueryFilters{});
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
    REQUIRE(db.insert(result.entry, msmap::GeoIpResult{}));
}

TEST_CASE("Duplicate suppression: identical entries produce exactly one row")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    const auto entry = make_tcp_entry();

    // First insert succeeds; second is silently ignored by INSERT OR IGNORE.
    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));

    const auto rows = db.query_connections(msmap::QueryFilters{});
    CHECK(rows.size() == 1);
}

TEST_CASE("Duplicate suppression: ICMP entries (NULL ports) deduplicate correctly")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    const auto entry = make_icmp_entry();

    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));

    const auto rows = db.query_connections(msmap::QueryFilters{});
    CHECK(rows.size() == 1);
}

TEST_CASE("Duplicate suppression: different timestamps are distinct rows")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.ts = 1000;
    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    entry.ts = 2000;
    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));

    const auto rows = db.query_connections(msmap::QueryFilters{});
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
    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));

    entry.ts = 2000;
    entry.src_ip = "198.51.100.10";
    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));

    entry.ts = 3000;
    entry.src_ip = "203.0.113.25";
    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));

    const auto snapshot = db.status_snapshot();
    REQUIRE(snapshot.has_value());
    REQUIRE(snapshot->latest_event_ts.has_value());
    CHECK(*snapshot->latest_event_ts == 3000);
    CHECK(snapshot->rows_24h == 3);
    CHECK(snapshot->distinct_sources_24h == 2);
}

TEST_CASE("prune_expired: removes rows older than 24h relative to now")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.ts = static_cast<std::int64_t>(std::time(nullptr)) - (25 * 3600);
    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    entry.ts = static_cast<std::int64_t>(std::time(nullptr)) - 60;
    REQUIRE(db.insert(entry, msmap::GeoIpResult{}));

    CHECK(db.prune_expired() == 1);

    const auto rows = db.query_connections(msmap::QueryFilters{});
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

TEST_CASE("query_map_rows: threat filters exact threat buckets", "[db][query]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::GeoIpResult geo;
    geo.country = "US";
    geo.lat = 37.751;
    geo.lon = -97.822;
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
        REQUIRE(rows.size() == 2);
        CHECK(rows.at(0).src_ip == "198.51.100.14");
        CHECK(rows.at(1).src_ip == "198.51.100.10");
        REQUIRE(rows.at(1).threat_max.has_value());
        CHECK(*rows.at(1).threat_max == 80);
        CHECK(rows.at(1).count == 1);
    }
}

TEST_CASE("query_connections: exclude_icmp hides ICMP unless proto is explicit")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto tcp = make_tcp_entry();
    tcp.ts = 1000;
    auto icmp = make_icmp_entry();
    icmp.ts = 2000;

    REQUIRE(db.insert(tcp, msmap::GeoIpResult{}));
    REQUIRE(db.insert(icmp, msmap::GeoIpResult{}));

    msmap::QueryFilters filtered;
    filtered.exclude_icmp = true;
    const auto rows = db.query_connections(filtered);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().proto == "TCP");

    msmap::QueryFilters icmp_only;
    icmp_only.exclude_icmp = true;
    icmp_only.proto = "ICMP";
    const auto icmp_rows = db.query_connections(icmp_only);
    REQUIRE(icmp_rows.size() == 1);
    CHECK(icmp_rows.front().proto == "ICMP");
}

TEST_CASE("query_detail_page: returns next cursor when another page exists")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    for (int i = 0; i < 3; ++i) {
        entry.ts = 1000 + i;
        REQUIRE(db.insert(entry, msmap::GeoIpResult{}));
    }

    msmap::QueryFilters filters;
    filters.src_ip = entry.src_ip;
    filters.limit = 2;
    const auto page = db.query_detail_page(filters);
    REQUIRE(page.rows.size() == 2);
    REQUIRE(page.next_cursor.has_value());
    CHECK(*page.next_cursor == 2);
}

TEST_CASE("query_connections: IP intel flags are surfaced from ip_intel_cache")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    auto entry = make_tcp_entry();
    entry.src_ip = "198.51.100.10";
    entry.ts = 1000;

    REQUIRE(db.insert(entry, msmap::GeoIpResult{}, 42));
    REQUIRE(db.upsert_ip_intel(entry.src_ip, msmap::IpIntel{
        .tor_exit = true,
        .spamhaus_drop = false,
    }));

    const auto rows = db.query_connections(msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    REQUIRE(rows.front().tor_exit.has_value());
    REQUIRE(*rows.front().tor_exit);
    REQUIRE(rows.front().spamhaus_drop.has_value());
    REQUIRE_FALSE(*rows.front().spamhaus_drop);
}

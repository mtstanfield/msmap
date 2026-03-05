#include "db.h"
#include "filter_utils.h"
#include "geoip.h"
#include "json.h"
#include "parser.h"

#include <catch2/catch_test_macros.hpp>
#include <optional>
#include <string>
#include <string_view>

namespace {

msmap::GeoIpResult make_renderable_geo()
{
    msmap::GeoIpResult geo;
    geo.country = "US";
    geo.lat = 37.751;
    geo.lon = -97.822;
    geo.has_coords = true;
    geo.asn = "AS64500 Example ISP";
    return geo;
}

} // namespace

// ── json::append_string ───────────────────────────────────────────────────────

TEST_CASE("append_string: plain ASCII is quoted and unchanged", "[json]")
{
    std::string out;
    msmap::json::append_string(out, "hello");
    REQUIRE(out == "\"hello\"");
}

TEST_CASE("append_string: double-quote and backslash are escaped", "[json]")
{
    std::string out;
    msmap::json::append_string(out, "a\"b\\c");
    REQUIRE(out == "\"a\\\"b\\\\c\"");
}

TEST_CASE("append_string: newline, tab, carriage-return are escaped", "[json]")
{
    std::string out;
    msmap::json::append_string(out, "\n\t\r");
    REQUIRE(out == "\"\\n\\t\\r\"");
}

TEST_CASE("append_string: control characters encoded as \\u00XX", "[json]")
{
    std::string out;
    msmap::json::append_string(out, std::string_view("\x01\x1f", 2));
    REQUIRE(out == "\"\\u0001\\u001f\"");
}

TEST_CASE("append_string: empty string becomes empty JSON string", "[json]")
{
    std::string out;
    msmap::json::append_string(out, "");
    REQUIRE(out == "\"\"");
}

// ── json::append_string_or_null ───────────────────────────────────────────────

TEST_CASE("append_string_or_null: non-empty value is quoted", "[json]")
{
    std::string out;
    msmap::json::append_string_or_null(out, "US");
    REQUIRE(out == "\"US\"");
}

TEST_CASE("append_string_or_null: empty value becomes null", "[json]")
{
    std::string out;
    msmap::json::append_string_or_null(out, "");
    REQUIRE(out == "null");
}

// ── json::append_int_or_null ──────────────────────────────────────────────────

TEST_CASE("append_int_or_null: present value is rendered as integer", "[json]")
{
    std::string out;
    msmap::json::append_int_or_null(out, std::optional<int>{443});
    REQUIRE(out == "443");
}

TEST_CASE("append_int_or_null: nullopt becomes null", "[json]")
{
    std::string out;
    msmap::json::append_int_or_null(out, std::nullopt);
    REQUIRE(out == "null");
}

// ── json::append_double_or_null ───────────────────────────────────────────────

TEST_CASE("append_double_or_null: nullopt becomes null", "[json]")
{
    std::string out;
    msmap::json::append_double_or_null(out, std::nullopt);
    REQUIRE(out == "null");
}

TEST_CASE("append_double_or_null: value rendered to six decimal places", "[json]")
{
    std::string out;
    msmap::json::append_double_or_null(out, std::optional<double>{37.751});
    REQUIRE(out == "37.751000");
}

TEST_CASE("append_double_or_null: negative coordinate", "[json]")
{
    std::string out;
    msmap::json::append_double_or_null(out, std::optional<double>{-97.822});
    REQUIRE(out == "-97.822000");
}

// ── Database::query_connections ───────────────────────────────────────────────

TEST_CASE("query_connections: empty database returns empty vector", "[db][query]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    const auto rows = db.query_connections({});
    REQUIRE(rows.empty());
}

TEST_CASE("query_connections: returns all rows when no filters set", "[db][query]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::LogEntry e1{};
    e1.ts = 1000; e1.src_ip = "1.2.3.4"; e1.src_port = 1111;
    e1.dst_ip = "10.0.0.1"; e1.dst_port = 80; e1.proto = "TCP";
    e1.tcp_flags = "SYN"; e1.chain = "input"; e1.in_iface = "ether1";
    e1.rule = "FW_INPUT_NEW"; e1.conn_state = "new"; e1.pkt_len = 52;

    msmap::LogEntry e2 = e1;
    e2.ts = 2000; e2.src_ip = "5.6.7.8"; e2.dst_port = 443;

    const auto geo = make_renderable_geo();
    db.insert(e1, geo);
    db.insert(e2, geo);

    const auto rows = db.query_connections({});
    REQUIRE(rows.size() == 2);
    // Results ordered newest-first.
    REQUIRE(rows.at(0).ts == 2000);
    REQUIRE(rows.at(1).ts == 1000);
}

TEST_CASE("query_connections: filter by src_ip", "[db][query]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::LogEntry base{};
    base.ts = 1000; base.src_ip = "1.2.3.4"; base.src_port = 1000;
    base.dst_ip = "10.0.0.1"; base.dst_port = 80; base.proto = "TCP";
    base.tcp_flags = "SYN"; base.chain = "input"; base.in_iface = "ether1";
    base.rule = "FW_INPUT_NEW"; base.conn_state = "new"; base.pkt_len = 52;

    msmap::LogEntry other = base;
    other.src_ip = "9.9.9.9"; other.ts = 2000;

    const auto geo = make_renderable_geo();
    db.insert(base,  geo);
    db.insert(other, geo);

    msmap::QueryFilters f;
    f.src_ip = "1.2.3.4";
    const auto rows = db.query_connections(f);
    REQUIRE(rows.size() == 1);
    REQUIRE(rows.at(0).src_ip == "1.2.3.4");
}

TEST_CASE("query_connections: filter by dst_port", "[db][query]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::LogEntry base{};
    base.ts = 1000; base.src_ip = "1.2.3.4"; base.src_port = 1000;
    base.dst_ip = "10.0.0.1"; base.dst_port = 80; base.proto = "TCP";
    base.tcp_flags = "SYN"; base.chain = "input"; base.in_iface = "ether1";
    base.rule = "FW_INPUT_NEW"; base.conn_state = "new"; base.pkt_len = 52;

    msmap::LogEntry https = base;
    https.dst_port = 443; https.ts = 2000;

    const auto geo = make_renderable_geo();
    db.insert(base,  geo);
    db.insert(https, geo);

    msmap::QueryFilters f;
    f.dst_port = 443;
    const auto rows = db.query_connections(f);
    REQUIRE(rows.size() == 1);
    REQUIRE(rows.at(0).dst_port.value_or(0) == 443);
}

TEST_CASE("query_connections: limit is respected", "[db][query]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::LogEntry base{};
    base.src_ip = "1.2.3.4"; base.src_port = 1000;
    base.dst_ip = "10.0.0.1"; base.dst_port = 80; base.proto = "TCP";
    base.tcp_flags = "SYN"; base.chain = "input"; base.in_iface = "ether1";
    base.rule = "FW_INPUT_NEW"; base.conn_state = "new"; base.pkt_len = 52;

    const auto geo = make_renderable_geo();
    for (int i = 0; i < 5; ++i) {
        base.ts = static_cast<std::int64_t>(i + 1);
        db.insert(base, geo);
    }

    msmap::QueryFilters f;
    f.limit = 3;
    const auto rows = db.query_connections(f);
    REQUIRE(rows.size() == 3);
}

TEST_CASE("query_connections: GeoIP columns round-trip correctly", "[db][query]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::LogEntry e{};
    e.ts = 1000; e.src_ip = "1.2.3.4"; e.src_port = 1234;
    e.dst_ip = "10.0.0.1"; e.dst_port = 80; e.proto = "TCP";
    e.tcp_flags = "SYN"; e.chain = "input"; e.in_iface = "ether1";
    e.rule = "FW_INPUT_NEW"; e.conn_state = "new"; e.pkt_len = 52;

    msmap::GeoIpResult geo;
    geo.country = "DE";
    geo.lat     = 51.5;
    geo.lon     = 10.0;
    geo.has_coords = true;
    geo.asn     = "AS1234 Example ISP";
    db.insert(e, geo);

    const auto rows = db.query_connections({});
    REQUIRE(rows.size() == 1);
    REQUIRE(rows.at(0).country        == "DE");
    REQUIRE(rows.at(0).lat.has_value());
    REQUIRE(rows.at(0).lon.has_value());
    REQUIRE(rows.at(0).asn            == "AS1234 Example ISP");
}

TEST_CASE("query_connections: ICMP row has null ports", "[db][query]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::LogEntry e{};
    e.ts = 1000; e.src_ip = "1.2.3.4"; e.src_port = -1; // ICMP sentinel
    e.dst_ip = "10.0.0.1"; e.dst_port = -1;
    e.proto = "ICMP"; e.chain = "input"; e.in_iface = "ether1";
    e.rule = "FW_INPUT_NEW"; e.conn_state = "new"; e.pkt_len = 28;

    db.insert(e, make_renderable_geo());

    const auto rows = db.query_connections({});
    REQUIRE(rows.size() == 1);
    REQUIRE_FALSE(rows.at(0).src_port.has_value());
    REQUIRE_FALSE(rows.at(0).dst_port.has_value());
}

TEST_CASE("normalize_asn_filter: trims and enforces practical ASN charset", "[http][asn]")
{
    SECTION("accepts and trims valid input")
    {
        const auto normalized = msmap::normalize_asn_filter("  google  ");
        REQUIRE(normalized.has_value());
        CHECK(*normalized == "google");
    }

    SECTION("accepts common ASN punctuation including colon")
    {
        const auto normalized =
            msmap::normalize_asn_filter("AS15169 Google LLC:Global (US-East)");
        REQUIRE(normalized.has_value());
        CHECK(*normalized == "AS15169 Google LLC:Global (US-East)");
    }

    SECTION("rejects empty/whitespace input")
    {
        CHECK_FALSE(msmap::normalize_asn_filter("").has_value());
        CHECK_FALSE(msmap::normalize_asn_filter("   ").has_value());
    }

    SECTION("rejects shorter than 3 chars after trim")
    {
        CHECK_FALSE(msmap::normalize_asn_filter("go").has_value());
        CHECK_FALSE(msmap::normalize_asn_filter("  x ").has_value());
    }

    SECTION("rejects disallowed characters")
    {
        CHECK_FALSE(msmap::normalize_asn_filter(std::string{"good\tname"}).has_value());
        CHECK_FALSE(msmap::normalize_asn_filter(std::string{"bad\nname"}).has_value());
        CHECK_FALSE(msmap::normalize_asn_filter("100%_literal").has_value());
        CHECK_FALSE(msmap::normalize_asn_filter("evil;drop").has_value());
    }

    SECTION("rejects values longer than 64 chars")
    {
        const std::string long_asn(65, 'a');
        CHECK_FALSE(msmap::normalize_asn_filter(long_asn).has_value());
    }
}

TEST_CASE("parse_positive_i64_exact: validates strict decimal positive integers", "[http][parse]")
{
    SECTION("accepts valid positive integers")
    {
        const auto parsed = msmap::parse_positive_i64_exact("86400");
        REQUIRE(parsed.has_value());
        CHECK(*parsed == 86400);
    }

    SECTION("rejects empty, zero, negatives, and non-digits")
    {
        CHECK_FALSE(msmap::parse_positive_i64_exact("").has_value());
        CHECK_FALSE(msmap::parse_positive_i64_exact("0").has_value());
        CHECK_FALSE(msmap::parse_positive_i64_exact("-1").has_value());
        CHECK_FALSE(msmap::parse_positive_i64_exact("+1").has_value());
        CHECK_FALSE(msmap::parse_positive_i64_exact("10s").has_value());
    }

    SECTION("rejects overflow")
    {
        CHECK_FALSE(msmap::parse_positive_i64_exact("9223372036854775808").has_value());
    }
}

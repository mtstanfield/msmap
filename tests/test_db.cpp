#include "db.h"
#include "parser.h"

#include <catch2/catch_test_macros.hpp>

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

TEST_CASE("TCP entry inserts without error")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());
    REQUIRE(db.insert(make_tcp_entry()));
}

TEST_CASE("ICMP entry inserts without error — ports stored as NULL")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());
    REQUIRE(db.insert(make_icmp_entry()));
}

TEST_CASE("Multiple entries insert without error")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    for (int i = 0; i < 10; ++i) {
        REQUIRE(db.insert(make_tcp_entry()));
        REQUIRE(db.insert(make_icmp_entry()));
    }
}

TEST_CASE("Entry parsed via parse_log inserts correctly")
{
    using namespace std::string_view_literals;
    constexpr auto kLine =
        "2026-02-27T08:14:23+00:00 router firewall,info FW_INPUT_NEW "
        "input: in:ether1 out:(unknown 0), connection-state:new "
        "src-mac bc:9a:8e:fb:12:f1, proto TCP (ACK), "
        "172.234.31.140:65226->108.89.67.16:44258, len 52"sv;

    const msmap::ParseResult result = msmap::parse_log(kLine);
    REQUIRE(result.ok());

    msmap::Database db{":memory:"};
    REQUIRE(db.valid());
    REQUIRE(db.insert(result.entry));
}

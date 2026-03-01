#include <catch2/catch_test_macros.hpp>

#include "parser.h"

using namespace msmap;

// ── Canonical test lines ──────────────────────────────────────────────────────

// TCP with src-mac, out:(unknown 0), timezone +00:00
// 2026-02-27T08:14:23 UTC = epoch 1772180063
static constexpr std::string_view kTcpLine =
    "2026-02-27T08:14:23+00:00 router firewall,info FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto TCP (ACK), "
    "172.234.31.140:65226->108.89.67.16:44258, len 52";

// UDP, no flags, src-mac present
static constexpr std::string_view kUdpLine =
    "2026-02-27T08:14:23+00:00 router firewall,info FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto UDP, "
    "172.234.31.140:12345->108.89.67.16:53, len 28";

// ICMP, no ports
static constexpr std::string_view kIcmpLine =
    "2026-02-27T08:14:23+00:00 router firewall,info FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto ICMP, "
    "172.234.31.140->108.89.67.16, len 28";

// Forward chain, real out_iface (ether2), no src-mac, SYN flags
static constexpr std::string_view kForwardLine =
    "2026-02-27T08:14:23+00:00 router firewall,info FW_FWD_DROP forward: "
    "in:ether1 out:ether2, connection-state:invalid "
    "proto TCP (SYN), 1.2.3.4:12345->10.0.0.1:80, len 44";

// No rule name — chain keyword follows topic,level directly
static constexpr std::string_view kNoRuleLine =
    "2026-02-27T08:14:23+00:00 router firewall,info input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "proto TCP (ACK), 1.2.3.4:1234->5.6.7.8:80, len 52";

// Non-zero timezone offset (+05:00) — same UTC moment as kTcpLine
static constexpr std::string_view kTzPlusLine =
    "2026-02-27T13:14:23+05:00 router firewall,info FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "proto TCP (ACK), 1.2.3.4:1234->5.6.7.8:80, len 52";

// Negative timezone offset (-05:00) — same UTC moment (03:14:23 - (-5h) = 08:14:23 UTC)
static constexpr std::string_view kTzMinusLine =
    "2026-02-27T03:14:23-05:00 router firewall,info FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "proto TCP (ACK), 1.2.3.4:1234->5.6.7.8:80, len 52";

// TCP line with trailing newline (rsyslog may append one)
static constexpr std::string_view kTrailingNl =
    "2026-02-27T08:14:23+00:00 router firewall,info FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "proto TCP (ACK), 1.2.3.4:1234->5.6.7.8:80, len 52\n";

// ── Happy-path tests ──────────────────────────────────────────────────────────

TEST_CASE("TCP line with src-mac parses correctly", "[parser][tcp]") {
    const auto result = parse_log(kTcpLine);
    REQUIRE(result.ok());

    // Epoch: 2026-02-27T08:14:23Z computed offline.
    // 2026-01-01 UTC = 1767225600
    // + 31 (Jan) * 86400 = 1769904000
    // + 26 (Feb days before 27th) * 86400 = 1772150400
    // + 8*3600 + 14*60 + 23 = 29663
    // = 1772180063
    CHECK(result.entry.ts         == 1772180063LL);
    CHECK(result.entry.hostname   == "router");
    CHECK(result.entry.topic      == "firewall");
    CHECK(result.entry.level      == "info");
    CHECK(result.entry.rule       == "FW_INPUT_NEW");
    CHECK(result.entry.chain      == "input");
    CHECK(result.entry.in_iface   == "ether1");
    CHECK(result.entry.out_iface  == "(unknown 0)");
    CHECK(result.entry.conn_state == "new");
    CHECK(result.entry.proto      == "TCP");
    CHECK(result.entry.tcp_flags  == "ACK");
    CHECK(result.entry.src_ip     == "172.234.31.140");
    CHECK(result.entry.src_port   == 65226);
    CHECK(result.entry.dst_ip     == "108.89.67.16");
    CHECK(result.entry.dst_port   == 44258);
    CHECK(result.entry.pkt_len    == 52);
}

TEST_CASE("UDP line parses correctly", "[parser][udp]") {
    const auto result = parse_log(kUdpLine);
    REQUIRE(result.ok());

    CHECK(result.entry.proto      == "UDP");
    CHECK(result.entry.tcp_flags.empty());
    CHECK(result.entry.src_ip     == "172.234.31.140");
    CHECK(result.entry.src_port   == 12345);
    CHECK(result.entry.dst_ip     == "108.89.67.16");
    CHECK(result.entry.dst_port   == 53);
    CHECK(result.entry.pkt_len    == 28);
}

TEST_CASE("ICMP line parses correctly — no ports", "[parser][icmp]") {
    const auto result = parse_log(kIcmpLine);
    REQUIRE(result.ok());

    CHECK(result.entry.proto      == "ICMP");
    CHECK(result.entry.tcp_flags.empty());
    CHECK(result.entry.src_ip     == "172.234.31.140");
    CHECK(result.entry.src_port   == -1);
    CHECK(result.entry.dst_ip     == "108.89.67.16");
    CHECK(result.entry.dst_port   == -1);
    CHECK(result.entry.pkt_len    == 28);
}

TEST_CASE("Forward chain, real out_iface, no src-mac", "[parser][forward]") {
    const auto result = parse_log(kForwardLine);
    REQUIRE(result.ok());

    CHECK(result.entry.chain      == "forward");
    CHECK(result.entry.rule       == "FW_FWD_DROP");
    CHECK(result.entry.out_iface  == "ether2");
    CHECK(result.entry.conn_state == "invalid");
    CHECK(result.entry.tcp_flags  == "SYN");
    CHECK(result.entry.src_ip     == "1.2.3.4");
    CHECK(result.entry.src_port   == 12345);
    CHECK(result.entry.dst_ip     == "10.0.0.1");
    CHECK(result.entry.dst_port   == 80);
    CHECK(result.entry.pkt_len    == 44);
}

TEST_CASE("No rule name — chain keyword directly after level", "[parser][norule]") {
    const auto result = parse_log(kNoRuleLine);
    REQUIRE(result.ok());

    CHECK(result.entry.rule.empty());
    CHECK(result.entry.chain == "input");
}

TEST_CASE("Positive timezone offset normalised to UTC", "[parser][tz]") {
    // +05:00 means local time is 5 h ahead; UTC = local - 5 h
    const auto result = parse_log(kTzPlusLine);
    REQUIRE(result.ok());
    CHECK(result.entry.ts == 1772180063LL);
}

TEST_CASE("Negative timezone offset normalised to UTC", "[parser][tz]") {
    // -05:00 means local time is 5 h behind; UTC = local + 5 h
    const auto result = parse_log(kTzMinusLine);
    REQUIRE(result.ok());
    CHECK(result.entry.ts == 1772180063LL);
}

TEST_CASE("Trailing newline stripped cleanly", "[parser][whitespace]") {
    const auto result = parse_log(kTrailingNl);
    REQUIRE(result.ok());
    CHECK(result.entry.pkt_len == 52);
}

// ── BSD syslog format tests ───────────────────────────────────────────────────

// BSD syslog: <PRI>Mmm DD HH:MM:SS HOSTNAME MSG
// PRI 134 = facility local0 (16*8) + severity info (6) — typical Mikrotik value.
// These lines are what msmap receives directly from Mikrotik over UDP 514,
// without any rsyslog reformatting.

static constexpr std::string_view kBsdTcpLine =
    "<134>Feb 27 08:14:23 router firewall,info FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto TCP (SYN), "
    "185.220.101.47:54321->203.0.113.1:22, len 60";

static constexpr std::string_view kBsdUdpLine =
    "<134>Feb 27 08:14:26 router firewall,info FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto UDP, "
    "8.8.8.8:5353->203.0.113.1:53, len 64";

static constexpr std::string_view kBsdIcmpLine =
    "<134>Feb 27 08:14:27 router firewall,info FW_INPUT_DROP input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto ICMP, "
    "1.1.1.1->203.0.113.1, len 84";

// Single-digit day uses space-padding: "Jan  5" (two spaces before the digit).
static constexpr std::string_view kBsdSingleDigitDay =
    "<134>Jan  5 12:00:00 router firewall,info FW_INPUT_NEW input: "
    "in:ether1 out:ether2, connection-state:new "
    "proto TCP (ACK), 10.0.0.1:1234->10.0.0.2:80, len 52";

TEST_CASE("BSD syslog TCP line parses correctly", "[parser][bsd][tcp]") {
    const auto result = parse_log(kBsdTcpLine);
    REQUIRE(result.ok());

    // Year inferred from system clock; ts must be a plausible recent epoch.
    CHECK(result.entry.ts > 0);
    CHECK(result.entry.hostname   == "router");
    CHECK(result.entry.topic      == "firewall");
    CHECK(result.entry.level      == "info");
    CHECK(result.entry.rule       == "FW_INPUT_NEW");
    CHECK(result.entry.chain      == "input");
    CHECK(result.entry.in_iface   == "ether1");
    CHECK(result.entry.out_iface  == "(unknown 0)");
    CHECK(result.entry.conn_state == "new");
    CHECK(result.entry.proto      == "TCP");
    CHECK(result.entry.tcp_flags  == "SYN");
    CHECK(result.entry.src_ip     == "185.220.101.47");
    CHECK(result.entry.src_port   == 54321);
    CHECK(result.entry.dst_ip     == "203.0.113.1");
    CHECK(result.entry.dst_port   == 22);
    CHECK(result.entry.pkt_len    == 60);
}

TEST_CASE("BSD syslog UDP line parses correctly", "[parser][bsd][udp]") {
    const auto result = parse_log(kBsdUdpLine);
    REQUIRE(result.ok());

    CHECK(result.entry.ts > 0);
    CHECK(result.entry.proto     == "UDP");
    CHECK(result.entry.tcp_flags.empty());
    CHECK(result.entry.src_ip    == "8.8.8.8");
    CHECK(result.entry.src_port  == 5353);
    CHECK(result.entry.dst_ip    == "203.0.113.1");
    CHECK(result.entry.dst_port  == 53);
    CHECK(result.entry.pkt_len   == 64);
}

TEST_CASE("BSD syslog ICMP line parses correctly — no ports", "[parser][bsd][icmp]") {
    const auto result = parse_log(kBsdIcmpLine);
    REQUIRE(result.ok());

    CHECK(result.entry.ts > 0);
    CHECK(result.entry.proto     == "ICMP");
    CHECK(result.entry.tcp_flags.empty());
    CHECK(result.entry.src_ip    == "1.1.1.1");
    CHECK(result.entry.src_port  == -1);
    CHECK(result.entry.dst_ip    == "203.0.113.1");
    CHECK(result.entry.dst_port  == -1);
    CHECK(result.entry.pkt_len   == 84);
}

TEST_CASE("BSD syslog single-digit day (space-padded) parses correctly", "[parser][bsd]") {
    const auto result = parse_log(kBsdSingleDigitDay);
    REQUIRE(result.ok());

    CHECK(result.entry.ts > 0);
    CHECK(result.entry.proto     == "TCP");
    CHECK(result.entry.tcp_flags == "ACK");
    CHECK(result.entry.src_ip    == "10.0.0.1");
    CHECK(result.entry.src_port  == 1234);
    CHECK(result.entry.dst_ip    == "10.0.0.2");
    CHECK(result.entry.dst_port  == 80);
    CHECK(result.entry.pkt_len   == 52);
}

// ── Error-path tests ──────────────────────────────────────────────────────────

TEST_CASE("Empty line returns error", "[parser][error]") {
    const auto result = parse_log("");
    CHECK_FALSE(result.ok());
    CHECK(result.error == "empty line");
}

TEST_CASE("Bad timestamp returns error", "[parser][error]") {
    const auto result = parse_log("NOT-A-TIMESTAMP router firewall,info input: "
                                  "in:ether1 out:ether2, connection-state:new "
                                  "proto TCP (ACK), 1.2.3.4:1->2.3.4.5:2, len 1");
    CHECK_FALSE(result.ok());
    CHECK(result.error.substr(0, 14) == "bad timestamp:");
}

TEST_CASE("Unknown chain name returns error", "[parser][error]") {
    const auto result = parse_log("2026-02-27T08:14:23+00:00 router firewall,info "
                                  "boguschain: in:ether1 out:ether2, "
                                  "connection-state:new proto TCP (ACK), "
                                  "1.2.3.4:1->2.3.4.5:2, len 1");
    CHECK_FALSE(result.ok());
    CHECK(result.error.find("unknown chain") != std::string::npos);
}

TEST_CASE("Unsupported protocol returns error", "[parser][error]") {
    const auto result = parse_log("2026-02-27T08:14:23+00:00 router firewall,info "
                                  "FW_INPUT_NEW input: in:ether1 out:(unknown 0), "
                                  "connection-state:new proto OSPF, len 1");
    CHECK_FALSE(result.ok());
    CHECK(result.error.find("unsupported protocol") != std::string::npos);
}

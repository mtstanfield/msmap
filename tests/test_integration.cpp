// test_integration.cpp
//
// End-to-end integration tests for the full ingest pipeline:
//   UDP socket → listener → parser → SQLite → query
//
// Each test spins up a fresh in-memory Database and GeoIp (disabled),
// starts run_listener() on a std::jthread, injects log lines as UDP
// datagrams to loopback, then queries the DB and asserts field values.
//
// Thread lifecycle: jthread destructor calls request_stop() then join();
// the listener's poll(50 ms) timeout ensures it exits within 50 ms.

#include "db.h"
#include "geoip.h"
#include "listener.h"

#include <catch2/catch_test_macros.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

// ── Helpers ───────────────────────────────────────────────────────────────────

namespace {

constexpr int kPort{54340};

/// Wait for the listener to bind and enter its recvfrom loop.
/// A short sleep is sufficient: socket() + bind() complete in microseconds
/// and the listener logs "[INFO]" before entering the poll loop.
[[nodiscard]] bool wait_ready(int /*port*/) noexcept
{
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return true;
}

/// Send each line as an individual UDP datagram to the listener on loopback.
/// Sleeps 20 ms after the last send so the listener has time to process and
/// insert all rows before the test queries the DB.
void send_lines(int port, std::initializer_list<std::string_view> lines)
{
    const int sock = socket(AF_INET, SOCK_DGRAM, 0);
    REQUIRE(sock >= 0);

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(static_cast<std::uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    for (const std::string_view line : lines) {
        const auto sent = sendto(sock, line.data(), line.size(), 0,
                                 reinterpret_cast<const sockaddr*>(&addr),
                                 sizeof(addr));
        REQUIRE(sent == static_cast<ssize_t>(line.size()));
    }

    (void)close(sock);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
}

/// RAII fixture: holds an in-memory Database, a no-op GeoIp, and a jthread
/// running run_listener().  Destructor calls request_stop() + join() so the
/// listener exits within one poll(50 ms) cycle; members are then destroyed
/// in reverse declaration order (thread first → geoip → db).
struct ListenerFixture {
    msmap::Database db{":memory:"};
    msmap::GeoIp    geoip{"/nonexistent/city.mmdb", ""};
    std::jthread    thread;

    explicit ListenerFixture(int port)
        : thread{[this, port](std::stop_token st) {
              msmap::run_listener(port, db, geoip, nullptr, st);
          }}
    {
        REQUIRE(wait_ready(port));
    }
};

// ── Canonical log lines (real Mikrotik BSD syslog TAG format) ─────────────────

// TCP SYN — well-known Tor exit node, inbound to port 22
constexpr std::string_view kTcpSyn =
    "2026-02-27T08:14:23+00:00 router FW_INPUT_NEW: FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto TCP (SYN), "
    "185.220.101.47:54321->203.0.113.1:22, len 60";

// TCP ACK — generic scanner, inbound to port 80
constexpr std::string_view kTcpAck =
    "2026-02-27T08:14:25+00:00 router FW_INPUT_NEW: FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto TCP (ACK), "
    "172.234.31.140:65226->203.0.113.1:80, len 52";

// UDP — Google DNS
constexpr std::string_view kUdp =
    "2026-02-27T08:14:26+00:00 router FW_INPUT_NEW: FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto UDP, "
    "8.8.8.8:5353->203.0.113.1:53, len 64";

// ICMP — Cloudflare ping
constexpr std::string_view kIcmp =
    "2026-02-27T08:14:27+00:00 router FW_INPUT_DROP: FW_INPUT_DROP input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto ICMP, "
    "1.1.1.1->203.0.113.1, len 84";

// +02:00 variant of kTcpSyn — same UTC moment, different source IP so it is
// a distinct row after dedup (used to verify timezone normalisation to UTC).
constexpr std::string_view kTcpSynPlusTwoHours =
    "2026-02-27T10:14:23+02:00 router FW_INPUT_NEW: FW_INPUT_NEW input: "
    "in:ether1 out:(unknown 0), connection-state:new "
    "src-mac bc:9a:8e:fb:12:f1, proto TCP (SYN), "
    "185.220.101.48:54321->203.0.113.1:22, len 60";

// Not a Mikrotik log line — parser should skip and log a WARN.
constexpr std::string_view kInvalid = "not a valid Mikrotik firewall log line";

} // anonymous namespace

// ── Test cases ────────────────────────────────────────────────────────────────

TEST_CASE("Integration: TCP line parsed and stored correctly")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kTcpSyn});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    const auto& r = rows.front();
    CHECK(r.src_ip     == "185.220.101.47");
    CHECK(r.src_port   == 54321);
    CHECK(r.dst_ip     == "203.0.113.1");
    CHECK(r.dst_port   == 22);
    CHECK(r.proto      == "TCP");
    CHECK(r.tcp_flags  == "SYN");
    CHECK(r.chain      == "input");
    CHECK(r.conn_state == "new");
    CHECK(r.pkt_len    == 60);
    CHECK(r.rule       == "FW_INPUT_NEW");
    CHECK(r.in_iface   == "ether1");
    // GeoIP absent → geo columns empty / nullopt
    CHECK(r.country.empty());
    CHECK(!r.lat.has_value());
    // AbuseIPDB absent (abuse=nullptr) → threat nullopt
    CHECK(!r.threat.has_value());
}

TEST_CASE("Integration: UDP line — no tcp_flags, ports present")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kUdp});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    const auto& r = rows.front();
    CHECK(r.proto      == "UDP");
    CHECK(r.tcp_flags.empty());
    CHECK(r.src_ip     == "8.8.8.8");
    CHECK(r.src_port   == 5353);
    CHECK(r.dst_port   == 53);
}

TEST_CASE("Integration: ICMP line — ports stored as NULL")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kIcmp});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    const auto& r = rows.front();
    CHECK(r.proto      == "ICMP");
    CHECK(r.src_ip     == "1.1.1.1");
    CHECK(!r.src_port.has_value());
    CHECK(!r.dst_port.has_value());
    CHECK(r.tcp_flags.empty());
}

TEST_CASE("Integration: non-UTC timezone normalised to UTC epoch")
{
    ListenerFixture fix{kPort};
    // kTcpSyn (UTC) and kTcpSynPlusTwoHours (+02:00) represent the same UTC
    // instant but have different source IPs so they are distinct DB rows.
    send_lines(kPort, {kTcpSyn, kTcpSynPlusTwoHours});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    REQUIRE(rows.size() == 2);
    // Both records represent the same instant — ts must be equal.
    CHECK(rows.at(0).ts == rows.at(1).ts);
}

TEST_CASE("Integration: multiple datagrams all inserted")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kTcpSyn, kUdp, kIcmp});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    REQUIRE(rows.size() == 3);
}

TEST_CASE("Integration: unparseable line skipped, valid line still inserted")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kInvalid, kTcpAck});

    // The invalid line is logged as a WARN and discarded; only kTcpAck is stored.
    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().proto == "TCP");
    CHECK(rows.front().src_ip == "172.234.31.140");
}

TEST_CASE("Integration: two sequential datagrams accumulate rows")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kTcpSyn});
    send_lines(kPort, {kUdp});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    REQUIRE(rows.size() == 2);
}

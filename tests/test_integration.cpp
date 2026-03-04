// test_integration.cpp
//
// End-to-end integration tests for the full ingest pipeline:
//   UDP socket → listener → parser → SQLite → query
//
// Each test spins up a fresh in-memory Database and a GeoIp instance without a
// valid City DB, starts run_listener() on a std::jthread, injects log lines as
// UDP datagrams to loopback, then asserts that map-unrenderable rows are
// dropped safely at ingest.
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
              msmap::run_listener(port, db, geoip, nullptr, nullptr, nullptr, {}, st);
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

TEST_CASE("Integration: valid TCP line is dropped when source GeoIP is unavailable")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kTcpSyn});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    CHECK(rows.empty());
}

TEST_CASE("Integration: valid UDP line is dropped when source GeoIP is unavailable")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kUdp});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    CHECK(rows.empty());
}

TEST_CASE("Integration: valid ICMP line is dropped when source GeoIP is unavailable")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kIcmp});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    CHECK(rows.empty());
}

TEST_CASE("Integration: timezone-normalised valid rows still drop without source GeoIP")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kTcpSyn, kTcpSynPlusTwoHours});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    CHECK(rows.empty());
}

TEST_CASE("Integration: multiple valid datagrams are all dropped without source GeoIP")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kTcpSyn, kUdp, kIcmp});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    CHECK(rows.empty());
}

TEST_CASE("Integration: unparseable line skipped, valid line still drops without source GeoIP")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kInvalid, kTcpAck});

    // The invalid line is logged as a WARN and the valid line is dropped later
    // because no City GeoIP is available in this fixture.
    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    CHECK(rows.empty());
}

TEST_CASE("Integration: repeated valid datagrams remain dropped without source GeoIP")
{
    ListenerFixture fix{kPort};
    send_lines(kPort, {kTcpSyn});
    send_lines(kPort, {kUdp});

    const auto rows = fix.db.query_connections(msmap::QueryFilters{});
    CHECK(rows.empty());
}

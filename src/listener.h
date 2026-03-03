#pragma once

#include <cstdint>
#include <stop_token>
#include <vector>

namespace msmap {

class Database;
class GeoIp;
class AbuseCache;
class HomeResolver;

/// Listen on UDP 0.0.0.0:port for BSD syslog datagrams sent directly by
/// Mikrotik (native format; no rsyslog intermediary required).
///
/// Each UDP datagram contains exactly one syslog message. The parser
/// auto-detects BSD (<PRI>) and RFC 3339 timestamp formats, so both
/// direct Mikrotik datagrams and rsyslog-reformatted lines are accepted.
/// Enriches each entry with GeoIP and AbuseIPDB data and inserts into `db`.
/// Checks geoip.reload_if_changed() on every received datagram (fast no-op
/// when the mmdb files have not changed).
/// Parse warnings and socket errors go to stderr.
///
/// Stops cleanly when `stoken.stop_requested()` becomes true (within one
/// poll(2) timeout, ≤ 50 ms). Default-constructed stop_token never fires,
/// so main() needs no change.
///
/// `abuse` may be null — pass nullptr to disable OSINT enrichment
/// (all threat columns will remain NULL).
///
/// `allow_ips` is a list of network-byte-order IPv4 addresses that are
/// allowed to send datagrams. Empty = accept from any source.
///
/// `home_resolver` may be null. When non-null and valid, new rows with RFC1918
/// destination IPv4s are rewritten to the resolved home IP before insert.
void run_listener(int port, Database& db, GeoIp& geoip, AbuseCache* abuse,
                  const HomeResolver* home_resolver = nullptr,
                  const std::vector<std::uint32_t>& allow_ips = {},
                  const std::stop_token& stoken = {});

} // namespace msmap

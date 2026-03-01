#pragma once

namespace msmap {

class Database;
class GeoIp;
class AbuseCache;

/// Block on TCP 127.0.0.1:port, parse each received syslog line,
/// enrich with GeoIP and AbuseIPDB, and insert into `db`.
///
/// One connection at a time; rsyslog opens a single persistent connection.
/// On disconnection, waits for the next connect (no busy-loop).
/// Checks geoip.reload_if_changed() on every recv() iteration (fast no-op
/// when the mmdb files have not changed).
/// Parse warnings and socket errors go to stderr.
/// This function does not return under normal operation.
///
/// `abuse` may be null — pass nullptr to disable OSINT enrichment
/// (all threat columns will remain NULL).
void run_listener(int port, Database& db, GeoIp& geoip, AbuseCache* abuse);

} // namespace msmap

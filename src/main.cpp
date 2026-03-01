// msmap – Mikrotik Firewall Log Viewer

#include "abuse_cache.h"
#include "db.h"
#include "geoip.h"
#include "http.h"
#include "listener.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

// Compile-time defaults — all overridable via environment variables.
// See the Environment variables section in README.md.
constexpr const char* kDefaultDbPath    {"/data/msmap.db"};
constexpr const char* kDefaultCityMmdb  {"/var/lib/msmap/geoip/GeoLite2-City.mmdb"};
constexpr const char* kDefaultAsnMmdb   {"/var/lib/msmap/geoip/GeoLite2-ASN.mmdb"};
constexpr int         kDefaultListenPort{5140};
constexpr int         kDefaultHttpPort  {8080};

/// Return env var value if set, otherwise the compile-time default.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::string env_or(const char* var, const char* fallback)
{
    const char* val = std::getenv(var); // NOLINT(concurrency-mt-unsafe)
    return val != nullptr ? std::string{val} : std::string{fallback};
}

/// Return the integer value of an env var, or `fallback` if unset / invalid.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int env_int(const char* var, int fallback)
{
    const char* val = std::getenv(var); // NOLINT(concurrency-mt-unsafe)
    if (val == nullptr || *val == '\0') { return fallback; }
    char* end = nullptr;
    const long parsed = std::strtol(val, &end, 10);
    return (*end == '\0' && parsed > 0 && parsed < 65536)
        ? static_cast<int>(parsed)
        : fallback;
}

} // namespace

int main() {
    // ── Resolve all configuration from environment variables ─────────────────
    const std::string db_path     = env_or("MSMAP_DB_PATH",      kDefaultDbPath);
    const std::string city_path   = env_or("MSMAP_CITY_MMDB",    kDefaultCityMmdb);
    const std::string asn_path    = env_or("MSMAP_ASN_MMDB",     kDefaultAsnMmdb);
    const std::string abuse_key   = env_or("ABUSEIPDB_API_KEY",  "");
    const int         listen_port = env_int("MSMAP_LISTEN_PORT",  kDefaultListenPort);
    const int         http_port   = env_int("MSMAP_HTTP_PORT",    kDefaultHttpPort);

    std::clog << "[INFO] db        : " << db_path     << '\n'
              << "[INFO] city mmdb : " << city_path   << '\n'
              << "[INFO] asn mmdb  : " << asn_path    << '\n'
              << "[INFO] listen    : 0.0.0.0:"   << listen_port << " (UDP/syslog)\n"
              << "[INFO] http      : 0.0.0.0:"   << http_port   << '\n';

    msmap::Database db{db_path};
    if (!db.valid()) {
        std::clog << "[FATAL] failed to open database: " << db_path << '\n';
        return EXIT_FAILURE;
    }

    // GeoIP is optional enrichment; we continue even if the mmdb files are absent.
    msmap::GeoIp geoip{city_path, asn_path};

    // AbuseIPDB OSINT enrichment — optional; disabled when key is unset.
    msmap::AbuseCache abuse{db_path, abuse_key};
    if (!abuse.valid()) {
        std::clog << "[WARN] AbuseCache failed to open; threat scores disabled\n";
    }
    if (abuse_key.empty()) {
        std::clog << "[INFO] ABUSEIPDB_API_KEY not set; threat scores disabled\n";
    }
    msmap::AbuseCache* const abuse_ptr = abuse.valid() ? &abuse : nullptr;

    // HTTP server starts its own internal thread; run_listener blocks below.
    msmap::HttpServer const http{static_cast<std::uint16_t>(http_port), db};
    if (!http.valid()) {
        std::clog << "[FATAL] HTTP server failed to start on port "
                  << http_port << '\n';
        return EXIT_FAILURE;
    }

    msmap::run_listener(listen_port, db, geoip, abuse_ptr);
    return EXIT_SUCCESS;
}

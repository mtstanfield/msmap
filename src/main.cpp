// msmap – Mikrotik Firewall Log Viewer

#include "db.h"
#include "geoip.h"
#include "http.h"
#include "listener.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

constexpr int            kListenPort    {5140};
constexpr std::uint16_t  kHttpPort      {8080};
constexpr const char*    kDbPath        {"msmap.db"};
constexpr const char*    kDefaultCityMmdb{"/var/lib/msmap/geoip/GeoLite2-City.mmdb"};
constexpr const char*    kDefaultAsnMmdb {"/var/lib/msmap/geoip/GeoLite2-ASN.mmdb"};

/// Return env var value if set, otherwise the compile-time default.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::string env_or(const char* var, const char* fallback)
{
    const char* val = std::getenv(var); // NOLINT(concurrency-mt-unsafe)
    return val != nullptr ? std::string{val} : std::string{fallback};
}

} // namespace

int main() {
    msmap::Database db{kDbPath};
    if (!db.valid()) {
        std::clog << "[FATAL] failed to open database: " << kDbPath << '\n';
        return EXIT_FAILURE;
    }

    // GeoIP is optional enrichment; we continue even if the mmdb files are absent.
    const std::string city_path = env_or("MSMAP_CITY_MMDB", kDefaultCityMmdb);
    const std::string asn_path  = env_or("MSMAP_ASN_MMDB",  kDefaultAsnMmdb);
    msmap::GeoIp geoip{city_path, asn_path};

    // HTTP server starts its own internal thread; run_listener blocks below.
    msmap::HttpServer const http{kHttpPort, db};
    if (!http.valid()) {
        std::clog << "[FATAL] HTTP server failed to start on port "
                  << kHttpPort << '\n';
        return EXIT_FAILURE;
    }

    msmap::run_listener(kListenPort, db, geoip);
    return EXIT_SUCCESS;
}

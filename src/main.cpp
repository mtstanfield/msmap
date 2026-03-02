// msmap – Mikrotik Firewall Log Viewer

#include "abuse_cache.h"
#include "db.h"
#include "geoip.h"
#include "home_resolver.h"
#include "http.h"
#include "listener.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

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

/// Parse a comma-separated list of IPv4 addresses into network-byte-order u32s.
/// Tokens that fail inet_pton are skipped with a warning.
std::vector<std::uint32_t> parse_allow_ips(std::string_view raw)
{
    std::vector<std::uint32_t> result;
    while (!raw.empty()) {
        const auto comma = raw.find(',');
        const std::string_view token = (comma == std::string_view::npos)
            ? raw : raw.substr(0, comma);
        raw = (comma == std::string_view::npos) ? "" : raw.substr(comma + 1);

        // Trim leading/trailing whitespace from token.
        const auto first = token.find_first_not_of(" \t");
        if (first == std::string_view::npos) { continue; }
        const auto last  = token.find_last_not_of(" \t");
        const std::string ip_str{token.substr(first, last - first + 1)};

        in_addr addr{};
        if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
            result.push_back(addr.s_addr);
        } else {
            std::clog << "[WARN] MSMAP_INGEST_ALLOW: invalid IP skipped: "
                      << ip_str << '\n';
        }
    }
    return result;
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
    const std::string home_host   = env_or("MSMAP_HOME_HOST",    "");
    const int         listen_port = env_int("MSMAP_LISTEN_PORT",  kDefaultListenPort);
    const int         http_port   = env_int("MSMAP_HTTP_PORT",    kDefaultHttpPort);
    const std::vector<std::uint32_t> allow_ips =
        parse_allow_ips(env_or("MSMAP_INGEST_ALLOW", ""));

    std::clog << "[INFO] db        : " << db_path     << '\n'
              << "[INFO] city mmdb : " << city_path   << '\n'
              << "[INFO] asn mmdb  : " << asn_path    << '\n'
              << "[INFO] home host : " << (home_host.empty() ? "(not set)" : home_host) << '\n'
              << "[INFO] listen    : 0.0.0.0:"   << listen_port << " (UDP/syslog)\n"
              << "[INFO] http      : 0.0.0.0:"   << http_port   << '\n';

    if (allow_ips.empty()) {
        std::clog << "[INFO] ingest    : open (no allowlist)\n";
    } else {
        for (const std::uint32_t ip : allow_ips) {
            std::array<char, INET_ADDRSTRLEN> buf{};
            in_addr a{};
            a.s_addr = ip;
            std::clog << "[INFO] ingest allow: "
                      << inet_ntop(AF_INET, &a, buf.data(), buf.size()) << '\n';
        }
    }

    msmap::Database db{db_path};
    if (!db.valid()) {
        std::clog << "[FATAL] failed to open database: " << db_path << '\n';
        return EXIT_FAILURE;
    }

    // GeoIP is optional enrichment; we continue even if the mmdb files are absent.
    msmap::GeoIp geoip{city_path, asn_path};

    // Resolve MSMAP_HOME_HOST → lat/lon for the arc animation.  HomeResolver
    // performs the initial lookup synchronously then re-checks every 30 minutes
    // in a background thread.  When home_host is empty the resolver is not
    // constructed and HttpServer receives a null pointer — /api/home returns 404.
    std::unique_ptr<msmap::HomeResolver> home_resolver;
    if (!home_host.empty()) {
        home_resolver = std::make_unique<msmap::HomeResolver>(home_host, geoip);
        const msmap::HomePoint hp = home_resolver->get();
        if (hp.valid) {
            std::clog << "[INFO] home geo   : " << hp.lat << ", " << hp.lon << '\n';
        }
        // Resolution failure warnings are emitted inside HomeResolver.
    }

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
    msmap::HttpServer const http{static_cast<std::uint16_t>(http_port), db,
                                 home_resolver.get()};
    if (!http.valid()) {
        std::clog << "[FATAL] HTTP server failed to start on port "
                  << http_port << '\n';
        return EXIT_FAILURE;
    }

    msmap::run_listener(listen_port, db, geoip, abuse_ptr, allow_ips);
    return EXIT_SUCCESS;
}

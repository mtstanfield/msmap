#pragma once

#include "home_resolver.h"

#include <cstdint>
#include <memory>

// Opaque libmicrohttpd daemon handle; full definition only needed in http.cpp.
struct MHD_Daemon; // NOLINT(readability-identifier-naming) — third-party C name

namespace msmap {

class Database;
class AbuseCache;
class IpIntelCache;

/// Context bundle passed to the MHD request callback as `cls`.
/// Groups the server-owned state the callback needs.
struct HandlerCtx {
    Database*            db;
    const HomeResolver*  home_resolver;  // null when MSMAP_HOME_HOST is unset
    const AbuseCache*    abuse_cache;    // null when AbuseIPDB is disabled
    const IpIntelCache*  intel_cache;    // null when Tor/DROP intel is disabled
    bool                 abuse_enabled;
    bool                 intel_enabled;
};

/// Custom deleter: calls MHD_stop_daemon, which stops libmicrohttpd's internal
/// polling thread and worker pool before returning. Declared here; defined in
/// http.cpp where the full microhttpd.h is included.
struct MhdDaemonCloser {
    void operator()(MHD_Daemon* d) const noexcept;
};

/// Embedded HTTP/1.1 server backed by libmicrohttpd.
///
/// Starts libmicrohttpd with one internal polling thread plus a configurable
/// request-worker pool. The server stops and joins those internal threads when
/// this object is destroyed.
///
/// Endpoints:
///   GET /api/map           — aggregate JSON object for the requested window
///   GET /api/detail        — paginated raw rows for popup drilldown
///   GET /api/home          — JSON {lat,lon} if MSMAP_HOME_HOST is set, else 404
///   GET /api/status        — lightweight operator status snapshot
///   GET /                  — full map UI (HTML)
class HttpServer {
public:
    /// `home_resolver` may be null when MSMAP_HOME_HOST is not configured;
    /// /api/home will return 404 in that case.
    HttpServer(std::uint16_t       port,
               Database&           db,
               const HomeResolver* home_resolver,
               const AbuseCache*   abuse_cache,
               const IpIntelCache* intel_cache,
               bool                abuse_enabled,
               bool                intel_enabled,
               unsigned int        thread_pool_size = 4) noexcept;

    // Destructor defined in http.cpp (stops MHD daemon, joins thread).
    ~HttpServer() noexcept;

    HttpServer(const HttpServer&)            = delete;
    HttpServer& operator=(const HttpServer&) = delete;
    HttpServer(HttpServer&&)                 = delete;
    HttpServer& operator=(HttpServer&&)      = delete;

    /// True if MHD_start_daemon succeeded and the server is listening.
    [[nodiscard]] bool valid() const noexcept { return daemon_ != nullptr; }

private:
    // Declaration order matches initialisation order (C++ standard):
    //   db_ is initialised first, then ctx_ (which points into it),
    //   then daemon_ last so MHD_stop_daemon runs before anything else is destroyed.
    Database&           db_;
    HandlerCtx          ctx_;
    std::unique_ptr<MHD_Daemon, MhdDaemonCloser> daemon_;
};

} // namespace msmap

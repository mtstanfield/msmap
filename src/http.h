#pragma once

#include <cstdint>
#include <memory>

// Opaque libmicrohttpd daemon handle; full definition only needed in http.cpp.
struct MHD_Daemon; // NOLINT(readability-identifier-naming) — third-party C name

namespace msmap {

class Database;

/// Home location resolved from MSMAP_HOME_HOST at startup.
/// Passed to HttpServer and served via GET /api/home.
struct HomePoint {
    bool   valid{false};
    double lat{0.0};
    double lon{0.0};
};

/// Context bundle passed to the MHD request callback as `cls`.
/// Groups the two pieces of state the callback needs.
struct HandlerCtx {
    Database* db;
    HomePoint home;
};

/// Custom deleter: calls MHD_stop_daemon, which joins the internal polling
/// thread before returning.  Declared here; defined in http.cpp where the
/// full microhttpd.h is included.
struct MhdDaemonCloser {
    void operator()(MHD_Daemon* d) const noexcept;
};

/// Embedded HTTP/1.1 server backed by libmicrohttpd.
///
/// Starts one internal polling thread on construction; that thread handles
/// all incoming HTTP connections.  The server stops (and the thread exits)
/// when this object is destroyed.
///
/// Endpoints:
///   GET /api/connections   — JSON array, filterable via query parameters:
///                             since=<epoch>  until=<epoch>  ip=<addr>
///                             country=<CC>   proto=<TCP|UDP|ICMP>
///                             port=<n>       limit=<n>  (default 25 000, max 25 000)
///   GET /api/home          — JSON {lat,lon} if MSMAP_HOME_HOST is set, else 404
///   GET /                  — full map UI (HTML)
class HttpServer {
public:
    HttpServer(std::uint16_t port, Database& db, const HomePoint& home) noexcept;

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
    //   db_ and home_ are initialised first, then ctx_ (which points into them),
    //   then daemon_ last so MHD_stop_daemon runs before anything else is destroyed.
    Database& db_;
    HomePoint home_;
    HandlerCtx ctx_;
    std::unique_ptr<MHD_Daemon, MhdDaemonCloser> daemon_;
};

} // namespace msmap

#pragma once

#include <cstdint>
#include <memory>

// Opaque libmicrohttpd daemon handle; full definition only needed in http.cpp.
struct MHD_Daemon; // NOLINT(readability-identifier-naming) — third-party C name

namespace msmap {

class Database;

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
///                             port=<n>       limit=<n>  (default 1000, max 10 000)
///   GET /                  — placeholder HTML (full map UI added later)
class HttpServer {
public:
    HttpServer(std::uint16_t port, Database& db) noexcept;

    // Destructor defined in http.cpp (stops MHD daemon, joins thread).
    ~HttpServer() noexcept;

    HttpServer(const HttpServer&)            = delete;
    HttpServer& operator=(const HttpServer&) = delete;
    HttpServer(HttpServer&&)                 = delete;
    HttpServer& operator=(HttpServer&&)      = delete;

    /// True if MHD_start_daemon succeeded and the server is listening.
    [[nodiscard]] bool valid() const noexcept { return daemon_ != nullptr; }

private:
    // db_ must be declared before daemon_ so that the daemon is destroyed
    // (MHD_stop_daemon called) before db_ could become a dangling reference.
    Database& db_;
    std::unique_ptr<MHD_Daemon, MhdDaemonCloser> daemon_;
};

} // namespace msmap

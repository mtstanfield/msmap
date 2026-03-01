#include "listener.h"
#include "abuse_cache.h"
#include "db.h"
#include "geoip.h"
#include "parser.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <iostream> // std::clog
#include <optional>
#include <string>
#include <string_view>

namespace msmap {
namespace {

// ── RAII file descriptor ──────────────────────────────────────────────────────

class ScopedFd {
public:
    explicit ScopedFd(int fd) noexcept : fd_(fd) {}

    ~ScopedFd() noexcept {
        if (fd_ >= 0) {
            (void)close(fd_); // close() failure is unrecoverable in a destructor
        }
    }

    ScopedFd(const ScopedFd&)            = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    ScopedFd(ScopedFd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    ScopedFd& operator=(ScopedFd&&)      = delete;

    [[nodiscard]] int  get()   const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

private:
    int fd_;
};

// ── Constants ─────────────────────────────────────────────────────────────────

// Guard against a runaway sender filling our heap.
constexpr std::size_t kMaxLineLen{8192};

// Receive buffer size (stack-allocated per connection).
constexpr std::size_t kRecvBufSize{4096};

// ── Per-connection handler ────────────────────────────────────────────────────

void handle_connection(int conn_fd, Database& db, GeoIp& geoip,
                       AbuseCache* abuse) {
    std::string                  buf;
    std::array<char, kRecvBufSize> tmp{};

    buf.reserve(512);

    for (;;) {
        // Check for updated mmdb files at most once per minute.
        (void)geoip.reload_if_changed();

        const ssize_t n = recv(conn_fd, tmp.data(), tmp.size(), 0);
        if (n <= 0) {
            break; // peer closed or recv error
        }

        buf.append(tmp.data(), static_cast<std::size_t>(n));

        // Process all complete newline-terminated lines.
        std::string::size_type pos{0};
        while ((pos = buf.find('\n')) != std::string::npos) {
            const std::string_view line(buf.data(), pos);

            const ParseResult result = parse_log(line);
            if (result.ok()) {
                const GeoIpResult    geo    = geoip.lookup(result.entry.src_ip);
                const std::optional<int> threat =
                    (abuse != nullptr) ? abuse->lookup(result.entry.src_ip)
                                       : std::optional<int>{std::nullopt};
                (void)db.insert(result.entry, geo, threat);
                if (abuse != nullptr) {
                    abuse->submit(result.entry.src_ip);
                }
            } else {
                std::clog << "[WARN] parse: " << result.error << " | " << line << '\n';
            }

            buf.erase(0, pos + 1);
        }

        // Prevent unbounded growth if a sender omits newlines.
        if (buf.size() > kMaxLineLen) {
            std::clog << "[WARN] line exceeds " << kMaxLineLen
                      << " bytes — discarding buffer\n";
            buf.clear();
        }
    }

    if (!buf.empty()) {
        std::clog << "[WARN] connection closed with unterminated line: " << buf << '\n';
    }
}

} // anonymous namespace

// ── Public API ────────────────────────────────────────────────────────────────

void run_listener(int port, Database& db, GeoIp& geoip, AbuseCache* abuse) {
    const ScopedFd srv{socket(AF_INET, SOCK_STREAM, 0)};
    if (!srv.valid()) {
        std::clog << "[FATAL] socket: " << std::strerror(errno) << '\n';
        return;
    }

    const int enable = 1;
    if (setsockopt(srv.get(), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        std::clog << "[WARN] SO_REUSEADDR: " << std::strerror(errno) << '\n';
        // Non-fatal: proceed without it.
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only

    if (bind(srv.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::clog << "[FATAL] bind 127.0.0.1:" << port << ": "
                  << std::strerror(errno) << '\n';
        return;
    }

    if (listen(srv.get(), /*backlog=*/1) < 0) {
        std::clog << "[FATAL] listen: " << std::strerror(errno) << '\n';
        return;
    }

    std::clog << "[INFO] msmap listening on 127.0.0.1:" << port << '\n';

    for (;;) {
        sockaddr_in peer{};
        socklen_t   peer_len = sizeof(peer);

        const ScopedFd conn{
            accept(srv.get(), reinterpret_cast<sockaddr*>(&peer), &peer_len)};

        if (!conn.valid()) {
            if (errno == EINTR) {
                continue; // interrupted by signal — retry
            }
            std::clog << "[WARN] accept: " << std::strerror(errno) << '\n';
            continue;
        }

        std::clog << "[INFO] rsyslog connected\n";
        handle_connection(conn.get(), db, geoip, abuse);
        std::clog << "[INFO] rsyslog disconnected\n";
    }
}

} // namespace msmap

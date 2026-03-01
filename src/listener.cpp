#include "listener.h"
#include "abuse_cache.h"
#include "db.h"
#include "geoip.h"
#include "parser.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream> // std::clog
#include <optional>
#include <stop_token>
#include <string_view>
#include <vector>

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

// Maximum expected syslog datagram size; Mikrotik lines are well under 1 KiB.
// RFC 5426 recommends receivers accept at least 480 B; 4096 provides headroom.
constexpr std::size_t kRecvBufSize{4096};

// ── Per-datagram handler ──────────────────────────────────────────────────────

void process_datagram(std::string_view data, Database& db, GeoIp& geoip,
                      AbuseCache* abuse) {
    // Strip any trailing CR / LF that Mikrotik may append.
    while (!data.empty() && (data.back() == '\n' || data.back() == '\r')) {
        data.remove_suffix(1);
    }
    if (data.empty()) { return; } // discard blank datagrams

    const ParseResult result = parse_log(data);
    if (result.ok()) {
        const GeoIpResult        geo    = geoip.lookup(result.entry.src_ip);
        const std::optional<int> threat =
            (abuse != nullptr) ? abuse->lookup(result.entry.src_ip)
                               : std::optional<int>{std::nullopt};
        (void)db.insert(result.entry, geo, threat);
        if (abuse != nullptr) {
            abuse->submit(result.entry.src_ip);
        }
    } else {
        std::clog << "[WARN] parse: " << result.error << " | " << data << '\n';
    }
}

} // anonymous namespace

// ── Public API ────────────────────────────────────────────────────────────────

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void run_listener(int port, Database& db, GeoIp& geoip, AbuseCache* abuse,
                  const std::vector<std::uint32_t>& allow_ips,
                  const std::stop_token& stoken) {
    const ScopedFd sock{socket(AF_INET, SOCK_DGRAM, 0)};
    if (!sock.valid()) {
        std::clog << "[FATAL] socket: " << std::strerror(errno) << '\n';
        return;
    }

    const int enable = 1;
    if (setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        std::clog << "[WARN] SO_REUSEADDR: " << std::strerror(errno) << '\n';
        // Non-fatal: proceed without it.
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0 — accept from LAN and loopback

    if (bind(sock.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::clog << "[FATAL] bind 0.0.0.0:" << port << ": "
                  << std::strerror(errno) << '\n';
        return;
    }

    std::clog << "[INFO] msmap listening on 0.0.0.0:" << port << " (UDP/syslog)\n";

    std::array<char, kRecvBufSize> buf{};

    while (!stoken.stop_requested()) {
        // Poll with timeout so the stop token is checked periodically.
        pollfd pfd{sock.get(), POLLIN, 0};
        const int ready = poll(&pfd, 1, /*timeout_ms=*/50);
        if (ready == 0)  { continue; }        // timeout — recheck stop token
        if (ready < 0)   {
            if (errno == EINTR) { continue; } // interrupted by signal — retry
            std::clog << "[WARN] poll: " << std::strerror(errno) << '\n';
            continue;
        }

        // Check for updated mmdb files at most once per minute.
        (void)geoip.reload_if_changed();

        sockaddr_in peer{};
        socklen_t   peer_len = sizeof(peer);

        const ssize_t n = recvfrom(
            sock.get(), buf.data(), buf.size(), 0,
            reinterpret_cast<sockaddr*>(&peer), &peer_len);

        if (n < 0) {
            if (errno == EINTR) { continue; }
            std::clog << "[WARN] recvfrom: " << std::strerror(errno) << '\n';
            continue;
        }

        // Enforce IP allowlist — silently drop datagrams from unknown senders.
        if (!allow_ips.empty() &&
            std::find(allow_ips.begin(), allow_ips.end(),
                      peer.sin_addr.s_addr) == allow_ips.end()) {
            continue;
        }

        // Each UDP datagram is one complete syslog message.
        process_datagram(std::string_view{buf.data(), static_cast<std::size_t>(n)},
                         db, geoip, abuse);
    }
}

} // namespace msmap

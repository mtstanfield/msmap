#include "home_resolver.h"
#include "geoip.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>

namespace msmap {

// ── Constructor / Destructor ──────────────────────────────────────────────────

HomeResolver::HomeResolver(const std::string& hostname, const GeoIp& geoip) noexcept
    : hostname_(hostname), geoip_(geoip)
{
    if (hostname_.empty()) {
        return;  // feature disabled — worker thread not started
    }

    // Resolve synchronously so get() is populated before the first HTTP request.
    const HomePoint initial = resolve_once();
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        result_ = initial;
        if (initial.valid) {
            updated_at_ = static_cast<std::int64_t>(std::time(nullptr));
        }
    }

    // Start background re-check thread.
    worker_thread_ = std::thread{[this]() noexcept { worker(); }};
}

HomeResolver::~HomeResolver() noexcept
{
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        stop_ = true;
    }
    cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

// ── Public ────────────────────────────────────────────────────────────────────

HomePoint HomeResolver::get() const noexcept
{
    const std::lock_guard<std::mutex> lock{mutex_};
    return result_;
}

std::optional<std::int64_t> HomeResolver::updated_at() const noexcept
{
    const std::lock_guard<std::mutex> lock{mutex_};
    return updated_at_;
}

// ── Private ───────────────────────────────────────────────────────────────────

HomePoint HomeResolver::resolve_once() const noexcept
{
    addrinfo hints{};
    hints.ai_family   = AF_INET;        // IPv4 — MaxMind is primarily IPv4
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res     = nullptr;

    const int err = getaddrinfo(hostname_.c_str(), nullptr, &hints, &res);
    if (err != 0) {
        std::clog << "[WARN] HomeResolver: getaddrinfo('" << hostname_
                  << "'): " << gai_strerror(err) << '\n';
        return {};
    }

    std::array<char, INET_ADDRSTRLEN> ip_buf{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto* sa4 = reinterpret_cast<const sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &sa4->sin_addr, ip_buf.data(), INET_ADDRSTRLEN);
    freeaddrinfo(res);

    const std::string resolved{ip_buf.data()};

    const GeoIpResult geo = geoip_.lookup(resolved);
    if (!geo.renderable()) {
        std::clog << "[WARN] HomeResolver: GeoIP lookup failed for "
                  << resolved << " — home point not updated\n";
        return {};
    }

    return HomePoint{true, geo.lat, geo.lon, resolved};
}

void HomeResolver::worker() noexcept
{
    while (true) {
        {
            std::unique_lock<std::mutex> lock{mutex_};
            cv_.wait_for(lock, std::chrono::seconds{kRecheckSecs},
                         [this]() noexcept { return stop_; });
            if (stop_) { return; }
        }

        // Resolve without holding the mutex (DNS may block briefly).
        const HomePoint fresh = resolve_once();

        const std::lock_guard<std::mutex> lock{mutex_};

        if (!fresh.valid) {
            // Resolution failed; keep the previous value so arcs keep working.
            std::clog << "[WARN] HomeResolver: re-check failed for '"
                      << hostname_ << "' — retaining previous home point\n";
            continue;
        }

        // Log only when the resolved IP or its derived coordinates changed.
        const bool changed = (!result_.valid ||
                              fresh.resolved_ip != result_.resolved_ip ||
                              fresh.lat != result_.lat ||
                              fresh.lon != result_.lon);
        result_ = fresh;
        if (changed) {
            updated_at_ = static_cast<std::int64_t>(std::time(nullptr));
            std::clog << "[INFO] HomeResolver: '" << hostname_
                      << "' re-resolved to " << fresh.resolved_ip << " ("
                      << fresh.lat << ", " << fresh.lon << ")\n";
        }
    }
}

} // namespace msmap

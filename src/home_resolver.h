#pragma once

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

namespace msmap {

class GeoIp;

// ── HomePoint ─────────────────────────────────────────────────────────────────

/// Geographic coordinates of the home host, resolved from MSMAP_HOME_HOST.
/// `valid` is false when the feature is disabled or resolution has failed.
struct HomePoint {
    bool   valid{false};
    double lat{0.0};
    double lon{0.0};
};

// ── HomeResolver ──────────────────────────────────────────────────────────────

/// Resolves MSMAP_HOME_HOST → lat/lon and re-checks every 30 minutes.
///
/// Performs the initial DNS + GeoIP resolution synchronously in the
/// constructor (so /api/home is ready before the first HTTP request).
/// A background thread then wakes every kRecheckSecs and repeats the
/// lookup; if the resolved IP changes the stored HomePoint is updated
/// and a [INFO] line is logged.
///
/// `get()` returns a copy of the current HomePoint under a mutex and is
/// safe to call from any thread (e.g. the MHD polling thread).
class HomeResolver {
public:
    static constexpr int kRecheckSecs = 30 * 60; // 30 minutes

    /// Resolve `hostname` immediately, then start the background thread.
    /// `hostname` may be an IPv4 literal or a DNS name.
    /// If `hostname` is empty the object is a no-op: `get()` always returns
    /// HomePoint{false}.
    HomeResolver(const std::string& hostname, const GeoIp& geoip) noexcept;

    /// Stop the background thread (signals + joins) before destruction.
    ~HomeResolver() noexcept;

    HomeResolver(const HomeResolver&)            = delete;
    HomeResolver& operator=(const HomeResolver&) = delete;
    HomeResolver(HomeResolver&&)                 = delete;
    HomeResolver& operator=(HomeResolver&&)      = delete;

    /// Return a copy of the current HomePoint.  Thread-safe.
    [[nodiscard]] HomePoint get() const noexcept;

private:
    /// Perform one DNS + GeoIP resolution cycle.  Returns the new HomePoint.
    /// Does not modify any member — result is applied by the caller.
    [[nodiscard]] HomePoint resolve_once() const noexcept;

    /// Background thread entry point.  Sleeps kRecheckSecs between cycles.
    void worker() noexcept;

    std::string    hostname_;
    const GeoIp&   geoip_;

    mutable std::mutex      mutex_;
    std::condition_variable cv_;
    HomePoint               result_;   // protected by mutex_
    bool                    stop_{false};
    std::string             last_ip_;  // last successfully resolved IP (for change detection)
    std::thread             worker_thread_;
};

} // namespace msmap

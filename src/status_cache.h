#pragma once

#include "db.h"
#include "home_resolver.h"

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>

namespace msmap {

class AbuseCache;
class IpIntelCache;

struct StatusPayload {
    bool                          ok{false};
    std::int64_t                  now{};
    std::optional<std::int64_t>   latest_event_ts;
    std::int64_t                  rows_24h{};
    std::int64_t                  distinct_sources_24h{};
    bool                          abuse_enabled{false};
    std::optional<int>            abuse_rate_remaining;
    bool                          abuse_quota_exhausted{false};
    bool                          intel_enabled{false};
    bool                          home_configured{false};
    bool                          home_valid{false};
    std::optional<std::int64_t>   intel_last_refresh_ts;
    std::optional<std::int64_t>   abuse_cache_rows;
    std::optional<std::uintmax_t> db_size_bytes;
    std::int64_t                  generated_at{};
};

class StatusCache {
public:
    StatusCache(Database& db,
                const HomeResolver* home_resolver,
                const AbuseCache* abuse_cache,
                const IpIntelCache* intel_cache,
                bool abuse_enabled,
                bool intel_enabled,
                std::int64_t refresh_secs = 60) noexcept;
    ~StatusCache() noexcept;

    StatusCache(const StatusCache&)            = delete;
    StatusCache& operator=(const StatusCache&) = delete;
    StatusCache(StatusCache&&)                 = delete;
    StatusCache& operator=(StatusCache&&)      = delete;

    // True when the cache has any snapshot to serve, including an explicit
    // unhealthy snapshot published after a refresh failure.
    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] std::optional<StatusPayload> snapshot() const noexcept;

private:
    void worker() noexcept;
    void refresh_snapshot() noexcept;

    Database&           db_;
    const HomeResolver* home_resolver_;
    const AbuseCache*   abuse_cache_;
    const IpIntelCache* intel_cache_;
    bool                abuse_enabled_;
    bool                intel_enabled_;
    std::int64_t        refresh_secs_;

    mutable std::mutex              snapshot_mutex_;
    std::optional<StatusPayload>    snapshot_;

    std::mutex                      wait_mutex_;
    std::condition_variable         wait_cv_;
    bool                            stop_{false};
    std::thread                     worker_thread_;
};

} // namespace msmap

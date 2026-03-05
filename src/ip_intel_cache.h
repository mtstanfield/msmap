#pragma once

#include "db.h"

#include <condition_variable>
#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>

namespace msmap {

struct IpIntelSources {
    std::string tor_url;
    std::string drop_url;
};

struct IpNet {
    int                          family{};
    std::array<std::uint8_t, 16> bytes{};
    std::uint8_t                 prefix_len{0};

    bool operator==(const IpNet&) const noexcept = default;
};

class IpIntelCache {
public:
    IpIntelCache(Database& db, const IpIntelSources& sources,
                 std::int64_t refresh_secs) noexcept;
    ~IpIntelCache() noexcept;

    IpIntelCache(const IpIntelCache&)            = delete;
    IpIntelCache& operator=(const IpIntelCache&) = delete;
    IpIntelCache(IpIntelCache&&)                 = delete;
    IpIntelCache& operator=(IpIntelCache&&)      = delete;

    [[nodiscard]] bool valid() const noexcept { return valid_; }

    void submit(const std::string& ip) noexcept;
    [[nodiscard]] std::optional<std::int64_t> last_refresh_ts() const noexcept;
    [[nodiscard]] bool refresh_attempted() const noexcept;

private:
    struct SnapshotState {
        bool               tor_loaded{false};
        bool               drop_loaded{false};
        std::vector<IpNet> tor_nets;
        std::vector<IpNet> drop_nets;
    };

    void worker() noexcept;
    [[nodiscard]] bool refresh_sources() noexcept;
    void refresh_known_ips() noexcept;
    void process_pending(const std::unordered_set<std::string>& pending) noexcept;
    [[nodiscard]] IpIntel classify_ip(const std::string& ip) const noexcept;

    Database&    db_;
    std::string  tor_url_;
    std::string  drop_url_;
    std::int64_t refresh_secs_;
    bool         valid_{false};

    // Source snapshots are owned per-cache instance so tests and future
    // refactors cannot accidentally share stale Tor/DROP state across objects.
    mutable std::mutex snapshot_mutex_;
    SnapshotState      snapshot_;
    std::optional<std::int64_t> last_refresh_ts_;
    bool               refresh_attempted_{false};

    std::mutex                     queue_mutex_;
    std::condition_variable        queue_cv_;
    std::unordered_set<std::string> queue_;
    bool                           stop_{false};
    std::thread                    worker_thread_;
};

} // namespace msmap

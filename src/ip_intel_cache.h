#pragma once

#include "db.h"

#include <condition_variable>
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

private:
    void worker() noexcept;
    void refresh_sources() noexcept;
    void refresh_known_ips() noexcept;
    void process_pending(const std::unordered_set<std::string>& pending) noexcept;
    [[nodiscard]] static IpIntel classify_ip(const std::string& ip) noexcept;

    Database&    db_;
    std::string  tor_url_;
    std::string  drop_url_;
    std::int64_t refresh_secs_;
    bool         valid_{false};

    std::mutex                     queue_mutex_;
    std::condition_variable        queue_cv_;
    std::unordered_set<std::string> queue_;
    bool                           stop_{false};
    std::thread                    worker_thread_;
};

} // namespace msmap

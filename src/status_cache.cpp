#include "status_cache.h"

#include "abuse_cache.h"
#include "ip_intel_cache.h"

#include <chrono>
#include <ctime>
#include <utility>

namespace msmap {

namespace {

StatusPayload build_failed_payload(const std::optional<StatusPayload>& previous,
                                   const HomeResolver*                home_resolver,
                                   bool                               abuse_enabled,
                                   bool                               intel_enabled,
                                   const IpIntelCache*                intel_cache,
                                   const AbuseCache*                  abuse_cache) noexcept
{
    StatusPayload payload = previous.value_or(StatusPayload{});
    payload.ok = false;
    payload.now = static_cast<std::int64_t>(std::time(nullptr));
    payload.abuse_enabled = abuse_enabled;
    payload.abuse_rate_remaining =
        (abuse_enabled && abuse_cache != nullptr)
            ? std::optional<int>{abuse_cache->rate_remaining()}
            : std::nullopt;
    payload.abuse_quota_exhausted =
        abuse_enabled && payload.abuse_rate_remaining.has_value() &&
        *payload.abuse_rate_remaining <= 0;
    payload.intel_enabled = intel_enabled;
    payload.home_configured = home_resolver != nullptr;
    payload.home_valid = payload.home_configured && home_resolver->get().valid;
    payload.intel_last_refresh_ts =
        intel_cache != nullptr ? intel_cache->last_refresh_ts() : std::nullopt;
    payload.abuse_cache_rows =
        abuse_cache != nullptr ? abuse_cache->cache_row_count() : std::nullopt;
    payload.generated_at = payload.now;
    return payload;
}

} // namespace

StatusCache::StatusCache(Database& db,
                         const HomeResolver* home_resolver,
                         const AbuseCache* abuse_cache,
                         const IpIntelCache* intel_cache,
                         bool abuse_enabled,
                         bool intel_enabled,
                         std::int64_t refresh_secs) noexcept
    : db_(db),
      home_resolver_(home_resolver),
      abuse_cache_(abuse_cache),
      intel_cache_(intel_cache),
      abuse_enabled_(abuse_enabled),
      intel_enabled_(intel_enabled),
      refresh_secs_(refresh_secs > 0 ? refresh_secs : 60)
{
    refresh_snapshot();
    worker_thread_ = std::thread{[this]() noexcept { worker(); }};
}

StatusCache::~StatusCache() noexcept
{
    {
        const std::lock_guard<std::mutex> lock{wait_mutex_};
        stop_ = true;
    }
    wait_cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

bool StatusCache::valid() const noexcept
{
    const std::lock_guard<std::mutex> lock{snapshot_mutex_};
    return snapshot_.has_value();
}

std::optional<StatusPayload> StatusCache::snapshot() const noexcept
{
    const std::lock_guard<std::mutex> lock{snapshot_mutex_};
    return snapshot_;
}

void StatusCache::worker() noexcept
{
    std::unique_lock<std::mutex> lock{wait_mutex_};
    while (!stop_) {
        if (wait_cv_.wait_for(lock, std::chrono::seconds{refresh_secs_},
                              [this]() noexcept { return stop_; })) {
            break;
        }
        lock.unlock();
        refresh_snapshot();
        lock.lock();
    }
}

void StatusCache::refresh_snapshot() noexcept
{
    const auto db_snapshot = db_.status_snapshot();
    if (!db_snapshot.has_value()) {
        const std::lock_guard<std::mutex> lock{snapshot_mutex_};
        // Publish an explicit unhealthy snapshot so /api/status does not keep
        // serving an old healthy payload forever after refresh failures.
        snapshot_ = build_failed_payload(snapshot_, home_resolver_, abuse_enabled_,
                                         intel_enabled_, intel_cache_, abuse_cache_);
        return;
    }

    StatusPayload payload;
    payload.ok = db_snapshot->ok;
    payload.now = db_snapshot->now;
    payload.latest_event_ts = db_snapshot->latest_event_ts;
    payload.rows_24h = db_snapshot->rows_24h;
    payload.distinct_sources_24h = db_snapshot->distinct_sources_24h;
    payload.db_size_bytes = db_snapshot->db_size_bytes;
    payload.abuse_enabled = abuse_enabled_;
    payload.abuse_rate_remaining =
        (abuse_enabled_ && abuse_cache_ != nullptr)
            ? std::optional<int>{abuse_cache_->rate_remaining()}
            : std::nullopt;
    payload.abuse_quota_exhausted =
        abuse_enabled_ && payload.abuse_rate_remaining.has_value() &&
        *payload.abuse_rate_remaining <= 0;
    payload.intel_enabled = intel_enabled_;
    payload.home_configured = home_resolver_ != nullptr;
    payload.home_valid = payload.home_configured && home_resolver_->get().valid;
    payload.intel_last_refresh_ts =
        intel_cache_ != nullptr ? intel_cache_->last_refresh_ts() : std::nullopt;
    payload.abuse_cache_rows =
        abuse_cache_ != nullptr ? abuse_cache_->cache_row_count() : std::nullopt;
    payload.generated_at = static_cast<std::int64_t>(std::time(nullptr));

    const std::lock_guard<std::mutex> lock{snapshot_mutex_};
    snapshot_ = payload;
}

} // namespace msmap

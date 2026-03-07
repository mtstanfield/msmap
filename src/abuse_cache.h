#pragma once

#include "db.h"   // SqliteCloser, StmtFinalizer (forward-declared sqlite3 types)

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

struct sqlite3;
struct sqlite3_stmt;

namespace msmap {

/// Hard cache TTL: re-query AbuseIPDB after this many seconds (30 days).
/// Threat scores change slowly; the AbuseIPDB free tier allows 1000 checks/day,
/// so a long TTL is essential to preserve quota for new IPs.
inline constexpr std::int64_t kCacheTtlSecs{30LL * 24LL * 3600LL};
/// Still-valid entries older than this can use the low-priority early-refresh pool.
inline constexpr std::int64_t kSoftRefreshAgeSecs{14LL * 24LL * 3600LL};

/// AbuseIPDB free-tier daily quota and the reserved low-priority early-refresh pool.
inline constexpr int kDailyQuota{1000};
inline constexpr int kSoftRefreshBudgetPerDay{150};

/// Fields extracted from an AbuseIPDB /api/v2/check response.
struct AbuseResult {
    int         score{0};         ///< abuseConfidenceScore (0–100)
    std::string usage_type;       ///< usageType; empty string if not present
};

struct AbuseCacheEntry {
    AbuseResult  result;
    std::int64_t last_checked{0};
};

/// Parse an AbuseIPDB /api/v2/check JSON body into AbuseResult.
/// Returns nullopt when abuseConfidenceScore is missing/invalid.
/// Exposed primarily for deterministic parser unit tests.
[[nodiscard]] std::optional<AbuseResult>
parse_abuse_response(const std::string& json) noexcept;

enum class AbuseLookupState : std::uint8_t {
    kMissing,
    kFresh,
    kSoftRefreshEligible,
    kStale,
};

struct PendingSelection {
    std::string ip;
    bool        is_soft_refresh{false};
    std::int64_t soft_last_checked{0};
};

// ── AbuseCache ────────────────────────────────────────────────────────────────

/// Manages the `abuse_cache` SQLite table and a background worker thread
/// that resolves queued IPs via the AbuseIPDB v2 API.
///
/// Thread model
///   Caller (listener) thread  : calls lookup() and submit() — both fast/non-blocking.
///   Background worker thread  : pops IPs, calls AbuseIPDB, writes cache,
///                               then patches connections rows with NULL threat.
///
/// SQLite concurrency
///   AbuseCache opens its own sqlite3* against the same msmap.db file.
///   WAL mode (set by Database) allows concurrent access safely.
///
/// Lifecycle
///   Construct before run_listener(). Destructor joins the background thread.
///   If api_key is empty, valid() is true but submit() is a no-op (API disabled).
class AbuseCache {
public:
    /// Open (or create) the abuse_cache table in the database at `db_path`.
    /// `api_key` is the raw AbuseIPDB API key string (not an env-var name).
    /// Pass an empty string to disable API lookups (cache reads still work).
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    AbuseCache(const std::string& db_path, const std::string& api_key) noexcept;

    /// Stop the background thread and close the SQLite connection.
    ~AbuseCache() noexcept;

    AbuseCache(const AbuseCache&)            = delete;
    AbuseCache& operator=(const AbuseCache&) = delete;
    AbuseCache(AbuseCache&&)                 = delete;
    AbuseCache& operator=(AbuseCache&&)      = delete;

    /// True if the database was opened and the table was created successfully.
    [[nodiscard]] bool valid() const noexcept { return db_ != nullptr; }

    /// Fast synchronous cache lookup.
    /// Returns the cached AbuseResult if present and still within the 30-day
    /// hard TTL, including entries that are eligible for low-priority early refresh.
    /// Returns nullopt on a cache miss or a hard-stale entry.
    /// Thread-safe; never calls the API.
    [[nodiscard]] std::optional<AbuseResult> lookup(const std::string& ip) const noexcept;

    /// Classify cached AbuseIPDB age against the fresh/soft/stale policy.
    [[nodiscard]] static AbuseLookupState classify_cache_age(
        std::int64_t now,
        std::int64_t last_checked) noexcept;

    /// Enqueue `ip` for background resolution if needed and not already queued.
    /// Missing and 30-day-stale entries go to the normal queue; 14-30 day cached
    /// entries may use the reserved low-priority early-refresh pool.
    /// Non-blocking. Safe to call from the listener hot path.
    /// No-op when api_key_ is empty or the object is invalid.
    void submit(const std::string& ip) noexcept;

    /// Upsert a result into the cache table.
    /// Called by the background worker after a successful API fetch.
    /// Also exposed for testing (cache_store + lookup round-trip).
    bool cache_store(const std::string& ip, const AbuseResult& result) noexcept;

    /// UPDATE connections SET threat, usage_type WHERE src_ip=ip AND usage_type IS NULL.
    /// Backfills rows that were inserted before the background fetch completed.
    /// Called by the background worker after cache_store().
    void update_connections_abuse(const std::string& ip, const AbuseResult& result) noexcept;

    // ── Exposed for tests ────────────────────────────────────────────────────

    /// Current number of API calls remaining today.
    [[nodiscard]] int rate_remaining() const noexcept;

    /// Last quota remaining value confirmed by an AbuseIPDB HTTP response.
    [[nodiscard]] std::optional<int> confirmed_rate_remaining() const noexcept;
    [[nodiscard]] bool has_pending_work() const noexcept;
    [[nodiscard]] bool can_accept_new_lookups() const noexcept;

    /// Next scheduled epoch timestamp for a post-midnight quota retry probe.
    [[nodiscard]] std::optional<std::int64_t> quota_retry_after_ts() const noexcept;

    /// Test hook for simulating quota exhaustion or partial remaining quota.
    void set_rate_remaining_for_test(int remaining) noexcept;

    /// Test hook for simulating the soft-refresh reserve.
    void set_soft_refresh_remaining_for_test(int remaining) noexcept;

    /// Current number of soft-refresh requests remaining today.
    [[nodiscard]] int soft_refresh_remaining() const noexcept;

    /// Test hook for adjusting cached entry age.
    bool set_last_checked_for_test(const std::string& ip,
                                   std::int64_t       last_checked) noexcept;

    /// Test hook for inspecting lookup classification without queueing work.
    [[nodiscard]] AbuseLookupState lookup_state_for_test(const std::string& ip,
                                                         std::int64_t now) const noexcept;

    /// Test hook for exercising submit queueing without waking the worker.
    bool enqueue_submit_candidate_for_test(const std::string& ip) noexcept;

    /// Test hook for checking which queue currently owns an IP.
    [[nodiscard]] bool normal_queue_contains_for_test(const std::string& ip) const noexcept;
    [[nodiscard]] bool soft_queue_contains_for_test(const std::string& ip) const noexcept;
    [[nodiscard]] bool in_flight_contains_for_test(const std::string& ip) const noexcept;

    /// Test hook for checking worker queue selection order.
    [[nodiscard]] std::optional<PendingSelection> pop_next_pending_for_test() noexcept;

    /// Test hook for verifying stale soft-refresh work is promoted to normal.
    void requeue_pending_for_test(const std::string& ip,
                                  bool               is_soft_refresh,
                                  std::int64_t       soft_last_checked,
                                  std::int64_t       now) noexcept;

    /// Test hook for stopping the background worker before queue inspection.
    void shutdown_worker_for_test() noexcept;

    /// Test hook for simulating worker ownership of a pending IP.
    void mark_in_flight_for_test(const std::string& ip) noexcept;

    /// Test hook for arming the short post-midnight retry timer.
    void arm_quota_retry_for_test(std::int64_t retry_after_ts,
                                  bool post_reset_mode = true) noexcept;

    /// Test hook for releasing a single retry probe once the timer expires.
    bool release_quota_retry_probe_if_due_for_test(std::int64_t now) noexcept;

    /// Number of rows currently stored in the abuse cache table.
    [[nodiscard]] std::optional<std::int64_t> cache_row_count() const noexcept;

    /// Reset the daily counter if the UTC day has rolled over.
    /// Returns true if a reset occurred.
    bool rate_limit_reset_if_new_day() noexcept;

    /// Test hook for forcing the next rate-limit reset call to see a new UTC day.
    void rewind_rate_reset_day_for_test() noexcept;

    /// Test hook for exercising apply_fetch_result() queue handling directly.
    void apply_fetch_result_for_test(const std::string&        ip,
                                     bool                      is_soft_refresh,
                                     std::int64_t              soft_last_checked,
                                     bool                      request_made,
                                     bool                      quota_exhausted,
                                     std::optional<int>        confirmed_remaining =
                                         std::nullopt) noexcept;

private:
    bool                        open() noexcept;
    void                        worker() noexcept;

    /// Sleep until the next UTC midnight reset, or until a short post-midnight
    /// retry backoff expires if AbuseIPDB is late applying the documented
    /// quota reset. Caller must hold queue_mutex_ via `lock`; the lock is
    /// released and reacquired during each wait_for() interval.
    void                        wait_for_quota_reset(
                                    std::unique_lock<std::mutex>& lock) noexcept;

    /// Allow one post-midnight probe request once the retry timer expires.
    /// Caller must hold queue_mutex_.
    bool                        maybe_release_quota_retry_probe(
                                    std::int64_t now) noexcept;

    [[nodiscard]] std::optional<AbuseCacheEntry>
                                lookup_entry(const std::string& ip) const noexcept;

    bool                        enqueue_submit_candidate(const std::string& ip,
                                    bool notify_worker) noexcept;

    [[nodiscard]] std::optional<PendingSelection>
                                pop_next_pending_locked() noexcept;

    void                        requeue_pending_locked(const std::string& ip,
                                                       bool               is_soft_refresh,
                                                       std::int64_t       soft_last_checked,
                                                       std::int64_t       now) noexcept;

    /// Sets `request_made` to true if an HTTP request reached AbuseIPDB
    /// (regardless of HTTP status), so the caller only decrements the rate
    /// counter when a real API call was issued (not on curl/network failures).
    /// Sets `quota_exhausted` to true specifically on HTTP 429 so the caller
    /// can zero rate_remaining_ immediately instead of decrementing by one.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    std::optional<AbuseResult>  fetch_abuse(const std::string& ip,
                                             bool& request_made,
                                             bool& quota_exhausted,
                                             std::optional<int>& confirmed_remaining) noexcept;

    /// Update rate counter, in_flight set, and SQLite cache after a fetch.
    /// Extracted from worker() to keep its cognitive complexity in bounds.
    void apply_fetch_result(const std::string&                ip,
                            const std::optional<AbuseResult>& result,
                            bool                               is_soft_refresh,
                            std::int64_t                       soft_last_checked,
                            bool                               request_made,
                            bool                               quota_exhausted,
                            std::optional<int>                 confirmed_remaining) noexcept;

    // ── Configuration ────────────────────────────────────────────────────────
    std::string db_path_;
    std::string api_key_;

    // ── SQLite state ────────────────────────────────────────────────────────
    // All three statements plus the db handle are protected by db_mutex_.
    // lookup() runs on the caller thread; cache_store/update_connections run on
    // the worker thread. db_mutex_ is never held across a network call.
    mutable std::mutex                           db_mutex_;
    std::unique_ptr<sqlite3,      SqliteCloser>  db_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> lookup_stmt_;       // SELECT score,last_checked,usage_type WHERE ip=?
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> upsert_stmt_;       // INSERT OR REPLACE INTO abuse_cache
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> update_conn_stmt_;  // UPDATE connections SET threat,usage_type

    // ── Background worker ────────────────────────────────────────────────────
    mutable std::mutex              queue_mutex_;
    std::condition_variable         queue_cv_;
    std::unordered_set<std::string> queue_;       // pending IPs (set deduplicates)
    std::unordered_map<std::string, std::int64_t> soft_queue_; // ip -> last_checked
    std::unordered_set<std::string> in_flight_;   // IPs currently being fetched
    bool                            stop_{false};
    std::thread                     worker_thread_;

    // ── Rate limiting ────────────────────────────────────────────────────────
    // Accessed only under queue_mutex_.
    int          rate_remaining_{kDailyQuota};
    int          soft_refresh_remaining_{kSoftRefreshBudgetPerDay};
    std::optional<int> confirmed_rate_remaining_;
    std::int64_t rate_reset_day_{0};              // epoch_day() at last reset
    bool         quota_warned_{false};            // suppress repeated log lines
    std::optional<std::int64_t> quota_retry_after_ts_;
    int          quota_retry_backoff_secs_{60};
    bool         post_reset_retry_mode_{false};

};

} // namespace msmap

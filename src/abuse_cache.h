#pragma once

#include "db.h"   // SqliteCloser, StmtFinalizer (forward-declared sqlite3 types)

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>

struct sqlite3;
struct sqlite3_stmt;

namespace msmap {

/// Cache TTL: re-query AbuseIPDB after this many seconds.
inline constexpr std::int64_t kCacheTtlSecs{24 * 3600};

/// AbuseIPDB free-tier daily quota.
inline constexpr int kDailyQuota{1000};

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
    /// Returns the cached score (0-100) if present and not expired (TTL = kCacheTtlSecs).
    /// Returns nullopt on a cache miss or a stale entry.
    /// Thread-safe; never calls the API.
    [[nodiscard]] std::optional<int> lookup(const std::string& ip) const noexcept;

    /// Enqueue `ip` for background resolution if not already cached/queued.
    /// Non-blocking. Safe to call from the listener hot path.
    /// No-op when api_key_ is empty or the object is invalid.
    void submit(const std::string& ip) noexcept;

    /// Upsert a score into the cache table.
    /// Called by the background worker after a successful API fetch.
    /// Also exposed for testing (cache_store + lookup round-trip).
    bool cache_store(const std::string& ip, int score) noexcept;

    /// UPDATE connections SET threat=score WHERE src_ip=ip AND threat IS NULL.
    /// Backfills rows that were inserted before the background fetch completed.
    /// Called by the background worker after cache_store().
    void update_connections_threat(const std::string& ip, int score) noexcept;

    // ── Exposed for tests ────────────────────────────────────────────────────

    /// Current number of API calls remaining today.
    [[nodiscard]] int rate_remaining() const noexcept;

    /// Reset the daily counter if the UTC day has rolled over.
    /// Returns true if a reset occurred.
    bool rate_limit_reset_if_new_day() noexcept;

private:
    bool               open() noexcept;
    void               worker() noexcept;
    std::optional<int> fetch_score(const std::string& ip) noexcept;

    // ── Configuration ────────────────────────────────────────────────────────
    std::string db_path_;
    std::string api_key_;

    // ── SQLite state ────────────────────────────────────────────────────────
    // All three statements plus the db handle are protected by db_mutex_.
    // lookup() runs on the caller thread; cache_store/update_connections run on
    // the worker thread. db_mutex_ is never held across a network call.
    mutable std::mutex                           db_mutex_;
    std::unique_ptr<sqlite3,      SqliteCloser>  db_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> lookup_stmt_;       // SELECT score,last_checked WHERE ip=?
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> upsert_stmt_;       // INSERT OR REPLACE INTO abuse_cache
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> update_conn_stmt_;  // UPDATE connections SET threat=?

    // ── Background worker ────────────────────────────────────────────────────
    mutable std::mutex              queue_mutex_;
    std::condition_variable         queue_cv_;
    std::unordered_set<std::string> queue_;       // pending IPs (set deduplicates)
    std::unordered_set<std::string> in_flight_;   // IPs currently being fetched
    bool                            stop_{false};
    std::thread                     worker_thread_;

    // ── Rate limiting ────────────────────────────────────────────────────────
    // Accessed only under queue_mutex_.
    int          rate_remaining_{kDailyQuota};
    std::int64_t rate_reset_day_{0};              // epoch_day() at last reset

};

} // namespace msmap

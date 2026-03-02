#pragma once

#include "parser.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// Forward-declare the opaque SQLite types so callers of db.h don't
// need to pull in the full sqlite3.h header.
struct sqlite3;
struct sqlite3_stmt;

namespace msmap {

// Full definition in geoip.h; forward declaration is enough for the
// insert() signature since GeoIpResult is passed by const reference.
struct GeoIpResult;

// Custom deleters for the unique_ptr handles — defined in db.cpp where
// the full SQLite header is available.
struct SqliteCloser   { void operator()(sqlite3*      p) const noexcept; };
struct StmtFinalizer  { void operator()(sqlite3_stmt* p) const noexcept; };

// ── Query result type ─────────────────────────────────────────────────────────

/// One row returned by Database::query_connections().
/// Nullable DB columns map to std::optional / empty std::string.
struct ConnectionRow {
    std::int64_t       ts{};
    std::string        src_ip;
    std::optional<int> src_port;        // nullopt for ICMP
    std::string        dst_ip;
    std::optional<int> dst_port;        // nullopt for ICMP
    std::string        proto;
    std::string        tcp_flags;       // empty string when not TCP
    std::string        rule;
    std::string        country;         // empty string when no GeoIP
    std::optional<double> lat;          // nullopt when no GeoIP
    std::optional<double> lon;          // nullopt when no GeoIP
    std::string        asn;             // empty string when no GeoIP
    std::optional<int> threat;          // nullopt = not yet enriched
    std::string        usage_type;      // AbuseIPDB usageType; empty when not enriched
    std::optional<bool> is_tor;         // AbuseIPDB isTor; nullopt when not enriched
};

// ── Query filter type ─────────────────────────────────────────────────────────

/// Filters for Database::query_connections().  Unset fields mean "no constraint".
struct QueryFilters {
    std::int64_t since{0};      // ts >= since;  0 = no lower bound
    std::int64_t until{0};      // ts <= until;  0 = no upper bound
    std::string  src_ip;        // exact match;  empty = any
    std::string  country;       // exact match;  empty = any
    std::string  proto;         // exact match;  empty = any
    int          dst_port{0};   // exact match;  0 = any
    int          limit{25000};  // row cap (enforced max: 25 000)
};

// ── Database class ────────────────────────────────────────────────────────────

class Database {
public:
    /// Open (or create) the SQLite database at `path`.
    /// Applies WAL mode, creates schema, and prepares statements.
    /// On failure, valid() returns false and errors are logged to stderr.
    /// Pass ":memory:" for an in-process test database.
    explicit Database(const std::string& path) noexcept;

    // Destructor defined in db.cpp so unique_ptr can see the full sqlite3 type.
    ~Database() noexcept;

    Database(const Database&)            = delete;
    Database& operator=(const Database&) = delete;
    Database(Database&&)                 = delete;
    Database& operator=(Database&&)      = delete;

    /// True if the database was opened and initialised successfully.
    [[nodiscard]] bool valid() const noexcept { return db_ != nullptr; }

    /// Insert a parsed log entry with its GeoIP enrichment.
    /// Pass a default-constructed GeoIpResult{} to store NULLs for geo columns.
    /// `threat` is the AbuseIPDB confidence score (0-100), or nullopt if not yet known.
    /// Thread-safe: acquires an internal mutex before touching SQLite.
    bool insert(const LogEntry& entry, const GeoIpResult& geo,
                std::optional<int> threat = std::nullopt) noexcept;

    /// Return up to filters.limit rows matching the given filters.
    /// Rows are ordered newest-first (ORDER BY ts DESC).
    /// Thread-safe: acquires an internal mutex before touching SQLite.
    [[nodiscard]] std::vector<ConnectionRow>
        query_connections(const QueryFilters& filters) const noexcept;

    /// Delete all rows with ts < cutoff_ts and return the count removed.
    /// Thread-safe: acquires an internal mutex.
    /// Production code uses the automatic trigger inside insert() (every 10 000
    /// rows, 24h cutoff); call this directly when a specific cutoff is
    /// needed (manual maintenance, tests).
    int prune_older_than(std::int64_t cutoff_ts = 86400 /* 24h */) noexcept;

private:
    bool exec(const char* sql) noexcept;
    /// Shared DELETE implementation — caller must already hold mutex_.
    int  prune_unlocked(std::int64_t cutoff_ts) noexcept;
    /// Called from insert() (already under mutex_) with the 24h cutoff.
    void prune_old() noexcept;

    /// In-memory cache of recent rows (ts DESC, 24h prune).
    /// Protects against DB mutex contention for UI queries (read-mostly).
    mutable std::mutex                           cache_mutex_;
    std::vector<ConnectionRow>                   recent_cache_;  // ts DESC
    static constexpr std::size_t                 kMaxCacheSize = 300'000;  // ~120MB
    static constexpr std::int64_t                kCacheRetentionSecs = 86400;  // 24h
    void insert_to_cache(const ConnectionRow& row) noexcept;
    void prune_cache() noexcept;
    [[nodiscard]] std::vector<ConnectionRow> query_cache(const QueryFilters& f) const noexcept;
    void load_cache_from_db() noexcept;

    // mutex_ serialises all SQLite calls from the listener thread (insert)
    // and the HTTP thread (query_connections).  Declared mutable so that
    // const methods (query_connections) can lock it.
    mutable std::mutex                           mutex_;
    std::unique_ptr<sqlite3,      SqliteCloser>  db_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> insert_stmt_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> prune_stmt_;
    std::size_t                                  insert_count_{0};
};

} // namespace msmap

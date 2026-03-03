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

struct IpIntel {
    std::optional<bool> tor_exit;
    std::optional<bool> spamhaus_drop;
};

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
    std::optional<bool> tor_exit;       // Tor Project authoritative signal
    std::optional<bool> spamhaus_drop;  // Spamhaus DROP membership
};

// ── Query filter type ─────────────────────────────────────────────────────────

/// Filters for Database::query_connections().  Unset fields mean "no constraint".
struct QueryFilters {
    std::int64_t since{0};      // ts >= since;  0 = no lower bound
    std::int64_t until{0};      // ts <= until;  0 = no upper bound
    std::string  src_ip;        // exact match;  empty = any
    std::string  country;       // exact match;  empty = any
    std::string  proto;         // exact match;  empty = any
    bool         exclude_icmp{false}; // when true and proto unset, hide ICMP
    int          dst_port{0};   // exact match;  0 = any
    int          offset{0};     // pagination offset; 0 = first page
    int          limit{25000};  // row cap (enforced max: 25 000)
};

struct MapFilters {
    std::int64_t since{0};      // ts >= since
    std::int64_t until{0};      // ts <= until; 0 = now
    std::string  src_ip;        // exact match; empty = any
    std::string  country;       // exact match; empty = any
    std::string  proto;         // exact match; empty = any
    bool         exclude_icmp{false}; // when true and proto unset, hide ICMP
    int          dst_port{0};   // exact match; 0 = any
};

struct MapRow {
    std::string            src_ip;
    std::int64_t           first_ts{};
    std::int64_t           last_ts{};
    int                    count{};
    std::optional<double>  lat;
    std::optional<double>  lon;
    std::string            country;
    std::string            asn;
    std::optional<int>     threat_latest;
    std::optional<int>     threat_max;
    std::optional<int>     sample_dst_port;
    std::string            usage_type;
    std::optional<bool>    tor_exit;
    std::optional<bool>    spamhaus_drop;
};

struct DetailPage {
    std::vector<ConnectionRow> rows;
    std::optional<int>         next_cursor;
};

struct StatusSnapshot {
    bool                          ok{false};
    std::int64_t                  now{};
    std::optional<std::int64_t>   latest_event_ts;
    std::int64_t                  rows_24h{};
    std::int64_t                  distinct_sources_24h{};
    std::optional<std::uintmax_t> db_size_bytes;
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

    /// Upsert cached source-IP intelligence derived from local/bulk feeds.
    bool upsert_ip_intel(const std::string& ip, const IpIntel& intel) noexcept;

    /// Distinct source IPs currently present in the retained window.
    [[nodiscard]] std::vector<std::string> distinct_source_ips() const noexcept;

    /// Return up to filters.limit rows matching the given filters.
    /// Rows are ordered newest-first (ORDER BY ts DESC).
    /// Thread-safe: acquires an internal mutex before touching SQLite.
    [[nodiscard]] std::vector<ConnectionRow>
        query_connections(const QueryFilters& filters) const noexcept;

    /// Return a complete per-source aggregate set for the requested window and filters.
    /// Used by the public map endpoint so the browser can render the full 24h view
    /// without a hard row ceiling on raw events.
    [[nodiscard]] std::vector<MapRow>
        query_map_rows(const MapFilters& filters) const noexcept;

    /// Return one bounded detail page for a drilldown query.
    [[nodiscard]] DetailPage
        query_detail_page(const QueryFilters& filters) const noexcept;

    /// Return a lightweight operational snapshot for the retained 24h window.
    [[nodiscard]] std::optional<StatusSnapshot> status_snapshot() const noexcept;

    /// Delete all rows with ts < cutoff_ts and return the count removed.
    /// Thread-safe: acquires an internal mutex.
    /// Production code uses the automatic trigger inside insert() (every 10 000
    /// rows, 24h cutoff); call this directly when a specific cutoff is
    /// needed (manual maintenance, tests).
    int prune_older_than(std::int64_t cutoff_ts) noexcept;
    /// Prune using the production retention window relative to now.
    int prune_expired() noexcept;

private:
    bool exec(const char* sql) noexcept;
    /// Shared DELETE implementation — caller must already hold mutex_.
    int  prune_unlocked(std::int64_t cutoff_ts) noexcept;
    /// Called from insert() (already under mutex_) with the production 24h cutoff.
    void prune_old() noexcept;

    // mutex_ serialises all SQLite calls from the listener thread (insert)
    // and the HTTP thread (query_connections).  Declared mutable so that
    // const methods (query_connections) can lock it.
    mutable std::mutex                           mutex_;
    std::unique_ptr<sqlite3,      SqliteCloser>  db_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> insert_stmt_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> prune_stmt_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> upsert_ip_intel_stmt_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> distinct_source_ips_stmt_;
    std::size_t                                  insert_count_{0};
};

} // namespace msmap

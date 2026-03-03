#include "db.h"
#include "geoip.h"

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sqlite3.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace msmap {

// ── Custom deleters ────────────────────────────────────────────────────────────

void SqliteCloser::operator()(sqlite3* p) const noexcept
{
    sqlite3_close(p);
}

void StmtFinalizer::operator()(sqlite3_stmt* p) const noexcept
{
    sqlite3_finalize(p);
}

// ── Module-level constants ─────────────────────────────────────────────────────

namespace {

// Run a retention prune once every N successful inserts.
constexpr std::size_t kPruneInterval{10'000};

// Rows older than this are deleted during a prune pass.
constexpr std::int64_t kRetentionSecs{24LL * 3600};

// SQLITE_STATIC means the string is managed by the caller and is
// guaranteed to remain valid for the lifetime of the sqlite3_bind call.
// We prefer this explicit constant over the macro to avoid the C-style cast
// inside the SQLITE_STATIC macro definition.
const auto kStaticText =
    static_cast<sqlite3_destructor_type>(nullptr); // NOLINT(*-avoid-non-const-global-variables)

constexpr const char* kCreateTable = R"sql(
CREATE TABLE IF NOT EXISTS connections (
    id         INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    src_ip     TEXT    NOT NULL,
    src_port   INTEGER,
    dst_ip     TEXT    NOT NULL,
    dst_port   INTEGER,
    proto      TEXT    NOT NULL,
    tcp_flags  TEXT,
    rule       TEXT    NOT NULL DEFAULT '',
    country    TEXT,
    lat        REAL,
    lon        REAL,
    asn        TEXT,
    threat     INTEGER,
    usage_type TEXT,
    is_tor     INTEGER
))sql";

constexpr const char* kCreateIndexTs =
    "CREATE INDEX IF NOT EXISTS idx_ts       ON connections(ts)";
constexpr const char* kCreateIndexSrcIp =
    "CREATE INDEX IF NOT EXISTS idx_src_ip   ON connections(src_ip)";
constexpr const char* kCreateIndexDstPort =
    "CREATE INDEX IF NOT EXISTS idx_dst_port ON connections(dst_port)";
constexpr const char* kCreateIndexCountry =
    "CREATE INDEX IF NOT EXISTS idx_country  ON connections(country)";

// Expression index for duplicate suppression.
// COALESCE(port, -1) makes NULL ports (ICMP) participate in the unique key.
// SQLite expression indices require ≥ 3.25.0 (bookworm has 3.39.x).
constexpr const char* kCreateIndexDedup = R"sql(
CREATE UNIQUE INDEX IF NOT EXISTS ux_conn_dedup
ON connections(ts, src_ip, dst_ip, proto,
               COALESCE(src_port, -1),
               COALESCE(dst_port, -1)))sql";

constexpr const char* kInsertSql = R"sql(
INSERT OR IGNORE INTO connections(
    ts, src_ip, src_port, dst_ip, dst_port, proto, tcp_flags,
    rule, country, lat, lon, asn, threat, usage_type, is_tor)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?))sql";

constexpr const char* kPruneSql =
    "DELETE FROM connections WHERE ts < ?";

// RAII wrapper for the char* that sqlite3_exec may write into errmsg.
struct SqliteErrFree {
    void operator()(char* p) const noexcept { sqlite3_free(p); }
};

// ── Column-reading helpers (used by query_connections) ─────────────────────────

/// Read a TEXT column; returns an empty string for SQL NULL.
std::string col_text(sqlite3_stmt* stmt, int col) noexcept
{
    const auto* p = sqlite3_column_text(stmt, col);
    if (p == nullptr) {
        return {};
    }
    const int len = sqlite3_column_bytes(stmt, col);
    // sqlite3_column_text returns UTF-8 as unsigned char*; reinterpret to char*
    // is safe since both are single-byte, same-alignment types.
    return {reinterpret_cast<const char*>(p), // NOLINT(*-reinterpret-cast)
            static_cast<std::size_t>(len)};
}

/// Read an INTEGER column; returns nullopt for SQL NULL.
std::optional<int> col_opt_int(sqlite3_stmt* stmt, int col) noexcept
{
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) {
        return std::nullopt;
    }
    return sqlite3_column_int(stmt, col);
}

/// Read a REAL column; returns nullopt for SQL NULL.
std::optional<double> col_opt_double(sqlite3_stmt* stmt, int col) noexcept
{
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) {
        return std::nullopt;
    }
    return sqlite3_column_double(stmt, col);
}

/// Read an INTEGER column as bool (0 = false, non-zero = true); returns nullopt for SQL NULL.
std::optional<bool> col_opt_bool(sqlite3_stmt* stmt, int col) noexcept
{
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) {
        return std::nullopt;
    }
    return sqlite3_column_int(stmt, col) != 0;
}

ConnectionRow read_connection_row(sqlite3_stmt* stmt) noexcept
{
    ConnectionRow row;
    row.ts         = sqlite3_column_int64(stmt,              0);
    row.src_ip     = col_text(stmt,                          1);
    row.src_port   = col_opt_int(stmt,                       2);
    row.dst_ip     = col_text(stmt,                          3);
    row.dst_port   = col_opt_int(stmt,                       4);
    row.proto      = col_text(stmt,                          5);
    row.tcp_flags  = col_text(stmt,                          6);
    row.rule       = col_text(stmt,                          7);
    row.country    = col_text(stmt,                          8);
    row.lat        = col_opt_double(stmt,                    9);
    row.lon        = col_opt_double(stmt,                   10);
    row.asn        = col_text(stmt,                         11);
    row.threat     = col_opt_int(stmt,                      12);
    row.usage_type = col_text(stmt,                         13);
    row.is_tor     = col_opt_bool(stmt,                     14);
    return row;
}

struct BoundFilterState {
    bool has_since{false};
    bool has_until{false};
    bool has_src_ip{false};
    bool has_country{false};
    bool has_proto{false};
    bool exclude_icmp{false};
    bool has_port{false};
};

struct WhereInputs {
    std::string_view src_ip;
    std::string_view country;
    std::string_view proto;
    bool             exclude_icmp{false};
    std::int64_t     since{};
    std::int64_t     until{};
    int              dst_port{};
};

BoundFilterState build_where_clause(std::string& sql, const WhereInputs& inputs)
{
    BoundFilterState state;
    state.has_since   = inputs.since > 0;
    state.has_until   = inputs.until > 0;
    state.has_src_ip  = !inputs.src_ip.empty();
    state.has_country = !inputs.country.empty();
    state.has_proto   = !inputs.proto.empty();
    state.exclude_icmp = !state.has_proto && inputs.exclude_icmp;
    state.has_port    = inputs.dst_port > 0;

    std::string where;
    auto add_cond = [&where](const char* cond) {
        where += where.empty() ? " WHERE " : " AND ";
        where += cond;
    };
    if (state.has_since)   { add_cond("ts >= ?"); }
    if (state.has_until)   { add_cond("ts <= ?"); }
    if (state.has_src_ip)  { add_cond("src_ip = ?"); }
    if (state.has_country) { add_cond("country = ?"); }
    if (state.has_proto)   { add_cond("proto = ?"); }
    if (state.exclude_icmp) { add_cond("proto != 'ICMP'"); }
    if (state.has_port)    { add_cond("dst_port = ?"); }

    sql += where;
    return state;
}

int bind_where_clause(sqlite3_stmt* stmt,
                      const BoundFilterState& state,
                      const WhereInputs& inputs) noexcept
{
    int idx = 1;
    if (state.has_since) {
        (void)sqlite3_bind_int64(stmt, idx++, inputs.since);
    }
    if (state.has_until) {
        (void)sqlite3_bind_int64(stmt, idx++, inputs.until);
    }
    if (state.has_src_ip) {
        (void)sqlite3_bind_text(stmt, idx++, inputs.src_ip.data(), -1, kStaticText);
    }
    if (state.has_country) {
        (void)sqlite3_bind_text(stmt, idx++, inputs.country.data(), -1, kStaticText);
    }
    if (state.has_proto) {
        (void)sqlite3_bind_text(stmt, idx++, inputs.proto.data(), -1, kStaticText);
    }
    if (state.has_port) {
        (void)sqlite3_bind_int(stmt, idx++, inputs.dst_port);
    }
    return idx;
}

void update_map_row(MapRow& out, const ConnectionRow& row, bool inserted)
{
    if (inserted) {
        out.src_ip          = row.src_ip;
        out.first_ts        = row.ts;
        out.last_ts         = row.ts;
        out.count           = 0;
        out.threat_latest   = row.threat;
        out.threat_max      = row.threat;
        out.sample_dst_port = row.dst_port;
        out.usage_type      = row.usage_type;
        out.is_tor          = row.is_tor;
    }

    out.count += 1;
    out.first_ts = std::min(out.first_ts, row.ts);
    out.last_ts  = std::max(out.last_ts, row.ts);

    if (row.threat.has_value() &&
        (!out.threat_max.has_value() || *row.threat > *out.threat_max)) {
        out.threat_max = row.threat;
    }
    if (out.usage_type.empty() && !row.usage_type.empty()) {
        out.usage_type = row.usage_type;
    }
    if (!out.is_tor.has_value() && row.is_tor.has_value()) {
        out.is_tor = row.is_tor;
    }

    if (!out.lat.has_value() && row.lat.has_value() && row.lon.has_value()) {
        out.lat     = row.lat;
        out.lon     = row.lon;
        out.country = row.country;
        out.asn     = row.asn;
        if (row.dst_port.has_value()) {
            out.sample_dst_port = row.dst_port;
        }
    }
}

std::vector<MapRow> collect_geo_rows(std::unordered_map<std::string, MapRow>& by_ip)
{
    std::vector<MapRow> rows;
    rows.reserve(by_ip.size());
    for (auto& [_, row] : by_ip) {
        if (row.lat.has_value() && row.lon.has_value()) {
            rows.push_back(std::move(row));
        }
    }
    std::sort(rows.begin(), rows.end(), [](const MapRow& lhs, const MapRow& rhs) {
        if (lhs.last_ts != rhs.last_ts) {
            return lhs.last_ts > rhs.last_ts;
        }
        return lhs.src_ip < rhs.src_ip;
    });
    return rows;
}

} // anonymous namespace

// ── Database implementation ────────────────────────────────────────────────────

Database::Database(const std::string& path) noexcept
{
    sqlite3* raw_db = nullptr;
    if (sqlite3_open(path.c_str(), &raw_db) != SQLITE_OK) {
        std::clog << "[FATAL] sqlite3_open(" << path
                  << "): " << sqlite3_errmsg(raw_db) << '\n';
        sqlite3_close(raw_db); // must close even on a failed open
        return;
    }
    db_.reset(raw_db);

    // Best-effort: just warn on failure; a missing timeout isn't fatal.
    if (sqlite3_busy_timeout(raw_db, 5000) != SQLITE_OK) {
        std::clog << "[WARN] sqlite3_busy_timeout: "
                  << sqlite3_errmsg(raw_db) << '\n';
    }

    // Apply pragmas and build the schema.
    if (!exec("PRAGMA journal_mode=WAL")        ||
        !exec("PRAGMA synchronous=NORMAL")      ||
        !exec("PRAGMA temp_store=MEMORY")       ||
        !exec("PRAGMA mmap_size=268435456")     ||
        !exec("PRAGMA cache_size=-131072")      ||
        !exec("PRAGMA wal_autocheckpoint=2000") ||
        !exec(kCreateTable)                     ||
        !exec(kCreateIndexTs)                   ||
        !exec(kCreateIndexSrcIp)                ||
        !exec(kCreateIndexDstPort)              ||
        !exec(kCreateIndexCountry)              ||
        !exec(kCreateIndexDedup)) {
        db_.reset(); // mark invalid
        return;
    }

    // Prepare the reusable INSERT statement.
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(raw_db, kInsertSql, -1, &raw_stmt, nullptr)
            != SQLITE_OK) {
        std::clog << "[FATAL] prepare INSERT: "
                  << sqlite3_errmsg(raw_db) << '\n';
        db_.reset();
        return;
    }
    insert_stmt_.reset(raw_stmt);

    // Prepare the retention-prune DELETE statement.
    raw_stmt = nullptr;
    if (sqlite3_prepare_v2(raw_db, kPruneSql, -1, &raw_stmt, nullptr)
            != SQLITE_OK) {
        std::clog << "[FATAL] prepare prune: "
                  << sqlite3_errmsg(raw_db) << '\n';
        db_.reset();
        return;
    }
    prune_stmt_.reset(raw_stmt);
}

// Defined here (not inline in db.h) so the unique_ptr destructors are
// instantiated only in this TU, where sqlite3/sqlite3_stmt are complete.
Database::~Database() noexcept = default;

bool Database::exec(const char* sql) noexcept
{
    char* raw_err = nullptr;
    const int rc  = sqlite3_exec(db_.get(), sql, nullptr, nullptr, &raw_err);
    const auto err = std::unique_ptr<char, SqliteErrFree>{raw_err};
    if (rc != SQLITE_OK) {
        std::clog << "[FATAL] sqlite3_exec: "
                  << (err ? err.get() : "unknown error") << '\n';
        return false;
    }
    return true;
}

bool Database::insert(const LogEntry& entry, const GeoIpResult& geo,
                      std::optional<int> threat) noexcept
{
    const std::lock_guard<std::mutex> lock{mutex_};

    sqlite3_stmt* const stmt = insert_stmt_.get();

    // Bind all fifteen parameters (1-indexed).
    (void)sqlite3_bind_int64(stmt,  1, entry.ts);
    (void)sqlite3_bind_text( stmt,  2, entry.src_ip.c_str(), -1, kStaticText);

    if (entry.src_port >= 0) {
        (void)sqlite3_bind_int(stmt, 3, entry.src_port);
    } else {
        (void)sqlite3_bind_null(stmt, 3);
    }

    (void)sqlite3_bind_text(stmt, 4, entry.dst_ip.c_str(), -1, kStaticText);

    if (entry.dst_port >= 0) {
        (void)sqlite3_bind_int(stmt, 5, entry.dst_port);
    } else {
        (void)sqlite3_bind_null(stmt, 5);
    }

    (void)sqlite3_bind_text(stmt, 6, entry.proto.c_str(),      -1, kStaticText);

    if (!entry.tcp_flags.empty()) {
        (void)sqlite3_bind_text(stmt, 7, entry.tcp_flags.c_str(), -1, kStaticText);
    } else {
        (void)sqlite3_bind_null(stmt, 7);
    }

    (void)sqlite3_bind_text(stmt, 8, entry.rule.c_str(), -1, kStaticText);

    // GeoIP enrichment — NULL when not resolved.
    if (geo.found()) {
        (void)sqlite3_bind_text(  stmt,  9, geo.country.c_str(), -1, kStaticText);
        (void)sqlite3_bind_double(stmt, 10, geo.lat);
        (void)sqlite3_bind_double(stmt, 11, geo.lon);
    } else {
        (void)sqlite3_bind_null(stmt,  9);
        (void)sqlite3_bind_null(stmt, 10);
        (void)sqlite3_bind_null(stmt, 11);
    }

    if (!geo.asn.empty()) {
        (void)sqlite3_bind_text(stmt, 12, geo.asn.c_str(), -1, kStaticText);
    } else {
        (void)sqlite3_bind_null(stmt, 12);
    }

    // AbuseIPDB threat score — NULL when not yet enriched.
    if (threat.has_value()) {
        (void)sqlite3_bind_int(stmt, 13, *threat);
    } else {
        (void)sqlite3_bind_null(stmt, 13);
    }

    // usage_type and is_tor are always NULL at insert time; the AbuseCache
    // background worker backfills them via update_connections_abuse().
    (void)sqlite3_bind_null(stmt, 14);
    (void)sqlite3_bind_null(stmt, 15);

    const int rc = sqlite3_step(stmt);
    (void)sqlite3_reset(stmt);

    if (rc != SQLITE_DONE) {
        std::clog << "[WARN] insert: " << sqlite3_errmsg(db_.get()) << '\n';
        return false;
    }

    ++insert_count_;
    if (insert_count_ % kPruneInterval == 0) {
        prune_old(); // runs under the mutex already held by insert()
    }
    return true;
}

int Database::prune_unlocked(std::int64_t cutoff_ts) noexcept
{
    sqlite3_stmt* const stmt = prune_stmt_.get();
    (void)sqlite3_bind_int64(stmt, 1, cutoff_ts);
    (void)sqlite3_step(stmt);
    (void)sqlite3_reset(stmt);
    return sqlite3_changes(db_.get());
}

void Database::prune_old() noexcept
{
    // Called from insert() which already holds mutex_ — do NOT re-acquire here.
    const auto now    = static_cast<std::int64_t>(std::time(nullptr));
    const auto cutoff = now - kRetentionSecs;
    const int deleted = prune_unlocked(cutoff);
    if (deleted > 0) {
        std::clog << "[INFO] pruned " << deleted
                  << " rows older than 24h\n";
    }
}

int Database::prune_older_than(std::int64_t cutoff_ts) noexcept
{
    if (!db_) {
        return 0;
    }
    const std::lock_guard<std::mutex> lock{mutex_};
    return prune_unlocked(cutoff_ts);
}

int Database::prune_expired() noexcept
{
    return prune_older_than(static_cast<std::int64_t>(std::time(nullptr)) - kRetentionSecs);
}

std::vector<ConnectionRow>
Database::query_connections(const QueryFilters& f) const noexcept
{
    if (!db_) {
        return {};
    }

    const std::lock_guard<std::mutex> lock{mutex_};

    std::string sql =
        "SELECT ts, src_ip, src_port, dst_ip, dst_port, "
        "proto, tcp_flags, rule, "
        "country, lat, lon, asn, threat, usage_type, is_tor "
        "FROM connections";
    const WhereInputs inputs{f.src_ip, f.country, f.proto, f.exclude_icmp,
                             f.since, f.until, f.dst_port};
    const BoundFilterState state = build_where_clause(sql, inputs);
    sql += " ORDER BY ts DESC LIMIT ? OFFSET ?";

    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db_.get(), sql.c_str(), -1, &raw, nullptr)
            != SQLITE_OK) {
        std::clog << "[WARN] query_connections prepare: "
                  << sqlite3_errmsg(db_.get()) << '\n';
        return {};
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};

    const int idx = bind_where_clause(stmt.get(), state, inputs);
    const int cap = (f.limit > 0 && f.limit <= 25000) ? f.limit : 25000;
    (void)sqlite3_bind_int(stmt.get(), idx, cap);
    (void)sqlite3_bind_int(stmt.get(), idx + 1, std::max(f.offset, 0));

    // Collect result rows.
    std::vector<ConnectionRow> rows;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rows.push_back(read_connection_row(stmt.get()));
    }
    return rows;
}

DetailPage Database::query_detail_page(const QueryFilters& f) const noexcept
{
    QueryFilters page = f;
    page.limit = (page.limit > 0 && page.limit <= 500) ? page.limit : 100;
    page.offset = std::max(page.offset, 0);

    DetailPage result;
    result.rows = query_connections(page);
    if (static_cast<int>(result.rows.size()) == page.limit) {
        result.next_cursor = page.offset + page.limit;
    }
    return result;
}

std::vector<MapRow> Database::query_map_rows(const MapFilters& f) const noexcept
{
    if (!db_) {
        return {};
    }

    const std::lock_guard<std::mutex> lock{mutex_};

    std::string sql =
        "SELECT ts, src_ip, src_port, dst_ip, dst_port, "
        "proto, tcp_flags, rule, "
        "country, lat, lon, asn, threat, usage_type, is_tor "
        "FROM connections";
    const WhereInputs inputs{f.src_ip, f.country, f.proto, f.exclude_icmp,
                             f.since, f.until, f.dst_port};
    const BoundFilterState state = build_where_clause(sql, inputs);
    sql += " ORDER BY ts DESC";

    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db_.get(), sql.c_str(), -1, &raw, nullptr)
            != SQLITE_OK) {
        std::clog << "[WARN] query_map_rows prepare: "
                  << sqlite3_errmsg(db_.get()) << '\n';
        return {};
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};

    (void)bind_where_clause(stmt.get(), state, inputs);

    std::unordered_map<std::string, MapRow> by_ip;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const ConnectionRow row = read_connection_row(stmt.get());
        auto [it, inserted] = by_ip.try_emplace(row.src_ip);
        update_map_row(it->second, row, inserted);
    }
    return collect_geo_rows(by_ip);
}

} // namespace msmap

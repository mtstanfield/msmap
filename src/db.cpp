#include "db.h"
#include "filter_utils.h"
#include "geoip.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sqlite3.h>
#include <string>
#include <thread>
#include <utility>
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
    lat        REAL,
    lon        REAL,
    asn        TEXT,
    threat     INTEGER,
    usage_type TEXT
))sql";

constexpr const char* kCreateIpIntelTable = R"sql(
CREATE TABLE IF NOT EXISTS ip_intel_cache (
    ip             TEXT PRIMARY KEY,
    tor_exit       INTEGER,
    spamhaus_drop  INTEGER,
    last_checked   INTEGER NOT NULL
))sql";

constexpr const char* kCreateIndexTs =
    "CREATE INDEX IF NOT EXISTS idx_ts       ON connections(ts)";
constexpr const char* kCreateIndexSrcIp =
    "CREATE INDEX IF NOT EXISTS idx_src_ip   ON connections(src_ip)";
constexpr const char* kCreateIndexDstPort =
    "CREATE INDEX IF NOT EXISTS idx_dst_port ON connections(dst_port)";
constexpr const char* kCreateIndexSrcIpTsId =
    "CREATE INDEX IF NOT EXISTS idx_src_ip_ts_id ON connections(src_ip, ts DESC, id DESC)";
constexpr const char* kCreateIndexTsSrcIp =
    "CREATE INDEX IF NOT EXISTS idx_ts_src_ip ON connections(ts DESC, src_ip)";

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
    rule, lat, lon, asn, threat, usage_type)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?))sql";

constexpr const char* kMigratedTableCreateSql = R"sql(
CREATE TABLE connections_new (
    id         INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    src_ip     TEXT    NOT NULL,
    src_port   INTEGER,
    dst_ip     TEXT    NOT NULL,
    dst_port   INTEGER,
    proto      TEXT    NOT NULL,
    tcp_flags  TEXT,
    rule       TEXT    NOT NULL DEFAULT '',
    lat        REAL,
    lon        REAL,
    asn        TEXT,
    threat     INTEGER,
    usage_type TEXT
))sql";

constexpr const char* kCopyMigratedConnectionRowsSql = R"sql(
INSERT INTO connections_new(
    id, ts, src_ip, src_port, dst_ip, dst_port, proto, tcp_flags, rule,
    lat, lon, asn, threat, usage_type
)
SELECT
    id, ts, src_ip, src_port, dst_ip, dst_port, proto, tcp_flags, rule,
    lat, lon, asn, threat, usage_type
FROM connections
)sql";

constexpr const char* kPruneSql =
    "DELETE FROM connections WHERE ts < ?";

constexpr const char* kPruneIpIntelSql =
    "DELETE FROM ip_intel_cache WHERE ip NOT IN (SELECT DISTINCT src_ip FROM connections)";

constexpr const char* kUpsertIpIntelSql = R"sql(
INSERT INTO ip_intel_cache(ip, tor_exit, spamhaus_drop, last_checked)
VALUES (?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
    tor_exit = excluded.tor_exit,
    spamhaus_drop = excluded.spamhaus_drop,
    last_checked = excluded.last_checked
)sql";

constexpr const char* kDistinctSourceIpsSql =
    "SELECT DISTINCT src_ip FROM connections";

// RAII wrapper for the char* that sqlite3_exec may write into errmsg.
struct SqliteErrFree {
    void operator()(char* p) const noexcept { sqlite3_free(p); }
};

bool exec_sql(sqlite3* db, const char* sql) noexcept
{
    char* raw_err = nullptr;
    const int rc  = sqlite3_exec(db, sql, nullptr, nullptr, &raw_err);
    const auto err = std::unique_ptr<char, SqliteErrFree>{raw_err};
    if (rc != SQLITE_OK) {
        std::clog << "[FATAL] sqlite3_exec: "
                  << (err ? err.get() : "unknown error") << '\n';
        return false;
    }
    return true;
}

bool apply_connection_pragmas(sqlite3* db, bool configure_wal) noexcept
{
    if (sqlite3_busy_timeout(db, 5000) != SQLITE_OK) {
        std::clog << "[WARN] sqlite3_busy_timeout: " << sqlite3_errmsg(db) << '\n';
    }

    if (configure_wal && !exec_sql(db, "PRAGMA journal_mode=WAL")) {
        return false;
    }
    return exec_sql(db, "PRAGMA synchronous=NORMAL") &&
           exec_sql(db, "PRAGMA temp_store=MEMORY") &&
           exec_sql(db, "PRAGMA mmap_size=268435456") &&
           exec_sql(db, "PRAGMA cache_size=-131072") &&
           exec_sql(db, "PRAGMA wal_autocheckpoint=2000");
}

bool table_exists(sqlite3* db, const char* table) noexcept
{
    constexpr const char* k_table_exists_sql =
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?";
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, k_table_exists_sql, -1, &raw, nullptr) != SQLITE_OK) {
        std::clog << "[WARN] table_exists prepare: " << sqlite3_errmsg(db) << '\n';
        return false;
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};
    (void)sqlite3_bind_text(stmt.get(), 1, table, -1, kStaticText);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

bool has_country_column(sqlite3* db) noexcept
{
    const std::string pragma = "PRAGMA table_info(connections)";
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, pragma.c_str(), -1, &raw, nullptr) != SQLITE_OK) {
        std::clog << "[WARN] has_column prepare: " << sqlite3_errmsg(db) << '\n';
        return false;
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto* col_name = sqlite3_column_text(stmt.get(), 1);
        if (col_name != nullptr && std::strcmp(reinterpret_cast<const char*>(col_name), "country") == 0) { // NOLINT(*-reinterpret-cast)
            return true;
        }
    }
    return false;
}

bool migrate_drop_country_column(sqlite3* db) noexcept
{
    if (!table_exists(db, "connections") || !has_country_column(db)) {
        return true;
    }

    std::clog << "[INFO] migrating connections schema to drop country column\n";
    if (!exec_sql(db, "BEGIN IMMEDIATE")) {
        return false;
    }

    const bool ok =
        exec_sql(db, kMigratedTableCreateSql) &&
        exec_sql(db, kCopyMigratedConnectionRowsSql) &&
        exec_sql(db, "DROP TABLE connections") &&
        exec_sql(db, "ALTER TABLE connections_new RENAME TO connections") &&
        exec_sql(db, kCreateIndexTs) &&
        exec_sql(db, kCreateIndexSrcIp) &&
        exec_sql(db, kCreateIndexDstPort) &&
        exec_sql(db, kCreateIndexSrcIpTsId) &&
        exec_sql(db, kCreateIndexTsSrcIp) &&
        exec_sql(db, kCreateIndexDedup);

    if (!ok) {
        (void)exec_sql(db, "ROLLBACK");
        std::clog << "[FATAL] country-column migration failed (rolled back)\n";
        return false;
    }
    if (!exec_sql(db, "COMMIT")) {
        (void)exec_sql(db, "ROLLBACK");
        std::clog << "[FATAL] country-column migration commit failed\n";
        return false;
    }
    return true;
}

// ── Column-reading helpers ─────────────────────────────────────────────────────

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

struct BoundFilterState {
    bool has_since{false};
    bool has_until{false};
    bool has_src_ip{false};
    bool has_asn{false};
    bool has_proto{false};
    bool has_threat{false};
    bool exclude_icmp{false};
    bool has_port{false};
};

struct WhereInputs {
    std::string_view src_ip;
    std::string_view asn;
    std::string_view proto;
    std::string_view threat;
    bool             exclude_icmp{false};
    std::int64_t     since{};
    std::int64_t     until{};
    int              dst_port{};
};

std::string make_lower_like_contains_pattern(std::string_view raw)
{
    std::string pattern;
    pattern.reserve(raw.size() * 2 + 2);
    pattern.push_back('%');
    for (const char ch : raw) {
        const auto uch = static_cast<unsigned char>(ch);
        const char lower = static_cast<char>(std::tolower(uch));
        if (lower == '\\' || lower == '%' || lower == '_') {
            pattern.push_back('\\');
        }
        pattern.push_back(lower);
    }
    pattern.push_back('%');
    return pattern;
}

BoundFilterState build_where_clause(std::string& sql, const WhereInputs& inputs)
{
    BoundFilterState state;
    state.has_since   = inputs.since > 0;
    state.has_until   = inputs.until > 0;
    state.has_src_ip  = !inputs.src_ip.empty();
    state.has_asn = !inputs.asn.empty();
    state.has_proto   = !inputs.proto.empty();
    state.has_threat = !inputs.threat.empty();
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
    if (state.has_asn)     { add_cond("LOWER(asn) LIKE ? ESCAPE '\\'"); }
    if (state.has_proto)   { add_cond("proto = ?"); }
    if (state.has_threat) {
        if (inputs.threat == "unknown") {
            add_cond("threat IS NULL");
            add_cond("COALESCE(intel.spamhaus_drop, 0) = 0");
        } else if (inputs.threat == "clean") {
            add_cond("threat = 0");
            add_cond("COALESCE(intel.spamhaus_drop, 0) = 0");
        } else if (inputs.threat == "low") {
            add_cond("threat BETWEEN 1 AND 33");
            add_cond("COALESCE(intel.spamhaus_drop, 0) = 0");
        } else if (inputs.threat == "medium") {
            add_cond("threat BETWEEN 34 AND 66");
            add_cond("COALESCE(intel.spamhaus_drop, 0) = 0");
        } else if (inputs.threat == "high") {
            add_cond("(threat BETWEEN 67 AND 100 OR COALESCE(intel.spamhaus_drop, 0) = 1)");
        }
    }
    if (state.exclude_icmp) { add_cond("proto != 'ICMP'"); }
    if (state.has_port)    { add_cond("dst_port = ?"); }

    sql += where;
    return state;
}

int bind_where_clause(sqlite3_stmt* stmt,
                      const BoundFilterState& state,
                      const WhereInputs& inputs) noexcept
{
    const std::string asn_pattern = state.has_asn
        ? make_lower_like_contains_pattern(inputs.asn)
        : std::string{};
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
    if (state.has_asn) {
        (void)sqlite3_bind_text(stmt, idx++, asn_pattern.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (state.has_proto) {
        (void)sqlite3_bind_text(stmt, idx++, inputs.proto.data(), -1, kStaticText);
    }
    if (state.has_port) {
        (void)sqlite3_bind_int(stmt, idx++, inputs.dst_port);
    }
    return idx;
}

ConnectionRow read_connection_row_from_offset(sqlite3_stmt* stmt, int base_col) noexcept
{
    ConnectionRow row;
    row.ts            = sqlite3_column_int64(stmt, base_col + 0);
    row.src_ip        = col_text(stmt, base_col + 1);
    row.src_port      = col_opt_int(stmt, base_col + 2);
    row.dst_ip        = col_text(stmt, base_col + 3);
    row.dst_port      = col_opt_int(stmt, base_col + 4);
    row.proto         = col_text(stmt, base_col + 5);
    row.tcp_flags     = col_text(stmt, base_col + 6);
    row.rule          = col_text(stmt, base_col + 7);
    row.lat           = col_opt_double(stmt, base_col + 8);
    row.lon           = col_opt_double(stmt, base_col + 9);
    row.asn           = col_text(stmt, base_col + 10);
    row.threat        = col_opt_int(stmt, base_col + 11);
    row.usage_type    = col_text(stmt, base_col + 12);
    row.tor_exit      = col_opt_bool(stmt, base_col + 13);
    row.spamhaus_drop = col_opt_bool(stmt, base_col + 14);
    return row;
}

std::optional<std::pair<std::int64_t, std::int64_t>>
parse_detail_cursor(std::string_view cursor) noexcept
{
    if (cursor.empty() || cursor.size() > 64) {
        return std::nullopt;
    }
    const auto sep = cursor.find(':');
    if (sep == std::string_view::npos || sep == 0 || sep + 1 >= cursor.size()) {
        return std::nullopt;
    }
    if (cursor.find(':', sep + 1) != std::string_view::npos) {
        return std::nullopt;
    }

    const auto ts = parse_positive_i64_exact(cursor.substr(0, sep));
    const auto id = parse_positive_i64_exact(cursor.substr(sep + 1));
    if (!ts.has_value() || !id.has_value()) {
        return std::nullopt;
    }
    return std::pair<std::int64_t, std::int64_t>{*ts, *id};
}

std::string make_detail_cursor(std::int64_t ts, std::int64_t id)
{
    return std::to_string(ts) + ":" + std::to_string(id);
}

constexpr std::size_t kDefaultReadPoolSize{4};
constexpr int kSqliteOpenFlags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                  SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_URI;

} // anonymous namespace

// ── Database implementation ────────────────────────────────────────────────────

Database::Database(const std::string& path) noexcept
{
    if (path == ":memory:") {
        db_open_path_ = "file:msmap-memory-" +
                        std::to_string(static_cast<unsigned long long>(
                            std::hash<std::thread::id>{}(std::this_thread::get_id()))) +
                        "-" + std::to_string(static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(this))) +
                        "?mode=memory&cache=shared";
    } else {
        db_open_path_ = path;
    }
    db_open_flags_ = kSqliteOpenFlags;

    sqlite3* raw_write = nullptr;
    if (sqlite3_open_v2(db_open_path_.c_str(), &raw_write, db_open_flags_, nullptr) != SQLITE_OK) {
        std::clog << "[FATAL] sqlite3_open(" << path
                  << "): " << sqlite3_errmsg(raw_write) << '\n';
        sqlite3_close(raw_write);
        return;
    }
    write_db_.reset(raw_write);
    if (!apply_connection_pragmas(write_db_.get(), true)) {
        write_db_.reset();
        return;
    }
    if (!migrate_drop_country_column(write_db_.get())) {
        write_db_.reset();
        return;
    }

    if (!exec_sql(write_db_.get(), kCreateTable)          ||
        !exec_sql(write_db_.get(), kCreateIpIntelTable)   ||
        !exec_sql(write_db_.get(), kCreateIndexTs)        ||
        !exec_sql(write_db_.get(), kCreateIndexSrcIp)     ||
        !exec_sql(write_db_.get(), kCreateIndexDstPort)   ||
        !exec_sql(write_db_.get(), kCreateIndexSrcIpTsId) ||
        !exec_sql(write_db_.get(), kCreateIndexTsSrcIp)   ||
        !exec_sql(write_db_.get(), kCreateIndexDedup)) {
        write_db_.reset();
        return;
    }

    auto prepare = [&](const char* sql,
                       std::unique_ptr<sqlite3_stmt, StmtFinalizer>& out,
                       const char* label) {
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(write_db_.get(), sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
            std::clog << "[FATAL] prepare " << label << ": "
                      << sqlite3_errmsg(write_db_.get()) << '\n';
            write_db_.reset();
            return false;
        }
        out.reset(raw_stmt);
        return true;
    };

    if (!prepare(kInsertSql, insert_stmt_, "INSERT") ||
        !prepare(kPruneSql, prune_stmt_, "prune") ||
        !prepare(kUpsertIpIntelSql, upsert_ip_intel_stmt_, "ip_intel upsert")) {
        return;
    }

    for (std::size_t i = 0; i < kDefaultReadPoolSize; ++i) {
        sqlite3* raw_read = nullptr;
        if (sqlite3_open_v2(db_open_path_.c_str(), &raw_read, db_open_flags_, nullptr) != SQLITE_OK) {
            std::clog << "[FATAL] sqlite3_open(read pool): " << sqlite3_errmsg(raw_read) << '\n';
            sqlite3_close(raw_read);
            write_db_.reset();
            read_dbs_.clear();
            return;
        }
        std::unique_ptr<sqlite3, SqliteCloser> read_db{raw_read};
        if (!apply_connection_pragmas(read_db.get(), false)) {
            write_db_.reset();
            read_dbs_.clear();
            return;
        }
        read_dbs_.push_back(std::move(read_db));
        read_in_use_.push_back(false);
    }

    if (!bootstrap_status_counters()) {
        write_db_.reset();
        read_dbs_.clear();
        return;
    }
}

// Defined here (not inline in db.h) so the unique_ptr destructors are
// instantiated only in this TU, where sqlite3/sqlite3_stmt are complete.
Database::~Database() noexcept = default;

bool Database::bootstrap_status_counters() noexcept
{
    if (!write_db_) {
        return false;
    }
    const std::lock_guard<std::mutex> lock{write_mutex_};
    return rebuild_status_counters_unlocked();
}

bool Database::rebuild_status_counters_unlocked() noexcept
{
    sqlite3_stmt* raw = nullptr;
    constexpr const char* k_status_counts_sql =
        "SELECT src_ip, COUNT(*), MAX(ts) FROM connections GROUP BY src_ip";
    if (sqlite3_prepare_v2(write_db_.get(), k_status_counts_sql, -1, &raw, nullptr) != SQLITE_OK) {
        std::clog << "[WARN] rebuild_status_counters prepare: "
                  << sqlite3_errmsg(write_db_.get()) << '\n';
        return false;
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};

    std::unordered_map<std::string, std::int64_t> refcounts;
    std::int64_t rows = 0;
    std::optional<std::int64_t> latest_ts;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const std::string src_ip = col_text(stmt.get(), 0);
        const auto count = sqlite3_column_int64(stmt.get(), 1);
        const auto max_ts = sqlite3_column_int64(stmt.get(), 2);
        rows += count;
        refcounts.insert_or_assign(src_ip, count);
        if (!latest_ts.has_value() || max_ts > *latest_ts) {
            latest_ts = max_ts;
        }
    }

    const std::lock_guard<std::mutex> status_lock{status_mutex_};
    status_source_refcounts_ = std::move(refcounts);
    status_rows_24h_ = rows;
    status_distinct_sources_24h_ = static_cast<std::int64_t>(status_source_refcounts_.size());
    status_latest_event_ts_ = latest_ts;
    return true;
}

void Database::on_insert_success_unlocked(const LogEntry& entry) noexcept
{
    const std::lock_guard<std::mutex> status_lock{status_mutex_};
    ++status_rows_24h_;
    auto& refcount = status_source_refcounts_[entry.src_ip];
    if (refcount == 0) {
        ++status_distinct_sources_24h_;
    }
    ++refcount;
    if (!status_latest_event_ts_.has_value() || entry.ts > *status_latest_event_ts_) {
        status_latest_event_ts_ = entry.ts;
    }
}

std::vector<std::pair<std::string, std::int64_t>>
Database::collect_prune_src_counts_unlocked(std::int64_t cutoff_ts) noexcept
{
    std::vector<std::pair<std::string, std::int64_t>> counts;
    sqlite3_stmt* raw = nullptr;
    constexpr const char* k_prune_src_counts_sql =
        "SELECT src_ip, COUNT(*) FROM connections WHERE ts < ? GROUP BY src_ip";
    if (sqlite3_prepare_v2(write_db_.get(), k_prune_src_counts_sql, -1, &raw, nullptr) != SQLITE_OK) {
        return counts;
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};
    (void)sqlite3_bind_int64(stmt.get(), 1, cutoff_ts);
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        counts.emplace_back(col_text(stmt.get(), 0), sqlite3_column_int64(stmt.get(), 1));
    }
    return counts;
}

std::optional<std::size_t> Database::acquire_read_slot() const noexcept
{
    std::unique_lock<std::mutex> lock{read_pool_mutex_};
    read_pool_cv_.wait(lock, [this]() noexcept {
        return std::any_of(read_in_use_.begin(), read_in_use_.end(),
                           [](bool in_use) noexcept { return !in_use; });
    });
    for (std::size_t i = 0; i < read_in_use_.size(); ++i) {
        if (!read_in_use_[i]) {
            read_in_use_[i] = true;
            return i;
        }
    }
    return std::nullopt;
}

void Database::release_read_slot(std::size_t slot) const noexcept
{
    {
        const std::lock_guard<std::mutex> lock{read_pool_mutex_};
        if (slot < read_in_use_.size()) {
            read_in_use_[slot] = false;
        }
    }
    read_pool_cv_.notify_one();
}

sqlite3* Database::read_db_for_slot(std::size_t slot) const noexcept
{
    if (slot >= read_dbs_.size()) {
        return nullptr;
    }
    return read_dbs_[slot].get();
}

bool Database::insert(const LogEntry& entry, const GeoIpResult& geo,
                      std::optional<int> threat) noexcept
{
    if (!write_db_ || !geo.renderable()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock{write_mutex_};

    sqlite3_stmt* const stmt = insert_stmt_.get();

    // Bind all thirteen parameters (1-indexed).
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

    // GeoIP enrichment — renderable rows only.
    (void)sqlite3_bind_double(stmt, 9, geo.lat);
    (void)sqlite3_bind_double(stmt, 10, geo.lon);

    if (!geo.asn.empty()) {
        (void)sqlite3_bind_text(stmt, 11, geo.asn.c_str(), -1, kStaticText);
    } else {
        (void)sqlite3_bind_null(stmt, 11);
    }

    // AbuseIPDB threat score — NULL when not yet enriched.
    if (threat.has_value()) {
        (void)sqlite3_bind_int(stmt, 12, *threat);
    } else {
        (void)sqlite3_bind_null(stmt, 12);
    }

    // usage_type is NULL at insert time; AbuseCache backfills it later.
    (void)sqlite3_bind_null(stmt, 13);

    const int rc = sqlite3_step(stmt);
    const int changed = sqlite3_changes(write_db_.get());
    (void)sqlite3_reset(stmt);

    if (rc != SQLITE_DONE) {
        std::clog << "[WARN] insert: " << sqlite3_errmsg(write_db_.get()) << '\n';
        return false;
    }
    if (changed == 0) {
        return true;
    }

    on_insert_success_unlocked(entry);

    ++insert_count_;
    if (insert_count_ % kPruneInterval == 0) {
        prune_old();
    }
    return true;
}

bool Database::upsert_ip_intel(const std::string& ip, const IpIntel& intel) noexcept
{
    if (!write_db_) {
        return false;
    }

    const std::lock_guard<std::mutex> lock{write_mutex_};
    sqlite3_stmt* const stmt = upsert_ip_intel_stmt_.get();
    (void)sqlite3_bind_text(stmt, 1, ip.c_str(), -1, kStaticText);
    if (intel.tor_exit.has_value()) {
        (void)sqlite3_bind_int(stmt, 2, *intel.tor_exit ? 1 : 0);
    } else {
        (void)sqlite3_bind_null(stmt, 2);
    }
    if (intel.spamhaus_drop.has_value()) {
        (void)sqlite3_bind_int(stmt, 3, *intel.spamhaus_drop ? 1 : 0);
    } else {
        (void)sqlite3_bind_null(stmt, 3);
    }
    (void)sqlite3_bind_int64(stmt, 4, static_cast<std::int64_t>(std::time(nullptr)));

    const int rc = sqlite3_step(stmt);
    (void)sqlite3_reset(stmt);
    if (rc != SQLITE_DONE) {
        std::clog << "[WARN] upsert_ip_intel: " << sqlite3_errmsg(write_db_.get()) << '\n';
        return false;
    }
    return true;
}

std::vector<std::string> Database::distinct_source_ips() const noexcept
{
    if (!write_db_) {
        return {};
    }
    const auto slot = acquire_read_slot();
    if (!slot.has_value()) {
        return {};
    }
    sqlite3* const db = read_db_for_slot(*slot);
    if (db == nullptr) {
        release_read_slot(*slot);
        return {};
    }
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, kDistinctSourceIpsSql, -1, &raw, nullptr) != SQLITE_OK) {
        std::clog << "[WARN] distinct_source_ips prepare: " << sqlite3_errmsg(db) << '\n';
        release_read_slot(*slot);
        return {};
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};
    std::vector<std::string> ips;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        ips.push_back(col_text(stmt.get(), 0));
    }
    release_read_slot(*slot);
    return ips;
}

int Database::prune_unlocked(std::int64_t cutoff_ts) noexcept
{
    const auto decrements = collect_prune_src_counts_unlocked(cutoff_ts);
    sqlite3_stmt* const stmt = prune_stmt_.get();
    (void)sqlite3_bind_int64(stmt, 1, cutoff_ts);
    (void)sqlite3_step(stmt);
    (void)sqlite3_reset(stmt);
    const int deleted = sqlite3_changes(write_db_.get());
    (void)exec_sql(write_db_.get(), kPruneIpIntelSql);
    if (deleted > 0) {
        {
            const std::lock_guard<std::mutex> status_lock{status_mutex_};
            status_rows_24h_ = std::max<std::int64_t>(0, status_rows_24h_ - deleted);
            for (const auto& [ip, dec] : decrements) {
                auto it = status_source_refcounts_.find(ip);
                if (it == status_source_refcounts_.end()) {
                    continue;
                }
                it->second -= dec;
                if (it->second <= 0) {
                    status_source_refcounts_.erase(it);
                }
            }
            status_distinct_sources_24h_ =
                static_cast<std::int64_t>(status_source_refcounts_.size());
            if (status_rows_24h_ == 0) {
                status_latest_event_ts_.reset();
            }
        }
        (void)rebuild_status_counters_unlocked();
    }
    return deleted;
}

void Database::prune_old() noexcept
{
    // Called from insert() which already holds write_mutex_.
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
    if (!write_db_) {
        return 0;
    }
    const std::lock_guard<std::mutex> lock{write_mutex_};
    return prune_unlocked(cutoff_ts);
}

int Database::prune_expired() noexcept
{
    return prune_older_than(static_cast<std::int64_t>(std::time(nullptr)) - kRetentionSecs);
}

DetailPage Database::query_detail_page(const QueryFilters& f) const noexcept
{
    DetailPage result;
    if (!write_db_) {
        return result;
    }
    const auto slot = acquire_read_slot();
    if (!slot.has_value()) {
        return result;
    }
    sqlite3* const db = read_db_for_slot(*slot);
    if (db == nullptr) {
        release_read_slot(*slot);
        return result;
    }

    const int cap = (f.limit > 0 && f.limit <= 500) ? f.limit : 100;
    const auto cursor = parse_detail_cursor(f.cursor);

    std::string sql =
        "SELECT connections.id, ts, src_ip, src_port, dst_ip, dst_port, "
        "proto, tcp_flags, rule, "
        "lat, lon, asn, threat, usage_type, "
        "intel.tor_exit, intel.spamhaus_drop "
        "FROM connections "
        "LEFT JOIN ip_intel_cache AS intel ON intel.ip = connections.src_ip";
    const WhereInputs inputs{f.src_ip, f.asn, f.proto, "", f.exclude_icmp,
                             f.since, f.until, f.dst_port};
    const BoundFilterState state = build_where_clause(sql, inputs);
    if (cursor.has_value()) {
        sql += state.has_since || state.has_until || state.has_src_ip || state.has_asn ||
                       state.has_proto || state.has_threat || state.exclude_icmp || state.has_port
            ? " AND "
            : " WHERE ";
        sql += "(ts < ? OR (ts = ? AND connections.id < ?))";
    }
    sql += " ORDER BY ts DESC, connections.id DESC LIMIT ?";

    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &raw, nullptr)
            != SQLITE_OK) {
        std::clog << "[WARN] query_detail_page prepare: "
                  << sqlite3_errmsg(db) << '\n';
        release_read_slot(*slot);
        return result;
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};

    int idx = bind_where_clause(stmt.get(), state, inputs);
    if (cursor.has_value()) {
        (void)sqlite3_bind_int64(stmt.get(), idx++, cursor->first);
        (void)sqlite3_bind_int64(stmt.get(), idx++, cursor->first);
        (void)sqlite3_bind_int64(stmt.get(), idx++, cursor->second);
    }
    (void)sqlite3_bind_int(stmt.get(), idx, cap + 1);

    std::int64_t last_ts = 0;
    std::int64_t last_id = 0;
    bool has_more = false;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        if (static_cast<int>(result.rows.size()) >= cap) {
            has_more = true;
            break;
        }
        last_id = sqlite3_column_int64(stmt.get(), 0);
        last_ts = sqlite3_column_int64(stmt.get(), 1);
        result.rows.push_back(read_connection_row_from_offset(stmt.get(), 1));
    }
    if (has_more && !result.rows.empty()) {
        result.next_cursor = make_detail_cursor(last_ts, last_id);
    }
    release_read_slot(*slot);
    return result;
}

std::optional<StatusSnapshot> Database::status_snapshot() const noexcept
{
    if (!write_db_) {
        return std::nullopt;
    }

    StatusSnapshot snapshot;
    snapshot.ok = true;
    snapshot.now = static_cast<std::int64_t>(std::time(nullptr));
    {
        const std::lock_guard<std::mutex> status_lock{status_mutex_};
        snapshot.latest_event_ts = status_latest_event_ts_;
        snapshot.rows_24h = status_rows_24h_;
        snapshot.distinct_sources_24h = status_distinct_sources_24h_;
    }

    if (const char* db_filename = sqlite3_db_filename(write_db_.get(), "main");
        db_filename != nullptr) {
        std::error_code ec;
        const auto path = std::filesystem::path{db_filename};
        if (!path.empty() && std::filesystem::exists(path, ec) && !ec) {
            snapshot.db_size_bytes = std::filesystem::file_size(path, ec);
            if (ec) {
                snapshot.db_size_bytes.reset();
            }
        }
    }

    return snapshot;
}

std::vector<MapRow> Database::query_map_rows(const MapFilters& f) const noexcept
{
    if (!write_db_) {
        return {};
    }
    const auto slot = acquire_read_slot();
    if (!slot.has_value()) {
        return {};
    }
    sqlite3* const db = read_db_for_slot(*slot);
    if (db == nullptr) {
        release_read_slot(*slot);
        return {};
    }

    std::string sql =
        "WITH filtered AS ("
        "SELECT connections.id, ts, src_ip, dst_port, lat, lon, asn, "
        "threat, usage_type, intel.tor_exit, intel.spamhaus_drop "
        "FROM connections "
        "LEFT JOIN ip_intel_cache AS intel ON intel.ip = connections.src_ip";
    const WhereInputs inputs{f.src_ip, f.asn, f.proto, f.threat, f.exclude_icmp,
                             f.since, f.until, f.dst_port};
    const BoundFilterState state = build_where_clause(sql, inputs);
    sql += "), "
           "latest AS ("
           "SELECT src_ip, threat AS threat_latest, dst_port AS sample_dst_port, "
           "lat, lon, asn, tor_exit, spamhaus_drop "
           "FROM ("
           "SELECT src_ip, threat, dst_port, lat, lon, asn, tor_exit, spamhaus_drop, "
           "ROW_NUMBER() OVER (PARTITION BY src_ip ORDER BY ts DESC, id DESC) AS rn "
           "FROM filtered"
           ") WHERE rn = 1"
           "), "
           "usage_pick AS ("
           "SELECT src_ip, usage_type "
           "FROM ("
           "SELECT src_ip, usage_type, "
           "ROW_NUMBER() OVER ("
           "PARTITION BY src_ip ORDER BY "
           "CASE WHEN usage_type IS NOT NULL AND usage_type != '' THEN 0 ELSE 1 END, "
           "ts DESC, id DESC"
           ") AS rn "
           "FROM filtered"
           ") WHERE rn = 1"
           "), "
           "agg AS ("
           "SELECT src_ip, MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS count, "
           "MAX(threat) AS threat_max "
           "FROM filtered GROUP BY src_ip"
           ") "
           "SELECT agg.src_ip, agg.first_ts, agg.last_ts, agg.count, "
           "latest.lat, latest.lon, latest.asn, "
           "latest.threat_latest, agg.threat_max, latest.sample_dst_port, "
           "usage_pick.usage_type, latest.tor_exit, latest.spamhaus_drop "
           "FROM agg "
           "JOIN latest ON latest.src_ip = agg.src_ip "
           "LEFT JOIN usage_pick ON usage_pick.src_ip = agg.src_ip "
           "WHERE latest.lat IS NOT NULL AND latest.lon IS NOT NULL "
           "ORDER BY agg.last_ts DESC, agg.src_ip ASC";

    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &raw, nullptr)
            != SQLITE_OK) {
        std::clog << "[WARN] query_map_rows prepare: "
                  << sqlite3_errmsg(db) << '\n';
        release_read_slot(*slot);
        return {};
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};

    (void)bind_where_clause(stmt.get(), state, inputs);

    std::vector<MapRow> rows;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        MapRow row;
        row.src_ip          = col_text(stmt.get(), 0);
        row.first_ts        = sqlite3_column_int64(stmt.get(), 1);
        row.last_ts         = sqlite3_column_int64(stmt.get(), 2);
        row.count           = sqlite3_column_int(stmt.get(), 3);
        row.lat             = col_opt_double(stmt.get(), 4);
        row.lon             = col_opt_double(stmt.get(), 5);
        row.asn             = col_text(stmt.get(), 6);
        row.threat_latest   = col_opt_int(stmt.get(), 7);
        row.threat_max      = col_opt_int(stmt.get(), 8);
        row.sample_dst_port = col_opt_int(stmt.get(), 9);
        row.usage_type      = col_text(stmt.get(), 10);
        row.tor_exit        = col_opt_bool(stmt.get(), 11);
        row.spamhaus_drop   = col_opt_bool(stmt.get(), 12);
        rows.push_back(std::move(row));
    }
    release_read_slot(*slot);
    return rows;
}

} // namespace msmap

#include "db.h"
#include "geoip.h"

#include <cstdint>
#include <ctime>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sqlite3.h>
#include <string>
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
constexpr std::int64_t kRetentionSecs{365LL * 24 * 3600};

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
    chain      TEXT    NOT NULL,
    in_iface   TEXT    NOT NULL,
    rule       TEXT    NOT NULL DEFAULT '',
    conn_state TEXT    NOT NULL,
    pkt_len    INTEGER NOT NULL,
    country    TEXT,
    lat        REAL,
    lon        REAL,
    asn        TEXT,
    threat     INTEGER
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
    chain, in_iface, rule, conn_state, pkt_len,
    country, lat, lon, asn, threat)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?))sql";

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
    if (!exec("PRAGMA journal_mode=WAL")  ||
        !exec("PRAGMA synchronous=NORMAL") ||
        !exec(kCreateTable)               ||
        !exec(kCreateIndexTs)             ||
        !exec(kCreateIndexSrcIp)          ||
        !exec(kCreateIndexDstPort)        ||
        !exec(kCreateIndexCountry)        ||
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

    // Bind all seventeen parameters (1-indexed).
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

    (void)sqlite3_bind_text(stmt,  8, entry.chain.c_str(),      -1, kStaticText);
    (void)sqlite3_bind_text(stmt,  9, entry.in_iface.c_str(),   -1, kStaticText);
    (void)sqlite3_bind_text(stmt, 10, entry.rule.c_str(),       -1, kStaticText);
    (void)sqlite3_bind_text(stmt, 11, entry.conn_state.c_str(), -1, kStaticText);
    (void)sqlite3_bind_int( stmt, 12, entry.pkt_len);

    // GeoIP enrichment — NULL when not resolved.
    if (geo.found()) {
        (void)sqlite3_bind_text(  stmt, 13, geo.country.c_str(), -1, kStaticText);
        (void)sqlite3_bind_double(stmt, 14, geo.lat);
        (void)sqlite3_bind_double(stmt, 15, geo.lon);
    } else {
        (void)sqlite3_bind_null(stmt, 13);
        (void)sqlite3_bind_null(stmt, 14);
        (void)sqlite3_bind_null(stmt, 15);
    }

    if (!geo.asn.empty()) {
        (void)sqlite3_bind_text(stmt, 16, geo.asn.c_str(), -1, kStaticText);
    } else {
        (void)sqlite3_bind_null(stmt, 16);
    }

    // AbuseIPDB threat score — NULL when not yet enriched.
    if (threat.has_value()) {
        (void)sqlite3_bind_int(stmt, 17, *threat);
    } else {
        (void)sqlite3_bind_null(stmt, 17);
    }

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
                  << " rows older than 1 year\n";
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

std::vector<ConnectionRow>
Database::query_connections(const QueryFilters& f) const noexcept
{
    if (!db_) {
        return {};
    }

    const std::lock_guard<std::mutex> lock{mutex_};

    // Build a fully-parameterised SELECT.  User values go through bind
    // parameters only — no string concatenation of user data into SQL.
    const bool has_since   = f.since > 0;
    const bool has_until   = f.until > 0;
    const bool has_src_ip  = !f.src_ip.empty();
    const bool has_country = !f.country.empty();
    const bool has_proto   = !f.proto.empty();
    const bool has_port    = f.dst_port > 0;

    std::string sql =
        "SELECT id, ts, src_ip, src_port, dst_ip, dst_port, "
        "proto, tcp_flags, chain, in_iface, rule, conn_state, pkt_len, "
        "country, lat, lon, asn, threat "
        "FROM connections";

    std::string where;
    auto add_cond = [&where](const char* cond) {
        where += where.empty() ? " WHERE " : " AND ";
        where += cond;
    };
    if (has_since) {
        add_cond("ts >= ?");
    }
    if (has_until) {
        add_cond("ts <= ?");
    }
    if (has_src_ip) {
        add_cond("src_ip = ?");
    }
    if (has_country) {
        add_cond("country = ?");
    }
    if (has_proto) {
        add_cond("proto = ?");
    }
    if (has_port) {
        add_cond("dst_port = ?");
    }

    sql += where;
    sql += " ORDER BY ts DESC LIMIT ?";

    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db_.get(), sql.c_str(), -1, &raw, nullptr)
            != SQLITE_OK) {
        std::clog << "[WARN] query_connections prepare: "
                  << sqlite3_errmsg(db_.get()) << '\n';
        return {};
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};

    // Bind parameters in the same order that WHERE conditions were added.
    int idx = 1;
    if (has_since) {
        (void)sqlite3_bind_int64(stmt.get(), idx++, f.since);
    }
    if (has_until) {
        (void)sqlite3_bind_int64(stmt.get(), idx++, f.until);
    }
    if (has_src_ip) {
        (void)sqlite3_bind_text(stmt.get(), idx++, f.src_ip.c_str(), -1, kStaticText);
    }
    if (has_country) {
        (void)sqlite3_bind_text(stmt.get(), idx++, f.country.c_str(), -1, kStaticText);
    }
    if (has_proto) {
        (void)sqlite3_bind_text(stmt.get(), idx++, f.proto.c_str(), -1, kStaticText);
    }
    if (has_port) {
        (void)sqlite3_bind_int(stmt.get(), idx++, f.dst_port);
    }

    const int cap = (f.limit > 0 && f.limit <= 10000) ? f.limit : 1000;
    (void)sqlite3_bind_int(stmt.get(), idx, cap);

    // Collect result rows.
    std::vector<ConnectionRow> rows;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        ConnectionRow row;
        row.id         = sqlite3_column_int64(stmt.get(),  0);
        row.ts         = sqlite3_column_int64(stmt.get(),  1);
        row.src_ip     = col_text(stmt.get(),              2);
        row.src_port   = col_opt_int(stmt.get(),           3);
        row.dst_ip     = col_text(stmt.get(),              4);
        row.dst_port   = col_opt_int(stmt.get(),           5);
        row.proto      = col_text(stmt.get(),              6);
        row.tcp_flags  = col_text(stmt.get(),              7);
        row.chain      = col_text(stmt.get(),              8);
        row.in_iface   = col_text(stmt.get(),              9);
        row.rule       = col_text(stmt.get(),             10);
        row.conn_state = col_text(stmt.get(),             11);
        row.pkt_len    = sqlite3_column_int(stmt.get(),   12);
        row.country    = col_text(stmt.get(),             13);
        row.lat        = col_opt_double(stmt.get(),       14);
        row.lon        = col_opt_double(stmt.get(),       15);
        row.asn        = col_text(stmt.get(),             16);
        row.threat     = col_opt_int(stmt.get(),          17);
        rows.push_back(std::move(row));
    }
    return rows;
}

} // namespace msmap

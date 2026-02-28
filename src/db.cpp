#include "db.h"

#include <cstdint>
#include <ctime>
#include <iostream>
#include <memory>
#include <sqlite3.h>

namespace msmap {

// ── Custom deleters ────────────────────────────────────────────────────────

void SqliteCloser::operator()(sqlite3* p) const noexcept
{
    sqlite3_close(p);
}

void StmtFinalizer::operator()(sqlite3_stmt* p) const noexcept
{
    sqlite3_finalize(p);
}

// ── Module-level constants ─────────────────────────────────────────────────

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

constexpr const char* kInsertSql = R"sql(
INSERT INTO connections(
    ts, src_ip, src_port, dst_ip, dst_port, proto, tcp_flags,
    chain, in_iface, rule, conn_state, pkt_len)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?))sql";

constexpr const char* kPruneSql =
    "DELETE FROM connections WHERE ts < ?";

// RAII wrapper for the char* that sqlite3_exec may write into errmsg.
struct SqliteErrFree {
    void operator()(char* p) const noexcept { sqlite3_free(p); }
};

} // anonymous namespace

// ── Database implementation ────────────────────────────────────────────────

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
        !exec(kCreateIndexCountry)) {
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

bool Database::insert(const LogEntry& entry) noexcept
{
    sqlite3_stmt* const stmt = insert_stmt_.get();

    // Bind all twelve parameters (1-indexed).
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

    const int rc = sqlite3_step(stmt);
    (void)sqlite3_reset(stmt);

    if (rc != SQLITE_DONE) {
        std::clog << "[WARN] insert: " << sqlite3_errmsg(db_.get()) << '\n';
        return false;
    }

    ++insert_count_;
    if (insert_count_ % kPruneInterval == 0) {
        prune_old();
    }
    return true;
}

void Database::prune_old() noexcept
{
    const auto now    = static_cast<std::int64_t>(std::time(nullptr));
    const auto cutoff = now - kRetentionSecs;

    sqlite3_stmt* const stmt = prune_stmt_.get();
    (void)sqlite3_bind_int64(stmt, 1, cutoff);
    (void)sqlite3_step(stmt);
    (void)sqlite3_reset(stmt);

    const int deleted = sqlite3_changes(db_.get());
    if (deleted > 0) {
        std::clog << "[INFO] pruned " << deleted
                  << " rows older than 1 year\n";
    }
}

} // namespace msmap

#pragma once

#include "parser.h"

#include <cstddef>
#include <memory>
#include <string>

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
    /// Triggers a retention prune every kPruneInterval inserts.
    bool insert(const LogEntry& entry, const GeoIpResult& geo) noexcept;

private:
    bool exec(const char* sql) noexcept;
    void prune_old() noexcept;

    std::unique_ptr<sqlite3,      SqliteCloser>  db_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> insert_stmt_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> prune_stmt_;
    std::size_t                                  insert_count_{0};
};

} // namespace msmap

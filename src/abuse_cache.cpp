#include "abuse_cache.h"

#include <curl/curl.h>
#include <sqlite3.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <string>

namespace msmap {

namespace {

// SQLITE_STATIC: string lifetime is managed by the caller (same pattern as db.cpp).
const auto kStaticText = // NOLINT(*-avoid-non-const-global-variables)
    static_cast<sqlite3_destructor_type>(nullptr);

constexpr const char* kCreateAbuseCacheTable = R"sql(
CREATE TABLE IF NOT EXISTS abuse_cache (
    ip           TEXT    PRIMARY KEY,
    score        INTEGER NOT NULL,
    last_checked INTEGER NOT NULL
))sql";

constexpr const char* kLookupSql =
    "SELECT score, last_checked FROM abuse_cache WHERE ip = ?";

constexpr const char* kUpsertSql =
    "INSERT OR REPLACE INTO abuse_cache(ip, score, last_checked) VALUES(?, ?, ?)";

// Only patch rows where threat IS NULL — avoids overwriting scores that were
// already stored at insert time (listener may cache-hit after the worker runs).
constexpr const char* kUpdateConnSql =
    "UPDATE connections SET threat = ? WHERE src_ip = ? AND threat IS NULL";

constexpr const char* kAbuseIpdbEndpoint =
    "https://api.abuseipdb.com/api/v2/check";

// ── libcurl write callback ────────────────────────────────────────────────────

std::size_t curl_write_cb(const char* ptr, std::size_t /*size*/,
                          std::size_t nmemb, void* userdata) noexcept
{
    auto* const buf = static_cast<std::string*>(userdata);
    buf->append(ptr, nmemb);
    return nmemb;
}

// ── Minimal JSON extractor ────────────────────────────────────────────────────

/// Find "abuseConfidenceScore": N in the API response.
/// Returns nullopt if the key is absent or the value is not a valid integer.
std::optional<int> extract_score(const std::string& json) noexcept
{
    constexpr std::string_view key{"\"abuseConfidenceScore\":"};
    const auto pos = json.find(key);
    if (pos == std::string::npos) {
        return std::nullopt;
    }
    const char* p = json.c_str() + pos + key.size();
    while (*p == ' ' || *p == '\t') { ++p; }
    char* end = nullptr;
    const long val = std::strtol(p, &end, 10);
    if (end == p || val < 0 || val > 100) {
        return std::nullopt;
    }
    return static_cast<int>(val);
}

// ── Rate-limit day helper ─────────────────────────────────────────────────────

std::int64_t epoch_day() noexcept
{
    return static_cast<std::int64_t>(std::time(nullptr)) / 86400LL;
}

} // anonymous namespace

// ── AbuseCache implementation ─────────────────────────────────────────────────

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
AbuseCache::AbuseCache(const std::string& db_path,
                       const std::string& api_key) noexcept
    : db_path_(db_path), api_key_(api_key),
      rate_reset_day_(epoch_day())
{
    // Initialise libcurl once for the lifetime of this object.
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        std::clog << "[WARN] AbuseCache: curl_global_init failed\n";
        return;
    }

    if (!open()) {
        return;
    }

    worker_thread_ = std::thread{[this]() noexcept { worker(); }};
}

AbuseCache::~AbuseCache() noexcept
{
    {
        const std::lock_guard<std::mutex> lock{queue_mutex_};
        stop_ = true;
    }
    queue_cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    // db_ unique_ptr destructor finalises statements and closes the connection.
    curl_global_cleanup();
}

// ── open() ────────────────────────────────────────────────────────────────────

bool AbuseCache::open() noexcept
{
    sqlite3* raw_db = nullptr;
    if (sqlite3_open(db_path_.c_str(), &raw_db) != SQLITE_OK) {
        std::clog << "[WARN] AbuseCache: sqlite3_open(" << db_path_
                  << "): " << sqlite3_errmsg(raw_db) << '\n';
        sqlite3_close(raw_db);
        return false;
    }
    db_.reset(raw_db);

    (void)sqlite3_busy_timeout(raw_db, 5000);

    // Create the cache table if it does not exist.
    char* raw_err = nullptr;
    struct ErrFree { void operator()(char* p) const noexcept { sqlite3_free(p); } };
    if (sqlite3_exec(raw_db, kCreateAbuseCacheTable, nullptr, nullptr, &raw_err)
            != SQLITE_OK) {
        const std::unique_ptr<char, ErrFree> err{raw_err};
        std::clog << "[WARN] AbuseCache: create table: "
                  << (err ? err.get() : "unknown") << '\n';
        db_.reset();
        return false;
    }

    // Prepare statements.
    auto prepare = [&](const char* sql,
                       std::unique_ptr<sqlite3_stmt, StmtFinalizer>& out) -> bool {
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(raw_db, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
            std::clog << "[WARN] AbuseCache: prepare: "
                      << sqlite3_errmsg(raw_db) << '\n';
            db_.reset();
            return false;
        }
        out.reset(raw_stmt);
        return true;
    };

    if (!prepare(kLookupSql, lookup_stmt_) || !prepare(kUpsertSql, upsert_stmt_)) {
        return false;
    }

    // Non-fatal: the connections table lives in the main Database connection.
    // When AbuseCache opens a separate :memory: DB (e.g., in unit tests), the
    // table does not exist and prepare will fail.  We log and continue — backfill
    // is simply disabled, the rest of the cache still works.
    sqlite3_stmt* raw_update = nullptr;
    if (sqlite3_prepare_v2(raw_db, kUpdateConnSql, -1, &raw_update, nullptr) == SQLITE_OK) {
        update_conn_stmt_.reset(raw_update);
    } else {
        std::clog << "[INFO] AbuseCache: connections table not found in this DB; "
                     "threat backfill disabled\n";
    }

    return true;
}

// ── lookup() ─────────────────────────────────────────────────────────────────

std::optional<int> AbuseCache::lookup(const std::string& ip) const noexcept
{
    if (!db_) { return std::nullopt; }

    const std::lock_guard<std::mutex> lock{db_mutex_};

    sqlite3_stmt* const stmt = lookup_stmt_.get();
    (void)sqlite3_bind_text(stmt, 1, ip.c_str(), -1, kStaticText);

    std::optional<int> result{std::nullopt};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const int          score        = sqlite3_column_int(stmt,   0);
        const std::int64_t last_checked = sqlite3_column_int64(stmt, 1);
        const auto         now          = static_cast<std::int64_t>(std::time(nullptr));
        if (now - last_checked < kCacheTtlSecs) {
            result = score;
        }
        // Stale: return nullopt — submit() will re-queue for refresh.
    }
    (void)sqlite3_reset(stmt);
    return result;
}

// ── submit() ─────────────────────────────────────────────────────────────────

void AbuseCache::submit(const std::string& ip) noexcept
{
    if (api_key_.empty() || !db_) { return; }

    {
        const std::lock_guard<std::mutex> lock{queue_mutex_};
        if (queue_.contains(ip) || in_flight_.contains(ip)) {
            return; // already queued or being fetched
        }
        queue_.insert(ip);
    }
    queue_cv_.notify_one();
}

// ── cache_store() ────────────────────────────────────────────────────────────

bool AbuseCache::cache_store(const std::string& ip, int score) noexcept
{
    if (!db_) { return false; }

    const std::lock_guard<std::mutex> lock{db_mutex_};

    sqlite3_stmt* const stmt = upsert_stmt_.get();
    const auto now = static_cast<std::int64_t>(std::time(nullptr));

    (void)sqlite3_bind_text( stmt, 1, ip.c_str(), -1, kStaticText);
    (void)sqlite3_bind_int(  stmt, 2, score);
    (void)sqlite3_bind_int64(stmt, 3, now);

    const int rc = sqlite3_step(stmt);
    (void)sqlite3_reset(stmt);

    if (rc != SQLITE_DONE) {
        std::clog << "[WARN] AbuseCache: upsert: "
                  << sqlite3_errmsg(db_.get()) << '\n';
        return false;
    }
    return true;
}

// ── update_connections_threat() ──────────────────────────────────────────────

void AbuseCache::update_connections_threat(const std::string& ip,
                                           int                score) noexcept
{
    if (!db_ || !update_conn_stmt_) { return; }

    const std::lock_guard<std::mutex> lock{db_mutex_};

    sqlite3_stmt* const stmt = update_conn_stmt_.get();
    (void)sqlite3_bind_int( stmt, 1, score);
    (void)sqlite3_bind_text(stmt, 2, ip.c_str(), -1, kStaticText);

    (void)sqlite3_step(stmt);
    const int patched = sqlite3_changes(db_.get());
    (void)sqlite3_reset(stmt);

    if (patched > 0) {
        std::clog << "[INFO] AbuseCache: patched " << patched
                  << " row(s) for " << ip << " threat=" << score << '\n';
    }
}

// ── rate_remaining() / rate_limit_reset_if_new_day() ─────────────────────────

int AbuseCache::rate_remaining() const noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return rate_remaining_;
}

bool AbuseCache::rate_limit_reset_if_new_day() noexcept
{
    // Caller must hold queue_mutex_.
    const std::int64_t today = epoch_day();
    if (today != rate_reset_day_) {
        rate_remaining_ = kDailyQuota;
        rate_reset_day_ = today;
        return true;
    }
    return false;
}

// ── worker() ────────────────────────────────────────────────────────────────

void AbuseCache::worker() noexcept
{
    for (;;) {
        std::string ip;

        {
            std::unique_lock<std::mutex> lock{queue_mutex_};
            queue_cv_.wait(lock, [this]() noexcept {
                return stop_ || !queue_.empty();
            });

            if (stop_ && queue_.empty()) {
                return;
            }

            auto it = queue_.begin();
            ip = *it;
            queue_.erase(it);
            in_flight_.insert(ip);
        }

        // Check and reset daily rate limit.
        {
            const std::lock_guard<std::mutex> lock{queue_mutex_};
            rate_limit_reset_if_new_day();
            if (rate_remaining_ <= 0) {
                std::clog << "[WARN] AbuseCache: daily quota exhausted; "
                             "skipping " << ip << '\n';
                in_flight_.erase(ip);
                continue;
            }
        }

        // Skip if a fresh cache entry appeared since submit() was called.
        if (lookup(ip).has_value()) {
            const std::lock_guard<std::mutex> lock{queue_mutex_};
            in_flight_.erase(ip);
            continue;
        }

        // Fetch from AbuseIPDB (network call — no mutex held).
        const auto score = fetch_score(ip);

        {
            const std::lock_guard<std::mutex> lock{queue_mutex_};
            --rate_remaining_;
            in_flight_.erase(ip);
        }

        if (score.has_value()) {
            if (cache_store(ip, *score)) {
                update_connections_threat(ip, *score);
            }
        } else {
            std::clog << "[WARN] AbuseCache: fetch failed for " << ip << '\n';
        }
    }
}

// ── fetch_score() ────────────────────────────────────────────────────────────

std::optional<int> AbuseCache::fetch_score(const std::string& ip) noexcept
{
    CURL* const curl = curl_easy_init();
    if (curl == nullptr) {
        std::clog << "[WARN] AbuseCache: curl_easy_init failed\n";
        return std::nullopt;
    }
    struct CurlCloser { void operator()(CURL* c) const noexcept { curl_easy_cleanup(c); } };
    const std::unique_ptr<CURL, CurlCloser> curl_guard{curl};

    // Build URL.
    const std::string url = std::string{kAbuseIpdbEndpoint}
                          + "?ipAddress=" + ip
                          + "&maxAgeInDays=90";

    // Build header list.
    curl_slist* raw_headers = nullptr;
    const std::string key_header = "Key: " + api_key_;
    raw_headers = curl_slist_append(raw_headers, key_header.c_str());
    raw_headers = curl_slist_append(raw_headers, "Accept: application/json");
    struct SlistCloser { void operator()(curl_slist* s) const noexcept { curl_slist_free_all(s); } };
    const std::unique_ptr<curl_slist, SlistCloser> headers_guard{raw_headers};

    std::string body;
    body.reserve(512);

    (void)curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
    (void)curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     raw_headers);
    (void)curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curl_write_cb);
    (void)curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &body);
    (void)curl_easy_setopt(curl, CURLOPT_TIMEOUT,        10L);
    (void)curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    const CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::clog << "[WARN] AbuseCache: curl: "
                  << curl_easy_strerror(res) << '\n';
        return std::nullopt;
    }

    long http_code{0};
    (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        std::clog << "[WARN] AbuseCache: HTTP " << http_code
                  << " for " << ip << '\n';
        return std::nullopt;
    }

    return extract_score(body);
}

} // namespace msmap

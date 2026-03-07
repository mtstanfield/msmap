#include "abuse_cache.h"
#include "curl_global.h"

#include <curl/curl.h>
#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace msmap {

namespace {

// SQLITE_STATIC: string lifetime is managed by the caller (same pattern as db.cpp).
const auto kStaticText = // NOLINT(*-avoid-non-const-global-variables)
    static_cast<sqlite3_destructor_type>(nullptr);

constexpr const char* kCreateAbuseCacheTable = R"sql(
CREATE TABLE IF NOT EXISTS abuse_cache (
    ip           TEXT    PRIMARY KEY,
    score        INTEGER NOT NULL,
    usage_type   TEXT    NOT NULL DEFAULT '',
    last_checked INTEGER NOT NULL
))sql";

constexpr const char* kLookupSql =
    "SELECT score, last_checked, usage_type FROM abuse_cache WHERE ip = ?";

constexpr const char* kUpsertSql =
    "INSERT OR REPLACE INTO abuse_cache(ip, score, usage_type, last_checked)"
    " VALUES(?, ?, ?, ?)";

// Patch rows where usage_type IS NULL — covers both freshly-inserted rows and rows
// where threat was set at insert time but the new fields were not yet available.
constexpr const char* kUpdateConnSql =
    "UPDATE connections"
    " SET threat = ?, usage_type = ?"
    " WHERE src_ip = ? AND usage_type IS NULL";

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

struct RateHeaderState {
    std::optional<int> remaining;
};

std::size_t curl_header_cb(const char* ptr, std::size_t size,
                           std::size_t nmemb, void* userdata) noexcept
{
    auto* const state = static_cast<RateHeaderState*>(userdata);
    if (state == nullptr) {
        return size * nmemb;
    }

    const std::size_t len = size * nmemb;
    std::string line(ptr, len);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
        line.pop_back();
    }

    constexpr std::string_view k_remaining_header{"x-ratelimit-remaining:"};
    std::string lower;
    lower.reserve(line.size());
    std::transform(line.begin(), line.end(), std::back_inserter(lower),
                   [](unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });

    if (lower.starts_with(k_remaining_header)) {
        const char* value = line.c_str() + static_cast<std::ptrdiff_t>(k_remaining_header.size());
        while (*value == ' ' || *value == '\t') { ++value; }
        char* end = nullptr;
        const long parsed = std::strtol(value, &end, 10);
        if (end != value && parsed >= 0) {
            state->remaining = static_cast<int>(parsed);
        }
    }

    return len;
}

// ── Minimal JSON extractor ────────────────────────────────────────────────────

constexpr int hex_nibble(char ch) noexcept
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

bool parse_hex4(const char* p, std::uint32_t& codepoint) noexcept
{
    codepoint = 0;
    for (int i = 0; i < 4; ++i) {
        const int nib = hex_nibble(p[i]);
        if (nib < 0) {
            return false;
        }
        codepoint = (codepoint << 4U) | static_cast<std::uint32_t>(nib);
    }
    return true;
}

void append_replacement_utf8(std::string& out)
{
    out.push_back(static_cast<char>(0xEF));
    out.push_back(static_cast<char>(0xBF));
    out.push_back(static_cast<char>(0xBD));
}

void append_codepoint_utf8(std::string& out, std::uint32_t codepoint)
{
    if (codepoint <= 0x7FU) {
        out.push_back(static_cast<char>(codepoint));
        return;
    }
    if (codepoint <= 0x7FFU) {
        out.push_back(static_cast<char>(0xC0U | (codepoint >> 6U)));
        out.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        return;
    }
    if (codepoint <= 0xFFFFU) {
        out.push_back(static_cast<char>(0xE0U | (codepoint >> 12U)));
        out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        return;
    }
    if (codepoint <= 0x10FFFFU) {
        out.push_back(static_cast<char>(0xF0U | (codepoint >> 18U)));
        out.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        return;
    }
    append_replacement_utf8(out);
}

bool parse_json_unicode_escape(const char*& p, std::string& out) noexcept
{
    std::uint32_t codepoint = 0;
    if (!parse_hex4(p, codepoint)) {
        return false;
    }
    p += 4;

    if (codepoint >= 0xD800U && codepoint <= 0xDBFFU) {
        if (p[0] != '\\' || p[1] != 'u') {
            return false;
        }
        std::uint32_t low = 0;
        if (!parse_hex4(p + 2, low) || low < 0xDC00U || low > 0xDFFFU) {
            return false;
        }
        p += 6;
        codepoint = 0x10000U + (((codepoint - 0xD800U) << 10U) | (low - 0xDC00U));
    } else if (codepoint >= 0xDC00U && codepoint <= 0xDFFFU) {
        return false;
    }

    append_codepoint_utf8(out, codepoint);
    return true;
}

bool parse_json_escape(const char*& p, std::string& out) noexcept
{
    const char esc = *p++;
    if (esc == '\0') {
        return false;
    }
    switch (esc) {
    case '"': out.push_back('"'); return true;
    case '\\': out.push_back('\\'); return true;
    case '/': out.push_back('/'); return true;
    case 'b': out.push_back('\b'); return true;
    case 'f': out.push_back('\f'); return true;
    case 'n': out.push_back('\n'); return true;
    case 'r': out.push_back('\r'); return true;
    case 't': out.push_back('\t'); return true;
    case 'u': return parse_json_unicode_escape(p, out);
    default: return false;
    }
}

bool parse_json_quoted_string(const char* p,
                              std::string& out) noexcept
{
    if (p == nullptr || *p != '"') {
        return false;
    }
    ++p; // opening quote
    out.clear();

    while (*p != '\0') {
        const char ch = *p++;
        if (ch == '"') {
            return true;
        }
        if (ch != '\\') {
            out.push_back(ch);
            continue;
        }
        if (!parse_json_escape(p, out)) {
            return false;
        }
    }
    return false;
}

/// Extract abuseConfidenceScore and usageType from the AbuseIPDB response.
/// Returns nullopt if the score key is absent or its value is not a valid integer.
std::optional<AbuseResult> extract_abuse(const std::string& json) noexcept
{
    // ── score (required) ──────────────────────────────────────────────────────
    constexpr std::string_view k_score_key{"\"abuseConfidenceScore\":"};
    const auto score_pos = json.find(k_score_key);
    if (score_pos == std::string::npos) {
        return std::nullopt;
    }
    const char* p = json.c_str() + score_pos + k_score_key.size();
    while (*p == ' ' || *p == '\t') { ++p; }
    char* end = nullptr;
    const long score_val = std::strtol(p, &end, 10);
    if (end == p || score_val < 0 || score_val > 100) {
        return std::nullopt;
    }

    AbuseResult result;
    result.score = static_cast<int>(score_val);

    // ── usageType (optional string) ───────────────────────────────────────────
    constexpr std::string_view k_usage_key{R"("usageType")"};
    const auto usage_pos = json.find(k_usage_key);
    if (usage_pos != std::string::npos) {
        const char* usage_ptr = json.c_str() + usage_pos + static_cast<std::ptrdiff_t>(k_usage_key.size());
        while (*usage_ptr == ' ' || *usage_ptr == '\t' || *usage_ptr == '\n' || *usage_ptr == '\r') {
            ++usage_ptr;
        }
        if (*usage_ptr == ':') {
            ++usage_ptr;
            while (*usage_ptr == ' ' || *usage_ptr == '\t' || *usage_ptr == '\n' || *usage_ptr == '\r') {
                ++usage_ptr;
            }
            std::string decoded;
            if (parse_json_quoted_string(usage_ptr, decoded)) {
                result.usage_type = std::move(decoded);
            }
        }
    }

    return result;
}

// ── Rate-limit day helper ─────────────────────────────────────────────────────

std::int64_t epoch_day() noexcept
{
    return static_cast<std::int64_t>(std::time(nullptr)) / 86400LL;
}

std::int64_t next_utc_midnight_ts(std::int64_t day) noexcept
{
    return (day + 1LL) * 86400LL;
}

} // anonymous namespace

std::optional<AbuseResult> parse_abuse_response(const std::string& json) noexcept
{
    return extract_abuse(json);
}

// ── AbuseCache implementation ─────────────────────────────────────────────────

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
AbuseCache::AbuseCache(const std::string& db_path,
                       const std::string& api_key) noexcept
    : db_path_(db_path), api_key_(api_key),
      rate_reset_day_(epoch_day())
{
    if (!ensure_curl_global_init()) {
        std::clog << "[WARN] AbuseCache: curl global init failed\n";
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

std::optional<AbuseCacheEntry> AbuseCache::lookup_entry(
    const std::string& ip) const noexcept
{
    if (!db_) { return std::nullopt; }

    const std::lock_guard<std::mutex> lock{db_mutex_};

    sqlite3_stmt* const stmt = lookup_stmt_.get();
    (void)sqlite3_bind_text(stmt, 1, ip.c_str(), -1, kStaticText);

    std::optional<AbuseCacheEntry> result{std::nullopt};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        AbuseCacheEntry entry;
        entry.result.score = sqlite3_column_int(stmt, 0);
        entry.last_checked = sqlite3_column_int64(stmt, 1);
        const auto* ut = sqlite3_column_text(stmt, 2);
        if (ut != nullptr) {
            entry.result.usage_type.assign(
                reinterpret_cast<const char*>(ut), // NOLINT(*-reinterpret-cast)
                static_cast<std::size_t>(sqlite3_column_bytes(stmt, 2)));
        }
        result = std::move(entry);
    }
    (void)sqlite3_reset(stmt);
    return result;
}

std::optional<AbuseResult> AbuseCache::lookup(const std::string& ip) const noexcept
{
    const auto entry = lookup_entry(ip);
    if (!entry.has_value()) {
        return std::nullopt;
    }
    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    if (classify_cache_age(now, entry->last_checked) == AbuseLookupState::kStale) {
        return std::nullopt;
    }
    return entry->result;
}

AbuseLookupState AbuseCache::classify_cache_age(std::int64_t now,
                                                std::int64_t last_checked) noexcept
{
    const auto age = now - last_checked;
    if (age < kSoftRefreshAgeSecs) {
        return AbuseLookupState::kFresh;
    }
    if (age < kCacheTtlSecs) {
        return AbuseLookupState::kSoftRefreshEligible;
    }
    return AbuseLookupState::kStale;
}

// ── submit() ─────────────────────────────────────────────────────────────────

void AbuseCache::submit(const std::string& ip) noexcept
{
    (void)enqueue_submit_candidate(ip, true);
}

bool AbuseCache::enqueue_submit_candidate(const std::string& ip,
                                          bool               notify_worker) noexcept
{
    if (api_key_.empty() || !db_) { return false; }

    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    const auto entry = lookup_entry(ip);
    const auto state = entry.has_value()
        ? classify_cache_age(now, entry->last_checked)
        : AbuseLookupState::kMissing;

    if (state == AbuseLookupState::kFresh) {
        return false;
    }

    bool queued = false;
    {
        const std::lock_guard<std::mutex> lock{queue_mutex_};
        rate_limit_reset_if_new_day();
        if (rate_remaining_ <= 0) {
            if (!quota_warned_) {
                std::clog << "[WARN] AbuseCache: daily quota reached; "
                             "new submissions suppressed until midnight reset\n";
                quota_warned_ = true;
            }
            return false;
        }
        if (queue_.contains(ip) || in_flight_.contains(ip)) {
            return false;
        }

        if (state == AbuseLookupState::kSoftRefreshEligible) {
            if (soft_refresh_remaining_ <= 0 || soft_queue_.contains(ip)) {
                return false;
            }
            soft_queue_.insert_or_assign(ip, entry->last_checked);
            queued = true;
        } else {
            soft_queue_.erase(ip);
            queued = queue_.insert(ip).second;
        }
    }

    if (queued && notify_worker) {
        queue_cv_.notify_one();
    }
    return queued;
}

// ── cache_store() ────────────────────────────────────────────────────────────

bool AbuseCache::cache_store(const std::string& ip,
                             const AbuseResult& result) noexcept
{
    if (!db_) { return false; }

    const std::lock_guard<std::mutex> lock{db_mutex_};

    sqlite3_stmt* const stmt = upsert_stmt_.get();
    const auto now = static_cast<std::int64_t>(std::time(nullptr));

    (void)sqlite3_bind_text( stmt, 1, ip.c_str(),              -1, kStaticText);
    (void)sqlite3_bind_int(  stmt, 2, result.score);
    (void)sqlite3_bind_text( stmt, 3, result.usage_type.c_str(), -1, kStaticText);
    (void)sqlite3_bind_int64(stmt, 4, now);

    const int rc = sqlite3_step(stmt);
    (void)sqlite3_reset(stmt);

    if (rc != SQLITE_DONE) {
        std::clog << "[WARN] AbuseCache: upsert: "
                  << sqlite3_errmsg(db_.get()) << '\n';
        return false;
    }
    return true;
}

// ── update_connections_abuse() ───────────────────────────────────────────────

void AbuseCache::update_connections_abuse(const std::string& ip,
                                          const AbuseResult& result) noexcept
{
    if (!db_ || !update_conn_stmt_) { return; }

    const std::lock_guard<std::mutex> lock{db_mutex_};

    sqlite3_stmt* const stmt = update_conn_stmt_.get();
    (void)sqlite3_bind_int(  stmt, 1, result.score);
    (void)sqlite3_bind_text( stmt, 2, result.usage_type.c_str(), -1, kStaticText);
    (void)sqlite3_bind_text( stmt, 3, ip.c_str(), -1, kStaticText);

    (void)sqlite3_step(stmt);
    const int patched = sqlite3_changes(db_.get());
    (void)sqlite3_reset(stmt);

    if (patched > 0) {
        std::clog << "[INFO] AbuseCache: patched " << patched
                  << " row(s) for " << ip
                  << " threat=" << result.score
                  << " usage=" << result.usage_type << '\n';
    }
}

// ── rate_remaining() / rate_limit_reset_if_new_day() ─────────────────────────

int AbuseCache::rate_remaining() const noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return rate_remaining_;
}

int AbuseCache::soft_refresh_remaining() const noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return soft_refresh_remaining_;
}

std::optional<int> AbuseCache::confirmed_rate_remaining() const noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return confirmed_rate_remaining_;
}

bool AbuseCache::has_pending_work() const noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return !queue_.empty() || !soft_queue_.empty() || !in_flight_.empty();
}

bool AbuseCache::can_accept_new_lookups() const noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return rate_remaining_ > 0;
}

std::optional<std::int64_t> AbuseCache::quota_retry_after_ts() const noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return quota_retry_after_ts_;
}

void AbuseCache::set_rate_remaining_for_test(int remaining) noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    rate_remaining_ = remaining < 0 ? 0 : remaining;
    confirmed_rate_remaining_ = rate_remaining_;
}

void AbuseCache::set_soft_refresh_remaining_for_test(int remaining) noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    soft_refresh_remaining_ = std::max(0, remaining);
}

bool AbuseCache::set_last_checked_for_test(const std::string& ip,
                                           std::int64_t       last_checked) noexcept
{
    if (!db_) { return false; }

    const std::lock_guard<std::mutex> lock{db_mutex_};
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db_.get(),
                           "UPDATE abuse_cache SET last_checked = ? WHERE ip = ?",
                           -1, &raw, nullptr) != SQLITE_OK) {
        return false;
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};
    (void)sqlite3_bind_int64(stmt.get(), 1, last_checked);
    (void)sqlite3_bind_text(stmt.get(), 2, ip.c_str(), -1, kStaticText);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return false;
    }
    return sqlite3_changes(db_.get()) > 0;
}

AbuseLookupState AbuseCache::lookup_state_for_test(const std::string& ip,
                                                   std::int64_t now) const noexcept
{
    const auto entry = lookup_entry(ip);
    if (!entry.has_value()) {
        return AbuseLookupState::kMissing;
    }
    return classify_cache_age(now, entry->last_checked);
}

bool AbuseCache::enqueue_submit_candidate_for_test(const std::string& ip) noexcept
{
    return enqueue_submit_candidate(ip, false);
}

bool AbuseCache::normal_queue_contains_for_test(const std::string& ip) const noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return queue_.contains(ip);
}

bool AbuseCache::soft_queue_contains_for_test(const std::string& ip) const noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return soft_queue_.contains(ip);
}

bool AbuseCache::in_flight_contains_for_test(const std::string& ip) const noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return in_flight_.contains(ip);
}

std::optional<PendingSelection> AbuseCache::pop_next_pending_for_test() noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return pop_next_pending_locked();
}

void AbuseCache::requeue_pending_for_test(const std::string& ip,
                                          bool               is_soft_refresh,
                                          std::int64_t       soft_last_checked,
                                          std::int64_t       now) noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    requeue_pending_locked(ip, is_soft_refresh, soft_last_checked, now);
}

void AbuseCache::shutdown_worker_for_test() noexcept
{
    {
        const std::lock_guard<std::mutex> lock{queue_mutex_};
        stop_ = true;
    }
    queue_cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void AbuseCache::mark_in_flight_for_test(const std::string& ip) noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    in_flight_.insert(ip);
}

void AbuseCache::arm_quota_retry_for_test(std::int64_t retry_after_ts,
                                          bool post_reset_mode) noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    quota_retry_after_ts_ = retry_after_ts;
    post_reset_retry_mode_ = post_reset_mode;
}

bool AbuseCache::release_quota_retry_probe_if_due_for_test(
    std::int64_t now) noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    return maybe_release_quota_retry_probe(now);
}

std::optional<std::int64_t> AbuseCache::cache_row_count() const noexcept
{
    const std::lock_guard<std::mutex> lock{db_mutex_};
    if (!db_) {
        return std::nullopt;
    }

    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db_.get(), "SELECT COUNT(*) FROM abuse_cache", -1, &raw, nullptr)
            != SQLITE_OK) {
        return std::nullopt;
    }
    const std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw};
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return sqlite3_column_int64(stmt.get(), 0);
}

bool AbuseCache::rate_limit_reset_if_new_day() noexcept
{
    // Caller must hold queue_mutex_.
    const std::int64_t today = epoch_day();
    if (today != rate_reset_day_) {
        rate_remaining_ = kDailyQuota;
        soft_refresh_remaining_ = kSoftRefreshBudgetPerDay;
        confirmed_rate_remaining_.reset();
        quota_retry_after_ts_.reset();
        quota_retry_backoff_secs_ = 60;
        post_reset_retry_mode_ = true;
        rate_reset_day_ = today;
        quota_warned_   = false;  // allow one new warning next quota period
        return true;
    }
    return false;
}

void AbuseCache::rewind_rate_reset_day_for_test() noexcept
{
    const std::lock_guard<std::mutex> lock{queue_mutex_};
    --rate_reset_day_;
}

void AbuseCache::apply_fetch_result_for_test(
    const std::string& ip,
    bool               is_soft_refresh,
    std::int64_t       soft_last_checked,
    bool               request_made,
    bool               quota_exhausted,
    std::optional<int> confirmed_remaining) noexcept
{
    {
        const std::lock_guard<std::mutex> lock{queue_mutex_};
        in_flight_.insert(ip);
    }
    apply_fetch_result(ip, std::nullopt, is_soft_refresh, soft_last_checked,
                       request_made, quota_exhausted, confirmed_remaining);
}

bool AbuseCache::maybe_release_quota_retry_probe(std::int64_t now) noexcept
{
    if (!quota_retry_after_ts_.has_value() || *quota_retry_after_ts_ > now) {
        return false;
    }
    quota_retry_after_ts_.reset();
    if (post_reset_retry_mode_ && rate_remaining_ <= 0) {
        rate_remaining_ = 1;
    }
    return true;
}

std::optional<PendingSelection> AbuseCache::pop_next_pending_locked() noexcept
{
    if (!queue_.empty()) {
        auto it = queue_.begin();
        PendingSelection selection{*it, false, 0};
        queue_.erase(it);
        return selection;
    }
    if (soft_queue_.empty()) {
        return std::nullopt;
    }

    auto best = soft_queue_.begin();
    for (auto it = std::next(soft_queue_.begin()); it != soft_queue_.end(); ++it) {
        if (it->second < best->second ||
            (it->second == best->second && it->first < best->first)) {
            best = it;
        }
    }
    PendingSelection selection{best->first, true, best->second};
    soft_queue_.erase(best);
    return selection;
}

void AbuseCache::requeue_pending_locked(const std::string& ip,
                                        bool               is_soft_refresh,
                                        std::int64_t       soft_last_checked,
                                        std::int64_t       now) noexcept
{
    if (!is_soft_refresh) {
        queue_.insert(ip);
        return;
    }

    if (classify_cache_age(now, soft_last_checked) == AbuseLookupState::kStale) {
        queue_.insert(ip);
        return;
    }

    soft_queue_.insert_or_assign(ip, soft_last_checked);
}

// ── wait_for_quota_reset() ───────────────────────────────────────────────────

void AbuseCache::wait_for_quota_reset(
    std::unique_lock<std::mutex>& lock) noexcept
{
    while (!stop_) {
        const auto now = static_cast<std::int64_t>(std::time(nullptr));
        std::int64_t target_ts = next_utc_midnight_ts(rate_reset_day_);
        if (quota_retry_after_ts_.has_value()) {
            target_ts = *quota_retry_after_ts_;
            if (maybe_release_quota_retry_probe(now)) {
                break;
            }
            std::clog << "[INFO] AbuseCache: quota reset not live yet; retrying in "
                      << (target_ts - now) << "s\n";
        } else {
            std::clog << "[INFO] AbuseCache: daily quota reached; waiting until UTC midnight reset\n";
        }

        const auto wait_for = std::chrono::seconds{
            std::max<std::int64_t>(1, target_ts - now)
        };
        queue_cv_.wait_for(lock, wait_for, [this]() noexcept { return stop_; });
        if (rate_limit_reset_if_new_day()) {
            std::clog << "[INFO] AbuseCache: quota reset; resuming\n";
            break;
        }
    }
}

// ── worker() ────────────────────────────────────────────────────────────────

void AbuseCache::worker() noexcept
{
    for (;;) {
        PendingSelection selection;

        {
            std::unique_lock<std::mutex> lock{queue_mutex_};
            queue_cv_.wait(lock, [this]() noexcept {
                return stop_ || !queue_.empty() || !soft_queue_.empty();
            });

            if (stop_ && queue_.empty() && soft_queue_.empty()) {
                return;
            }

            const auto next = pop_next_pending_locked();
            if (!next.has_value()) {
                continue;
            }
            selection = *next;
            in_flight_.insert(selection.ip);
        }

        // Check and reset daily rate limit.
        {
            std::unique_lock<std::mutex> lock{queue_mutex_};
            rate_limit_reset_if_new_day();
            if (rate_remaining_ <= 0) {
                // Re-queue (if not shutting down) so the IP is processed
                // once quota resets.
                if (!stop_) {
                    requeue_pending_locked(selection.ip, selection.is_soft_refresh,
                                           selection.soft_last_checked,
                                           static_cast<std::int64_t>(std::time(nullptr)));
                }
                in_flight_.erase(selection.ip);

                if (!stop_) {
                    // Wait until the UTC reset, or a short post-midnight probe.
                    wait_for_quota_reset(lock);
                }
                continue;
            }
        }

        // Skip if a cache entry no longer needs this class of refresh.
        const auto entry = lookup_entry(selection.ip);
        const auto now = static_cast<std::int64_t>(std::time(nullptr));
        const auto state = entry.has_value()
            ? classify_cache_age(now, entry->last_checked)
            : AbuseLookupState::kMissing;
        if (state == AbuseLookupState::kFresh) {
            const std::lock_guard<std::mutex> lock{queue_mutex_};
            in_flight_.erase(selection.ip);
            continue;
        }

        // Fetch from AbuseIPDB (network call — no mutex held).
        // request_made is set true only when curl connected and sent the
        // HTTP request; pure network failures don't consume API quota.
        bool request_made    = false;
        bool quota_exhausted = false;
        std::optional<int> confirmed_remaining;
        const auto result = fetch_abuse(selection.ip, request_made, quota_exhausted, confirmed_remaining);
        apply_fetch_result(selection.ip, result, selection.is_soft_refresh, selection.soft_last_checked,
                           request_made, quota_exhausted, confirmed_remaining);
    }
}

// ── apply_fetch_result() ─────────────────────────────────────────────────────

void AbuseCache::apply_fetch_result(const std::string&                ip,
                                    const std::optional<AbuseResult>& result,
                                    bool                               is_soft_refresh,
                                    std::int64_t                       soft_last_checked,
                                    bool                               request_made,
                                    bool                               quota_exhausted,
                                    std::optional<int>                 confirmed_remaining) noexcept
{
    {
        const std::lock_guard<std::mutex> lock{queue_mutex_};
        if (is_soft_refresh && request_made && soft_refresh_remaining_ > 0) {
            --soft_refresh_remaining_;
        }
        if (quota_exhausted) {
            // 429: server confirms quota gone.  Zero counter immediately so
            // the next worker() iteration enters wait_for_quota_reset instead
            // of firing another request.  Re-queue the IP so it is processed
            // once the daily quota resets at midnight.
            rate_remaining_ = 0;
            confirmed_rate_remaining_ = 0;
            if (post_reset_retry_mode_) {
                const auto now = static_cast<std::int64_t>(std::time(nullptr));
                quota_retry_after_ts_ = now + quota_retry_backoff_secs_;
                quota_retry_backoff_secs_ = std::min(quota_retry_backoff_secs_ * 2, 900);
            } else {
                quota_retry_after_ts_.reset();
            }
            if (!stop_) {
                requeue_pending_locked(ip, is_soft_refresh, soft_last_checked,
                                       static_cast<std::int64_t>(std::time(nullptr)));
            }
        } else if (confirmed_remaining.has_value()) {
            rate_remaining_ = *confirmed_remaining;
            confirmed_rate_remaining_ = confirmed_remaining;
            quota_retry_after_ts_.reset();
            quota_retry_backoff_secs_ = 60;
            post_reset_retry_mode_ = false;
        } else if (request_made) {
            --rate_remaining_;
        }
        in_flight_.erase(ip);
    }

    if (result.has_value()) {
        if (cache_store(ip, *result)) {
            update_connections_abuse(ip, *result);
        }
        if (is_soft_refresh) {
            std::clog << "[INFO] AbuseCache: soft refresh " << ip
                      << " budget_left=" << soft_refresh_remaining() << '\n';
        }
    } else if (quota_exhausted) {
        std::clog << "[WARN] AbuseCache: 429 from AbuseIPDB for " << ip
                  << " — quota exhausted; re-queued for midnight reset\n";
    } else if (request_made) {
        std::clog << "[WARN] AbuseCache: fetch failed for " << ip << '\n';
    }
}

// ── fetch_abuse() ────────────────────────────────────────────────────────────

std::optional<AbuseResult> AbuseCache::fetch_abuse(const std::string& ip,
                                                    bool& request_made,    // NOLINT(bugprone-easily-swappable-parameters)
                                                    bool& quota_exhausted,
                                                    std::optional<int>& confirmed_remaining) noexcept
{
    request_made    = false;
    quota_exhausted = false;
    confirmed_remaining.reset();

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
    RateHeaderState headers;

    (void)curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
    (void)curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     raw_headers);
    (void)curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curl_write_cb);
    (void)curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &body);
    (void)curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_header_cb);
    (void)curl_easy_setopt(curl, CURLOPT_HEADERDATA,     &headers);
    (void)curl_easy_setopt(curl, CURLOPT_TIMEOUT,        10L);
    (void)curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    const CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        // Pure network/curl failure — no HTTP request reached AbuseIPDB,
        // so this should not count against the daily quota.
        std::clog << "[WARN] AbuseCache: curl: "
                  << curl_easy_strerror(res) << '\n';
        return std::nullopt;
    }

    // An HTTP response was received; the API call counts against quota
    // regardless of the status code.
    request_made = true;
    confirmed_remaining = headers.remaining;

    long http_code{0};
    (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code == 429) {
        // Daily quota exhausted server-side.  Signal the worker to zero
        // rate_remaining_ immediately so it stops firing requests rather
        // than waiting for our local counter to count down to zero.
        quota_exhausted = true;
        confirmed_remaining = 0;
        return std::nullopt;
    }
    if (http_code != 200) {
        std::clog << "[WARN] AbuseCache: HTTP " << http_code
                  << " for " << ip << '\n';
        return std::nullopt;
    }

    return parse_abuse_response(body);
}

} // namespace msmap

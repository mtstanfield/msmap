# OSINT / AbuseIPDB Enrichment — Implementation Plan

## Goal

Look up each `src_ip` against the AbuseIPDB v2 API (free tier: 1 000 checks/day),
cache results in a new `abuse_cache` SQLite table, and surface the `threat` score
(0–100) in the Leaflet popup and the `/api/connections` JSON response.

API key supplied via `ABUSEIPDB_API_KEY` environment variable.

---

## Architecture

```
Listener thread (hot path)
  parse_log()
    ↓
  geoip.lookup(src_ip)           ← unchanged
    ↓
  abuse.lookup(src_ip)           ← fast: SELECT from abuse_cache table (mutex-guarded)
    returns optional<int>: cached score or nullopt if miss/stale
    ↓
  db.insert(entry, geo, threat)  ← threat = score or nullopt
    ↓
  abuse.submit(src_ip)           ← non-blocking: push to queue, notify CV

Background worker thread (inside AbuseCache)
  wait on condition_variable
    ↓
  pop IP from queue
    ↓
  check rate limit (≤1 000/day, resets at UTC midnight)
    ↓
  lookup(ip) again — may have been cached by a concurrent insert
    skip if fresh
    ↓
  fetch_score(ip) via libcurl HTTPS
    GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90
    Headers: Key: <api_key>, Accept: application/json
    Extract "abuseConfidenceScore" from JSON response body
    ↓
  cache_store(ip, score)         ← INSERT OR REPLACE into abuse_cache
    ↓
  update_connections_threat(ip, score)
    UPDATE connections SET threat=? WHERE src_ip=? AND threat IS NULL
    (backfills rows inserted before the background thread caught up)
```

Key properties:
- Listener is **never blocked** by API calls — all network I/O is on the background thread
- Historical `connections` rows with `threat IS NULL` are backfilled by the UPDATE
- Cache TTL = 24 h. Stale entries trigger a re-fetch (via submit) but until the fetch
  completes the stale value is **not** returned (nullopt), so new rows get NULL threat
  temporarily — acceptable
- Rate limit tracked in-memory; exhausted-quota IPs are left as NULL (logged as WARN)
- `AbuseCache` opened against the same `msmap.db` file via its own `sqlite3*` connection;
  WAL mode (already set by `Database`) handles concurrent access safely

---

## New files

### `src/abuse_cache.h`

```cpp
namespace msmap {

inline constexpr std::int64_t kCacheTtlSecs{24 * 3600};
inline constexpr int          kDailyQuota{1000};

class AbuseCache {
public:
    AbuseCache(const std::string& db_path, std::string api_key) noexcept;
    ~AbuseCache() noexcept;
    AbuseCache(const AbuseCache&)            = delete;
    AbuseCache& operator=(const AbuseCache&) = delete;

    [[nodiscard]] bool             valid()    const noexcept;
    [[nodiscard]] std::optional<int> lookup(const std::string& ip) const noexcept;
    void                           submit(const std::string& ip) noexcept;

    // Exposed for tests:
    bool cache_store(const std::string& ip, int score) noexcept;
    void update_connections_threat(const std::string& ip, int score) noexcept;
    [[nodiscard]] int  rate_remaining() const noexcept;
    [[nodiscard]] bool rate_limit_reset_if_new_day() noexcept;

private:
    bool               open() noexcept;
    void               worker() noexcept;
    std::optional<int> fetch_score(const std::string& ip) noexcept;

    std::string db_path_;
    std::string api_key_;

    mutable std::mutex                           db_mutex_;
    std::unique_ptr<sqlite3,      SqliteCloser>  db_;
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> lookup_stmt_;   // SELECT score,last_checked WHERE ip=?
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> upsert_stmt_;   // INSERT OR REPLACE
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> update_conn_stmt_; // UPDATE connections SET threat=?

    std::mutex                      queue_mutex_;
    std::condition_variable         queue_cv_;
    std::unordered_set<std::string> queue_;       // pending IPs (deduplicates)
    std::unordered_set<std::string> in_flight_;   // currently being fetched
    bool                            stop_{false};
    std::thread                     worker_thread_;

    int          rate_remaining_{kDailyQuota};
    std::int64_t rate_reset_day_{0};  // epoch / 86400
};

} // namespace msmap
```

Includes `db.h` for `SqliteCloser` / `StmtFinalizer` (no circular dependency —
`db.h` does not include `abuse_cache.h`).

### `src/abuse_cache.cpp`

Key implementation details:

- **`open()`**: `sqlite3_open`, `sqlite3_busy_timeout(5000)`, create `abuse_cache`
  table, `sqlite3_prepare_v2` for all three statements.

- **`abuse_cache` table**:
  ```sql
  CREATE TABLE IF NOT EXISTS abuse_cache (
      ip           TEXT    PRIMARY KEY,
      score        INTEGER NOT NULL,
      last_checked INTEGER NOT NULL
  )
  ```

- **`lookup()`**: SELECT under `db_mutex_`; return `score` only if
  `now - last_checked < kCacheTtlSecs`.

- **`submit()`**: early-return if `api_key_` empty; insert into `queue_` under
  `queue_mutex_` only if not already in `queue_` or `in_flight_`; notify CV.

- **`worker()`**: `wait()` on CV; pop IP; rate-limit check (reset if new day);
  call `lookup()` again (may have been cached since submit); call `fetch_score()`;
  decrement `rate_remaining_`; call `cache_store()` + `update_connections_threat()`.

- **`fetch_score()`**: libcurl easy interface, RAII via `unique_ptr<CURL, CurlCloser>`;
  build URL with `ipAddress=<ip>&maxAgeInDays=90`; headers `Key:` + `Accept:`;
  `CURLOPT_TIMEOUT = 10L`; write-callback appends to `std::string`; check HTTP 200;
  hand-roll extract of `"abuseConfidenceScore":` from JSON body using `strtol`.

- **`destructor`**: set `stop_ = true`, notify CV, `join()` if `joinable()`.
  `curl_global_init(CURL_GLOBAL_DEFAULT)` in constructor;
  `curl_global_cleanup()` in destructor.

- **`update_connections_threat()`**: `UPDATE connections SET threat=? WHERE src_ip=? AND threat IS NULL`
  — the `AND threat IS NULL` guard prevents overwriting scores inserted by the
  listener after the background thread already ran.

### `tests/test_abuse_cache.cpp`

No live API calls. Tests cover:

| # | Test | Method |
|---|------|--------|
| 1 | Opens in-memory DB | `valid() == true` |
| 2 | `lookup` on empty cache → nullopt | `lookup("1.2.3.4")` |
| 3 | `cache_store` then `lookup` → score | store 99, lookup 99 |
| 4 | `cache_store` zero score round-trips | store 0, lookup 0 |
| 5 | `kCacheTtlSecs` is 24 h | constant check |
| 6 | `submit` no-op without API key | `rate_remaining` unchanged |
| 7 | `rate_remaining` starts at `kDailyQuota` | check 1000 |
| 8 | `rate_limit_reset_if_new_day` same-day → false | no reset |
| 9 | `update_connections_threat` patches NULL rows | temp file, real DB+AbuseCache |
| 10 | `update_connections_threat` does not overwrite existing score | `WHERE threat IS NULL` |

Tests 9 and 10 use a named `/tmp/test_abuse_<ts>.db` file and clean up with `std::remove`.

---

## Modified files

### `src/db.h`

Two changes only:

1. Add `threat` field to `ConnectionRow` after `asn`:
   ```cpp
   std::string        asn;
   std::optional<int> threat;   // nullopt = not yet enriched
   ```

2. Add `threat` default parameter to `insert()`:
   ```cpp
   bool insert(const LogEntry& entry, const GeoIpResult& geo,
               std::optional<int> threat = std::nullopt) noexcept;
   ```
   Default means all existing call sites compile unchanged.

### `src/db.cpp`

1. **`kInsertSql`**: add `threat` as 17th column + 17th `?` placeholder.
2. **`insert()`**: add bind at position 17 — `sqlite3_bind_int` or `sqlite3_bind_null`
   depending on `threat.has_value()`.
3. **SELECT** in `query_connections`: add `threat` to column list.
4. **Row reading**: read `threat` as col 17 using `col_opt_int`.
5. **`test_db.cpp`**: add one test case that round-trips a non-null threat via
   `insert(..., std::optional<int>{42})` and checks `query_connections` returns 42.

### `src/http.cpp`

In `connections_to_json()`: make `asn` the second-to-last field (add comma after),
add `threat` as the last field:

```cpp
out += "\"asn\":";    json::append_string_or_null(out, row.asn);  out += ',';
out += "\"threat\":"; json::append_int_or_null(out, row.threat);
out += '}';
```

### `src/listener.h` / `src/listener.cpp`

`listener.h`: forward-declare `AbuseCache`; change signature to:
```cpp
void run_listener(int port, Database& db, GeoIp& geoip, AbuseCache* abuse);
```
`AbuseCache*` (nullable pointer, not reference) — expresses "optional dependency"
cleanly; caller passes `nullptr` if no API key.

`listener.cpp`: after `geoip.lookup()`, add:
```cpp
const std::optional<int> threat =
    (abuse != nullptr) ? abuse->lookup(result.entry.src_ip) : std::nullopt;
(void)db.insert(result.entry, geo, threat);
if (abuse != nullptr) { abuse->submit(result.entry.src_ip); }
```

### `src/main.cpp`

```cpp
const std::string abuse_key = env_or("ABUSEIPDB_API_KEY", "");
msmap::AbuseCache abuse{kDbPath, abuse_key};
if (!abuse.valid()) {
    std::clog << "[WARN] AbuseCache failed to open; threat scores disabled\n";
}
msmap::AbuseCache* const abuse_ptr = abuse.valid() ? &abuse : nullptr;
// ...
msmap::run_listener(kListenPort, db, geoip, abuse_ptr);
```

Destruction order on stack unwind is safe: `abuse` outlives the call to
`run_listener`; its destructor stops the background thread before `db` closes.

### `CMakeLists.txt`

1. Add `pkg_check_modules(LIBCURL REQUIRED IMPORTED_TARGET libcurl)` (static variant
   when `MSMAP_LINK_STATIC=ON`).
2. Add `src/abuse_cache.cpp` to `msmap` sources.
3. Add `PkgConfig::LIBCURL` to `target_link_libraries(msmap ...)`.
4. Add `test_abuse_cache` target (sources: `tests/test_abuse_cache.cpp`,
   `src/abuse_cache.cpp`, `src/db.cpp`, `src/geoip.cpp`, `src/parser.cpp`).

### `Dockerfile`

In the dev-stage `apt-get install` block, add:
```
        libcurl4-openssl-dev \
        libssl-dev \
```
(`libssl-dev` is needed for static linking of libcurl against OpenSSL.)

### `web/app.js`

1. Add `threatClass(score)` helper → CSS class name (`threat-clean`, `threat-low`,
   `threat-medium`, `threat-high`, `threat-unknown`).
2. Add `threatLabel(score)` helper → display string (`"clean (0)"`, `"score 75"`, etc.).
3. In `buildPopup()`, add after the `r.asn` row:
   ```javascript
   (r.threat !== null && r.threat !== undefined)
       ? '<span class="label">threat </span>'
         + '<span class="' + threatClass(r.threat) + '">'
         + threatLabel(r.threat) + '</span><br>'
       : '',
   ```
4. Adjust marker colour: high-threat IPs (score ≥ 67) override protocol colour
   with `#f85149` (red). Replaces the single `PROTO_COLORS[r.proto]` lookup.

### `web/app.css`

Add threat CSS classes using the existing GitHub dark palette:
```css
.threat-unknown { color: #8b949e; }
.threat-clean   { color: #3fb950; font-weight: 600; }
.threat-low     { color: #d29922; font-weight: 600; }
.threat-medium  { color: #f0883e; font-weight: 600; }
.threat-high    { color: #f85149; font-weight: 600; }
```

---

## Implementation order (keeps build green at every step)

| Step | Files | Gate |
|------|-------|------|
| 1 | `db.h`, `db.cpp`, `tests/test_db.cpp` | `threat` field + INSERT/SELECT; 48 tests |
| 2 | `http.cpp` | Add `threat` to JSON; build + tests |
| 3 | `Dockerfile` rebuild | Add `libcurl4-openssl-dev`; verify `docker build` |
| 4 | `CMakeLists.txt` | Add libcurl; re-cmake; build (msmap, no abuse_cache yet) |
| 5 | `abuse_cache.h`, `abuse_cache.cpp` | Full implementation; add to CMakeLists |
| 6 | `tests/test_abuse_cache.cpp` | 10 tests; all pass |
| 7 | `listener.h`, `listener.cpp` | Wire in lookup/submit |
| 8 | `main.cpp` | Construct AbuseCache from env var |
| 9 | `web/app.js`, `web/app.css` | Popup + marker colour; rebuild bundle |
| 10 | Full quality gates | `ninja test` (58+ tests), clang-tidy, cppcheck |
| 11 | `PLAN.md` tick + commit | "Add AbuseIPDB OSINT enrichment" |

---

## Open design notes

- **No TTL-expired backfill**: when `lookup()` finds a stale entry it returns
  `nullopt` and `submit()` re-queues the IP. Until the background thread completes
  the refresh, new rows for that IP get `threat=NULL`. This is intentional and
  honest — it avoids serving stale risk data.

- **`update_connections_threat` scope**: only rows with `threat IS NULL` are
  backfilled. This is safe against partial-insert races (listener inserts row with
  NULL → background thread fires UPDATE → listener inserts another row for same IP
  with the now-cached score). The second row gets the score from the cache at insert
  time; the first row gets it from the UPDATE.

- **curl_global_init**: called once in the `AbuseCache` constructor; cleaned up
  in destructor. This is fine for a single-instance binary. If multiple `AbuseCache`
  objects were created (not our use case), a global init counter would be needed.

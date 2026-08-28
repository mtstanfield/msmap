# Self-Hosted Basemap (PMTiles) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the CARTO raster basemap (now watermarked "API KEY REQUIRED") with a self-hosted Protomaps PMTiles extract served by msmap's own HTTP server.

**Architecture:** msmap serves the raw `.pmtiles` archive at `GET /basemap.pmtiles` with HTTP Range support (libmicrohttpd fd-backed responses). The vendored `protomaps-leaflet` library (which bundles the PMTiles reader) renders vector tiles client-side on canvas with its built-in `dark` theme. A one-time script produces the z0–6 extract; msmap refuses to start without a valid archive.

**Tech Stack:** C++23 / libmicrohttpd / Catch2 / libFuzzer; Leaflet 1.9.4 + protomaps-leaflet 4.0.1 (vendored); bash + go-pmtiles CLI for the extract.

**Spec:** `docs/superpowers/specs/2026-08-28-self-hosted-basemap-design.md`

**Spec deviation (agreed rationale):** the spec suggested a checked-in binary fixture in `tests/fixtures/`; the validator only inspects the first 8 bytes, so tests generate tiny temp files at runtime instead — hermetic, and no binary blobs in git.

## Global Constraints

- ALL build/test/analysis commands run inside Docker: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev <cmd>`. Never run build tools on the Windows host. (Adjust the mount path if executing from a worktree.)
- `git` runs on the host (Windows), from the repo root, on branch `feature/self-hosted-basemap`.
- C++23, `-Wall -Wextra -Wpedantic -Werror` — zero warnings.
- clang-tidy (`run-clang-tidy-18 -p build '/workspace/src/.*'`) and cppcheck must be clean before every commit.
- Tests are Catch2 v3.7.1 (FetchContent). Frontend: no CDN, no npm; vendored files only.
- Hand-written linear parsing, no regex.
- Commit messages: imperative, no prefix (match `git log`), with trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- If the build directory is not configured yet, configure once first:
  `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_STANDARD=23 -DCMAKE_CXX_EXTENSIONS=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`

---

### Task 1: Range-header parser (`src/basemap.h/.cpp`)

**Files:**
- Create: `src/basemap.h`
- Create: `src/basemap.cpp`
- Create: `tests/test_basemap.cpp`
- Modify: `CMakeLists.txt` (new `test_basemap` target; add `src/basemap.cpp` to the `msmap` executable's source list)

**Interfaces:**
- Consumes: nothing (leaf unit).
- Produces (used by Tasks 2–4):
  - `msmap::RangeSpec { bool valid; std::uint64_t offset; std::uint64_t length; }`
  - `msmap::RangeSpec msmap::parse_range_header(std::string_view value, std::uint64_t file_size) noexcept`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_basemap.cpp`:

```cpp
#include "basemap.h"

#include <catch2/catch_test_macros.hpp>

// ── parse_range_header ────────────────────────────────────────────────────────

TEST_CASE("range: closed range a-b", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=100-199", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 100);
    REQUIRE(r.length == 100);
}

TEST_CASE("range: single first byte", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=0-0", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 0);
    REQUIRE(r.length == 1);
}

TEST_CASE("range: open-ended a- runs to EOF", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=100-", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 100);
    REQUIRE(r.length == 900);
}

TEST_CASE("range: suffix -n takes last n bytes", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=-200", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 800);
    REQUIRE(r.length == 200);
}

TEST_CASE("range: suffix larger than file clamps to whole file", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=-5000", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 0);
    REQUIRE(r.length == 1000);
}

TEST_CASE("range: end past EOF is clamped", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=900-1999", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 900);
    REQUIRE(r.length == 100);
}

TEST_CASE("range: start at or past EOF is invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("bytes=1000-", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=5000-5999", 1000).valid);
}

TEST_CASE("range: reversed bounds are invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("bytes=200-100", 1000).valid);
}

TEST_CASE("range: multipart is invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("bytes=0-1,5-9", 1000).valid);
}

TEST_CASE("range: non-bytes unit is invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("items=0-1", 1000).valid);
}

TEST_CASE("range: malformed values are invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=-", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=abc-def", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=1x-5", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes= 0-1", 1000).valid);
}

TEST_CASE("range: uint64 overflow is invalid", "[range]")
{
    REQUIRE_FALSE(
        msmap::parse_range_header("bytes=99999999999999999999-", 1000).valid);
}

TEST_CASE("range: zero-size file rejects all ranges", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("bytes=0-0", 0).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=-1", 0).valid);
}

TEST_CASE("range: suffix of zero bytes is invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("bytes=-0", 1000).valid);
}
```

Create `src/basemap.h` with only the parser declared (Task 2 adds the rest):

```cpp
#pragma once

#include <cstdint>
#include <string_view>

namespace msmap {

/// Result of parsing an HTTP `Range` header against a known file size.
/// When `valid` is false the request must be answered with 416.
struct RangeSpec {
    bool          valid;
    std::uint64_t offset;  ///< first byte to serve
    std::uint64_t length;  ///< number of bytes to serve
};

/// Parse a single-range `Range` header value (`bytes=a-b`, `bytes=a-`,
/// `bytes=-n`). Multipart ranges and any malformed input yield valid=false.
/// A range whose end lies past EOF is clamped to `file_size`.
[[nodiscard]] RangeSpec parse_range_header(std::string_view value,
                                           std::uint64_t    file_size) noexcept;

} // namespace msmap
```

Create `src/basemap.cpp` with an empty stub so the test target links and the
suite genuinely fails on assertions (not on a missing symbol):

```cpp
#include "basemap.h"

namespace msmap {

RangeSpec parse_range_header(std::string_view /*value*/,
                             std::uint64_t /*file_size*/) noexcept
{
    return {.valid = false, .offset = 0, .length = 0};
}

} // namespace msmap
```

Register the test target in `CMakeLists.txt` after the `test_http` block
(mirror the existing pattern exactly):

```cmake
    add_executable(test_basemap
        tests/test_basemap.cpp
        src/basemap.cpp)

    target_compile_features(test_basemap PRIVATE cxx_std_23)
    msmap_apply_cpu_target(test_basemap)
    target_include_directories(test_basemap PRIVATE src)
    msmap_set_warnings(test_basemap)
    msmap_enable_sanitizers(test_basemap)
    target_link_libraries(test_basemap PRIVATE Catch2::Catch2WithMain)

    catch_discover_tests(test_basemap)
```

Also add `src/basemap.cpp` to the `add_executable(msmap ...)` source list
(after `src/http.cpp`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build test_basemap && ./build/test_basemap"`
Expected: builds, then FAILS — every positive test case asserts (`r.valid` is false); the invalid-input cases pass. That's the correct red state.

- [ ] **Step 3: Write the implementation**

Replace the body of `src/basemap.cpp`:

```cpp
#include "basemap.h"

#include <algorithm>
#include <limits>
#include <optional>

namespace {

/// Consume a decimal uint64 from the front of `sv`, advancing it.
/// Returns nullopt when the front is not a digit or the value overflows.
std::optional<std::uint64_t> take_uint(std::string_view& sv) noexcept
{
    if (sv.empty() || sv.front() < '0' || sv.front() > '9') {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    std::size_t   i     = 0;
    while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') {
        const auto digit = static_cast<std::uint64_t>(sv[i] - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10ULL) {
            return std::nullopt;
        }
        value = value * 10ULL + digit;
        ++i;
    }
    sv.remove_prefix(i);
    return value;
}

constexpr msmap::RangeSpec kInvalid{.valid = false, .offset = 0, .length = 0};

} // namespace

namespace msmap {

RangeSpec parse_range_header(std::string_view value,
                             std::uint64_t    file_size) noexcept
{
    constexpr std::string_view k_prefix{"bytes="};
    if (file_size == 0 || !value.starts_with(k_prefix)) {
        return kInvalid;
    }
    value.remove_prefix(k_prefix.size());

    if (value.starts_with('-')) {
        // Suffix form: bytes=-n → the last n bytes.
        value.remove_prefix(1);
        const auto n = take_uint(value);
        if (!n.has_value() || *n == 0 || !value.empty()) {
            return kInvalid;
        }
        const std::uint64_t len = std::min(*n, file_size);
        return {.valid = true, .offset = file_size - len, .length = len};
    }

    const auto first = take_uint(value);
    if (!first.has_value() || !value.starts_with('-')) {
        return kInvalid;
    }
    value.remove_prefix(1);

    if (*first >= file_size) {
        return kInvalid;
    }

    if (value.empty()) {
        // Open-ended form: bytes=a- → a through EOF.
        return {.valid = true, .offset = *first, .length = file_size - *first};
    }

    const auto last = take_uint(value);
    if (!last.has_value() || !value.empty() || *last < *first) {
        return kInvalid;
    }
    const std::uint64_t end = std::min(*last, file_size - 1);
    return {.valid = true, .offset = *first, .length = end - *first + 1};
}

} // namespace msmap
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build test_basemap && ./build/test_basemap"`
Expected: All test cases PASS.

- [ ] **Step 5: Run static analysis**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build msmap && run-clang-tidy-18 -p build '/workspace/src/basemap.*' && cppcheck --enable=style,performance,warning,portability --error-exitcode=1 src/basemap.cpp src/basemap.h"`
Expected: clean build, zero findings.

- [ ] **Step 6: Commit**

```bash
git add src/basemap.h src/basemap.cpp tests/test_basemap.cpp CMakeLists.txt
git commit -m "Add HTTP Range header parser for basemap serving"
```
(with the Co-Authored-By trailer per Global Constraints)

---

### Task 2: PMTiles archive validation (`load_basemap_info`)

**Files:**
- Modify: `src/basemap.h`
- Modify: `src/basemap.cpp`
- Modify: `tests/test_basemap.cpp`

**Interfaces:**
- Consumes: nothing new.
- Produces (used by Tasks 3–4):
  - `msmap::BasemapInfo { std::string path; std::uint64_t size; std::string etag; }`
  - `std::optional<msmap::BasemapInfo> msmap::load_basemap_info(const std::string& path)`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_basemap.cpp` (add the new includes at the top of the file):

```cpp
#include <filesystem>
#include <fstream>
#include <string>
```

```cpp
// ── load_basemap_info ─────────────────────────────────────────────────────────

namespace {

/// Write `bytes` to a uniquely named temp file and return its path.
std::filesystem::path write_temp(const std::string& name, std::string_view bytes)
{
    const auto p = std::filesystem::temp_directory_path() / name;
    std::ofstream out{p, std::ios::binary | std::ios::trunc};
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return p;
}

constexpr std::string_view kMagic{"PMTiles\x03", 8};

} // namespace

TEST_CASE("basemap: valid v3 magic yields info with size and quoted etag", "[basemap]")
{
    std::string content{kMagic};
    content += "trailing archive bytes";
    const auto p    = write_temp("msmap_test_valid.pmtiles", content);
    const auto info = msmap::load_basemap_info(p.string());
    REQUIRE(info.has_value());
    REQUIRE(info->path == p.string());
    REQUIRE(info->size == content.size());
    REQUIRE(info->etag.size() >= 3);
    REQUIRE(info->etag.front() == '"');
    REQUIRE(info->etag.back() == '"');
    std::filesystem::remove(p);
}

TEST_CASE("basemap: wrong magic is rejected", "[basemap]")
{
    const auto p = write_temp("msmap_test_badmagic.pmtiles",
                              "NOTTILES this is not a pmtiles archive");
    REQUIRE_FALSE(msmap::load_basemap_info(p.string()).has_value());
    std::filesystem::remove(p);
}

TEST_CASE("basemap: wrong version byte is rejected", "[basemap]")
{
    const auto p = write_temp("msmap_test_badver.pmtiles",
                              std::string_view{"PMTiles\x02........", 16});
    REQUIRE_FALSE(msmap::load_basemap_info(p.string()).has_value());
    std::filesystem::remove(p);
}

TEST_CASE("basemap: truncated file is rejected", "[basemap]")
{
    const auto p = write_temp("msmap_test_trunc.pmtiles", "PM");
    REQUIRE_FALSE(msmap::load_basemap_info(p.string()).has_value());
    std::filesystem::remove(p);
}

TEST_CASE("basemap: missing file is rejected", "[basemap]")
{
    REQUIRE_FALSE(
        msmap::load_basemap_info("/nonexistent/msmap_no_such.pmtiles").has_value());
}

TEST_CASE("basemap: etag changes when file size changes", "[basemap]")
{
    std::string content{kMagic};
    const auto p  = write_temp("msmap_test_etag.pmtiles", content);
    const auto a  = msmap::load_basemap_info(p.string());
    content += "more bytes";
    (void)write_temp("msmap_test_etag.pmtiles", content);
    const auto b  = msmap::load_basemap_info(p.string());
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(a->etag != b->etag);
    std::filesystem::remove(p);
}
```

Append to `src/basemap.h` (inside `namespace msmap`, after `parse_range_header`;
add `#include <optional>` and `#include <string>` to the header's includes):

```cpp
/// Metadata for the basemap archive served at /basemap.pmtiles,
/// captured once at startup.
struct BasemapInfo {
    std::string   path;
    std::uint64_t size;
    std::string   etag;  ///< derived from size + mtime; includes quotes
};

/// Open and sanity-check the PMTiles archive at `path` (readable, PMTiles v3
/// magic). Returns std::nullopt when the file is missing, unreadable,
/// truncated, or not a v3 archive.
[[nodiscard]] std::optional<BasemapInfo> load_basemap_info(const std::string& path);
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build test_basemap 2>&1 | tail -20"`
Expected: FAILS to compile — `load_basemap_info` declared but not defined (link error) or not declared if header edit missed. Red state confirmed.

- [ ] **Step 3: Write the implementation**

Append to `src/basemap.cpp` (add includes `<array>`, `<chrono>`, `<filesystem>`, `<fstream>` at the top):

```cpp
std::optional<BasemapInfo> load_basemap_info(const std::string& path)
{
    std::error_code ec;
    const std::uint64_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::nullopt;
    }

    std::ifstream in{path, std::ios::binary};
    std::array<char, 8> header{};
    if (!in.read(header.data(), header.size())) {
        return std::nullopt;
    }
    constexpr std::string_view k_magic{"PMTiles\x03", 8};
    if (std::string_view{header.data(), header.size()} != k_magic) {
        return std::nullopt;
    }

    const auto mtime = std::filesystem::last_write_time(path, ec);
    if (ec) {
        return std::nullopt;
    }
    const auto mtime_s = std::chrono::duration_cast<std::chrono::seconds>(
                             mtime.time_since_epoch())
                             .count();
    return BasemapInfo{
        .path = path,
        .size = size,
        .etag = "\"" + std::to_string(size) + "-" + std::to_string(mtime_s) + "\"",
    };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build test_basemap && ./build/test_basemap"`
Expected: All PASS (both `[range]` and `[basemap]` tags).

- [ ] **Step 5: Run static analysis**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build msmap && run-clang-tidy-18 -p build '/workspace/src/basemap.*' && cppcheck --enable=style,performance,warning,portability --error-exitcode=1 src/basemap.cpp src/basemap.h"`
Expected: zero findings.

- [ ] **Step 6: Commit**

```bash
git add src/basemap.h src/basemap.cpp tests/test_basemap.cpp
git commit -m "Add PMTiles archive validation with size+mtime ETag"
```

---

### Task 3: libFuzzer target for the Range parser

**Files:**
- Create: `src/fuzz_range.cpp`
- Modify: `CMakeLists.txt` (new `fuzz_range` target next to `fuzz_parser`)

**Interfaces:**
- Consumes: `msmap::parse_range_header` from Task 1.
- Produces: nothing (leaf).

- [ ] **Step 1: Write the fuzz target**

Create `src/fuzz_range.cpp` (mirror the structure of `src/fuzz_parser.cpp` — read it first and match its header-comment style):

```cpp
#include "basemap.h"

#include <cstdint>
#include <cstring>
#include <string_view>

/// libFuzzer entry point: first 8 bytes are the file size, the rest is the
/// Range header value. The parser must never crash, overflow, or return a
/// range that reaches past EOF.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size < 8) {
        return 0;
    }
    std::uint64_t file_size = 0;
    std::memcpy(&file_size, data, sizeof(file_size));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const std::string_view header{reinterpret_cast<const char*>(data + 8),
                                  size - 8};
    const msmap::RangeSpec spec = msmap::parse_range_header(header, file_size);
    if (spec.valid) {
        // Invariants the HTTP layer relies on.
        if (spec.length == 0 || spec.offset >= file_size ||
            file_size - spec.offset < spec.length) {
            __builtin_trap();
        }
    }
    return 0;
}
```

Add to `CMakeLists.txt` directly after the `fuzz_parser` block, same style:

```cmake
  # libFuzzer Range-header fuzz
  add_executable(fuzz_range src/fuzz_range.cpp src/basemap.cpp)
  target_compile_features(fuzz_range PRIVATE cxx_std_23)
  msmap_apply_cpu_target(fuzz_range)
  target_include_directories(fuzz_range PRIVATE src)
  msmap_set_warnings(fuzz_range)
  msmap_enable_sanitizers(fuzz_range)
  target_compile_options(fuzz_range PRIVATE -fsanitize=fuzzer)
  target_link_options(fuzz_range PRIVATE -fsanitize=fuzzer)
```

- [ ] **Step 2: Build and run a short fuzz session**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build fuzz_range && ./build/fuzz_range -max_total_time=60 -print_final_stats=1"`
Expected: builds clean; 60-second run ends with `Done` and **zero crashes**. If it crashes, STOP — that is a real parser bug; return to Task 1's implementation with the crashing input.

- [ ] **Step 3: Commit**

```bash
git add src/fuzz_range.cpp CMakeLists.txt
git commit -m "Add libFuzzer target for Range header parser"
```

---

### Task 4: Serve /basemap.pmtiles and refuse to start without it

**Files:**
- Modify: `src/http.h` (forward-declare `BasemapInfo`, add ctx field + ctor param, endpoint doc)
- Modify: `src/http.cpp` (route + `serve_basemap`)
- Modify: `src/main.cpp` (env var, startup validation, wiring)

**Interfaces:**
- Consumes: `msmap::BasemapInfo`, `msmap::parse_range_header`, `msmap::load_basemap_info` (Tasks 1–2).
- Produces: `GET /basemap.pmtiles` (200/206/304/416); `HttpServer` ctor gains `const BasemapInfo* basemap` parameter inserted **after** `status_cache` and before `abuse_enabled`; `HandlerCtx` gains `const BasemapInfo* basemap;` after `status_cache`.

- [ ] **Step 1: Extend `src/http.h`**

Inside `namespace msmap`, next to the existing forward declarations, add:

```cpp
struct BasemapInfo;
```

In `HandlerCtx`, after the `status_cache` member add:

```cpp
    const BasemapInfo*   basemap;        // null only in tests; main requires it
```

In the endpoint doc comment add the line:

```cpp
///   GET /basemap.pmtiles   — PMTiles basemap archive (supports Range requests)
```

In the constructor, after the `status_cache` parameter add:

```cpp
               const BasemapInfo*  basemap,
```

- [ ] **Step 2: Implement the route in `src/http.cpp`**

Add includes near the top with the other includes:

```cpp
#include "basemap.h"

#include <fcntl.h>
#include <unistd.h>
```

Add `serve_basemap` in the anonymous namespace after `send_response`:

```cpp
/// Serve the PMTiles archive with single-range support. The fd-backed MHD
/// response streams from disk; MHD takes ownership of the fd and closes it
/// when the response is destroyed.
MHD_Result serve_basemap(MHD_Connection* conn, const msmap::BasemapInfo& info)
{
    if (client_has_etag(conn, info.etag)) {
        return send_response(conn, MHD_HTTP_NOT_MODIFIED,
                             "application/octet-stream", {},
                             "public, max-age=86400", info.etag);
    }

    const char* range_hdr =
        MHD_lookup_connection_value(conn, MHD_HEADER_KIND, MHD_HTTP_HEADER_RANGE);

    std::uint64_t offset = 0;
    std::uint64_t length = info.size;
    unsigned int  status = MHD_HTTP_OK;
    if (range_hdr != nullptr) {
        const msmap::RangeSpec spec =
            msmap::parse_range_header(range_hdr, info.size);
        if (!spec.valid) {
            const std::string unsat = "bytes */" + std::to_string(info.size);
            MHD_Response* const resp = MHD_create_response_from_buffer(
                0, nullptr, MHD_RESPMEM_PERSISTENT);
            if (resp == nullptr) {
                return MHD_NO;
            }
            (void)MHD_add_response_header(resp, "Content-Range", unsat.c_str());
            (void)MHD_add_response_header(resp, "Accept-Ranges", "bytes");
            const MHD_Result ret = MHD_queue_response(
                conn, MHD_HTTP_RANGE_NOT_SATISFIABLE, resp);
            MHD_destroy_response(resp);
            return ret;
        }
        offset = spec.offset;
        length = spec.length;
        status = MHD_HTTP_PARTIAL_CONTENT;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg) — POSIX open is variadic
    const int fd = open(info.path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return send_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                             "text/plain", "basemap unavailable");
    }

    MHD_Response* const resp =
        MHD_create_response_from_fd_at_offset64(length, fd, offset);
    if (resp == nullptr) {
        (void)close(fd);
        return MHD_NO;
    }
    (void)MHD_add_response_header(resp, "Content-Type", "application/octet-stream");
    (void)MHD_add_response_header(resp, "Accept-Ranges", "bytes");
    (void)MHD_add_response_header(resp, "Cache-Control", "public, max-age=86400");
    (void)MHD_add_response_header(resp, "ETag", info.etag.c_str());
    (void)MHD_add_response_header(resp, "X-Content-Type-Options", "nosniff");
    if (status == MHD_HTTP_PARTIAL_CONTENT) {
        const std::string content_range =
            "bytes " + std::to_string(offset) + "-" +
            std::to_string(offset + length - 1) + "/" + std::to_string(info.size);
        (void)MHD_add_response_header(resp, "Content-Range", content_range.c_str());
    }
    const MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}
```

Add the route in `handle_request` directly before the `"/"` route:

```cpp
    if (url_sv == "/basemap.pmtiles") {
        if (ctx->basemap == nullptr) {
            return send_response(conn, MHD_HTTP_NOT_FOUND,
                                 "text/plain", "Not Found");
        }
        return serve_basemap(conn, *ctx->basemap);
    }
```

Update the `HttpServer` constructor definition in `http.cpp`: add the
`const BasemapInfo* basemap` parameter in the same position as the header, and
initialize the new `basemap` field of `ctx_` from it (match how
`status_cache` is initialized).

- [ ] **Step 3: Wire up `src/main.cpp`**

Add with the other defaults:

```cpp
constexpr const char* kDefaultBasemapPmtiles{"/var/lib/msmap/basemap/basemap.pmtiles"};
```

Add with the other env reads:

```cpp
    const std::string basemap_path =
        env_or("MSMAP_BASEMAP_PMTILES", kDefaultBasemapPmtiles);
```

Add to the `[INFO]` log block:

```cpp
              << "[INFO] basemap   : " << basemap_path << '\n'
```

After the database open/validation block and **before** the GeoIP block, add:

```cpp
    // Basemap archive is required: the map is unusable without tiles, and a
    // silent blank map would hide an ops mistake. Fail fast with remediation.
    const std::optional<msmap::BasemapInfo> basemap =
        msmap::load_basemap_info(basemap_path);
    if (!basemap.has_value()) {
        std::clog << "[FATAL] basemap PMTiles missing or invalid: " << basemap_path
                  << "\n        run scripts/fetch_basemap.sh to create it, then "
                     "mount it or set MSMAP_BASEMAP_PMTILES\n";
        return EXIT_FAILURE;
    }
```

Add `#include "basemap.h"` and `#include <optional>` to main.cpp's includes if
not already present. Pass `&*basemap` to the `HttpServer` constructor in the
new parameter position (after `&status_cache`).

- [ ] **Step 4: Build and verify both startup branches**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build msmap && cd /tmp && printf 'PMTiles\x03pad' > ok.pmtiles && (MSMAP_DB_PATH=/tmp/t1.db MSMAP_BASEMAP_PMTILES=/tmp/missing.pmtiles /workspace/build/msmap; echo exit=\$?) && (MSMAP_DB_PATH=/tmp/t2.db MSMAP_BASEMAP_PMTILES=/tmp/ok.pmtiles /workspace/build/msmap; echo exit=\$?)"` (the `\$?` stays escaped so the container shell, not the host shell, expands it)
Expected: first run prints `[FATAL] basemap PMTiles missing or invalid` and `exit=1` (proves refuse-to-start). Second run gets **past** the basemap check and instead fails on the GeoIP check (`[FATAL] GeoIP City database unavailable`, `exit=1`) — proving a valid archive is accepted. (End-to-end 200/206 responses are exercised in Task 8's smoke test where real mmdb/pmtiles files are mounted.)

- [ ] **Step 5: Run tests and static analysis**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build && ninja -C build test && run-clang-tidy-18 -p build '/workspace/src/.*' && cppcheck --enable=style,performance,warning,portability --error-exitcode=1 src/"`
Expected: everything green, zero findings.

- [ ] **Step 6: Commit**

```bash
git add src/http.h src/http.cpp src/main.cpp
git commit -m "Serve basemap PMTiles with Range support; require it at startup"
```

---

### Task 5: Vendor protomaps-leaflet and plumb it through the bundle

**Files:**
- Create: `web/vendor/protomaps-leaflet.js`
- Modify: `web/index.html:212` (new script token after `{{LEAFLET_JS}}`)
- Modify: `web/bundle.py` (`_PLACEHOLDERS` entry)
- Modify: `CMakeLists.txt` (web bundle `DEPENDS` entry)

**Interfaces:**
- Consumes: nothing.
- Produces: global `protomapsL` (IIFE) available to `state.js`; `protomapsL.leafletLayer(options)` accepts `url` (a `.pmtiles` path — the PMTiles reader is bundled in this dist), `theme` (`'dark'`), `maxDataZoom`, plus Leaflet GridLayer options (`attribution`, `noWrap`, `bounds`).

- [ ] **Step 1: Download and verify the exact pinned dist**

```bash
curl -fsSL -o web/vendor/protomaps-leaflet.js "https://unpkg.com/protomaps-leaflet@4.0.1/dist/protomaps-leaflet.js"
```

Then verify integrity (Git Bash on host):

```bash
sha256sum web/vendor/protomaps-leaflet.js
```

Expected hash (verified 2026-08-28): `8e3d2aa0f5a2fd46871ff9c6ed47fdcdb969bc6ed10bf6719dee507b46a2ec9e`. If it differs, STOP — do not commit an unverified file.

Also confirm the raw-string delimiter is absent (bundle.py would reject it):

```bash
grep -c MSMAP_HTML_END web/vendor/protomaps-leaflet.js
```

Expected: `0`.

- [ ] **Step 2: Add the bundle token**

`web/index.html` — after the line `<script>{{LEAFLET_JS}}</script>` (line 212) insert:

```html
    <script>{{PROTOMAPS_LEAFLET_JS}}</script>
```

`web/bundle.py` — in `_PLACEHOLDERS`, after the `{{LEAFLET_JS}}` entry insert:

```python
    ('{{PROTOMAPS_LEAFLET_JS}}',    'vendor/protomaps-leaflet.js'),
```

`CMakeLists.txt` — in the web-bundle `add_custom_command` `DEPENDS` list, after
`"${WEB_DIR}/vendor/leaflet.min.js"` insert:

```cmake
        "${WEB_DIR}/vendor/protomaps-leaflet.js"
```

- [ ] **Step 3: Verify the bundle builds and embeds the library**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build msmap && grep -c protomapsL build/index_html.h"`
Expected: clean build; grep count ≥ 1.

- [ ] **Step 4: Commit**

```bash
git add web/vendor/protomaps-leaflet.js web/index.html web/bundle.py CMakeLists.txt
git commit -m "Vendor protomaps-leaflet 4.0.1 and embed it in the web bundle"
```

---

### Task 6: Swap the map layer to the self-hosted basemap

**Files:**
- Modify: `web/state.js:146-168`
- Modify: `web/global.d.ts` (declare `protomapsL`)

**Interfaces:**
- Consumes: `protomapsL.leafletLayer` (Task 5); `GET /basemap.pmtiles` (Task 4).
- Produces: `lmap` unchanged for all downstream consumers (`cluster`, arcs, popups) — only the base layer and zoom cap change.

- [ ] **Step 1: Replace the tile layer**

In `web/state.js`, add `maxZoom` to the map options — the `L.map` call becomes:

```js
const lmap = L.map('map', {
    center:             [20, 0],
    zoom:               2,
    minZoom:            2,
    maxZoom:            9,
    maxBounds:          [[-90, -180], [90, 180]],
    maxBoundsViscosity: 1.0,
});
```

Replace the entire `L.tileLayer(...).addTo(lmap);` block (the CARTO layer) with:

```js
// Self-hosted Protomaps basemap: z0–6 vector data served by msmap itself
// (/basemap.pmtiles, Range requests). z7–9 render overzoomed z6 geometry.
protomapsL.leafletLayer({
    url:         '/basemap.pmtiles',
    theme:       'dark',
    maxDataZoom: 6,
    attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>' +
        ' contributors &copy; <a href="https://protomaps.com">Protomaps</a>',
    noWrap:      true,
    bounds:      [[-90, -180], [90, 180]],
}).addTo(lmap);
```

- [ ] **Step 2: Declare the global for type tooling**

In `web/global.d.ts`, add alongside the existing ambient declarations (match the file's style):

```ts
declare const protomapsL: {
    leafletLayer(options: Record<string, unknown>): { addTo(map: unknown): unknown };
};
```

- [ ] **Step 3: Verify no external hosts remain and tests pass**

Run (Git Bash on host): `grep -rn "cartocdn\|tile.openstreetmap" web/*.js web/index.html`
Expected: no matches.

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build && ninja -C build test"`
Expected: clean build (bundle regenerates), all tests pass including `frontend_js_validators`.

- [ ] **Step 4: Commit**

```bash
git add web/state.js web/global.d.ts
git commit -m "Render basemap from self-hosted PMTiles with dark theme"
```

---

### Task 7: Basemap fetch script

**Files:**
- Create: `scripts/fetch_basemap.sh`
- Modify: `.gitignore` (ignore `data/`)

**Interfaces:**
- Consumes: nothing from the codebase.
- Produces: `data/basemap/basemap.pmtiles` (dev default `/workspace/data/basemap/basemap.pmtiles`), consumed by Task 8's smoke test and by production mounts.

- [ ] **Step 1: Write the script**

Create `scripts/fetch_basemap.sh`:

```bash
#!/usr/bin/env bash
# fetch_basemap.sh — produce the z0–6 PMTiles basemap extract msmap serves at
# /basemap.pmtiles. One-time, ~50–100 MB download; the result works offline.
#
# Run inside the msmap-dev container:
#
#   MSYS_NO_PATHCONV=1 docker run --rm \
#     -v "C:/Users/ms/projects/msmap:/workspace" \
#     msmap-dev bash -c "bash /workspace/scripts/fetch_basemap.sh"
#
# Usage: fetch_basemap.sh [output.pmtiles] [YYYYMMDD]
#   output  default: /workspace/data/basemap/basemap.pmtiles
#   build   default: newest daily build at build.protomaps.com (probes back 3 days)

set -euo pipefail

PMTILES_VERSION="1.31.2"
PMTILES_TAR="go-pmtiles_${PMTILES_VERSION}_Linux_x86_64.tar.gz"
PMTILES_URL="https://github.com/protomaps/go-pmtiles/releases/download/v${PMTILES_VERSION}/${PMTILES_TAR}"
PMTILES_SHA256="3ed7dbf4ec2e6dfe5e25b6f70d1ffc932729f93c86db353bf514dd71010a312f"
MAXZOOM=6

OUT="${1:-/workspace/data/basemap/basemap.pmtiles}"
BUILD="${2:-}"

# ── ensure the pmtiles CLI ────────────────────────────────────────────────────
if ! command -v pmtiles >/dev/null 2>&1; then
    echo "[INFO] downloading go-pmtiles v${PMTILES_VERSION}…"
    tmp="$(mktemp -d)"
    curl -fsSL -o "${tmp}/${PMTILES_TAR}" "${PMTILES_URL}"
    echo "${PMTILES_SHA256}  ${tmp}/${PMTILES_TAR}" | sha256sum -c -
    tar -xzf "${tmp}/${PMTILES_TAR}" -C "${tmp}" pmtiles
    install -m 0755 "${tmp}/pmtiles" /usr/local/bin/pmtiles
    rm -rf "${tmp}"
fi

# ── pick the newest available daily build ─────────────────────────────────────
if [[ -z "${BUILD}" ]]; then
    for d in 0 1 2 3; do
        cand="$(date -u -d "-${d} day" +%Y%m%d)"
        if curl -fsI "https://build.protomaps.com/${cand}.pmtiles" >/dev/null 2>&1; then
            BUILD="${cand}"
            break
        fi
    done
    if [[ -z "${BUILD}" ]]; then
        echo "[FATAL] no recent daily build found at build.protomaps.com" >&2
        exit 1
    fi
fi

mkdir -p "$(dirname "${OUT}")"
echo "[INFO] extracting z0-${MAXZOOM} from build ${BUILD} → ${OUT}"
pmtiles extract "https://build.protomaps.com/${BUILD}.pmtiles" "${OUT}" \
    --maxzoom="${MAXZOOM}"
echo "[OK] wrote ${OUT} ($(du -h "${OUT}" | cut -f1))"
```

- [ ] **Step 2: Ignore the data directory**

Append to `.gitignore` under the `## Logs / Temp` section:

```
## Runtime data (DB, basemap extract — see scripts/fetch_basemap.sh)
data/
```

- [ ] **Step 3: Syntax-check and probe build discovery**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "bash -n /workspace/scripts/fetch_basemap.sh && curl -fsI https://build.protomaps.com/\$(date -u +%Y%m%d).pmtiles >/dev/null && echo probe-ok || curl -fsI https://build.protomaps.com/\$(date -u -d '-1 day' +%Y%m%d).pmtiles >/dev/null && echo probe-ok-yesterday"`
Expected: no syntax errors; one `probe-ok*` line. (The full ~50–100 MB extract run happens once in Task 9. If the dev image lacks the `curl` CLI, add `curl` and `ca-certificates` to the dev stage of `Dockerfile`, rebuild `msmap-dev`, and include the Dockerfile change in this task's commit.)

- [ ] **Step 4: Commit**

```bash
git add scripts/fetch_basemap.sh .gitignore
git commit -m "Add basemap fetch script for pinned Protomaps z0-6 extract"
```

---

### Task 8: Smoke test and docs

**Files:**
- Modify: `scripts/smoke_test.sh` (basemap precondition + range-request check)
- Modify: `CLAUDE.md` (smoke-test invocation, basemap note)
- Modify: `README.md` (architecture/setup mentions of CARTO → self-hosted basemap; add fetch step)

**Interfaces:**
- Consumes: `GET /basemap.pmtiles` (Task 4), `data/basemap/basemap.pmtiles` (Task 7).
- Produces: nothing downstream.

- [ ] **Step 1: Extend `scripts/smoke_test.sh`**

In the *sanity checks* section, after the binary check, add:

```bash
BASEMAP="${MSMAP_BASEMAP_PMTILES:-/workspace/data/basemap/basemap.pmtiles}"
if [[ ! -r "${BASEMAP}" ]]; then
    red "Basemap not found at ${BASEMAP}"
    red "Run once: bash scripts/fetch_basemap.sh   (~50-100 MB download)"
    exit 1
fi
export MSMAP_BASEMAP_PMTILES="${BASEMAP}"
```

In the startup info block add:

```bash
info "Basemap  : ${BASEMAP}"
```

After the *API check* section, add a basemap range check:

```bash
bold "=== Basemap range request ==="
RANGE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Range: bytes=0-13" \
    "http://${LOG_HOST}:${HTTP_PORT}/basemap.pmtiles")
if [[ "${RANGE_STATUS}" == "206" ]]; then
    green "GET /basemap.pmtiles with Range → 206 Partial Content"
else
    red "GET /basemap.pmtiles with Range returned ${RANGE_STATUS} (expected 206)"
    exit 1
fi
echo
```

- [ ] **Step 2: Update docs**

`CLAUDE.md` — in the *Local smoke test* block, add the one-time prerequisite
line above the smoke command:

```bash
# One-time: fetch the z0–6 basemap extract (~50–100 MB)
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:/Users/ms/projects/msmap:/workspace" \
  msmap-dev bash -c "bash /workspace/scripts/fetch_basemap.sh"
```

and add `[-e MSMAP_BASEMAP_PMTILES=/path/to/basemap.pmtiles]` to the optional
env list of the smoke command.

`README.md` — search for `CARTO`/`cartocdn`/basemap mentions and update: the
map now renders a self-hosted Protomaps PMTiles extract (OSM-derived, ODbL)
served by msmap itself at `/basemap.pmtiles`; document
`MSMAP_BASEMAP_PMTILES` (default `/var/lib/msmap/basemap/basemap.pmtiles`),
the fetch script, and that startup fails without a valid archive. Keep edits
in the existing README voice; do not restructure unrelated sections.

- [ ] **Step 3: Verify script syntax**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -n /workspace/scripts/smoke_test.sh`
Expected: no output (clean syntax). Full end-to-end run happens in Task 9.

- [ ] **Step 4: Commit**

```bash
git add scripts/smoke_test.sh CLAUDE.md README.md
git commit -m "Require basemap in smoke test and document self-hosted tiles"
```

---

### Task 9: Full verification with a real extract

**Files:**
- Modify: `FINDINGS.md` (only if issues surface)

**Interfaces:**
- Consumes: everything above.
- Produces: verified feature; evidence for the final report.

- [ ] **Step 1: Fetch the real basemap extract (one-time, networked)**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "bash /workspace/scripts/fetch_basemap.sh"`
Expected: `[OK] wrote /workspace/data/basemap/basemap.pmtiles (…)`. Verify the size is plausible (tens of MB) with `ls -la data/basemap/` on the host.

- [ ] **Step 2: Run all quality gates**

Run: `docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev bash -c "ninja -C build && ninja -C build test && run-clang-tidy-18 -p build '/workspace/src/.*' && cppcheck --enable=style,performance,warning,portability --error-exitcode=1 src/"`
Expected: zero warnings, zero findings, all tests pass.

- [ ] **Step 3: Run the smoke test**

Run (background, then probe): `MSYS_NO_PATHCONV=1 docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" -p 8080:8080 -e MSMAP_CITY_MMDB=... msmap-dev bash -c "bash /workspace/scripts/smoke_test.sh"` — `MSMAP_CITY_MMDB` must point at the real GeoLite2-City.mmdb used for previous smoke runs (the existing GeoIP fail-fast requires it; ask the user for the path if it isn't discoverable in the repo or prior scripts).
Expected: basemap precondition passes, msmap starts, `GET /basemap.pmtiles` range check prints 206, API check returns rows.

While it runs, verify from the host:

```bash
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" -H "Range: bytes=0-16383" http://localhost:8080/basemap.pmtiles
```

Expected: `206 16384`.

- [ ] **Step 4: Visual verification in a browser**

Open `http://localhost:8080` (browser tooling or ask the user): dark world map renders from local tiles, zoom is capped at 9, cluster-click zoom works, and the network tab shows only same-origin requests (`/basemap.pmtiles` with 206 responses). This is the user-facing acceptance check — surface a screenshot or ask the user to confirm the look before closing out.

- [ ] **Step 5: Record any findings and finish**

Add anything discovered to `FINDINGS.md` (resolve or note per project workflow). Then use the superpowers:finishing-a-development-branch skill to integrate `feature/self-hosted-basemap`. Deployment note for the user: production needs the `.pmtiles` file mounted at `/var/lib/msmap/basemap/basemap.pmtiles` (or `MSMAP_BASEMAP_PMTILES` set) — startup now fails without it.

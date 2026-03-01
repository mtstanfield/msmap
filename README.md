# msmap – Mikrotik Firewall Log Viewer

A lightweight, self-contained C++23 application that ingests Mikrotik firewall
logs via rsyslog, enriches them with GeoIP and OSINT data, and serves a
single-page web UI showing inbound connections on a world map.

Ships as a single binary in a distroless container. No runtime filesystem
dependencies — all web assets are embedded at compile time.

Follows the [C++ Best Practices](https://github.com/cpp-best-practices/cppbestpractices)
guidelines throughout.

---

## Architecture

```
Mikrotik router
    │ syslog UDP 514
    ▼
rsyslog (reformats timestamp → RFC 3339, forwards to msmap)
    │ TCP 5140
    ▼
msmap binary
    ├── parser        (hand-written tokenizer, fuzz-tested)
    ├── SQLite DB     (WAL mode, 1-year retention)
    ├── GeoIP         (libmaxminddb + local GeoLite2-City.mmdb)
    ├── OSINT cache   (AbuseIPDB results cached in SQLite)
    └── HTTP server   (libmicrohttpd, port 8080)
            │ serves embedded assets + REST API
            ▼
        browser (Leaflet.js map, vanilla JS, no framework)
```

TLS termination and auth live outside the binary (nginx reverse proxy).

---

## Stack

| Layer       | Choice                           | Notes                                  |
|-------------|----------------------------------|----------------------------------------|
| Language    | C++23                            | `clang-18`, `-std=c++23`               |
| Build       | CMake 3.29+ + Ninja              | cmake via pip in dev container         |
| HTTP server | `libmicrohttpd` (GNU LGPL)       | Embedded, no framework overhead        |
| Database    | SQLite (WAL mode)                | Single file, parameterized queries only|
| GeoIP       | `libmaxminddb` + GeoLite2-City   | Local `.mmdb`, no external calls       |
| OSINT       | AbuseIPDB (cached)               | SQLite cache with TTL, no live queries |
| Frontend    | Leaflet.js + MarkerCluster       | Local copies, vanilla JS, no bundler   |
| Runtime     | `distroless/cc-debian12:nonroot` | Semi-static binary, uid 65532          |

---

## Development Environment

**All builds and dev work run inside Docker.** The host is Windows.

### First-time setup

```bash
# Build the dev image (re-run after Dockerfile changes)
docker build --target dev -t msmap-dev .
```

### Dev shell (live source mount)

```bash
docker run -it --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev
```

### Inside the container

```bash
# Configure (Debug)
cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_STANDARD=23 \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

# Build
ninja -C build msmap

# Run static analysis
ninja -C build clang-tidy   # or: run-clang-tidy -p build
cppcheck --enable=all src/
```

### One-off commands (non-interactive)

```bash
docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev \
  ninja -C build msmap
```

### Release image

```bash
docker build -t msmap .
docker run --rm -p 8080:8080 msmap
```

---

## Log Format

Mikrotik is configured to send syslog to rsyslog (UDP 514). rsyslog
reformats the timestamp to RFC 3339 and forwards to msmap on TCP 5140.

**Wire format received by msmap:**
```
2026-02-27T08:14:23+00:00 router firewall,info FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (ACK), 172.234.31.140:65226->108.89.67.16:44258, len 52
```

**Mikrotik router configuration:**
- NTP: enabled (Google NTP)
- Timezone: UTC
- Firewall `log-prefix` convention: `FW_<CHAIN>_<STATE>` (e.g. `FW_INPUT_NEW`, `FW_FWD_DROP`)

**rsyslog template** (`/etc/rsyslog.d/msmap.conf`):
```
template(name="MsmapFmt" type="string"
    string="%TIMESTAMP:::date-rfc3339% %HOSTNAME% %msg%\n")

input(type="imudp" port="514")

if $fromhost-ip == "YOUR.ROUTER.IP" then {
    action(type="omfwd" target="127.0.0.1" port="5140"
           protocol="tcp" template="MsmapFmt")
    stop
}
```

**Protocol variants:**
- TCP: `proto TCP (FLAGS), SRC:PORT->DST:PORT, len N`
- UDP: `proto UDP, SRC:PORT->DST:PORT, len N` (no flags)
- ICMP: `proto ICMP, SRC->DST, len N` (no ports)

---

## Project Structure

```
.
├── Dockerfile              # Multi-stage: dev → builder → distroless:nonroot
├── CMakeLists.txt          # Build system (cmake 3.29+, Ninja, clang-18)
├── PLAN.md                 # Detailed feature plan and todo list
├── CLAUDE.md               # Instructions for Claude Code
├── FINDINGS.md             # Issues log for remediation tracking
├── rsyslog.conf            # rsyslog forwarding config for Mikrotik logs
├── schema.sql              # SQLite schema (reference copy; applied in db.cpp)
├── src/
│   ├── main.cpp            # Entry point, signal handling, startup
│   ├── listener.cpp/.h     # TCP listener on port 5140
│   ├── parser.cpp/.h       # Hand-written RFC 3339 + Mikrotik log tokenizer
│   ├── db.cpp/.h           # SQLite WAL database, schema, queries
│   ├── geoip.cpp/.h        # MaxMind GeoLite2 enrichment
│   ├── abuse_cache.cpp/.h  # AbuseIPDB cache (SQLite-backed, background refresh)
│   ├── http.cpp/.h         # libmicrohttpd HTTP server + REST API
│   └── json.h              # Hand-rolled JSON serializer
├── web/
│   ├── index.html          # Single-page app shell
│   ├── app.js              # Leaflet map + filter panel
│   ├── app.css             # Styles
│   ├── bundle.py           # CMake step: inlines all assets → index_html.h
│   └── vendor/             # Leaflet.js, MarkerCluster (local copies)
├── tests/
│   ├── test_parser.cpp
│   ├── test_db.cpp
│   ├── test_geoip.cpp
│   ├── test_http.cpp
│   ├── test_abuse_cache.cpp
│   └── test_integration.cpp  # End-to-end: TCP socket → DB → query
├── cmake/
│   ├── CompilerWarnings.cmake
│   ├── Sanitizers.cmake
│   └── StaticAnalyzers.cmake
└── scripts/
    └── smoke_test.sh       # Manual smoke test (listener + DB + HTTP)
```

---

## Quality Standards

Follows [cpp-best-practices/cppbestpractices](https://github.com/cpp-best-practices/cppbestpractices):

- Warnings as errors (`-Wall -Wextra -Wpedantic -Werror`)
- clang-tidy clean (zero warnings)
- cppcheck clean
- ASan + UBSan in Debug and CI builds
- Parser fuzz-tested with libFuzzer
- Catch2 unit tests
- All SQL via parameterized queries — no string concatenation
- Distroless nonroot runtime
- Issues tracked in `FINDINGS.md`; reviewed before each feature increment

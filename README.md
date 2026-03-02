# msmap – Mikrotik Firewall Log Viewer

A lightweight, self-contained C++23 application that ingests Mikrotik firewall
logs directly via syslog UDP, enriches them with GeoIP and OSINT data, and serves
a single-page web UI showing inbound connections on a world map.

Ships as a single binary in a distroless container. No runtime filesystem
dependencies — all web assets are embedded at compile time.

Follows the [C++ Best Practices](https://github.com/cpp-best-practices/cppbestpractices)
guidelines throughout.

---

## Architecture

```
Mikrotik router
    │ syslog UDP 514 (BSD syslog, direct)
    ▼
msmap binary
    ├── parser        (hand-written tokenizer, fuzz-tested)
    ├── SQLite DB     (WAL mode, 30-day retention)
    ├── GeoIP         (libmaxminddb + local GeoLite2-City.mmdb)
    ├── OSINT cache   (AbuseIPDB results cached in SQLite)
    └── HTTP server   (libmicrohttpd, port 8080)
            │ serves embedded assets + REST API
            ▼
        browser (Leaflet.js map, vanilla JS, no framework)
```

TLS termination and auth live outside the binary (nginx/Caddy reverse proxy).

---

## Stack

| Layer       | Choice                           | Notes                                  |
|-------------|----------------------------------|----------------------------------------|
| Language    | C++23                            | `clang-18`, `-std=c++23`               |
| Build       | CMake 3.29+ + Ninja              | cmake via pip in dev container         |
| HTTP server | `libmicrohttpd` (GNU LGPL)       | Embedded, no framework overhead        |
| Database    | SQLite (WAL mode)                | Single file, parameterized queries only|
| GeoIP       | `libmaxminddb` + GeoLite2-City   | Local `.mmdb`, no external calls       |
| OSINT       | AbuseIPDB (cached)               | Score, usageType, isTor; 30-day SQLite cache; 1000 checks/day (free tier) |
| Frontend    | Leaflet.js + MarkerCluster       | Local copies, vanilla JS, no bundler   |
| Runtime     | `distroless/cc-debian12:nonroot` | Semi-static binary, uid 65532          |

---

## Deployment

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `MSMAP_DB_PATH` | `/data/msmap.db` | SQLite database path |
| `MSMAP_CITY_MMDB` | `/var/lib/msmap/geoip/GeoLite2-City.mmdb` | GeoIP city database |
| `MSMAP_ASN_MMDB` | `/var/lib/msmap/geoip/GeoLite2-ASN.mmdb` | GeoIP ASN database |
| `MSMAP_LISTEN_PORT` | `5140` | UDP syslog ingest port |
| `MSMAP_HTTP_PORT` | `8080` | Web UI / API port |
| `MSMAP_INGEST_ALLOW` | _(empty — accept all)_ | Comma-separated IPv4 allowlist for ingest |
| `ABUSEIPDB_API_KEY` | _(empty — disabled)_ | AbuseIPDB free-tier API key |

### Volumes

| Path | Purpose |
|---|---|
| `/data` | SQLite database — persist this across restarts |
| `/var/lib/msmap/geoip` | MaxMind `.mmdb` files — optional, mount read-only |

### docker run

```bash
docker run -d \
  --name msmap \
  --restart unless-stopped \
  -p 5140:5140/udp \
  -p 8080:8080 \
  -v msmap-data:/data \
  -v /path/to/geoip:/var/lib/msmap/geoip:ro \
  -e MSMAP_INGEST_ALLOW=192.168.88.1 \
  ghcr.io/mtstanfield/msmap:latest
```

With AbuseIPDB threat scoring:

```bash
docker run -d \
  --name msmap \
  --restart unless-stopped \
  -p 5140:5140/udp \
  -p 8080:8080 \
  -v msmap-data:/data \
  -v /path/to/geoip:/var/lib/msmap/geoip:ro \
  -e MSMAP_INGEST_ALLOW=192.168.88.1 \
  -e ABUSEIPDB_API_KEY=your_key_here \
  ghcr.io/mtstanfield/msmap:latest
```

### docker-compose.yml

```yaml
services:
  msmap:
    image: ghcr.io/mtstanfield/msmap:latest
    restart: unless-stopped
    ports:
      - "5140:5140/udp"
      - "8080:8080"
    volumes:
      - msmap-data:/data
      - /path/to/geoip:/var/lib/msmap/geoip:ro
    environment:
      MSMAP_INGEST_ALLOW: "192.168.88.1"
      # ABUSEIPDB_API_KEY: "your_key_here"

volumes:
  msmap-data:
```

### GeoLite2 databases (optional, recommended)

Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` from
[MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
(free account required) and place them in the directory mounted at
`/var/lib/msmap/geoip/`. msmap reloads changed `.mmdb` files automatically —
no restart needed after a geoipupdate run.

### Mikrotik router configuration

In Winbox or WebFig → **System → Logging → Actions**, add a new action:

| Field | Value |
|---|---|
| Name | `msmap` |
| Type | `remote` |
| Remote address | `<host running msmap>` |
| Remote port | `5140` |
| Src address | your router's LAN IP (e.g. `192.168.88.1`) |

Then under **System → Logging**, add a rule:

| Field | Value |
|---|---|
| Topics | `firewall` |
| Action | `msmap` |

Set `MSMAP_INGEST_ALLOW` to the router's LAN IP to reject syslog from
unexpected sources.

---

## Web UI

The UI is a single-page Leaflet.js map served at port 8080. Connections are
plotted as clustered markers; click any marker to open a detail popup.

### Filter panel

| Filter | Description |
|---|---|
| Time range | Last 15 min / 1 h / 6 h / 24 h |
| Protocol | All / TCP / UDP / ICMP |
| Source IP | Exact source IP match |
| Dst Port | Exact destination port match |
| Country | 2-letter ISO code (requires GeoIP) |
| Unique IPs | Deduplicate — show only the most recent connection per source IP |
| Tor exits | Show only confirmed Tor exit nodes (requires AbuseIPDB) |
| Datacenter | Show only datacenter / hosting IPs (requires AbuseIPDB) |
| Residential | Show only residential ISP IPs (requires AbuseIPDB) |

The Tor/datacenter/residential toggles are OR-combined when multiple are active.
When none are checked all connections are shown regardless of enrichment status.

### Connection popup

Clicking a marker shows:

- Timestamp, source IP:port, destination IP:port, protocol, TCP flags
- Country and ASN (GeoIP — shown when `.mmdb` files are mounted)
- **Threat score** — AbuseIPDB abuse confidence 0–100
- **Usage type** — e.g. `Data Center/Web Hosting/Transit`, `ISP/Residential`
- **Tor exit** — `yes` (highlighted) or `no`

The OSINT fields appear once the background worker has resolved the IP against
AbuseIPDB. Results are cached for 30 days; an API key is not required to view
previously cached data.

---

## Log Format

msmap listens on UDP 5140 and parses BSD syslog sent directly by Mikrotik:

```
<134>Mar  2 08:14:23 MikroTik FW_INPUT_NEW: FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (ACK), 172.234.31.140:65226->108.89.67.16:44258, len 52
```

RFC 3339 format (produced by an rsyslog relay) is also accepted automatically:

```
2026-02-27T08:14:23+00:00 router firewall,info FW_INPUT_NEW input: ...
```

**Protocol variants:**
- TCP: `proto TCP (FLAGS), SRC:PORT->DST:PORT, len N`
- UDP: `proto UDP, SRC:PORT->DST:PORT, len N` (no flags)
- ICMP: `proto ICMP, SRC->DST, len N` (no ports)

**Mikrotik router setup:**
- NTP: enabled (Google NTP)
- Timezone: UTC
- Firewall `log-prefix` convention: `FW_<CHAIN>_<STATE>` (e.g. `FW_INPUT_NEW`, `FW_FWD_DROP`)

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
run-clang-tidy-18 -p build '/workspace/src/.*'
cppcheck --enable=style,performance,warning,portability --error-exitcode=1 src/
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

## Project Structure

```
.
├── Dockerfile              # Multi-stage: dev → builder → distroless:nonroot
├── CMakeLists.txt          # Build system (cmake 3.29+, Ninja, clang-18)
├── PLAN.md                 # Feature plan and todo list
├── CLAUDE.md               # Instructions for Claude Code
├── FINDINGS.md             # Issues log for remediation tracking
├── rsyslog.conf            # Optional rsyslog forwarding config (reference only)
├── schema.sql              # SQLite schema (reference copy; applied in db.cpp)
├── src/
│   ├── main.cpp            # Entry point, signal handling, startup
│   ├── listener.cpp/.h     # UDP listener on port 5140
│   ├── parser.cpp/.h       # Hand-written BSD syslog + RFC 3339 tokenizer
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
│   └── test_integration.cpp  # End-to-end: UDP socket → DB → query
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

# msmap – Mikrotik Firewall Log Viewer

`msmap` is a self-contained C++23 application that ingests Mikrotik firewall
logs over syslog UDP, enriches them with GeoIP and cached threat intelligence,
and serves a single-page world map for live inbound traffic triage.

The current architecture is:

- 24-hour retention only
- aggregate-first map rendering via `GET /api/map`
- lazy raw-event drilldown via `GET /api/detail`
- AbuseIPDB for threat score and usage classification
- Tor Project and Spamhaus DROP enrichment for popup/source intel
- distroless runtime with embedded web assets

TLS termination, caching, and rate limiting are expected to live in front of
the binary (typically nginx).

---

## Architecture

```
Mikrotik router
    │ syslog UDP 514 (BSD syslog, direct)
    ▼
msmap binary
    ├── parser          (hand-written tokenizer, fuzz-tested)
    ├── SQLite DB       (WAL mode, 24h retention)
    ├── GeoIP           (libmaxminddb + local GeoLite2 City/ASN mmdb)
    ├── Abuse cache     (AbuseIPDB score + usage_type, SQLite-backed)
    ├── Intel cache     (Tor Project + Spamhaus DROP, background refreshed)
    ├── Home resolver   (optional home marker / arcs / RFC1918 dst rewrite)
    └── HTTP server     (libmicrohttpd, embedded assets + JSON API)
            │
            ▼
        browser (Leaflet.js map, vanilla JS)
```

---

## Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | C++23 | `clang-18`, `-std=c++23` |
| Build | CMake 3.29+ + Ninja | run inside the dev container |
| HTTP server | `libmicrohttpd` | embedded, no framework |
| Database | SQLite | WAL mode, parameterized queries only |
| GeoIP | `libmaxminddb` + GeoLite2 City/ASN | local `.mmdb`, no serve-time lookups |
| Threat / usage | AbuseIPDB | 30-day SQLite cache, optional API key |
| Source intel | Tor Project + Spamhaus DROP | background-refreshed local cache |
| Frontend | Leaflet.js + MarkerCluster | local copies, vanilla JS |
| Runtime | `distroless/cc-debian12:nonroot` | static-ish binary, uid 65532 |

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
| `MSMAP_HTTP_THREADS` | `4` | libmicrohttpd thread-pool size (`1`-`16`) |
| `MSMAP_INGEST_ALLOW` | _(empty — accept all)_ | Comma-separated IPv4 allowlist for ingest |
| `ABUSEIPDB_API_KEY` | _(empty — disabled)_ | AbuseIPDB free-tier API key |
| `MSMAP_HOME_HOST` | _(empty — disabled)_ | Hostname or IPv4 address of your public-facing host; enables the home marker, home-directed arcs, and RFC1918 destination rewrite for newly ingested rows |
| `MSMAP_INTEL_REFRESH_SECS` | `21600` | Refresh interval for Tor Project / Spamhaus source intel |
| `MSMAP_TOR_EXIT_URL` | `https://check.torproject.org/api/bulk` | Tor Project bulk exit source |
| `MSMAP_SPAMHAUS_DROP_URL` | `https://www.spamhaus.org/drop/drop_v4.json` | Spamhaus DROP source |

### Volumes

| Path | Purpose |
|---|---|
| `/data` | SQLite database and caches — persist this across restarts |
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

With optional home marker and source-intel overrides:

```bash
docker run -d \
  --name msmap \
  --restart unless-stopped \
  -p 5140:5140/udp \
  -p 8080:8080 \
  -v msmap-data:/data \
  -v /path/to/geoip:/var/lib/msmap/geoip:ro \
  -e MSMAP_INGEST_ALLOW=192.168.88.1 \
  -e MSMAP_HOME_HOST=your.public.hostname.or.ip \
  -e MSMAP_INTEL_REFRESH_SECS=21600 \
  ghcr.io/mtstanfield/msmap:latest
```

### docker-compose.yml

```yaml
services:
  geoipupdate:
    image: maxmindinc/geoipupdate:latest
    restart: unless-stopped
    volumes:
      - geoip-data:/var/lib/geoipupdate
    environment:
      GEOIPUPDATE_ACCOUNT_ID: ${GEOIPUPDATE_ACCOUNT_ID}
      GEOIPUPDATE_LICENSE_KEY: ${GEOIPUPDATE_LICENSE_KEY}
      GEOIPUPDATE_EDITION_IDS: GeoLite2-City GeoLite2-ASN
      GEOIPUPDATE_FREQUENCY: 24

  msmap:
    image: ghcr.io/mtstanfield/msmap:latest
    restart: unless-stopped
    ports:
      - "5140:5140/udp"
      - "8080:8080"
    volumes:
      - msmap-data:/data
      - geoip-data:/var/lib/msmap/geoip:ro
    environment:
      MSMAP_INGEST_ALLOW: "192.168.88.1"
      MSMAP_HTTP_THREADS: "4"
      MSMAP_INTEL_REFRESH_SECS: "21600"
      # ABUSEIPDB_API_KEY: "your_key_here"
      # MSMAP_HOME_HOST: "your.public.hostname.or.ip"
      # MSMAP_TOR_EXIT_URL: "https://check.torproject.org/api/bulk"
      # MSMAP_SPAMHAUS_DROP_URL: "https://www.spamhaus.org/drop/drop_v4.json"

volumes:
  msmap-data:
  geoip-data:
```

Notes:

- `geoipupdate` is optional, but recommended if you want country/ASN lookups.
- `ABUSEIPDB_API_KEY` is optional; without it, existing cached AbuseIPDB data is
  still readable but new threat/usage lookups are disabled.
- `MSMAP_HOME_HOST` is optional; without it, the home marker, home-directed
  arcs, and RFC1918 destination rewrite are disabled.

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

### nginx reference config

Production should put nginx in front of `msmap` for TLS termination, gzip,
microcaching, request coalescing, and basic rate limiting. The public hot path
is `GET /` plus `GET /api/map`; the raw drilldown endpoint `GET /api/detail`
should not be cached.

Sanitized example:

```nginx
proxy_cache_path /config/nginx/cache/msmap_api levels=1:2 keys_zone=msmap_api:64m max_size=4g inactive=10m use_temp_path=off;
limit_req_zone $binary_remote_addr zone=msmap_api_ratelimit:10m rate=1r/s;
limit_conn_zone $binary_remote_addr zone=msmap_api_conn:10m;

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;

    server_name map.example.invalid;

    include /config/nginx/ssl.conf;

    gzip on;
    gzip_comp_level 5;
    gzip_min_length 1024;
    gzip_types application/json text/plain text/css application/javascript text/javascript text/html image/svg+xml;

    location = /api/map {
        include /config/nginx/proxy.conf;
        proxy_cache msmap_api;
        proxy_cache_lock on;
        proxy_cache_background_update on;
        proxy_cache_use_stale updating error timeout invalid_header http_500 http_502 http_503 http_504;
        proxy_cache_valid 200 30s;
        proxy_cache_valid 404 10s;
        proxy_ignore_headers Set-Cookie;
        limit_req zone=msmap_api_ratelimit burst=20 nodelay;
        limit_conn msmap_api_conn 20;
        add_header X-Cache-Status $upstream_cache_status always;
        proxy_pass http://192.0.2.10:8080;
    }

    location = /api/home {
        include /config/nginx/proxy.conf;
        proxy_cache msmap_api;
        proxy_cache_lock on;
        proxy_cache_valid 200 300s;
        proxy_cache_valid 404 30s;
        add_header X-Cache-Status $upstream_cache_status always;
        proxy_pass http://192.0.2.10:8080;
    }

    location = /api/detail {
        include /config/nginx/proxy.conf;
        proxy_no_cache 1;
        proxy_cache_bypass 1;
        limit_req zone=msmap_api_ratelimit burst=5 nodelay;
        limit_conn msmap_api_conn 5;
        proxy_pass http://192.0.2.10:8080;
    }

    location / {
        include /config/nginx/proxy.conf;
        proxy_pass http://192.0.2.10:8080;
    }
}
```

---

## Web UI

The UI is a single-page Leaflet.js map served at port 8080. The main map polls
`GET /api/map`, which returns one aggregate marker per source IP for the
selected window. This lets the browser render the complete 24-hour view without
trying to plot every raw event. Clicking a marker then lazy-loads recent raw
events from `GET /api/detail`.

### Filter panel

| Filter | Description |
|---|---|
| Time range | Last 15 min / 1 h / 6 h / 24 h |
| Protocol | All / TCP / UDP |
| Source IP | Exact source IP match |
| Dst Port | Exact destination port match |
| Country | 2-letter ISO code (requires GeoIP) |
| Network type | All / Datacenter / Residential from AbuseIPDB `usage_type` |
| Animations | On / Off for marker ripple and home-directed arcs |
| Legend | Inline explanation of threat colours, animation semantics, and intel badges |

All selects apply immediately. Text filters auto-apply once the value is
valid, and `Defaults` resets the panel to the standard 15-minute view.

### Animations

When `MSMAP_HOME_HOST` is set, msmap resolves the hostname to an IPv4 address at
startup, GeoIP-locates it, and serves the coordinates via `GET /api/home`.  The
browser then:

1. Places a hollow blue ring marker at the home location (always visible,
   outside the cluster layer).
2. For newly active source IPs in a poll batch, selects the most relevant
   distinct origins and draws animated bezier arcs from those points toward
   home. Arcs are ranked by recency, threat, and hit count, and are coloured to
   match the threat level of the source.
3. The arc line draws itself over 0.8 s (`stroke-dashoffset` CSS transition),
   with a dot tracking the head; a pulse ring fires on arrival. The assembly
   fades out and is removed after roughly 1.1 s total.
4. Rate-limits arcs to 10 per poll batch and collapses near-identical origins
   so one hotspot does not dominate the animation budget.
5. Clears stale arcs on zoom, filter changes, animation-toggle changes, and
   home-point changes.

Marker circles also apply a one-shot ripple animation the first time a source IP
appears in the current browser session. The ripple does not replay on later
polls for the same IP.

If the hostname fails to resolve, or GeoIP has no record for the resolved IP, a
`[WARN]` is logged at startup and only the home-directed arcs are disabled. The
`Animations` toggle still controls marker ripple.

When home resolution succeeds, newly ingested RFC1918 destination IPs are
rewritten to the resolved home IP before storage so popup detail and raw drill
downs show the public home target instead of private LAN addresses. Existing
stored rows are left unchanged and age out normally.

### Connection popup

Clicking a marker shows:

- First/last seen timestamps for the aggregate source IP marker
- Hit count within the selected window
- Country and ASN (GeoIP — shown when `.mmdb` files are mounted)
- **Threat score** chip from AbuseIPDB
- **Usage type** — e.g. `Data Center/Web Hosting/Transit`, `Fixed Line ISP`
- **Tor exit** badge from Tor Project bulk exit data
- **Spamhaus DROP** badge when the source IP matches that list
- Compact pivot buttons for GreyNoise, AbuseIPDB, and AlienVault OTX
- A condensed recent-event viewer loaded on demand from `GET /api/detail`
- Arrow controls to step older/newer through the raw-event history for that
  aggregate source IP marker

The popup shows the newest raw event first and lazy-loads older pages only when
the user walks past the oldest loaded entry. It no longer dumps the full first
page of raw rows into the popup.

Threat colour and `usage_type` still come from AbuseIPDB. Tor status comes from
Tor Project bulk exit data, and Spamhaus DROP badges come from locally
cached list lookups. AbuseIPDB results are cached for 30 days; an API key is
not required to view previously cached data.

### Status bar

The bottom status bar shows the current operational state of the map:

- `Mapped`: aggregate markers currently rendered
- `Hits`: total matching event volume represented by the visible aggregate rows
- `Updated`: freshness of the last successful poll
- inline error text when the most recent poll failed

The footer metadata on the right shows `🌐 msmap`, the GitHub link, and the
embedded build timestamp.

---

## HTTP API

### `GET /`

Returns the embedded single-page web UI.

### `GET /api/map`

Returns aggregate map rows for the requested window and filters.

Supported query parameters:

| Parameter | Description |
|---|---|
| `window` | `900`, `3600`, `21600`, or `86400` |
| `proto` | optional exact protocol filter: `TCP`, `UDP`, or `ICMP` |
| `ip` | optional exact source IP filter |
| `port` | optional exact destination port filter |
| `country` | optional 2-letter country filter |

Notes:

- If `proto` is omitted, the UI/default API behavior excludes ICMP.
- Response rows are aggregate markers, not raw events.
- Responses include threat, usage, and source-intel flags.

### `GET /api/detail`

Returns raw connection rows for a narrowed drilldown query.

Supported query parameters:

| Parameter | Description |
|---|---|
| `ip` | exact source IP filter |
| `since` | lower timestamp bound |
| `until` | optional upper timestamp bound |
| `proto` | optional exact protocol filter |
| `port` | optional exact destination port filter |
| `limit` | page size, capped server-side |
| `cursor` | opaque pagination cursor from the previous page |

Notes:

- The popup uses this endpoint lazily.
- If `proto` is omitted, default behavior excludes ICMP.
- Responses include `next_cursor` when older pages are available.

### `GET /api/home`

Returns the resolved home coordinates when `MSMAP_HOME_HOST` is configured and
GeoIP successfully locates the resolved IP. Otherwise returns `404`.

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

**All builds and dev work run inside Docker.**

### First-time setup

```bash
# Build the dev image (re-run after Dockerfile changes)
docker build --target dev -t msmap-dev .
```

### Dev shell (live source mount)

```bash
docker run -it --rm -v "$PWD:/workspace" msmap-dev
```

### Inside the container

```bash
# Configure (Debug)
cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_STANDARD=23 \
  -DCMAKE_CXX_EXTENSIONS=OFF \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

# Build
ninja -C build msmap

# Run static analysis
run-clang-tidy-18 -p build '/workspace/src/.*'
cppcheck --enable=style,performance,warning,portability --error-exitcode=1 src/
ctest --test-dir build --output-on-failure
```

### Fuzzer (libFuzzer on syslog parser)

Run interactively:

```bash
docker run -it --rm -v "$PWD:/workspace" msmap-dev ninja -C build fuzz_parser
```

Generates `build/corpus/` (seed crashes/hangs) and `build/fuzz_cov.html` (coverage report).

### One-off commands (non-interactive)

```bash
docker run --rm -v "$PWD:/workspace" msmap-dev \
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
│   ├── ip_intel_cache.cpp/.h # Tor Project + Spamhaus DROP source-intel cache
│   ├── home_resolver.cpp/.h  # Home marker resolver and periodic refresh
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

# Project Plan: msmap – Mikrotik Firewall Log Viewer

## Overview
Ingest Mikrotik firewall logs via rsyslog → parse and store inbound connection
records in SQLite → enrich with GeoIP/OSINT → serve a self-contained web UI
(world map, filters, query interface) from a single distroless binary.

---

## Stack Decisions

### Backend (C++23)
| Concern         | Choice                         | Rationale                                              |
|-----------------|--------------------------------|--------------------------------------------------------|
| HTTP server     | `libmicrohttpd` (GNU LGPL)     | Lightweight embedded HTTP/1.1, no framework overhead   |
| Database        | SQLite (WAL mode)              | Single-file, zero-server, well-suited to log workloads |
| GeoIP           | `libmaxminddb` + local GeoLite2-City.mmdb | No external calls at runtime              |
| OSINT           | AbuseIPDB (cached in SQLite)   | SQLite cache with TTL; no live queries at serve time   |
| Log ingest      | rsyslog → TCP 5140             | rsyslog reformats timestamp; msmap listens on loopback |
| JSON            | Hand-rolled serializer         | Known data shapes; zero dependency; ~50 lines          |
| Build           | CMake 3.29+ + Ninja + clang-18 | Best practices template                                |
| Dependencies    | apt (.a static libs)           | No Conan/CPM; all libs in Debian bookworm              |

### Frontend
- **Leaflet.js** + MarkerCluster plugin – stored locally in repo, served from binary
- **Vanilla JS only** – no framework, no bundler, no npm
- **Web assets embedded** in binary as C byte arrays via `xxd -i` CMake step
  → zero filesystem dependencies at runtime; distroless-clean
- Timestamps stored as UTC epoch; browser converts to local timezone via `Intl` API

### Runtime
- Semi-static binary: `-static-libgcc -static-libstdc++` + static app libs (.a)
- `gcr.io/distroless/cc-debian12:nonroot` – glibc provided by image; runs as uid 65532
- `EXPOSE 8080`; nginx/caddy in front for TLS termination and auth

---

## Log Format (confirmed)

### Pipeline
```
Mikrotik (UDP 514) → rsyslog → TCP 5140 → msmap
```

rsyslog receives BSD syslog from Mikrotik and reformats the timestamp to RFC 3339
before forwarding. msmap never sees a year-ambiguous timestamp.

### rsyslog config (`/etc/rsyslog.d/msmap.conf`)
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

### Wire format (what msmap parses)
```
2026-02-27T08:14:23+00:00 router firewall,info FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (ACK), 172.234.31.140:65226->108.89.67.16:44258, len 52
```

### Grammar
```
message    := ISO8601_TS ' ' HOSTNAME ' ' mk_body
mk_body    := TOPIC ',' LEVEL ' ' [RULE_NAME ' '] chain_line
chain_line := CHAIN ': ' ifaces ', ' conn_state [' src-mac ' MAC ','] ' ' proto_line
ifaces     := 'in:' IFACE ' out:' IFACE_OR_UNKNOWN
conn_state := 'connection-state:' STATE
proto_line := 'proto ' PROTO proto_variant ', len ' INT
proto_variant (TCP/UDP) := [' (' FLAGS ')'] ', ' IP ':' PORT '->' IP ':' PORT
proto_variant (ICMP)    :=                  ', ' IP '->' IP
```

### Protocol variants
- TCP: `proto TCP (ACK), 1.2.3.4:1234->5.6.7.8:80, len 52`
- UDP: `proto UDP, 1.2.3.4:1234->5.6.7.8:53, len 28` (no flags)
- ICMP: `proto ICMP, 1.2.3.4->5.6.7.8, len 28` (no ports)

### Mikrotik router configuration (applied)
- NTP: enabled (Google NTP)
- Timezone: UTC
- Log-prefix convention: `FW_<CHAIN>_<STATE>` — e.g. `FW_INPUT_NEW`, `FW_FWD_DROP`
  (prefix prevents collision with chain keywords `input`/`forward`/`output`)

### SQLite schema (target)
| Column       | Type           | Notes                          |
|--------------|----------------|--------------------------------|
| `id`         | INTEGER PK     | autoincrement                  |
| `ts`         | INTEGER        | Unix epoch (UTC)               |
| `src_ip`     | TEXT           | source IP (v4 or v6)           |
| `src_port`   | INTEGER NULL   | NULL for ICMP                  |
| `dst_ip`     | TEXT           |                                |
| `dst_port`   | INTEGER NULL   | NULL for ICMP                  |
| `proto`      | TEXT           | TCP / UDP / ICMP               |
| `tcp_flags`  | TEXT NULL      | NULL for non-TCP               |
| `chain`      | TEXT           | input / forward                |
| `in_iface`   | TEXT           |                                |
| `rule`       | TEXT           | log-prefix value               |
| `conn_state` | TEXT           | new / established / etc.       |
| `pkt_len`    | INTEGER        |                                |
| `country`    | TEXT NULL      | filled by GeoIP enrichment     |
| `lat`        | REAL NULL      |                                |
| `lon`        | REAL NULL      |                                |
| `asn`        | TEXT NULL      |                                |
| `threat`     | INTEGER NULL   | AbuseIPDB score 0-100          |

---

## Build & Dev Workflow
All development and builds run inside Docker (Windows host).

```bash
# Build dev image (once or after Dockerfile changes)
docker build --target dev -t msmap-dev .

# Dev shell with live source mount
docker run -it --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev

# Inside container – configure (Debug)
cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_STANDARD=23 \
  -DCMAKE_CXX_EXTENSIONS=OFF \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

# Build
ninja -C build msmap

# Release image
docker build -t msmap .
```

---

## Todo

### Foundation
- [x] Confirm Mikrotik log format and protocol variants
- [x] Confirm router timezone (UTC) and NTP configuration
- [x] Define log-prefix naming convention (`FW_` prefix)
- [x] Multi-stage Dockerfile (dev / builder / distroless:nonroot)
- [x] CMakeLists.txt – warnings, sanitizers, static analysis hooks
- [x] `.clang-tidy` configuration
- [x] `.clang-format` configuration
- [x] `FINDINGS.md` template
- [x] CI: GitHub Actions – build + clang-tidy + cppcheck in dev container; publishes release image to ghcr.io/mtstanfield/msmap on main

### Ingest
- [ ] rsyslog config: receive UDP 514, reformat, forward TCP 5140
- [x] msmap TCP listener on 5140 (loopback only)
- [x] Log parser: hand-written linear tokenizer (see grammar above)
- [ ] Fuzz the parser with libFuzzer

### Storage
- [x] SQLite schema (see table above) + WAL mode pragma
- [x] Indexes: `ts`, `src_ip`, `dst_port`, `country`
- [x] Retention pruning (1 year): triggered on insert every 10 000 rows; public `prune_older_than()` for testing/maintenance

### Enrichment
- [x] GeoIP: libmaxminddb lookup on ingest → fill country/lat/lon/asn columns
- [x] OSINT: AbuseIPDB cache table (`ip`, `score`, `last_checked`); background refresh

### Web UI
- [x] libmicrohttpd HTTP server on port 8080
- [x] Asset embedding: `web/bundle.py` CMake step inlines Leaflet+MarkerCluster+app JS/CSS
      into a single `constexpr std::string_view` header; no xxd, no filesystem deps
- [x] REST API: `GET /api/connections` (JSON, filterable by ts range/ip/country/port/proto)
- [x] Map view: Leaflet + MarkerCluster, circle markers colour-coded by protocol/threat
      (CartoDB Dark Matter tiles; CircleMarker → no icon image assets needed)
- [x] Filter/time-range panel: protocol, src IP, dst port, country, limit; Enter-key support
- [~] Raw query UI: out of scope — filter panel covers the use case
- [x] Timestamp display: UTC epoch → local timezone via `Intl.DateTimeFormat`

### Safety & Quality
- [ ] GSL (header-only, CPM or vendored)
- [x] Sanitizer builds: ASan + UBSan + -fno-sanitize-recover=all enabled by default in Debug builds
- [x] clang-tidy clean (zero warnings, `-warnings-as-errors=*`)
- [x] cppcheck clean (`--error-exitcode=1`)
- [x] Unit tests: Catch2 (parser, DB layer, enrichment, HTTP/JSON, AbuseCache) — 60 tests passing
- [x] Integration test: full ingest → query pipeline (TCP socket → listener → parser → DB → query, 7 cases, 67 total)

### Security
- [x] Input validation on all HTTP query params: length caps, range checks, proto allowlist
- [x] SQL parameterized queries only — enforced, no exceptions
- [ ] Auth: handled by nginx reverse proxy, not the binary
- [ ] Distroless nonroot confirmed in CI

### Deploy
- [x] Env-var configuration: `MSMAP_DB_PATH`, `MSMAP_CITY_MMDB`, `MSMAP_ASN_MMDB`, `MSMAP_LISTEN_PORT`, `MSMAP_HTTP_PORT`, `ABUSEIPDB_API_KEY`; defaults suit a containerised deployment
- [x] Dockerfile: `/data` (db) and `/var/lib/msmap/geoip` (mmdb) directories pre-created with correct ownership for `nonroot` uid 65532; volume-mounts overlay cleanly
- [~] `docker-compose.yml`: N/A — deployment is via Unraid's Docker UI; volumes/env vars set there
- [~] GeoLite2 DB update: geoipupdate sidecar already running on shared volume (free MaxMind account)
- [ ] Documented rollback procedure (per FINDINGS.md process)
- [ ] Auth: nginx/caddy reverse proxy in front for TLS + auth (not in binary)

---

## Open Questions
1. OSINT: AbuseIPDB API key approach, or start with a static blocklist (e.g. Firehol)?
2. Expected sustained log volume? (informs SQLite WAL + index tuning)
3. Auth for the web UI: IP allowlist at nginx, or basic auth, or bearer token?
4. IPv6: ATT gateway theoretically supports it but not configured — handle defensively in parser, revisit later

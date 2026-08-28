#!/usr/bin/env bash
# smoke_test.sh — local integration test for msmap
#
# Run inside the msmap-dev container (no extra packages needed):
#
#   MSYS_NO_PATHCONV=1 docker run --rm \
#     -v "C:/Users/ms/projects/msmap:/workspace" \
#     -p 8080:8080 \
#     [-e ABUSEIPDB_API_KEY=<your_key>] \
#     [-e MSMAP_CITY_MMDB=/path/to/GeoLite2-City.mmdb] \
#     [-e MSMAP_ASN_MMDB=/path/to/GeoLite2-ASN.mmdb] \
#     [-e MSMAP_BASEMAP_PMTILES=/path/to/basemap.pmtiles] \
#     msmap-dev bash -c "bash /workspace/scripts/smoke_test.sh"
#
# A basemap file is required (see scripts/fetch_basemap.sh) unless
# MSMAP_BASEMAP_PMTILES points at one already.
#
# The web UI will be reachable at http://localhost:8080 while the script runs.
# Hit Ctrl-C to stop and clean up.

set -euo pipefail

BINARY="/workspace/build/msmap"
WORK_DIR="$(mktemp -d)"
# The container default DB path (/data) does not exist in the dev image.
export MSMAP_DB_PATH="${WORK_DIR}/msmap.db"
LOG_HOST="127.0.0.1"
LOG_PORT=5140
HTTP_PORT=8080

# ── helpers ───────────────────────────────────────────────────────────────────

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n'  "$*"; }
info()  { printf '[INFO] %s\n' "$*"; }

cleanup() {
    info "Stopping msmap (PID ${MSMAP_PID:-?})…"
    kill "${MSMAP_PID}" 2>/dev/null || true
    wait "${MSMAP_PID}" 2>/dev/null || true
    info "Removing temp dir ${WORK_DIR}"
    rm -rf "${WORK_DIR}"
    bold "Done."
}
trap cleanup EXIT INT TERM

# ── sanity checks ─────────────────────────────────────────────────────────────

if [[ ! -x "${BINARY}" ]]; then
    red "Binary not found at ${BINARY}. Run: ninja -C build"
    exit 1
fi

BASEMAP="${MSMAP_BASEMAP_PMTILES:-/workspace/data/basemap/basemap.pmtiles}"
if [[ ! -r "${BASEMAP}" ]]; then
    red "Basemap not found at ${BASEMAP}"
    red "Run once: bash scripts/fetch_basemap.sh   (~50-100 MB download)"
    exit 1
fi
export MSMAP_BASEMAP_PMTILES="${BASEMAP}"

# ── start msmap ───────────────────────────────────────────────────────────────

bold "=== msmap smoke test ==="
info "Work dir : ${WORK_DIR}"
info "Binary   : ${BINARY}"
info "Basemap  : ${BASEMAP}"
info "GeoIP    : ${MSMAP_CITY_MMDB:-<not set — geo columns will be NULL>}"
info "AbuseIPDB: ${ABUSEIPDB_API_KEY:+<key set — OSINT enrichment active>}${ABUSEIPDB_API_KEY:-<not set — threat scores disabled>}"
echo

# ASan: suppress leak detection for third-party libs (sqlite/curl global state).
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1}"

info "Starting msmap…"
(cd "${WORK_DIR}" && "${BINARY}") 2>&1 &
MSMAP_PID=$!

# Wait for the HTTP server to come up (same process also owns the UDP syslog listener).
READY=0
for i in $(seq 1 20); do
    if curl -sf -o /dev/null "http://${LOG_HOST}:${HTTP_PORT}/api/status"; then
        READY=1
        break
    fi
    sleep 0.5
done

if [[ ${READY} -eq 0 ]]; then
    red "msmap did not respond on http://${LOG_HOST}:${HTTP_PORT}/api/status within 10 s"
    red "Check that the build succeeded: ninja -C build"
    exit 1
fi
green "msmap is up and accepting connections (PID ${MSMAP_PID})"
echo

# ── inject test log lines ─────────────────────────────────────────────────────

bold "=== Injecting test log lines ==="

# Realistic Mikrotik log lines covering all three protocol variants, in the
# real wire format: a colon-terminated BSD TAG follows the hostname (FIND-014;
# see tests/test_parser.cpp fixtures — the old "firewall,info" TOPIC,LEVEL
# form never occurs on the wire and is rejected by the parser).
# Timestamps are generated at run time so the rows also land inside the UI's
# live map window (/api/map), not just the unwindowed detail view.
# Using well-known IPs so AbuseIPDB results are predictable.
#
# NOTE: msmap silently drops rows whose src_ip the City DB cannot geolocate
# (listener.cpp should_retain_for_map). The first two lines use IPs from
# MaxMind's documented test ranges (81.2.69.142 London, 89.160.20.112
# Linköping) so rows appear even when smoke-testing against the small
# GeoLite2-City-Test.mmdb; the rest need a real GeoLite2 database.
TS_UTC="$(date -u +%Y-%m-%dT%H:%M:%S)+00:00"
TS_PLUS2="$(date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%S)+02:00"   # same UTC instant
LINES=(
    # TCP SYN — MaxMind test-range IP (geolocates with test AND real City DBs)
    "${TS_UTC} router FW_INPUT_NEW: FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (SYN), 81.2.69.142:44321->203.0.113.1:22, len 60"
    # UDP — MaxMind test-range IP (geolocates with test AND real City DBs)
    "${TS_UTC} router FW_INPUT_NEW: FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto UDP, 89.160.20.112:9999->203.0.113.1:123, len 76"
    # TCP SYN — known Tor exit node (very high AbuseIPDB score expected)
    "${TS_UTC} router FW_INPUT_NEW: FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (SYN), 185.220.101.47:54321->203.0.113.1:22, len 60"
    # TCP ACK — generic scanner
    "${TS_UTC} router FW_INPUT_NEW: FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (ACK), 172.234.31.140:65226->203.0.113.1:80, len 52"
    # UDP — from Google DNS (score 0)
    "${TS_UTC} router FW_INPUT_NEW: FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto UDP, 8.8.8.8:5353->203.0.113.1:53, len 64"
    # ICMP — from Cloudflare (hidden in the default detail view: exclude_icmp)
    "${TS_UTC} router FW_INPUT_DROP: FW_INPUT_DROP input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto ICMP, 1.1.1.1->203.0.113.1, len 84"
    # TCP — forward chain, no rule name prefix (chain keyword follows the TAG)
    "${TS_UTC} router direct: forward: in:ether1 out:ether2, connection-state:new proto TCP (SYN), 45.33.32.156:12345->10.0.0.5:443, len 60"
    # UDP — SSDP scanner
    "${TS_UTC} router FW_INPUT_NEW: FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto UDP, 198.199.105.93:1900->203.0.113.1:1900, len 131"
    # TCP — positive timezone offset (tests RFC 3339 normalisation to UTC)
    "${TS_PLUS2} router FW_INPUT_NEW: FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (SYN,ACK), 91.108.4.1:443->203.0.113.1:59000, len 52"
)

# Send each line as its own UDP datagram, the same way the Mikrotik router
# talks to msmap directly (no rsyslog relay involved).
for line in "${LINES[@]}"; do
    printf '%s\n' "${line}" > /dev/udp/${LOG_HOST}/${LOG_PORT}
    sleep 0.05
done
# Brief pause so msmap flushes the last insert.
sleep 0.3

green "${#LINES[@]} log lines sent"
echo

# Short settle time for the final DB insert.
sleep 0.5

# ── API check ────────────────────────────────────────────────────────────────

bold "=== API query (immediate — threat scores will be null without key) ==="

# /api/detail returns {"rows":[...]} (default view hides ICMP), so the ICMP
# line above is expected to be absent from this table.
RESULT=$(curl -sf "http://${LOG_HOST}:${HTTP_PORT}/api/detail" || echo '{"rows":[]}')
python3 -c "
import json, sys

rows = json.loads(sys.argv[1]).get('rows', [])

if not rows:
    print('  (no rows returned — parse WARNs above, or the City DB does not')
    print('   cover the fixture IPs; ungeolocatable rows are dropped)')
    sys.exit(1)

hdr = f\"  {'ts':>12}  {'proto':6}  {'src_ip':>22}  {'dst_port':>8}  {'asn':>12}  {'threat':>6}\"
print(hdr)
print('  ' + '-' * (len(hdr) - 2))
for r in rows:
    ts    = str(r.get('ts', '?'))
    proto = r.get('proto', '?')
    src   = r.get('src_ip', '?')
    dport = str(r.get('dst_port') or 'N/A')
    asn   = (r.get('asn') or '---')[:12]
    thr   = str(r.get('threat')) if r.get('threat') is not None else 'null'
    print(f'  {ts:>12}  {proto:6}  {src:>22}  {dport:>8}  {asn:>12}  {thr:>6}')

print()
print(f'  Total rows: {len(rows)}')
" "${RESULT}"
echo

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

# ── AbuseIPDB enrichment wait ─────────────────────────────────────────────────

if [[ -n "${ABUSEIPDB_API_KEY:-}" ]]; then
    bold "=== Waiting 20 s for AbuseIPDB background worker ==="
    info "Worker queues unique IPs → calls AbuseIPDB API → backfills threat column"
    for i in $(seq 20 -1 1); do
        printf '\r  %2d s remaining…' "${i}"
        sleep 1
    done
    printf '\r%35s\r' ''

    RESULT=$(curl -sf "http://${LOG_HOST}:${HTTP_PORT}/api/detail" || echo '{"rows":[]}')
    bold "=== After enrichment ==="
    python3 -c "
import json, sys
rows = json.loads(sys.argv[1]).get('rows', [])
seen = {}
for r in rows:
    ip = r.get('src_ip','?')
    if ip not in seen:
        seen[ip] = {'threat': r.get('threat'), 'asn': r.get('asn')}
hdr = f\"  {'src_ip':>22}  {'threat':>6}  {'asn':<20}\"
print(hdr)
print('  ' + '-' * (len(hdr) - 2))
for ip, d in seen.items():
    t = str(d['threat']) if d['threat'] is not None else 'null'
    a = (d['asn'] or '---')[:20]
    flag = ' ← HIGH THREAT' if d['threat'] is not None and d['threat'] >= 67 else ''
    print(f'  {ip:>22}  {t:>6}  {a:<20}{flag}')
" "${RESULT}"
    echo
fi

# ── web UI ────────────────────────────────────────────────────────────────────

bold "=== Web UI available at http://localhost:${HTTP_PORT} ==="
echo "  Open in your browser to see the map with the injected connections."
echo "  Press Ctrl-C to stop msmap and clean up."
echo

# Block until killed (cleanup trap fires on exit).
wait "${MSMAP_PID}" || true

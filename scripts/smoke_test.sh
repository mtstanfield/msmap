#!/usr/bin/env bash
# smoke_test.sh — local integration test for msmap
#
# Run inside the msmap-dev container (no extra packages needed):
#
#   MSYS_NO_PATHCONV=1 docker run --rm \
#     -v "C:/Users/ms/projects/msmap/.claude/worktrees/loving-robinson:/workspace" \
#     -p 8080:8080 \
#     [-e ABUSEIPDB_API_KEY=<your_key>] \
#     [-e MSMAP_CITY_MMDB=/path/to/GeoLite2-City.mmdb] \
#     [-e MSMAP_ASN_MMDB=/path/to/GeoLite2-ASN.mmdb] \
#     msmap-dev bash -c "bash /workspace/scripts/smoke_test.sh"
#
# The web UI will be reachable at http://localhost:8080 while the script runs.
# Hit Ctrl-C to stop and clean up.

set -euo pipefail

BINARY="/workspace/build/msmap"
WORK_DIR="$(mktemp -d)"
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

# ── start msmap ───────────────────────────────────────────────────────────────

bold "=== msmap smoke test ==="
info "Work dir : ${WORK_DIR}"
info "Binary   : ${BINARY}"
info "GeoIP    : ${MSMAP_CITY_MMDB:-<not set — geo columns will be NULL>}"
info "AbuseIPDB: ${ABUSEIPDB_API_KEY:+<key set — OSINT enrichment active>}${ABUSEIPDB_API_KEY:-<not set — threat scores disabled>}"
echo

# ASan: suppress leak detection for third-party libs (sqlite/curl global state).
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1}"

info "Starting msmap…"
(cd "${WORK_DIR}" && "${BINARY}") 2>&1 &
MSMAP_PID=$!

# Wait for the listener to be ready using bash /dev/tcp (no nc required).
READY=0
for i in $(seq 1 20); do
    if (echo "" > /dev/tcp/${LOG_HOST}/${LOG_PORT}) 2>/dev/null; then
        READY=1
        break
    fi
    sleep 0.5
done

if [[ ${READY} -eq 0 ]]; then
    red "msmap did not accept connections on ${LOG_HOST}:${LOG_PORT} within 10 s"
    red "Check that the build succeeded: ninja -C build"
    exit 1
fi
green "msmap is up and accepting connections (PID ${MSMAP_PID})"
echo

# ── inject test log lines ─────────────────────────────────────────────────────

bold "=== Injecting test log lines ==="

# Realistic Mikrotik log lines covering all three protocol variants.
# Using well-known IPs so AbuseIPDB results are predictable.
LINES=(
    # TCP SYN — known Tor exit node (very high AbuseIPDB score expected)
    "2026-02-27T08:14:23+00:00 router firewall,info FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (SYN), 185.220.101.47:54321->203.0.113.1:22, len 60"
    # TCP ACK — generic scanner
    "2026-02-27T08:14:25+00:00 router firewall,info FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (ACK), 172.234.31.140:65226->203.0.113.1:80, len 52"
    # UDP — from Google DNS (score 0)
    "2026-02-27T08:14:26+00:00 router firewall,info FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto UDP, 8.8.8.8:5353->203.0.113.1:53, len 64"
    # ICMP — from Cloudflare (score 0)
    "2026-02-27T08:14:27+00:00 router firewall,info FW_INPUT_DROP input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto ICMP, 1.1.1.1->203.0.113.1, len 84"
    # TCP — forward chain, no rule name prefix
    "2026-02-27T08:14:28+00:00 router firewall,info forward input: in:ether1 out:ether2, connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (SYN), 45.33.32.156:12345->10.0.0.5:443, len 60"
    # UDP — SSDP scanner
    "2026-02-27T08:14:30+00:00 router firewall,info FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto UDP, 198.199.105.93:1900->203.0.113.1:1900, len 131"
    # TCP — positive timezone offset (tests RFC 3339 normalisation to UTC)
    "2026-02-27T10:14:31+02:00 router firewall,info FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (SYN,ACK), 91.108.4.1:443->203.0.113.1:59000, len 52"
)

# Open one persistent TCP connection and stream all lines (mirrors rsyslog).
{
    for line in "${LINES[@]}"; do
        printf '%s\n' "${line}"
        sleep 0.05
    done
    # Brief pause so msmap flushes the last insert before we close.
    sleep 0.3
} > /dev/tcp/${LOG_HOST}/${LOG_PORT}

green "${#LINES[@]} log lines sent"
echo

# Short settle time for the final DB insert.
sleep 0.5

# ── API check ────────────────────────────────────────────────────────────────

bold "=== API query (immediate — threat scores will be null without key) ==="

RESULT=$(curl -sf "http://${LOG_HOST}:${HTTP_PORT}/api/connections" || echo '[]')
python3 -c "
import json, sys

rows = json.loads(sys.argv[1])   # API returns a JSON array directly

if not rows:
    print('  (no rows returned — check listener logs above)')
    sys.exit(0)

hdr = f\"  {'ts':>12}  {'proto':6}  {'src_ip':>22}  {'dst_port':>8}  {'country':>7}  {'asn':>12}  {'threat':>6}\"
print(hdr)
print('  ' + '-' * (len(hdr) - 2))
for r in rows:
    ts    = str(r.get('ts', '?'))
    proto = r.get('proto', '?')
    src   = r.get('src_ip', '?')
    dport = str(r.get('dst_port') or 'N/A')
    cc    = r.get('country') or '---'
    asn   = (r.get('asn') or '---')[:12]
    thr   = str(r.get('threat')) if r.get('threat') is not None else 'null'
    print(f'  {ts:>12}  {proto:6}  {src:>22}  {dport:>8}  {cc:>7}  {asn:>12}  {thr:>6}')

print()
print(f'  Total rows: {len(rows)}')
" "${RESULT}"
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

    RESULT=$(curl -sf "http://${LOG_HOST}:${HTTP_PORT}/api/connections" || echo '[]')
    bold "=== After enrichment ==="
    python3 -c "
import json, sys
rows = json.loads(sys.argv[1])   # API returns a JSON array directly
seen = {}
for r in rows:
    ip = r.get('src_ip','?')
    if ip not in seen:
        seen[ip] = {'threat': r.get('threat'), 'country': r.get('country'), 'asn': r.get('asn')}
hdr = f\"  {'src_ip':>22}  {'threat':>6}  {'country':>7}  {'asn':<20}\"
print(hdr)
print('  ' + '-' * (len(hdr) - 2))
for ip, d in seen.items():
    t = str(d['threat']) if d['threat'] is not None else 'null'
    c = d['country'] or '---'
    a = (d['asn'] or '---')[:20]
    flag = ' ← HIGH THREAT' if d['threat'] is not None and d['threat'] >= 67 else ''
    print(f'  {ip:>22}  {t:>6}  {c:>7}  {a:<20}{flag}')
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

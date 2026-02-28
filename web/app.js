/* msmap – Firewall Live Map
 * Fetches /api/connections, plots source IPs as clustered circle markers.
 * Uses CircleMarker (no image assets needed).
 */
'use strict';

// ── Constants ───────────────────────────────────────────────────────────────

const PROTO_COLORS = { TCP: '#58a6ff', UDP: '#3fb950', ICMP: '#d29922' };
const DEFAULT_COLOR = '#8b949e';
const REFRESH_MS    = 30000;       // poll interval
const MAX_MARKERS   = 5000;        // cap on map to keep rendering fast

// ── Map initialisation ───────────────────────────────────────────────────────

const lmap = L.map('map', { center: [20, 0], zoom: 2, minZoom: 2 });

// CartoDB Dark Matter – suits a security dashboard; no API key required.
L.tileLayer(
    'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    {
        attribution:
            '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>' +
            ' contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19,
    }
).addTo(lmap);

const cluster = L.markerClusterGroup({
    showCoverageOnHover: false,
    maxClusterRadius:    50,
    chunkedLoading:      true,
});
lmap.addLayer(cluster);

// ── Status bar references ────────────────────────────────────────────────────

const statMapped = document.getElementById('stat-mapped');
const statTotal  = document.getElementById('stat-total');
const statTime   = document.getElementById('stat-time');
const statError  = document.getElementById('stat-error');

// ── State ────────────────────────────────────────────────────────────────────

let totalSeen   = 0;
let mappedCount = 0;
let lastTs      = 0;

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtTs(ts) {
    return new Date(ts * 1000).toLocaleString();
}

function fmtPort(p) {
    return (p !== null && p !== undefined) ? ':' + p : '';
}

function protoClass(proto) {
    const key = 'proto-' + String(proto || '').toLowerCase();
    return (key in { 'proto-tcp': 1, 'proto-udp': 1, 'proto-icmp': 1 }) ? key : 'proto-other';
}

function buildPopup(r) {
    const rows = [
        '<div class="popup-row">',
        '<span class="ip">' + r.src_ip + '</span>',
        ' &rarr; ',
        '<span class="ip">' + r.dst_ip + fmtPort(r.dst_port) + '</span>',
        '<br>',
        '<span class="' + protoClass(r.proto) + '">' + (r.proto || '?') + '</span>',
        r.tcp_flags ? ' (' + r.tcp_flags + ')' : '',
        '<br>',
        '<span class="label">time </span>' + fmtTs(r.ts) + '<br>',
        '<span class="label">rule </span>' + r.rule + '<br>',
        r.country ? '<span class="label">country </span>' + r.country + '<br>' : '',
        r.asn     ? '<span class="label">asn </span>' + r.asn + '<br>'     : '',
        '<span class="label">len </span>' + r.pkt_len + ' B',
        '</div>',
    ];
    return rows.join('');
}

// ── Polling ──────────────────────────────────────────────────────────────────

async function poll() {
    try {
        const qs   = lastTs > 0 ? '?since=' + (lastTs + 1) : '';
        const resp = await fetch('/api/connections' + qs);

        if (!resp.ok) {
            setError('API ' + resp.status);
            return;
        }

        const rows = await resp.json();
        setError('');

        totalSeen += rows.length;

        for (const r of rows) {
            if (mappedCount >= MAX_MARKERS) { break; }
            if (r.lat !== null && r.lon !== null) {
                const color = PROTO_COLORS[r.proto] || DEFAULT_COLOR;
                const m = L.circleMarker([r.lat, r.lon], {
                    radius:      5,
                    color:       color,
                    fillColor:   color,
                    fillOpacity: 0.75,
                    weight:      1,
                });
                m.bindPopup(buildPopup(r), { maxWidth: 340 });
                cluster.addLayer(m);
                mappedCount++;
            }
            if (r.ts > lastTs) { lastTs = r.ts; }
        }

        statMapped.textContent = mappedCount.toLocaleString() + ' mapped';
        statTotal.textContent  = totalSeen.toLocaleString() + ' total';
        statTime.textContent   = 'updated ' + new Date().toLocaleTimeString();

    } catch (err) {
        setError(err.message);
    }
}

function setError(msg) {
    if (statError) {
        statError.textContent = msg;
        statError.style.display = msg ? '' : 'none';
    }
}

// ── Boot ─────────────────────────────────────────────────────────────────────

poll();
setInterval(poll, REFRESH_MS);

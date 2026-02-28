/* msmap – Firewall Live Map
 * Fetches /api/connections, plots source IPs as clustered circle markers.
 * Uses CircleMarker (no image assets needed).
 */
'use strict';

// ── Constants ───────────────────────────────────────────────────────────────

const PROTO_COLORS = { TCP: '#58a6ff', UDP: '#3fb950', ICMP: '#d29922' };
const DEFAULT_COLOR = '#8b949e';
const REFRESH_MS    = 30000;       // poll interval
const MAX_MARKERS   = 5000;        // cap to keep rendering fast

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

// ── DOM references ───────────────────────────────────────────────────────────

const statMapped    = document.getElementById('stat-mapped');
const statTotal     = document.getElementById('stat-total');
const statTime      = document.getElementById('stat-time');
const statError     = document.getElementById('stat-error');
const filterToggle  = document.getElementById('filter-toggle');
const filterPanel   = document.getElementById('filter-panel');
const fProto        = document.getElementById('f-proto');
const fIp           = document.getElementById('f-ip');
const fPort         = document.getElementById('f-port');
const fCountry      = document.getElementById('f-country');
const fLimit        = document.getElementById('f-limit');

// ── Filter panel ─────────────────────────────────────────────────────────────

filterToggle.addEventListener('click', () => {
    const open = !filterPanel.hidden;
    filterPanel.hidden = open;
    filterToggle.classList.toggle('active', !open);
});

document.getElementById('f-apply').addEventListener('click', () => {
    resetAndFetch();
});

document.getElementById('f-clear').addEventListener('click', () => {
    fProto.value   = '';
    fIp.value      = '';
    fPort.value    = '';
    fCountry.value = '';
    fLimit.value   = '1000';
    resetAndFetch();
});

// Also apply when Enter is pressed in any text/number input.
[fIp, fPort, fCountry, fLimit].forEach((el) => {
    el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { resetAndFetch(); }
    });
});

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
    return (key === 'proto-tcp' || key === 'proto-udp' || key === 'proto-icmp')
        ? key : 'proto-other';
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

function buildQueryString() {
    const params = new URLSearchParams();
    if (lastTs > 0)           { params.set('since',   String(lastTs + 1)); }
    if (fProto.value)         { params.set('proto',   fProto.value); }
    if (fIp.value.trim())     { params.set('ip',      fIp.value.trim()); }
    if (fPort.value)          { params.set('port',    fPort.value); }
    if (fCountry.value.trim()) { params.set('country', fCountry.value.trim().toUpperCase()); }
    const lim = parseInt(fLimit.value, 10);
    if (lim > 0)              { params.set('limit',   String(lim)); }
    const qs = params.toString();
    return qs ? '?' + qs : '';
}

function setError(msg) {
    statError.textContent   = msg;
    statError.style.display = msg ? '' : 'none';
}

// ── Polling ──────────────────────────────────────────────────────────────────

async function poll() {
    try {
        const resp = await fetch('/api/connections' + buildQueryString());

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

/// Reset all accumulated state and trigger a full re-fetch.
function resetAndFetch() {
    lastTs      = 0;
    totalSeen   = 0;
    mappedCount = 0;
    cluster.clearLayers();
    statMapped.textContent = '0 mapped';
    statTotal.textContent  = '0 total';
    poll();
}

// ── Boot ─────────────────────────────────────────────────────────────────────

poll();
setInterval(poll, REFRESH_MS);

/* msmap – Firewall Live Map
 * Fetches /api/connections, plots source IPs as clustered circle markers.
 * Uses CircleMarker (no image assets needed).
 */
'use strict';

// ── Constants ───────────────────────────────────────────────────────────────

const REFRESH_MS  = 30000;         // poll interval
const MAX_MARKERS = 20000;         // cap to keep rendering fast

// ── Filter persistence ───────────────────────────────────────────────────────

const STORAGE_KEY = 'msmap_filters';

function saveFilters() {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify({
            time:        fTime.value,
            dedup:       fDedup.checked,
            tor:         fTor.checked,
            datacenter:  fDatacenter.checked,
            residential: fResidential.checked,
            proto:       fProto.value,
            ip:          fIp.value,
            port:        fPort.value,
            country:     fCountry.value,
        }));
    } catch (_) { /* private/storage-full — silently ignore */ }
}

function loadFilters() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) { return; }
        const s = JSON.parse(raw);
        if (s.time        !== undefined) { fTime.value        = s.time; }
        if (s.dedup       !== undefined) { fDedup.checked      = s.dedup; }
        if (s.tor         !== undefined) { fTor.checked        = s.tor; }
        if (s.datacenter  !== undefined) { fDatacenter.checked = s.datacenter; }
        if (s.residential !== undefined) { fResidential.checked = s.residential; }
        if (s.proto       !== undefined) { fProto.value        = s.proto; }
        if (s.ip          !== undefined) { fIp.value           = s.ip; }
        if (s.port        !== undefined) { fPort.value         = s.port; }
        if (s.country     !== undefined) { fCountry.value      = s.country; }
    } catch (_) { /* corrupted storage — silently ignore */ }
}

// ── Map initialisation ───────────────────────────────────────────────────────

const lmap = L.map('map', {
    center:             [20, 0],
    zoom:               2,
    minZoom:            2,
    maxBounds:          [[-90, -180], [90, 180]], // single world copy
    maxBoundsViscosity: 1.0,                      // hard edge — no rubber-band past ±180°
});

// CartoDB Dark Matter – suits a security dashboard; no API key required.
L.tileLayer(
    'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    {
        attribution:
            '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>' +
            ' contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains:        'abcd',
        maxZoom:           19,
        noWrap:            true,       // don't repeat tiles outside ±180°
        updateWhenIdle:    true,       // load tiles only after pan/zoom settles
        updateWhenZooming: false,      // skip tile loads during zoom animation
        keepBuffer:        4,          // pre-render 4 tile-widths beyond viewport
        crossOrigin:       'anonymous', // allow HTTP cache sharing across tabs
    }
).addTo(lmap);

const cluster = L.markerClusterGroup({
    showCoverageOnHover: false,
    maxClusterRadius:    50,
    chunkedLoading:      true,
    // Colour cluster badge by ratio of high-threat (threat >= 67) children.
    iconCreateFunction(clusterMarker) {
        const children = clusterMarker.getAllChildMarkers();
        const total    = children.length;
        const nHigh    = children.filter(
            m => m.options.threat !== null &&
                 m.options.threat !== undefined &&
                 m.options.threat >= 67
        ).length;
        const ratio = total > 0 ? nHigh / total : 0;
        let cls;
        if      (ratio === 0)  { cls = 'safe'; }
        else if (ratio < 0.34) { cls = 'low';  }
        else if (ratio < 0.67) { cls = 'mid';  }
        else                   { cls = 'high'; }
        return L.divIcon({
            html:      '<div><span>' + total + '</span></div>',
            className: 'marker-cluster marker-cluster-threat-' + cls,
            iconSize:  L.point(40, 40),
        });
    },
});
lmap.addLayer(cluster);

// ── DOM references ───────────────────────────────────────────────────────────

const statMapped    = document.getElementById('stat-mapped');
const statTotal     = document.getElementById('stat-total');
const statTime      = document.getElementById('stat-time');
const statError     = document.getElementById('stat-error');
const filterPanel   = document.getElementById('filter-panel');
const filterToggle  = document.getElementById('filter-toggle');
const fTime         = document.getElementById('f-time');
const fDedup        = document.getElementById('f-dedup');
const fProto        = document.getElementById('f-proto');
const fIp           = document.getElementById('f-ip');
const fPort         = document.getElementById('f-port');
const fCountry      = document.getElementById('f-country');
const fTor          = document.getElementById('f-tor');
const fDatacenter   = document.getElementById('f-datacenter');
const fResidential  = document.getElementById('f-residential');

// ── Filter panel ─────────────────────────────────────────────────────────────

// Panel starts open; gear is active (blue) when panel is visible.
// Use style.display (inline style = highest specificity) so it correctly
// overrides the CSS `display: flex` rule — the old `hidden` attribute didn't.
filterToggle.classList.add('active');
filterToggle.addEventListener('click', () => {
    const nowOpen = filterPanel.style.display !== 'none';
    filterPanel.style.display = nowOpen ? 'none' : '';
    filterToggle.classList.toggle('active', !nowOpen);
});

document.getElementById('f-apply').addEventListener('click', () => {
    resetAndFetch();
});

document.getElementById('f-clear').addEventListener('click', () => {
    fTime.value          = '900';
    fDedup.checked       = true;
    fTor.checked         = false;
    fDatacenter.checked  = false;
    fResidential.checked = false;
    fProto.value         = '';
    fIp.value            = '';
    fPort.value          = '';
    fCountry.value       = '';
    resetAndFetch();
});

fDedup.addEventListener('change',       () => { resetAndFetch(); });
fTor.addEventListener('change',         () => { resetAndFetch(); });
fDatacenter.addEventListener('change',  () => { resetAndFetch(); });
fResidential.addEventListener('change', () => { resetAndFetch(); });

// Also apply when Enter is pressed in any text/number input.
[fIp, fPort, fCountry].forEach((el) => {
    el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { resetAndFetch(); }
    });
});

// ── State ────────────────────────────────────────────────────────────────────

let totalSeen    = 0;
let mappedCount  = 0;
let lastTs       = 0;
let sincePreset  = 0;
let isInitialLoad = true;  // suppresses ripple animation during startup batch

// src_ip → { count, latestTs, marker } — populated only when fDedup.checked.
const dedupMap = new Map();

// ── Helpers ──────────────────────────────────────────────────────────────────

function computeSincePreset() {
    const offset = parseInt(fTime.value, 10);
    sincePreset = (offset > 0) ? Math.floor(Date.now() / 1000) - offset : 0;
}

function fmtTs(ts) {
    return new Date(ts * 1000).toLocaleString();
}

function fmtPort(p) {
    return (p !== null && p !== undefined) ? ':' + p : '';
}

function markerColor(threat) {
    if (threat === null || threat === undefined) { return '#8b949e'; }
    if (threat === 0)   { return '#3fb950'; }
    if (threat <= 33)   { return '#d29922'; }
    if (threat <= 66)   { return '#f0883e'; }
    return '#f85149';
}

function threatClass(score) {
    if (score === null || score === undefined) { return 'threat-unknown'; }
    if (score === 0)   { return 'threat-clean'; }
    if (score <= 33)   { return 'threat-low'; }
    if (score <= 66)   { return 'threat-medium'; }
    return 'threat-high';
}

function threatLabel(score) {
    if (score === null || score === undefined) { return null; }
    return 'score ' + score + '%';
}

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/// Client-side enrichment filters (Tor / datacenter / residential).
/// Returns true if the row should be shown, false if it should be hidden.
/// When no toggles are active, all rows pass.  Multiple active toggles = OR.
///
/// AbuseIPDB usageType values (complete list from API docs):
///   Commercial, Organization, Government, Military,
///   University/College/School, Library, Search Engine Spider, Reserved,
///   Content Delivery Network,        ← datacenter
///   Data Center/Web Hosting/Transit, ← datacenter
///   Fixed Line ISP,                  ← residential
///   Mobile ISP                       ← residential
function passesFilters(r) {
    const torActive  = fTor.checked;
    const dcActive   = fDatacenter.checked;
    const resActive  = fResidential.checked;
    if (!torActive && !dcActive && !resActive) { return true; }
    if (torActive  && r.is_tor === true)  { return true; }
    const ut = r.usage_type ? r.usage_type.toLowerCase() : '';
    if (dcActive   && (ut.includes('data center') || ut.includes('content delivery network'))) { return true; }
    if (resActive  && (ut.includes('fixed line isp') || ut.includes('mobile isp')))            { return true; }
    return false;
}

function buildPopup(r, hitCount) {
    const rows = [
        '<div class="popup-row">',
        '<span class="ip">' + escapeHtml(r.src_ip) + fmtPort(r.src_port) + '</span>',
        ' &rarr; ',
        '<span class="ip">' + escapeHtml(r.dst_ip) + fmtPort(r.dst_port) + '</span>',
        '<br>',
        hitCount > 1 ? '<span class="label">hits </span>' + hitCount + '<br>' : '',
        '<span class="label">proto </span>' + escapeHtml(r.proto || '?') + (r.tcp_flags ? ' (' + escapeHtml(r.tcp_flags) + ')' : '') + '<br>',
        '<span class="label">time </span>' + fmtTs(r.ts) + '<br>',
        '<span class="label">rule </span>' + escapeHtml(r.rule) + '<br>',
        r.country ? '<span class="label">country </span>' + escapeHtml(r.country) + '<br>' : '',
        r.asn     ? '<span class="label">asn </span>' + escapeHtml(r.asn) + '<br>'     : '',
        (r.lat !== null && r.lat !== undefined && r.lon !== null && r.lon !== undefined)
            ? '<span class="label">geo </span>' +
              r.lat.toFixed(4) + ', ' + r.lon.toFixed(4) + '<br>'
            : '',
        (r.threat !== null && r.threat !== undefined)
            ? '<span class="label">threat </span>'
              + '<span class="' + threatClass(r.threat) + '">'
              + threatLabel(r.threat) + '</span><br>'
            : '',
        r.usage_type ? '<span class="label">usage </span>' + escapeHtml(r.usage_type) + '<br>' : '',
        (r.is_tor !== null && r.is_tor !== undefined)
            ? '<span class="label">tor </span>'
              + (r.is_tor ? '<span class="threat-high">yes</span>' : 'no') + '<br>'
            : '',
        '</div>',
    ];
    return rows.join('');
}

function buildQueryString() {
    const params = new URLSearchParams();
    // since = incremental watermark (if any rows received), else preset floor
    const since = (lastTs > 0) ? lastTs + 1 : sincePreset;
    if (since > 0)            { params.set('since',   String(since)); }
    if (fProto.value)         { params.set('proto',   fProto.value); }
    if (fIp.value.trim())     { params.set('ip',      fIp.value.trim()); }
    if (fPort.value)          { params.set('port',    fPort.value); }
    if (fCountry.value.trim()) { params.set('country', fCountry.value.trim().toUpperCase()); }
    params.set('limit', '25000');
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

        for (const r of rows) {
            if (!passesFilters(r)) { continue; }
            totalSeen++;

            // Dedup mode: merge into existing marker when this IP is already mapped.
            // Rows arrive newest-first (ORDER BY ts DESC), so the first occurrence
            // in a batch is already the most recent — only update popup when newer.
            if (fDedup.checked && r.lat !== null && r.lon !== null
                    && dedupMap.has(r.src_ip)) {
                const entry = dedupMap.get(r.src_ip);
                entry.count++;
                // Escalate color whenever a higher threat score arrives (never downgrade).
                const curThreat = entry.marker.options.threat;
                const newIsHigher = r.threat !== null && r.threat !== undefined &&
                    (curThreat === null || curThreat === undefined || r.threat > curThreat);
                if (newIsHigher) {
                    const c = markerColor(r.threat);
                    entry.marker.setStyle({ color: c, fillColor: c });
                    entry.marker.options.threat = r.threat;
                }
                // Refresh popup details only when this row is more recent.
                if (r.ts > entry.latestTs) {
                    entry.latestTs = r.ts;
                    entry.marker.setPopupContent(buildPopup(r, entry.count));
                }
                if (r.ts > lastTs) { lastTs = r.ts; }
                continue;
            }

            // New marker path (both modes).
            if (mappedCount >= MAX_MARKERS) { break; }
            if (r.lat !== null && r.lon !== null) {
                const color = markerColor(r.threat);
                const m = L.circleMarker([r.lat, r.lon], {
                    radius:      5,
                    color:       color,
                    fillColor:   color,
                    fillOpacity: 0.75,
                    weight:      1,
                    threat:      r.threat,  // stored for iconCreateFunction
                });
                m.bindPopup(buildPopup(r, 1), { maxWidth: 340 });
                cluster.addLayer(m);
                if (!isInitialLoad) {
                    m.once('add', () => {
                        const el = m.getElement(); // SVG <path>; null in canvas fallback
                        if (!el) { return; }
                        el.classList.add('marker-new');
                        el.addEventListener('animationend',
                            () => el.classList.remove('marker-new'), { once: true });
                    });
                }
                mappedCount++;
                if (fDedup.checked) {
                    dedupMap.set(r.src_ip, { count: 1, latestTs: r.ts, marker: m });
                }
            }
            if (r.ts > lastTs) { lastTs = r.ts; }
        }

        statMapped.textContent = mappedCount.toLocaleString() + ' mapped';
        statTotal.textContent  = totalSeen.toLocaleString() + ' total';
        statTime.textContent   = 'updated ' + new Date().toLocaleTimeString();
        isInitialLoad = false;

    } catch (err) {
        setError(err.message);
    }
}

/// Reset all accumulated state and trigger a full re-fetch.
function resetAndFetch() {
    saveFilters();
    computeSincePreset();
    lastTs      = 0;
    totalSeen   = 0;
    mappedCount = 0;
    dedupMap.clear();
    cluster.clearLayers();
    statMapped.textContent = '0 mapped';
    statTotal.textContent  = '0 total';
    poll();
}

// ── Boot ─────────────────────────────────────────────────────────────────────

loadFilters();                // restore before computeSincePreset reads fTime
computeSincePreset();
setTimeout(poll, 0);          // defer first fetch past initial map paint
setInterval(poll, REFRESH_MS);

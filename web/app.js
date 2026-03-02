/* msmap – Firewall Live Map
 * Fetches /api/connections, plots source IPs as clustered circle markers.
 * Uses CircleMarker (no image assets needed).
 */
'use strict';

// ── Constants ───────────────────────────────────────────────────────────────

const REFRESH_MS  = 30000;         // poll interval
const MAX_MARKERS = 20000;         // cap to keep rendering fast

const ARC_DRAW_MS   = 1200;        // ms for the arc line to draw
const ARC_FADE_MS   =  500;        // ms for arc to fade out after arriving
const MAX_ARCS_POLL =   15;        // max arcs fired per poll batch (visual sanity)

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
            arcs:        fArcs.checked,
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
        if (s.arcs        !== undefined) { fArcs.checked        = s.arcs; }
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
        bounds:            [[-90, -180], [90, 180]], // suppress requests for out-of-range tile indices
        updateWhenIdle:    false,      // load tiles continuously while panning
        updateWhenZooming: false,      // skip tile loads during zoom animation
        keepBuffer:        4,          // pre-render 4 tile-widths beyond viewport
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
const fArcs         = document.getElementById('f-arcs');

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
    fArcs.checked        = true;
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
let arcsFired    = 0;      // rate-limiter reset each poll cycle

// src_ip → { count, latestTs, marker } — populated only when fDedup.checked.
const dedupMap = new Map();

// Home point from /api/home — null when MSMAP_HOME_HOST is not configured.
let homePt     = null;
let homeMarker = null;

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
    if (threat === null || threat === undefined) { return '#adbac7'; }
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

// ── Home point & arc animation ───────────────────────────────────────────────

/// Fetch the home point from /api/home.  Updates homePt and repositions the
/// home marker if the coordinates have changed (the backend re-resolves the
/// hostname every 30 minutes).  Returns true when homePt is now valid.
/// Safe to call on every poll cycle — the backend response is tiny.
async function fetchHome() {
    try {
        const resp = await fetch('/api/home');
        if (!resp.ok) {
            // 404 = feature not configured or initial resolution failed.
            // Transient errors (5xx) keep the previous homePt to avoid
            // disrupting the arc toggle during a brief server hiccup.
            if (resp.status === 404) {
                homePt = null;
                if (homeMarker) { homeMarker.remove(); homeMarker = null; }
            }
            return;
        }
        const fresh = await resp.json();
        if (!fresh ||
            !Number.isFinite(fresh.lat) ||
            !Number.isFinite(fresh.lon)) { return; }

        const changed = !homePt ||
                        homePt.lat !== fresh.lat ||
                        homePt.lon !== fresh.lon;
        if (changed) {
            homePt = fresh;
            // Re-place the home marker at the new coordinates.
            if (homeMarker) { homeMarker.remove(); homeMarker = null; }
            addHomeMarker();
            // Re-enable the arc toggle if it was disabled due to missing home.
            if (!fArcs.disabled) { return; }
            fArcs.disabled = false;
            fArcs.checked  = true;
        }
    } catch (_) { /* network error — keep previous homePt */ }
}

/// Place a distinctive ring marker at the home location.  No-op when called
/// before fetchHome resolves or when the feature is disabled.
function addHomeMarker() {
    if (!homePt || homeMarker) { return; }
    homeMarker = L.circleMarker([homePt.lat, homePt.lon], {
        radius:      7,
        color:       '#58a6ff',
        fillColor:   '#58a6ff',
        fillOpacity: 0.15,
        weight:      2,
        interactive: true,
    });
    homeMarker.bindTooltip('Home', { direction: 'top', offset: [0, -8] });
    homeMarker.addTo(lmap);  // outside cluster — always visible
}

/// Draw a bezier arc from [srcLat, srcLon] toward the home point, coloured
/// `color`.  The arc is drawn as an SVG path in the Leaflet overlay pane via
/// the stroke-dashoffset trick.  A dot tracks the head; an arrival pulse ring
/// fires when it reaches the home point.  The whole assembly fades out and is
/// removed after ARC_DRAW_MS + ARC_FADE_MS.
function fireArc(srcLat, srcLon, color) {
    if (!homePt) { return; }

    const src = lmap.latLngToLayerPoint([srcLat, srcLon]);
    const dst = lmap.latLngToLayerPoint([homePt.lat, homePt.lon]);

    const dx    = dst.x - src.x;
    const dy    = dst.y - src.y;
    const chord = Math.sqrt(dx * dx + dy * dy) || 1;
    const mx    = (src.x + dst.x) / 2;
    const my    = (src.y + dst.y) / 2;

    // Perpendicular unit vector that points upward (negative y) on screen.
    // For chord vector (dx, dy) the two perpendiculars are (-dy, dx) and
    // (dy, -dx).  We choose whichever has a negative y-component so the arc
    // always bows north on the Mercator projection.
    let nx;
    let ny;
    if (Math.abs(dx) < 1) {
        // Nearly vertical chord — perpendicular is purely horizontal;
        // force upward instead.
        nx = 0; ny = -1;
    } else if (dx > 0) {
        // (dy, -dx)/chord  →  y = -dx/chord < 0  ✓
        nx = dy / chord;  ny = -dx / chord;
    } else {
        // (-dy, dx)/chord  →  y = dx/chord < 0 (dx < 0)  ✓
        nx = -dy / chord; ny =  dx / chord;
    }
    const offset = Math.min(chord * 0.4, 350);
    const cpx = mx + nx * offset;
    const cpy = my + ny * offset;

    // Build the SVG assembly in Leaflet's overlay pane.
    const NS  = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.classList.add('msmap-arc');
    svg.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;overflow:visible';

    const path = document.createElementNS(NS, 'path');
    path.setAttribute('d', 'M ' + src.x + ' ' + src.y +
                            ' Q ' + cpx + ' ' + cpy +
                            ' ' + dst.x + ' ' + dst.y);
    path.setAttribute('fill',           'none');
    path.setAttribute('stroke',         color);
    path.setAttribute('stroke-width',   '2');
    path.setAttribute('stroke-linecap', 'round');
    path.setAttribute('stroke-opacity', '0.9');

    const dot = document.createElementNS(NS, 'circle');
    dot.setAttribute('r',    '3');
    dot.setAttribute('fill', color);
    dot.setAttribute('cx',   String(src.x));
    dot.setAttribute('cy',   String(src.y));

    svg.appendChild(path);
    svg.appendChild(dot);
    lmap.getPanes().overlayPane.appendChild(svg);

    // Stroke-dashoffset draw: start hidden (offset = total length) then
    // transition to 0 so the path appears to draw itself.
    const totalLen = path.getTotalLength();
    path.style.strokeDasharray  = String(totalLen);
    path.style.strokeDashoffset = String(totalLen);
    void path.getBoundingClientRect(); // force reflow before transitioning
    path.style.transition       = 'stroke-dashoffset ' + ARC_DRAW_MS + 'ms ease-in';
    path.style.strokeDashoffset = '0';

    // Animate the dot along the arc path head.
    const t0 = performance.now();
    function step(now) {
        const frac = Math.min((now - t0) / ARC_DRAW_MS, 1.0);
        const pt   = path.getPointAtLength(frac * totalLen);
        dot.setAttribute('cx', String(pt.x));
        dot.setAttribute('cy', String(pt.y));
        if (frac < 1.0) {
            requestAnimationFrame(step);
            return;
        }
        // Arrival: small pulse ring that expands and fades at the home point.
        const ring = document.createElementNS(NS, 'circle');
        ring.setAttribute('cx',           String(dst.x));
        ring.setAttribute('cy',           String(dst.y));
        ring.setAttribute('r',            '4');
        ring.setAttribute('fill',         'none');
        ring.setAttribute('stroke',       color);
        ring.setAttribute('stroke-width', '2');
        ring.classList.add('arc-arrive-ring');
        svg.appendChild(ring);
        // Fade out the whole arc assembly.
        svg.style.transition = 'opacity ' + ARC_FADE_MS + 'ms ease-out';
        svg.style.opacity = '0';
        setTimeout(() => { svg.remove(); }, ARC_FADE_MS + 50);
    }
    requestAnimationFrame(step);
}

// Remove stale arc SVGs when the zoom level changes (layer coordinates rescale).
lmap.on('zoomstart', () => {
    lmap.getPanes().overlayPane
        .querySelectorAll('svg.msmap-arc')
        .forEach((el) => { el.remove(); });
});

// ── Polling ──────────────────────────────────────────────────────────────────

async function poll() {
    arcsFired = 0;
    await fetchHome();   // re-check for IP changes; no-op if unchanged
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
                // Fire arc for repeat connections from known IPs — each row is a
                // live incoming packet regardless of whether the IP is already mapped.
                if (!isInitialLoad && homePt && fArcs.checked && arcsFired < MAX_ARCS_POLL) {
                    fireArc(r.lat, r.lon, markerColor(r.threat));
                    arcsFired++;
                }
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
                    if (homePt && fArcs.checked && arcsFired < MAX_ARCS_POLL) {
                        fireArc(r.lat, r.lon, color);
                        arcsFired++;
                    }
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

// Fetch the home point before first poll so the marker and arcs are ready.
// /api/home is a tiny local call; the latency is negligible.
fetchHome().then(() => {
    addHomeMarker();
    loadFilters();              // restore before computeSincePreset reads fTime
    computeSincePreset();

    // Arc toggle: disabled (and unchecked) when home is not configured.
    // When home IS configured, default to on for first-time users; respect any
    // previously saved preference.
    if (!homePt) {
        fArcs.checked  = false;
        fArcs.disabled = true;
    } else {
        let hasSavedPref = false;
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            hasSavedPref = raw !== null && JSON.parse(raw).arcs !== undefined;
        } catch (_) { /* ignore */ }
        if (!hasSavedPref) { fArcs.checked = true; }
    }

    setTimeout(poll, 0);        // defer first fetch past initial map paint
    setInterval(poll, REFRESH_MS);
});

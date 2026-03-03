/* msmap – Firewall Live Map
 * Polls /api/map for aggregate markers and lazily loads raw event drilldown.
 */
'use strict';

const NORMAL_REFRESH_MS = 30000;
const HIDDEN_REFRESH_MS = 300000;
const ERROR_REFRESH_MS  = 60000;
const DETAIL_PAGE_SIZE  = 100;

const ARC_DRAW_MS   = 1200;
const ARC_FADE_MS   =  500;
const MAX_ARCS_POLL =   15;

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
    } catch (_) {}
}

function loadFilters() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) { return; }
        const s = JSON.parse(raw);
        if (s.time        !== undefined) { fTime.value         = s.time; }
        if (s.dedup       !== undefined) { fDedup.checked      = s.dedup; }
        if (s.tor         !== undefined) { fTor.checked        = s.tor; }
        if (s.datacenter  !== undefined) { fDatacenter.checked = s.datacenter; }
        if (s.residential !== undefined) { fResidential.checked = s.residential; }
        if (s.arcs        !== undefined) { fArcs.checked       = s.arcs; }
        if (s.proto       !== undefined) { fProto.value        = s.proto; }
        if (s.ip          !== undefined) { fIp.value           = s.ip; }
        if (s.port        !== undefined) { fPort.value         = s.port; }
        if (s.country     !== undefined) { fCountry.value      = s.country; }
    } catch (_) {}
}

const lmap = L.map('map', {
    center:             [20, 0],
    zoom:               2,
    minZoom:            2,
    maxBounds:          [[-90, -180], [90, 180]],
    maxBoundsViscosity: 1.0,
});

L.tileLayer(
    'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    {
        attribution:
            '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>' +
            ' contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains:        'abcd',
        maxZoom:           19,
        noWrap:            true,
        bounds:            [[-90, -180], [90, 180]],
        updateWhenIdle:    false,
        updateWhenZooming: false,
        keepBuffer:        4,
    }
).addTo(lmap);

const cluster = L.markerClusterGroup({
    showCoverageOnHover: false,
    maxClusterRadius:    50,
    chunkedLoading:      true,
    iconCreateFunction(clusterMarker) {
        const children = clusterMarker.getAllChildMarkers();
        const total = children.length;
        const nHigh = children.filter(
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

filterToggle.classList.add('active');
filterToggle.addEventListener('click', () => {
    const nowOpen = filterPanel.style.display !== 'none';
    filterPanel.style.display = nowOpen ? 'none' : '';
    filterToggle.classList.toggle('active', !nowOpen);
});

document.getElementById('f-apply').addEventListener('click', () => {
    saveFilters();
    pollNow();
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
    saveFilters();
    pollNow();
});

fDedup.addEventListener('change',       () => { saveFilters(); pollNow(); });
fTor.addEventListener('change',         () => { saveFilters(); pollNow(); });
fDatacenter.addEventListener('change',  () => { saveFilters(); pollNow(); });
fResidential.addEventListener('change', () => { saveFilters(); pollNow(); });

[fIp, fPort, fCountry].forEach((el) => {
    el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            saveFilters();
            pollNow();
        }
    });
});

let mappedCount   = 0;
let totalSeen     = 0;
let lastMapTs     = 0;
let isInitialLoad = true;
let arcsFired     = 0;
let pollTimer     = null;

let homePt     = null;
let homeMarker = null;

function currentWindowSecs() {
    const n = parseInt(fTime.value, 10);
    return (n === 900 || n === 3600 || n === 21600 || n === 86400) ? n : 900;
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

function passesFilters(r) {
    const torActive  = fTor.checked;
    const dcActive   = fDatacenter.checked;
    const resActive  = fResidential.checked;
    if (!torActive && !dcActive && !resActive) { return true; }
    if (torActive && r.is_tor === true) { return true; }
    const ut = r.usage_type ? r.usage_type.toLowerCase() : '';
    if (dcActive && (ut.includes('data center') || ut.includes('content delivery network'))) { return true; }
    if (resActive && (ut.includes('fixed line isp') || ut.includes('mobile isp'))) { return true; }
    return false;
}

function buildMapQueryString() {
    const params = new URLSearchParams();
    params.set('window', String(currentWindowSecs()));
    if (fProto.value)          { params.set('proto', fProto.value); }
    if (fIp.value.trim())      { params.set('ip', fIp.value.trim()); }
    if (fPort.value)           { params.set('port', fPort.value); }
    if (fCountry.value.trim()) { params.set('country', fCountry.value.trim().toUpperCase()); }
    return '?' + params.toString();
}

function setError(msg) {
    statError.textContent   = msg;
    statError.style.display = msg ? '' : 'none';
}

async function fetchHome() {
    try {
        const resp = await fetch('/api/home');
        if (!resp.ok) {
            if (resp.status === 404) {
                homePt = null;
                if (homeMarker) { homeMarker.remove(); homeMarker = null; }
            }
            return;
        }
        const fresh = await resp.json();
        if (!fresh || !Number.isFinite(fresh.lat) || !Number.isFinite(fresh.lon)) {
            return;
        }

        const changed = !homePt || homePt.lat !== fresh.lat || homePt.lon !== fresh.lon;
        if (changed) {
            homePt = fresh;
            if (homeMarker) { homeMarker.remove(); homeMarker = null; }
            addHomeMarker();
            fArcs.disabled = false;
        }
    } catch (_) {}
}

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
    homeMarker.addTo(lmap);
}

function fireArc(srcLat, srcLon, color) {
    if (!homePt) { return; }

    const src = lmap.latLngToLayerPoint([srcLat, srcLon]);
    const dst = lmap.latLngToLayerPoint([homePt.lat, homePt.lon]);

    const dx = dst.x - src.x;
    const dy = dst.y - src.y;
    const chord = Math.sqrt(dx * dx + dy * dy) || 1;
    const mx = (src.x + dst.x) / 2;
    const my = (src.y + dst.y) / 2;

    let nx;
    let ny;
    if (Math.abs(dx) < 1) {
        nx = 0;
        ny = -1;
    } else if (dx > 0) {
        nx = dy / chord;
        ny = -dx / chord;
    } else {
        nx = -dy / chord;
        ny = dx / chord;
    }
    const offset = Math.min(chord * 0.4, 350);
    const cpx = mx + nx * offset;
    const cpy = my + ny * offset;

    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    const mapSz = lmap.getSize();
    svg.setAttribute('width', String(mapSz.x));
    svg.setAttribute('height', String(mapSz.y));
    svg.classList.add('msmap-arc');
    svg.style.cssText = 'position:absolute;top:0;left:0;pointer-events:none;overflow:visible';

    const path = document.createElementNS(NS, 'path');
    path.setAttribute('d', 'M ' + src.x + ' ' + src.y +
                            ' Q ' + cpx + ' ' + cpy +
                            ' ' + dst.x + ' ' + dst.y);
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', color);
    path.setAttribute('stroke-width', '2');
    path.setAttribute('stroke-linecap', 'round');
    path.setAttribute('stroke-opacity', '0.9');

    const dot = document.createElementNS(NS, 'circle');
    dot.setAttribute('r', '3');
    dot.setAttribute('fill', color);
    dot.setAttribute('cx', String(src.x));
    dot.setAttribute('cy', String(src.y));

    svg.appendChild(path);
    svg.appendChild(dot);
    lmap.getPanes().overlayPane.appendChild(svg);

    const totalLen = path.getTotalLength();
    path.style.strokeDasharray = String(totalLen);
    path.style.strokeDashoffset = String(totalLen);
    void path.getBoundingClientRect();
    path.style.transition = 'stroke-dashoffset ' + ARC_DRAW_MS + 'ms ease-in';
    path.style.strokeDashoffset = '0';

    const t0 = performance.now();
    function step(now) {
        const frac = Math.min((now - t0) / ARC_DRAW_MS, 1.0);
        const pt = path.getPointAtLength(frac * totalLen);
        dot.setAttribute('cx', String(pt.x));
        dot.setAttribute('cy', String(pt.y));
        if (frac < 1.0) {
            requestAnimationFrame(step);
            return;
        }
        const ring = document.createElementNS(NS, 'circle');
        ring.setAttribute('cx', String(dst.x));
        ring.setAttribute('cy', String(dst.y));
        ring.setAttribute('r', '4');
        ring.setAttribute('fill', 'none');
        ring.setAttribute('stroke', color);
        ring.setAttribute('stroke-width', '2');
        ring.classList.add('arc-arrive-ring');
        svg.appendChild(ring);
        svg.style.transition = 'opacity ' + ARC_FADE_MS + 'ms ease-out';
        svg.style.opacity = '0';
        setTimeout(() => { svg.remove(); }, ARC_FADE_MS + 50);
    }
    requestAnimationFrame(step);
}

lmap.on('zoomstart', () => {
    lmap.getPanes().overlayPane
        .querySelectorAll('svg.msmap-arc')
        .forEach((el) => { el.remove(); });
});

function buildAggregatePopup(r) {
    const rows = [
        '<div class="popup-row">',
        '<span class="ip">' + escapeHtml(r.src_ip) + '</span><br>',
        '<span class="label">hits </span>' + r.count + '<br>',
        '<span class="label">first seen </span>' + fmtTs(r.first_ts) + '<br>',
        '<span class="label">last seen </span>' + fmtTs(r.last_ts) + '<br>',
        r.sample_dst_port !== null && r.sample_dst_port !== undefined
            ? '<span class="label">sample dst port </span>' + r.sample_dst_port + '<br>'
            : '',
        r.country ? '<span class="label">country </span>' + escapeHtml(r.country) + '<br>' : '',
        r.asn ? '<span class="label">asn </span>' + escapeHtml(r.asn) + '<br>' : '',
        (r.threat_max !== null && r.threat_max !== undefined)
            ? '<span class="label">max threat </span><span class="' + threatClass(r.threat_max) + '">'
              + threatLabel(r.threat_max) + '</span><br>'
            : '',
        r.usage_type ? '<span class="label">usage </span>' + escapeHtml(r.usage_type) + '<br>' : '',
        (r.is_tor !== null && r.is_tor !== undefined)
            ? '<span class="label">tor </span>' + (r.is_tor ? '<span class="threat-high">yes</span>' : 'no') + '<br>'
            : '',
        '<div id="detail-' + escapeHtml(r.src_ip).replace(/\./g, '-') + '">Loading recent events...</div>',
        '</div>',
    ];
    return rows.join('');
}

function buildDetailRows(rows) {
    if (!rows.length) { return '<div class="label">No recent raw events in this window.</div>'; }
    const parts = ['<div class="popup-row">'];
    for (const r of rows) {
        parts.push(
            '<div style="margin-top:6px">',
            '<span class="label">time </span>' + fmtTs(r.ts) + '<br>',
            '<span class="label">flow </span>' + escapeHtml(r.src_ip) + fmtPort(r.src_port) +
                ' &rarr; ' + escapeHtml(r.dst_ip) + fmtPort(r.dst_port) + '<br>',
            '<span class="label">proto </span>' + escapeHtml(r.proto || '?') +
                (r.tcp_flags ? ' (' + escapeHtml(r.tcp_flags) + ')' : '') + '<br>',
            '<span class="label">rule </span>' + escapeHtml(r.rule) + '<br>',
            '</div>'
        );
    }
    parts.push('</div>');
    return parts.join('');
}

async function loadDetail(marker, srcIp) {
    const popup = marker.getPopup();
    if (!popup) { return; }

    const since = Math.floor(Date.now() / 1000) - currentWindowSecs();
    const params = new URLSearchParams({
        ip: srcIp,
        since: String(since),
        limit: String(DETAIL_PAGE_SIZE),
    });

    try {
        const resp = await fetch('/api/detail?' + params.toString());
        if (!resp.ok) { return; }
        const body = await resp.json();
        const current = popup.getContent();
        const slotId = 'detail-' + srcIp.replace(/\./g, '-');
        const detail = buildDetailRows(body.rows || []);
        popup.setContent(current.replace(
            '<div id="' + slotId + '">Loading recent events...</div>',
            '<div id="' + slotId + '">' + detail + '</div>'
        ));
    } catch (_) {}
}

function renderMap(rows) {
    cluster.clearLayers();
    mappedCount = 0;
    totalSeen = 0;
    arcsFired = 0;

    for (const r of rows) {
        totalSeen += r.count;
        if (!passesFilters(r)) { continue; }
        if (r.lat === null || r.lon === null || r.lat === undefined || r.lon === undefined) {
            continue;
        }

        const threat = (r.threat_max !== undefined) ? r.threat_max : null;
        const color = markerColor(threat);
        const marker = L.circleMarker([r.lat, r.lon], {
            radius:      5,
            color:       color,
            fillColor:   color,
            fillOpacity: 0.75,
            weight:      1,
            threat:      threat,
        });
        marker.bindPopup(buildAggregatePopup(r), { maxWidth: 360 });
        marker.on('popupopen', () => { void loadDetail(marker, r.src_ip); });
        cluster.addLayer(marker);
        mappedCount++;

        if (!isInitialLoad && homePt && fArcs.checked && arcsFired < MAX_ARCS_POLL && r.last_ts > lastMapTs) {
            fireArc(r.lat, r.lon, color);
            arcsFired++;
        }
    }
}

function scheduleNextPoll(delayMs) {
    if (pollTimer !== null) {
        clearTimeout(pollTimer);
    }
    pollTimer = setTimeout(() => { void poll(); }, delayMs);
}

async function poll() {
    await fetchHome();
    try {
        const resp = await fetch('/api/map' + buildMapQueryString(), { cache: 'default' });
        if (!resp.ok) {
            setError('API ' + resp.status);
            scheduleNextPoll(ERROR_REFRESH_MS);
            return;
        }

        const body = await resp.json();
        const rows = Array.isArray(body.rows) ? body.rows : [];
        setError('');
        renderMap(rows);

        let newestTs = 0;
        for (const r of rows) {
            if (typeof r.last_ts === 'number' && r.last_ts > newestTs) {
                newestTs = r.last_ts;
            }
        }
        lastMapTs = newestTs;
        statMapped.textContent = mappedCount.toLocaleString() + ' mapped';
        statTotal.textContent  = totalSeen.toLocaleString() + ' total';
        statTime.textContent   = 'updated ' + new Date().toLocaleTimeString();
        isInitialLoad = false;

        scheduleNextPoll(document.visibilityState === 'hidden' ? HIDDEN_REFRESH_MS : NORMAL_REFRESH_MS);
    } catch (err) {
        setError(err.message);
        scheduleNextPoll(ERROR_REFRESH_MS);
    }
}

function pollNow() {
    isInitialLoad = true;
    lastMapTs = 0;
    statMapped.textContent = '0 mapped';
    statTotal.textContent  = '0 total';
    void poll();
}

document.addEventListener('visibilitychange', () => {
    scheduleNextPoll(document.visibilityState === 'hidden' ? HIDDEN_REFRESH_MS : NORMAL_REFRESH_MS);
});

fetchHome().then(() => {
    addHomeMarker();
    loadFilters();

    if (!homePt) {
        fArcs.checked  = false;
        fArcs.disabled = true;
    } else {
        let hasSavedPref = false;
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            hasSavedPref = raw !== null && JSON.parse(raw).arcs !== undefined;
        } catch (_) {}
        if (!hasSavedPref) { fArcs.checked = true; }
    }

    pollNow();
});

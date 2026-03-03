/* msmap – Firewall Live Map
 * Polls /api/map for aggregate markers and lazily loads raw event drilldown.
 */
'use strict';

const NORMAL_REFRESH_MS = 30000;
const HIDDEN_REFRESH_MS = 300000;
const ERROR_REFRESH_MS  = 60000;
const STATUS_REFRESH_MS = 60000;
const DETAIL_PAGE_SIZE  = 20;
const TEXT_FILTER_DEBOUNCE_MS = 400;

const ARC_DRAW_MS   =  800;
const ARC_FADE_MS   =  300;
const MAX_ARCS_POLL =   10;

const STORAGE_KEY = 'msmap_filters';
const DEFAULT_FILTERS = Object.freeze({
    time: '900',
    proto: '',
    ip: '',
    port: '',
    country: '',
    animations: 'on',
});

const appliedTextFilters = {
    ip: DEFAULT_FILTERS.ip,
    port: DEFAULT_FILTERS.port,
    country: DEFAULT_FILTERS.country,
};

let textApplyTimer = null;

function currentFilterState() {
    return {
        time:        fTime.value,
        proto:       fProto.value,
        ip:          appliedTextFilters.ip,
        port:        appliedTextFilters.port,
        country:     appliedTextFilters.country,
        animations:  fAnimations.value,
    };
}

function writeFiltersToUrl() {
    const state = currentFilterState();
    const params = new URLSearchParams();
    if (state.time !== DEFAULT_FILTERS.time)               { params.set('window', state.time); }
    if (state.proto)                                       { params.set('proto', state.proto); }
    if (state.ip)                                          { params.set('ip', state.ip); }
    if (state.port)                                        { params.set('port', state.port); }
    if (state.country)                                     { params.set('country', state.country); }
    if (state.animations !== DEFAULT_FILTERS.animations)   { params.set('animations', state.animations); }
    const next = params.toString();
    const base = window.location.pathname || '/';
    const target = next ? (base + '?' + next) : base;
    history.replaceState(null, '', target);
}

function saveFilters() {
    writeFiltersToUrl();
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(currentFilterState()));
    } catch (_) {}
}

function parseUrlFilterState() {
    const params = new URLSearchParams(window.location.search);
    const state = {};
    let found = false;

    const setIfPresent = (param, key) => {
        if (!params.has(param)) { return; }
        state[key] = params.get(param) ?? '';
        found = true;
    };

    setIfPresent('window', 'time');
    setIfPresent('proto', 'proto');
    setIfPresent('ip', 'ip');
    setIfPresent('port', 'port');
    setIfPresent('country', 'country');
    setIfPresent('animations', 'animations');

    return found ? state : null;
}

function readStoredFilters() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        return raw ? JSON.parse(raw) : null;
    } catch (_) {
        return null;
    }
}

function loadFilters() {
    const s = parseUrlFilterState() || readStoredFilters();
    if (!s) {
        return;
    }

    if (s.time        !== undefined) { setSelectValue(fTime, s.time, DEFAULT_FILTERS.time); }
    if (s.proto       !== undefined) { setSelectValue(fProto, s.proto, DEFAULT_FILTERS.proto); }
    if (s.ip          !== undefined) { fIp.value = s.ip; }
    if (s.port        !== undefined) { fPort.value = s.port; }
    if (s.country     !== undefined) { fCountry.value = s.country; }
    if (s.animations  !== undefined) { setSelectValue(fAnimations, s.animations, DEFAULT_FILTERS.animations); }
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
        const nHigh = children.filter(m => m.options.severity === 'high').length;
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
const statEvents    = document.getElementById('stat-events');
const statSources   = document.getElementById('stat-sources');
const statIntel     = document.getElementById('stat-intel');
const statMappedValue = document.getElementById('stat-mapped-value');
const statTotalValue  = document.getElementById('stat-total-value');
const statTimeValue   = document.getElementById('stat-time-value');
const statEventsValue = document.getElementById('stat-events-value');
const statSourcesValue = document.getElementById('stat-sources-value');
const statIntelValue = document.getElementById('stat-intel-value');
const statError     = document.getElementById('stat-error');
const filterPanel   = document.getElementById('filter-panel');
const filterToggle  = document.getElementById('filter-toggle');
const fTime         = document.getElementById('f-time');
const fProto        = document.getElementById('f-proto');
const fIp           = document.getElementById('f-ip');
const fPort         = document.getElementById('f-port');
const fCountry      = document.getElementById('f-country');
const fAnimations   = document.getElementById('f-animations');
const legendHome    = document.getElementById('legend-home');
const statDot       = statTime.querySelector('.status-dot');
const statusOpSeparators = Array.from(document.querySelectorAll('.status-sep-ops'));

filterToggle.classList.add('active');
filterToggle.addEventListener('click', () => {
    const nowOpen = filterPanel.style.display !== 'none';
    filterPanel.style.display = nowOpen ? 'none' : '';
    filterToggle.classList.toggle('active', !nowOpen);
});

let mappedCount   = 0;
let totalSeen     = 0;
let lastMapTs     = 0;
let isInitialLoad = true;
let pollTimer     = null;
let pollInFlight  = false;
let pollQueued    = false;
let activePopupIp = '';
let suppressPopupAutoClose = false;
let lastMapSuccessAt = 0;
let mapFeedState = 'unknown';
let lastStatus = null;
let statusPollTimer = null;
let statusInFlight = false;

let homePt     = null;
let homeMarker = null;
// Stop retrying /api/home after a stable 404; the config only changes on reload.
let homeFetchDisabled = false;
const seenMarkerIps = new Set();
const detailStateByIp = new Map();
const activeArcs = new Set();

function isMobileMapUi() {
    return window.matchMedia('(max-width: 700px) and (pointer: coarse)').matches;
}

function animationsEnabled() {
    return fAnimations.value === 'on';
}

function currentWindowSecs() {
    const n = parseInt(fTime.value, 10);
    return (n === 900 || n === 3600 || n === 21600 || n === 86400) ? n : 900;
}

function setSelectValue(el, value, fallback) {
    const normalized = String(value);
    const allowed = Array.from(el.options, (option) => option.value);
    el.value = allowed.includes(normalized) ? normalized : fallback;
}

function setInputValidity(el, valid) {
    el.classList.toggle('filter-input-invalid', !valid);
    if (valid) {
        el.removeAttribute('title');
        return;
    }
    el.title = 'Enter a complete valid value or clear the field.';
}

function isValidIpv4(value) {
    const parts = value.split('.');
    if (parts.length !== 4) { return false; }
    return parts.every((part) => {
        if (!/^\d{1,3}$/.test(part)) { return false; }
        const num = Number(part);
        return num >= 0 && num <= 255;
    });
}

function isValidIpv6(value) {
    if (!/^[0-9A-Fa-f:.]+$/.test(value) || value.includes(':::')) {
        return false;
    }

    const doubleColon = value.indexOf('::');
    if (doubleColon !== -1 && value.indexOf('::', doubleColon + 1) !== -1) {
        return false;
    }

    const groups = [];
    const addGroups = (segment) => {
        if (!segment) { return true; }
        for (const part of segment.split(':')) {
            if (!part) { return false; }
            if (part.includes('.')) {
                if (part !== segment.split(':').at(-1) || !isValidIpv4(part)) {
                    return false;
                }
                groups.push('ipv4');
                continue;
            }
            if (!/^[0-9A-Fa-f]{1,4}$/.test(part)) { return false; }
            groups.push(part);
        }
        return true;
    };

    if (doubleColon === -1) {
        if (!addGroups(value)) { return false; }
        const count = groups.reduce((sum, group) => sum + (group === 'ipv4' ? 2 : 1), 0);
        return count === 8;
    }

    const left = value.slice(0, doubleColon);
    const right = value.slice(doubleColon + 2);
    if (!addGroups(left) || !addGroups(right)) { return false; }
    const count = groups.reduce((sum, group) => sum + (group === 'ipv4' ? 2 : 1), 0);
    return count < 8;
}

function validateIpValue(value) {
    const trimmed = value.trim();
    if (!trimmed) {
        return { valid: true, normalized: '' };
    }
    const valid = isValidIpv4(trimmed) || isValidIpv6(trimmed);
    return { valid, normalized: valid ? trimmed : appliedTextFilters.ip };
}

function validatePortValue(value) {
    const trimmed = value.trim();
    if (!trimmed) {
        return { valid: true, normalized: '' };
    }
    if (!/^\d+$/.test(trimmed)) {
        return { valid: false, normalized: appliedTextFilters.port };
    }
    const port = Number(trimmed);
    if (port < 1 || port > 65535) {
        return { valid: false, normalized: appliedTextFilters.port };
    }
    return { valid: true, normalized: String(port) };
}

function validateCountryValue(value) {
    const trimmed = value.trim().toUpperCase();
    if (!trimmed) {
        return { valid: true, normalized: '' };
    }
    const valid = /^[A-Z]{2}$/.test(trimmed);
    return { valid, normalized: valid ? trimmed : appliedTextFilters.country };
}

function updateTextValidity() {
    const ip = validateIpValue(fIp.value);
    const port = validatePortValue(fPort.value);
    const country = validateCountryValue(fCountry.value);
    setInputValidity(fIp, ip.valid);
    setInputValidity(fPort, port.valid);
    setInputValidity(fCountry, country.valid);
    return { ip, port, country };
}

function applyTextFilters() {
    const validation = updateTextValidity();
    let changed = false;

    if (validation.ip.valid && appliedTextFilters.ip !== validation.ip.normalized) {
        appliedTextFilters.ip = validation.ip.normalized;
        changed = true;
    }
    if (validation.port.valid && appliedTextFilters.port !== validation.port.normalized) {
        appliedTextFilters.port = validation.port.normalized;
        changed = true;
    }
    if (validation.country.valid && appliedTextFilters.country !== validation.country.normalized) {
        appliedTextFilters.country = validation.country.normalized;
        changed = true;
    }

    if (validation.ip.valid) {
        fIp.value = validation.ip.normalized;
    }
    if (validation.port.valid) {
        fPort.value = validation.port.normalized;
    }
    if (validation.country.valid) {
        fCountry.value = validation.country.normalized;
    }

    if (changed) {
        saveFilters();
        pollNow();
    }
}

function scheduleTextApply() {
    if (textApplyTimer !== null) {
        clearTimeout(textApplyTimer);
    }
    textApplyTimer = setTimeout(() => {
        textApplyTimer = null;
        applyTextFilters();
    }, TEXT_FILTER_DEBOUNCE_MS);
}

function resetToDefaults() {
    if (textApplyTimer !== null) {
        clearTimeout(textApplyTimer);
        textApplyTimer = null;
    }
    fTime.value         = DEFAULT_FILTERS.time;
    fProto.value        = DEFAULT_FILTERS.proto;
    fAnimations.value   = DEFAULT_FILTERS.animations;
    fIp.value           = DEFAULT_FILTERS.ip;
    fPort.value         = DEFAULT_FILTERS.port;
    fCountry.value      = DEFAULT_FILTERS.country;

    appliedTextFilters.ip      = DEFAULT_FILTERS.ip;
    appliedTextFilters.port    = DEFAULT_FILTERS.port;
    appliedTextFilters.country = DEFAULT_FILTERS.country;
    updateTextValidity();
    clearActiveArcs();
    saveFilters();
    pollNow();
}

function applyNonTextFilters() {
    clearActiveArcs();
    saveFilters();
    pollNow();
}

document.getElementById('f-defaults').addEventListener('click', resetToDefaults);
fTime.addEventListener('change', applyNonTextFilters);
fProto.addEventListener('change', applyNonTextFilters);
fAnimations.addEventListener('change', applyNonTextFilters);

[fIp, fPort, fCountry].forEach((el) => {
    el.addEventListener('input', () => {
        updateTextValidity();
        scheduleTextApply();
    });
    el.addEventListener('blur', () => {
        if (textApplyTimer !== null) {
            clearTimeout(textApplyTimer);
            textApplyTimer = null;
        }
        applyTextFilters();
    });
    el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            if (textApplyTimer !== null) {
                clearTimeout(textApplyTimer);
                textApplyTimer = null;
            }
            applyTextFilters();
        }
    });
});

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

function markerSeverity(row) {
    if (row.spamhaus_drop === true) { return 'high'; }
    const threat = row.threat_max;
    if (threat === null || threat === undefined) { return 'unknown'; }
    if (threat === 0)   { return 'clean'; }
    if (threat <= 33)   { return 'low'; }
    if (threat <= 66)   { return 'medium'; }
    return 'high';
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
    return true;
}

function detailSlotId(srcIp) {
    return 'detail-' + srcIp.replace(/[^A-Za-z0-9_-]/g, '-');
}

function detailStateLabel(state) {
    const total = state.rows.length;
    if (!state.nextCursor) {
        return String(total);
    }
    return total + '+';
}

function setStatusCounts(mapped, total) {
    statMappedValue.textContent = mapped.toLocaleString();
    statTotalValue.textContent = total.toLocaleString();
}

function setStatusFreshness(text) {
    statTimeValue.textContent = text;
}

function formatCompactCount(value) {
    return new Intl.NumberFormat(undefined, {
        notation: 'compact',
        maximumFractionDigits: 1,
    }).format(value);
}

function setOperatorStatus(status) {
    lastStatus = status;
    if (!status || status.ok !== true) {
        statEvents.style.display = 'none';
        statSources.style.display = 'none';
        statIntel.style.display = 'none';
        statusOpSeparators.forEach((el) => {
            el.style.display = 'none';
        });
        return;
    }

    statEvents.style.display = '';
    statSources.style.display = '';
    statIntel.style.display = '';
    statusOpSeparators.forEach((el) => {
        el.style.display = '';
    });

    statEventsValue.textContent = formatCompactCount(status.rows_24h ?? 0);
    statSourcesValue.textContent = formatCompactCount(status.distinct_sources_24h ?? 0);

    statIntelValue.classList.remove('status-state-ok', 'status-state-stale', 'status-state-off', 'status-state-syncing');
    if (status.intel_enabled !== true) {
        statIntelValue.textContent = 'off';
        statIntelValue.classList.add('status-state-off');
        return;
    }

    const now = Number.isFinite(status.now) ? status.now : Math.floor(Date.now() / 1000);
    const refreshTs = Number.isFinite(status.intel_last_refresh_ts) ? status.intel_last_refresh_ts : 0;
    if (refreshTs <= 0) {
        statIntelValue.textContent = 'syncing';
        statIntelValue.classList.add('status-state-syncing');
    } else if ((now - refreshTs) <= (12 * 3600)) {
        statIntelValue.textContent = 'ok';
        statIntelValue.classList.add('status-state-ok');
    } else {
        statIntelValue.textContent = 'stale';
        statIntelValue.classList.add('status-state-stale');
    }
}

function setMapFeedState(nextState) {
    mapFeedState = nextState;
    statDot.classList.remove('is-unknown', 'is-healthy', 'is-stale');
    statDot.classList.add(
        nextState === 'healthy' ? 'is-healthy' :
        nextState === 'stale' ? 'is-stale' :
        'is-unknown'
    );
}

function setHomeLegendVisible(visible) {
    legendHome.style.display = visible ? '' : 'none';
}

async function fetchStatus() {
    if (statusInFlight) {
        return;
    }
    statusInFlight = true;
    try {
        const resp = await fetch('/api/status', { cache: 'default' });
        if (!resp.ok) {
            setOperatorStatus(null);
            return;
        }
        const body = await resp.json();
        setOperatorStatus(body);
    } catch (_) {
        setOperatorStatus(null);
    } finally {
        statusInFlight = false;
    }
}

function scheduleStatusPoll(delayMs = STATUS_REFRESH_MS) {
    if (document.visibilityState === 'hidden') {
        if (statusPollTimer !== null) {
            clearTimeout(statusPollTimer);
            statusPollTimer = null;
        }
        return;
    }
    if (statusPollTimer !== null) {
        clearTimeout(statusPollTimer);
    }
    statusPollTimer = setTimeout(() => {
        statusPollTimer = null;
        void fetchStatus().then(() => {
            if (document.visibilityState === 'visible') {
                scheduleStatusPoll(STATUS_REFRESH_MS);
            }
        });
    }, delayMs);
}

function updateMapFeedIndicator(now = Date.now()) {
    if (lastMapSuccessAt === 0) {
        setMapFeedState('unknown');
        return;
    }
    const staleAfterMs = NORMAL_REFRESH_MS * 2;
    setMapFeedState((now - lastMapSuccessAt) <= staleAfterMs ? 'healthy' : 'stale');
}

function ensureDetailState(srcIp) {
    const windowSecs = currentWindowSecs();
    const existing = detailStateByIp.get(srcIp);
    if (existing && existing.windowSecs === windowSecs) {
        return existing;
    }

    const fresh = {
        rows: [],
        selectedIndex: 0,
        nextCursor: '',
        loading: false,
        error: '',
        loaded: false,
        windowSecs: windowSecs,
    };
    detailStateByIp.set(srcIp, fresh);
    return fresh;
}

function buildMapQueryString() {
    const params = new URLSearchParams();
    params.set('window', String(currentWindowSecs()));
    if (fProto.value)               { params.set('proto', fProto.value); }
    if (appliedTextFilters.ip)      { params.set('ip', appliedTextFilters.ip); }
    if (appliedTextFilters.port)    { params.set('port', appliedTextFilters.port); }
    if (appliedTextFilters.country) { params.set('country', appliedTextFilters.country); }
    return '?' + params.toString();
}

function buildThreatChip(score) {
    if (score === null || score === undefined) { return ''; }
    return '<span class="popup-chip ' + threatClass(score) + '">Threat ' + score + '</span>';
}

function greyNoiseIconSvg() {
    return '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5a6.5 6.5 0 1 0 0 13a6.5 6.5 0 0 0 0-13Zm0 1.5a5 5 0 0 1 4.74 3.4H8.8l-.96 1.66H3.18A5 5 0 0 1 8 3Zm-4.82 6.5h3.79L8 7.84l1.03 1.66h3.79A5 5 0 0 1 8 13a5 5 0 0 1-4.82-3.5Z"/></svg>';
}

function abuseIpdbIconSvg() {
    return '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1l5 2v3.9c0 3.2-2.08 6.1-5 7.1c-2.92-1-5-3.9-5-7.1V3l5-2Zm0 2.1L5 4.25V6.9c0 2.18 1.27 4.28 3 5.17c1.73-.89 3-2.99 3-5.17V4.25L8 3.1Zm-.75 1.9h1.5v3.2h2.15v1.4H7.25V5Z"/></svg>';
}

function otxIconSvg() {
    return '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5a6.5 6.5 0 1 0 0 13a6.5 6.5 0 0 0 0-13Zm0 1.5a5 5 0 0 1 4.46 2.74H9.72l-.9 1.56l.9 1.56h2.74A5 5 0 0 1 8 13a5 5 0 0 1-4.46-2.58h2.74l.9-1.56l-.9-1.56H3.54A5 5 0 0 1 8 3Zm-.62 2.74h1.24l1.77 3.06L8.62 11.9H7.38L5.61 8.8l1.77-3.06Z"/></svg>';
}

function shodanIconSvg() {
    return '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5a6.5 6.5 0 1 0 0 13A6.5 6.5 0 0 0 8 1.5Zm0 1.5a5 5 0 0 1 4.66 3.2H8.7V5.1H7.3v2.1h5.58A5 5 0 0 1 8 13a5 5 0 0 1-4.88-4.1H7.3v2h1.4v-2h3.92A5 5 0 0 1 8 3Z"/></svg>';
}

function buildIntelBadges(r) {
    const chips = [];
    const threat = buildThreatChip(r.threat_max);
    if (threat) { chips.push(threat); }
    if (r.tor_exit === true) {
        chips.push('<span class="popup-chip popup-chip-intel">Tor exit</span>');
    }
    if (r.spamhaus_drop === true) {
        chips.push('<span class="popup-chip popup-chip-intel">DROP</span>');
    }
    if (!chips.length) { return ''; }
    return '<div class="popup-chip-row">' + chips.join('') + '</div>';
}

function buildLinkouts(srcIp) {
    const safeIp = encodeURIComponent(srcIp);
    const links = [
        {
            href: 'https://viz.greynoise.io/ip/' + safeIp,
            icon: greyNoiseIconSvg(),
            title: 'Open GreyNoise',
        },
        {
            href: 'https://www.shodan.io/host/' + safeIp,
            icon: shodanIconSvg(),
            title: 'Open Shodan',
        },
        {
            href: 'https://www.abuseipdb.com/check/' + safeIp,
            icon: abuseIpdbIconSvg(),
            title: 'Open AbuseIPDB',
        },
        {
            href: 'https://otx.alienvault.com/indicator/ip/' + safeIp,
            icon: otxIconSvg(),
            title: 'Open AlienVault OTX',
        },
    ];
    return '<div class="popup-linkouts">' + links.map((link) =>
        '<a class="popup-linkout" href="' + link.href + '" target="_blank" rel="noopener noreferrer" title="' +
        link.title + '" aria-label="' + link.title + '">' + link.icon + '</a>'
    ).join('') + '</div>';
}

function buildSummaryItem(label, value, wide = false) {
    if (value === null || value === undefined || value === '') { return ''; }
    return [
        '<div class="popup-meta-item',
        wide ? ' popup-meta-item-wide' : '',
        '">',
        '<span class="label">', label, '</span>',
        '<span class="popup-meta-value">', value, '</span>',
        '</div>',
    ].join('');
}

function buildAggregateSummary(r) {
    const metaItems = [
        buildSummaryItem('Hits', escapeHtml(String(r.count))),
        buildSummaryItem(
            'Sample dst port',
            r.sample_dst_port !== null && r.sample_dst_port !== undefined
                ? escapeHtml(String(r.sample_dst_port))
                : ''
        ),
        buildSummaryItem('First seen', escapeHtml(fmtTs(r.first_ts))),
        buildSummaryItem('Last seen', escapeHtml(fmtTs(r.last_ts))),
        buildSummaryItem('Country', r.country ? escapeHtml(r.country) : ''),
        buildSummaryItem('ASN', r.asn ? escapeHtml(r.asn) : '', true),
    ].filter(Boolean).join('');

    return [
        '<div class="popup-summary">',
        '<div class="popup-header">',
        '<span class="ip">' + escapeHtml(r.src_ip) + '</span>',
        '<div class="popup-subtitle">Aggregate source activity in the selected window</div>',
        '</div>',
        '<div class="popup-meta-grid">' + metaItems + '</div>',
        buildIntelBadges(r),
        r.usage_type ? '<div class="popup-usage"><span class="label">usage </span>' +
            escapeHtml(r.usage_type) + '</div>' : '',
        buildLinkouts(r.src_ip),
        '</div>',
    ].join('');
}

function buildDetailCard(row) {
    return [
        '<div class="popup-detail-card">',
        '<div class="popup-detail-row"><span class="label">time </span>' + fmtTs(row.ts) + '</div>',
        '<div class="popup-detail-row popup-flow"><span class="label">flow </span><span class="mono">' + escapeHtml(row.src_ip) +
            fmtPort(row.src_port) + '</span> &rarr; <span class="mono">' +
            escapeHtml(row.dst_ip) + fmtPort(row.dst_port) + '</span></div>',
        '<div class="popup-detail-row"><span class="label">proto </span><span class="mono">' + escapeHtml(row.proto || '?') +
            (row.tcp_flags ? ' (' + escapeHtml(row.tcp_flags) + ')' : '') + '</span></div>',
        '<div class="popup-detail-row"><span class="label">rule </span>' + escapeHtml(row.rule) + '</div>',
        '</div>',
    ].join('');
}

function buildDetailPane(srcIp) {
    const state = ensureDetailState(srcIp);
    const slotId = detailSlotId(srcIp);

    if ((!state.loaded && !state.error) || (state.loading && state.rows.length === 0)) {
        return '<div id="' + slotId + '" class="popup-detail-state">Loading recent events...</div>';
    }

    if (state.error && state.rows.length === 0) {
        return [
            '<div id="' + slotId + '" class="popup-detail-state popup-detail-error">',
            '<div>' + escapeHtml(state.error) + '</div>',
            '<button type="button" class="popup-detail-button" data-action="retry" data-ip="' +
                escapeHtml(srcIp) + '">Retry</button>',
            '</div>',
        ].join('');
    }

    if (!state.rows.length) {
        return '<div id="' + slotId + '" class="popup-detail-state">No recent events in selected window.</div>';
    }

    const row = state.rows[state.selectedIndex];
    const disableNewer = state.selectedIndex === 0 || state.loading ? ' disabled' : '';
    const atOldestLoaded = state.selectedIndex >= state.rows.length - 1;
    const disablePrev = (atOldestLoaded && !state.nextCursor) || state.loading ? ' disabled' : '';

    return [
        '<div id="' + slotId + '" class="popup-detail-wrap">',
        '<div class="popup-detail-heading">Recent events</div>',
        buildDetailCard(row),
        '<div class="popup-detail-nav">',
        '<button type="button" class="popup-detail-button" data-action="older" data-ip="' +
            escapeHtml(srcIp) + '"' + disablePrev + '>&larr;</button>',
        '<span class="popup-detail-position">' + (state.selectedIndex + 1) + ' / ' +
            detailStateLabel(state) + '</span>',
        '<button type="button" class="popup-detail-button" data-action="newer" data-ip="' +
            escapeHtml(srcIp) + '"' + disableNewer + '>&rarr;</button>',
        '</div>',
        state.loading ? '<div class="popup-detail-hint">Loading older events...</div>' : '',
        '</div>',
    ].join('');
}

function setError(msg) {
    statError.textContent   = msg;
    statError.style.display = msg ? '' : 'none';
}

async function fetchHome() {
    if (homeFetchDisabled) {
        return;
    }
    try {
        const resp = await fetch('/api/home');
        if (!resp.ok) {
            if (resp.status === 404) {
                clearActiveArcs();
                homePt = null;
                if (homeMarker) { homeMarker.remove(); homeMarker = null; }
                setHomeLegendVisible(false);
                homeFetchDisabled = true;
            }
            return;
        }
        homeFetchDisabled = false;
        const fresh = await resp.json();
        if (!fresh || !Number.isFinite(fresh.lat) || !Number.isFinite(fresh.lon)) {
            return;
        }

        const changed = !homePt || homePt.lat !== fresh.lat || homePt.lon !== fresh.lon;
        if (changed) {
            clearActiveArcs();
            homePt = fresh;
            if (homeMarker) { homeMarker.remove(); homeMarker = null; }
            addHomeMarker();
        }
    } catch (_) {}
}

function addHomeMarker() {
    if (!homePt || homeMarker) { return; }
    setHomeLegendVisible(true);
    homeMarker = L.circleMarker([homePt.lat, homePt.lon], {
        radius:      8,
        color:       '#58a6ff',
        fillColor:   '#58a6ff',
        fillOpacity: 0.10,
        weight:      2.5,
        interactive: true,
    });
    homeMarker.bindTooltip('Home', { direction: 'top', offset: [0, -8] });
    homeMarker.addTo(lmap);
}

function shortestWrappedLon(srcLon, dstLon) {
    let best = srcLon;
    let bestDistance = Math.abs(srcLon - dstLon);
    for (const candidate of [srcLon - 360, srcLon + 360]) {
        const distance = Math.abs(candidate - dstLon);
        if (distance < bestDistance) {
            best = candidate;
            bestDistance = distance;
        }
    }
    return best;
}

function clearActiveArcs() {
    for (const arcState of activeArcs) {
        if (arcState.rafId !== null) {
            cancelAnimationFrame(arcState.rafId);
        }
        if (arcState.removeTimeoutId !== null) {
            clearTimeout(arcState.removeTimeoutId);
        }
        arcState.svg.remove();
    }
    activeArcs.clear();
}

function fireArc(srcLat, srcLon, color) {
    if (!homePt) { return; }

    const wrappedSrcLon = shortestWrappedLon(srcLon, homePt.lon);
    const src = lmap.latLngToLayerPoint([srcLat, wrappedSrcLon]);
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

    const arcState = {
        svg: svg,
        rafId: null,
        removeTimeoutId: null,
    };
    activeArcs.add(arcState);

    const totalLen = path.getTotalLength();
    path.style.strokeDasharray = String(totalLen);
    path.style.strokeDashoffset = String(totalLen);
    void path.getBoundingClientRect();
    path.style.transition = 'stroke-dashoffset ' + ARC_DRAW_MS + 'ms ease-in';
    path.style.strokeDashoffset = '0';

    const t0 = performance.now();
    function step(now) {
        if (!activeArcs.has(arcState)) { return; }

        const frac = Math.min((now - t0) / ARC_DRAW_MS, 1.0);
        const pt = path.getPointAtLength(frac * totalLen);
        dot.setAttribute('cx', String(pt.x));
        dot.setAttribute('cy', String(pt.y));
        if (frac < 1.0) {
            arcState.rafId = requestAnimationFrame(step);
            return;
        }
        arcState.rafId = null;
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
        arcState.removeTimeoutId = setTimeout(() => {
            svg.remove();
            activeArcs.delete(arcState);
            arcState.removeTimeoutId = null;
        }, ARC_FADE_MS + 50);
    }
    arcState.rafId = requestAnimationFrame(step);
}

lmap.on('zoomstart', clearActiveArcs);

function shouldCandidateArc(row) {
    return !isInitialLoad &&
        homePt &&
        animationsEnabled() &&
        typeof row.last_ts === 'number' &&
        row.last_ts > lastMapTs &&
        Number.isFinite(row.lat) &&
        Number.isFinite(row.lon);
}

function arcOriginKey(lat, lon) {
    const roundedLat = Math.round(lat * 2) / 2;
    const roundedLon = Math.round(lon * 2) / 2;
    return String(roundedLat) + ':' + String(roundedLon);
}

function makeArcCandidate(row, color) {
    return {
        srcIp: row.src_ip,
        lat: row.lat,
        lon: row.lon,
        lastTs: row.last_ts,
        threat: (row.threat_max !== null && row.threat_max !== undefined) ? row.threat_max : -1,
        count: Number.isFinite(row.count) ? row.count : 0,
        color: color,
        dedupeKey: arcOriginKey(row.lat, row.lon),
    };
}

function compareArcCandidates(left, right) {
    if (left.lastTs !== right.lastTs) { return right.lastTs - left.lastTs; }
    if (left.threat !== right.threat) { return right.threat - left.threat; }
    if (left.count !== right.count) { return right.count - left.count; }
    return left.srcIp.localeCompare(right.srcIp);
}

function dedupeArcCandidates(candidates) {
    const seenKeys = new Set();
    const deduped = [];
    for (const candidate of candidates) {
        if (seenKeys.has(candidate.dedupeKey)) { continue; }
        seenKeys.add(candidate.dedupeKey);
        deduped.push(candidate);
    }
    return deduped;
}

function renderArcBatch(candidates) {
    const ranked = candidates.slice().sort(compareArcCandidates);
    for (const candidate of dedupeArcCandidates(ranked).slice(0, MAX_ARCS_POLL)) {
        fireArc(candidate.lat, candidate.lon, candidate.color);
    }
}

function buildAggregatePopup(r) {
    return [
        '<div class="popup-row">',
        buildAggregateSummary(r),
        buildDetailPane(r.src_ip),
        '</div>',
    ].join('');
}

function updatePopupContent(marker, row) {
    marker.setPopupContent(buildAggregatePopup(row));
    if (marker.isPopupOpen()) {
        bindPopupControls(marker, row);
    }
}

async function fetchDetailPage(srcIp, cursor) {
    const since = Math.floor(Date.now() / 1000) - currentWindowSecs();
    const params = new URLSearchParams({
        ip: srcIp,
        since: String(since),
        limit: String(DETAIL_PAGE_SIZE),
    });
    if (cursor) { params.set('cursor', cursor); }

    const resp = await fetch('/api/detail?' + params.toString());
    if (!resp.ok) {
        throw new Error('detail unavailable');
    }
    return resp.json();
}

async function loadDetail(marker, row, cursor) {
    const state = ensureDetailState(row.src_ip);
    if (state.loading) { return; }

    state.loading = true;
    state.error = '';
    updatePopupContent(marker, row);
    try {
        const body = await fetchDetailPage(row.src_ip, cursor);
        const rows = Array.isArray(body.rows) ? body.rows : [];
        if (cursor) {
            state.rows = state.rows.concat(rows);
        } else {
            state.rows = rows;
            state.selectedIndex = 0;
        }
        state.nextCursor = Number.isInteger(body.next_cursor) && body.next_cursor >= 0
            ? String(body.next_cursor)
            : '';
        state.loaded = true;
    } catch (_) {
        state.error = 'Could not load recent events.';
        state.loaded = true;
    } finally {
        state.loading = false;
        updatePopupContent(marker, row);
    }
}

async function showOlderDetail(marker, row) {
    const state = ensureDetailState(row.src_ip);
    if (state.loading) { return; }
    if (state.selectedIndex < state.rows.length - 1) {
        state.selectedIndex++;
        updatePopupContent(marker, row);
        return;
    }
    if (!state.nextCursor) { return; }

    const priorLength = state.rows.length;
    await loadDetail(marker, row, state.nextCursor);
    if (state.rows.length > priorLength) {
        state.selectedIndex = priorLength;
        updatePopupContent(marker, row);
    }
}

function showNewerDetail(marker, row) {
    const state = ensureDetailState(row.src_ip);
    if (state.loading || state.selectedIndex === 0) { return; }
    state.selectedIndex--;
    updatePopupContent(marker, row);
}

function bindPopupControls(marker, row) {
    const popup = marker.getPopup();
    const popupEl = popup ? popup.getElement() : null;
    if (!popupEl) { return; }

    if (popupEl.dataset.mmPopupControlsBound === '1') { return; }

    popupEl.dataset.mmPopupControlsBound = '1';
    L.DomEvent.disableClickPropagation(popupEl);
    L.DomEvent.disableScrollPropagation(popupEl);

    ['mousedown', 'pointerdown', 'dblclick'].forEach((eventName) => {
        popupEl.addEventListener(eventName, (event) => {
            if (!event.target.closest('[data-action]')) { return; }
            event.stopPropagation();
        });
    });

    popupEl.addEventListener('click', (event) => {
        const button = event.target.closest('[data-action]');
        if (!button || !popupEl.contains(button)) { return; }

        event.preventDefault();
        event.stopPropagation();

        const action = button.getAttribute('data-action');
        if (action === 'retry') {
            const state = ensureDetailState(row.src_ip);
            state.rows = [];
            state.selectedIndex = 0;
            state.nextCursor = '';
            state.loaded = false;
            void loadDetail(marker, row, '');
            return;
        }
        if (action === 'older') {
            void showOlderDetail(marker, row);
            return;
        }
        if (action === 'newer') {
            showNewerDetail(marker, row);
        }
    });
}

function maybeAnimateMarker(marker, srcIp) {
    if (seenMarkerIps.has(srcIp) || !animationsEnabled()) { return; }
    const el = marker.getElement();
    if (!el) { return; }

    void el.getBoundingClientRect();
    el.classList.add('marker-new');
    seenMarkerIps.add(srcIp);
    setTimeout(() => { el.classList.remove('marker-new'); }, 700);
}

function isSpikeMarker(row) {
    const windowSecs = currentWindowSecs();
    if (windowSecs !== 900 && windowSecs !== 3600) { return false; }
    if (!Number.isFinite(row.count) || !Number.isFinite(row.first_ts) || !Number.isFinite(row.last_ts)) {
        return false;
    }

    const now = Math.floor(Date.now() / 1000);
    const count = row.count;
    const span = Math.max(0, row.last_ts - row.first_ts);
    const age = Math.max(0, now - row.last_ts);

    if (windowSecs === 900) {
        return count >= 10 && span <= 300 && age <= 120;
    }

    return count >= 25 && span <= 900 && age <= 300;
}

function applySpikeMarkerState(marker, spiking) {
    const el = marker.getElement();
    if (!el) { return; }
    el.classList.toggle('marker-spike', spiking && animationsEnabled());
}

function renderMap(rows) {
    const reopenIp = activePopupIp;
    let reopenMarker = null;
    let reopenRow = null;

    suppressPopupAutoClose = true;
    cluster.clearLayers();
    mappedCount = 0;
    totalSeen = 0;
    const arcCandidates = [];

    for (const r of rows) {
        if (!passesFilters(r)) { continue; }
        if (r.lat === null || r.lon === null || r.lat === undefined || r.lon === undefined) {
            continue;
        }
        totalSeen += Number.isFinite(r.count) ? r.count : 0;

        const severity = markerSeverity(r);
        const spiking = isSpikeMarker(r);
        const mobileUi = isMobileMapUi();
        const color = severity === 'high'
            ? '#f85149'
            : markerColor((r.threat_max !== undefined) ? r.threat_max : null);
        const marker = L.circleMarker([r.lat, r.lon], {
            radius:      mobileUi ? (spiking ? 8 : 7) : (spiking ? 6 : 5),
            color:       color,
            fillColor:   color,
            fillOpacity: 0.75,
            weight:      mobileUi ? (spiking ? 2.5 : 2) : (spiking ? 2 : 1),
            severity:    severity,
        });
        marker.bindPopup(buildAggregatePopup(r), { maxWidth: 360 });
        marker.on('add', () => {
            setTimeout(() => {
                maybeAnimateMarker(marker, r.src_ip);
                applySpikeMarkerState(marker, spiking);
            }, 0);
        });
        marker.on('popupopen', () => {
            activePopupIp = r.src_ip;
            bindPopupControls(marker, r);
            const state = ensureDetailState(r.src_ip);
            if (!state.rows.length && !state.loading) {
                void loadDetail(marker, r, '');
            } else {
                updatePopupContent(marker, r);
            }
        });
        marker.on('popupclose', () => {
            if (!suppressPopupAutoClose && activePopupIp === r.src_ip) {
                activePopupIp = '';
            }
        });
        cluster.addLayer(marker);
        mappedCount++;
        if (reopenIp && r.src_ip === reopenIp) {
            reopenMarker = marker;
            reopenRow = r;
        }

        if (shouldCandidateArc(r)) {
            arcCandidates.push(makeArcCandidate(r, color));
        }
    }

    if (!reopenMarker && reopenIp) {
        activePopupIp = '';
    }

    renderArcBatch(arcCandidates);
    if (reopenMarker && reopenRow) {
        reopenMarker.openPopup();
        updatePopupContent(reopenMarker, reopenRow);
        bindPopupControls(reopenMarker, reopenRow);
    }
    suppressPopupAutoClose = false;
}

function scheduleNextPoll(delayMs) {
    if (pollTimer !== null) {
        clearTimeout(pollTimer);
    }
    pollTimer = setTimeout(() => {
        pollTimer = null;
        void poll();
    }, delayMs);
}

function requestPollNow() {
    if (pollTimer !== null) {
        clearTimeout(pollTimer);
        pollTimer = null;
    }
    // Keep one queued refresh rather than overlapping fetch/render cycles.
    if (pollInFlight) {
        pollQueued = true;
        return;
    }
    void poll();
}

async function poll() {
    if (pollInFlight) {
        pollQueued = true;
        return;
    }
    pollInFlight = true;
    await fetchHome();
    updateMapFeedIndicator();
    try {
        const resp = await fetch('/api/map' + buildMapQueryString(), { cache: 'default' });
        if (!resp.ok) {
            setError('API ' + resp.status);
            updateMapFeedIndicator(Date.now() + (NORMAL_REFRESH_MS * 3));
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
        lastMapSuccessAt = Date.now();
        updateMapFeedIndicator(lastMapSuccessAt);
        setStatusCounts(mappedCount, totalSeen);
        setStatusFreshness('Updated ' + new Date().toLocaleTimeString());
        isInitialLoad = false;

        scheduleNextPoll(document.visibilityState === 'hidden' ? HIDDEN_REFRESH_MS : NORMAL_REFRESH_MS);
    } catch (err) {
        setError(err.message);
        updateMapFeedIndicator(Date.now() + (NORMAL_REFRESH_MS * 3));
        scheduleNextPoll(ERROR_REFRESH_MS);
    } finally {
        pollInFlight = false;
        if (pollQueued) {
            pollQueued = false;
            requestPollNow();
        }
    }
}

function pollNow() {
    clearActiveArcs();
    isInitialLoad = true;
    lastMapTs = 0;
    setStatusCounts(0, 0);
    setStatusFreshness('Refreshing...');
    requestPollNow();
}

document.addEventListener('visibilitychange', () => {
    updateMapFeedIndicator();
    if (document.visibilityState === 'visible') {
        void fetchStatus();
        scheduleStatusPoll();
        requestPollNow();
        return;
    }
    if (statusPollTimer !== null) {
        clearTimeout(statusPollTimer);
        statusPollTimer = null;
    }
    scheduleNextPoll(HIDDEN_REFRESH_MS);
});

fetchHome().then(() => {
    addHomeMarker();
    loadFilters();
    appliedTextFilters.ip      = validateIpValue(fIp.value).normalized;
    appliedTextFilters.port    = validatePortValue(fPort.value).normalized;
    appliedTextFilters.country = validateCountryValue(fCountry.value).normalized;
    fIp.value = appliedTextFilters.ip;
    fPort.value = appliedTextFilters.port;
    fCountry.value = appliedTextFilters.country;
    updateTextValidity();
    saveFilters();
    setOperatorStatus(null);
    updateMapFeedIndicator();
    void fetchStatus();
    scheduleStatusPoll();
    pollNow();
});

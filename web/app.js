/* msmap – Firewall Live Map
 * Polls /api/map for aggregate markers and lazily loads raw event drilldown.
 */
// @ts-check
'use strict';

/**
 * @typedef {{
 *   src_ip: string,
 *   lat: number|null|undefined,
 *   lon: number|null|undefined,
 *   count: number,
 *   first_ts: number,
 *   last_ts: number,
 *   threat_max: number|null|undefined,
 *   country?: string,
 *   asn?: string,
 *   usage_type?: string,
 *   spamhaus_drop?: boolean,
 *   tor_exit?: boolean
 * }} MapRow
 */

/**
 * @typedef {{
 *   ts: number,
 *   src_ip: string,
 *   dst_ip: string,
 *   src_port: number|null,
 *   dst_port: number|null,
 *   proto: string,
 *   tcp_flags?: string,
 *   rule: string
 * }} DetailRow
 */

/**
 * @typedef {{
 *   rows: DetailRow[],
 *   selectedIndex: number,
 *   nextCursor: string,
 *   loading: boolean,
 *   error: string,
 *   errorKind: string,
 *   retryAfterMs: number,
 *   retryTimerId: ReturnType<typeof setTimeout>|null,
 *   loaded: boolean,
 *   windowSecs: number,
 *   anchorTs: number
 * }} DetailEntryState
 */

/**
 * @typedef {{
 *   ok?: boolean,
 *   now?: number,
 *   rows_24h?: number,
 *   distinct_sources_24h?: number,
 *   intel_enabled?: boolean,
 *   intel_refresh_attempted?: boolean,
 *   intel_last_refresh_ts?: number,
 *   abuse_enabled?: boolean,
 *   abuse_rate_remaining?: number|null,
 *   abuse_quota_exhausted?: boolean,
 *   abuse_can_accept_new_lookups?: boolean,
 *   abuse_has_pending_work?: boolean,
 *   abuse_quota_retry_after_ts?: number|null,
 *   home_configured?: boolean,
 *   home_valid?: boolean,
 *   home_updated_at?: number|null
 * }} StatusPayload
 */

const NORMAL_REFRESH_MS = 30000;
const HIDDEN_REFRESH_MS = 300000;
const ERROR_REFRESH_MS  = 60000;
const STATUS_REFRESH_MS = 60000;
const HOME_FETCH_RETRY_MS = 60000;
const DETAIL_PAGE_SIZE  = 20;
const DETAIL_RETRY_COOLDOWN_MS = 10000;
const DETAIL_STATE_CACHE_MAX = 256;
const TEXT_FILTER_DEBOUNCE_MS = 400;

const ARC_DRAW_MS   =  800;
const ARC_FADE_MS   =  300;
const MAX_ARCS_POLL =   10;

const STORAGE_KEY = 'msmap_filters';
const MOTION_SESSION_KEY = 'msmap_motion';
const DEFAULT_FILTERS = Object.freeze({
    time: '900',
    proto: '',
    ip: '',
    port: '',
    asn: '',
    threat: '',
});

/**
 * @param {string} id
 * @returns {HTMLElement}
 */
function mustGetById(id) {
    const el = document.getElementById(id);
    if (!el) {
        throw new Error('Missing required element #' + id);
    }
    return el;
}

/**
 * @param {string} id
 * @returns {HTMLInputElement}
 */
function mustGetInput(id) {
    return /** @type {HTMLInputElement} */ (mustGetById(id));
}

/**
 * @param {string} id
 * @returns {HTMLSelectElement}
 */
function mustGetSelect(id) {
    return /** @type {HTMLSelectElement} */ (mustGetById(id));
}

/**
 * @param {string} id
 * @returns {HTMLButtonElement}
 */
function mustGetButton(id) {
    return /** @type {HTMLButtonElement} */ (mustGetById(id));
}

/**
 * @param {string} selector
 * @returns {HTMLElement[]}
 */
function queryAllHtml(selector) {
    return /** @type {HTMLElement[]} */ (Array.from(document.querySelectorAll(selector)));
}

/**
 * @param {string} selector
 * @returns {HTMLButtonElement[]}
 */
function queryAllButtons(selector) {
    return /** @type {HTMLButtonElement[]} */ (Array.from(document.querySelectorAll(selector)));
}

const filterState = {
    appliedTextFilters: {
        ip: DEFAULT_FILTERS.ip,
        port: DEFAULT_FILTERS.port,
        asn: DEFAULT_FILTERS.asn,
    },
    textApplyTimer: null,
    activeFilterPanelTab: 'filters',
    activeThreat: DEFAULT_FILTERS.threat,
    activeMotion: 'on',
};

const mapState = {
    mappedCount: 0,
    totalSeen: 0,
    lastMapTs: 0,
    lastMapGeneratedAt: 0,
    isInitialLoad: true,
    pollTimer: null,
    pollInFlight: false,
    pollQueued: false,
    lastMapSuccessAt: 0,
};

const popupState = {
    activePopupIp: '',
    activePopup: null,
    activePopupRow: null,
    detailStateByIp: new Map(),
};

const statusState = {
    statusPollTimer: null,
    statusInFlight: false,
};

const homeState = {
    homePt: null,
    homeMarker: null,
    homeFetchInFlight: false,
    homeRetryAfterMs: 0,
    homeStatusExpectedValid: false,
    lastHomeUpdatedAt: null,
};

const arcState = {
    activeArcs: new Set(),
};

function currentFilterState() {
    return {
        time:        fTime.value,
        proto:       fProto.value,
        ip:          filterState.appliedTextFilters.ip,
        port:        filterState.appliedTextFilters.port,
        asn:         filterState.appliedTextFilters.asn,
        threat:      filterState.activeThreat,
    };
}

function writeFiltersToUrl() {
    const state = currentFilterState();
    const params = new URLSearchParams();
    if (state.time !== DEFAULT_FILTERS.time)               { params.set('window', state.time); }
    if (state.proto)                                       { params.set('proto', state.proto); }
    if (state.ip)                                          { params.set('ip', state.ip); }
    if (state.port)                                        { params.set('port', state.port); }
    if (state.asn)                                         { params.set('asn', state.asn); }
    if (state.threat)                                      { params.set('threat', state.threat); }
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
    setIfPresent('asn', 'asn');
    setIfPresent('threat', 'threat');

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

function readStoredMotion() {
    try {
        return sessionStorage.getItem(MOTION_SESSION_KEY);
    } catch (_) {
        return null;
    }
}

function loadFilters() {
    const s = parseUrlFilterState() || readStoredFilters();
    if (s) {
        if (s.time        !== undefined) { setSelectValue(fTime, s.time, DEFAULT_FILTERS.time); }
        if (s.proto       !== undefined) { setSelectValue(fProto, s.proto, DEFAULT_FILTERS.proto); }
        if (s.ip          !== undefined) { fIp.value = s.ip; }
        if (s.port        !== undefined) { fPort.value = s.port; }
        if (s.asn         !== undefined) { fAsn.value = s.asn; }
        if (s.threat      !== undefined) { setThreatValue(s.threat, { save: false, repoll: false }); }
    }

    setMotionValue(readStoredMotion(), { save: false, repoll: false, force: true });
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
        const hasHigh = children.some((m) => m.options.threat === 'high');
        const hasMedium = children.some((m) => m.options.threat === 'medium');
        const hasLow = children.some((m) => m.options.threat === 'low');
        const hasSpike = children.some(m => m.options.spiking === true);
        let cls;
        if (hasHigh) {
            cls = 'high';
        } else if (hasMedium) {
            cls = 'mid';
        } else if (hasLow) {
            cls = 'low';
        } else {
            cls = 'safe';
        }
        return L.divIcon({
            html:      '<div><span>' + total + '</span>' + (hasSpike ? '<i class="cluster-spike-badge" aria-hidden="true">!</i>' : '') + '</div>',
            className: 'marker-cluster marker-cluster-threat-' + cls + (hasSpike ? ' marker-cluster-spike' : ''),
            iconSize:  L.point(40, 40),
        });
    },
});
lmap.addLayer(cluster);
lmap.on('popupclose', (event) => {
    if (popupState.activePopup && event.popup === popupState.activePopup) {
        popupState.activePopup = null;
        popupState.activePopupIp = '';
        popupState.activePopupRow = null;
    }
});

const statMapped    = mustGetById('stat-mapped');
const statTotal     = mustGetById('stat-total');
const statTime      = mustGetById('stat-time');
const statEvents    = mustGetById('stat-events');
const statSources   = mustGetById('stat-sources');
const statIntel     = mustGetById('stat-intel');
const statAbuse     = mustGetById('stat-abuse');
const statMappedValue = mustGetById('stat-mapped-value');
const statTotalValue  = mustGetById('stat-total-value');
const statTimeValue   = mustGetById('stat-time-value');
const statEventsValue = mustGetById('stat-events-value');
const statSourcesValue = mustGetById('stat-sources-value');
const statIntelValue = mustGetById('stat-intel-value');
const statAbuseValue = mustGetById('stat-abuse-value');
const statError     = mustGetById('stat-error');
const filterPanel   = mustGetById('filter-panel');
const filterToggle  = mustGetButton('filter-toggle');
const filterTabButtons = queryAllButtons('[data-panel-tab]');
const filterTabFilters = mustGetById('filter-tab-filters');
const filterTabLegend  = mustGetById('filter-tab-legend');
const fTime         = mustGetSelect('f-time');
const fProto        = mustGetSelect('f-proto');
const fIp           = mustGetInput('f-ip');
const fPort         = mustGetInput('f-port');
const fAsn          = mustGetInput('f-asn');
const fThreatButtons = queryAllButtons('[data-threat]');
const fThreatText = mustGetById('f-threat-text');
const fMotionOn     = mustGetButton('f-motion-on');
const fMotionOff    = mustGetButton('f-motion-off');
const legendHome    = mustGetById('legend-home');
const statDot = /** @type {HTMLElement} */ (mustGetById('stat-time').querySelector('.status-dot'));
const statusOpSeparators = queryAllHtml('.status-sep-ops');

function setFilterPanelTab(tabName) {
    const nextTab = tabName === 'legend' ? 'legend' : 'filters';
    filterState.activeFilterPanelTab = nextTab;
    filterTabButtons.forEach((button) => {
        const selected = button.dataset.panelTab === nextTab;
        button.classList.toggle('is-active', selected);
        button.setAttribute('aria-selected', selected ? 'true' : 'false');
        button.tabIndex = selected ? 0 : -1;
    });
    filterTabFilters.hidden = nextTab !== 'filters';
    filterTabLegend.hidden = nextTab !== 'legend';
}

function setFilterPanelOpen(open) {
    filterPanel.style.display = open ? '' : 'none';
    filterToggle.classList.toggle('active', open);
}

setFilterPanelTab('filters');
setFilterPanelOpen(!isMobileMapUi());
setThreatValue(DEFAULT_FILTERS.threat, { save: false, repoll: false });
setMotionValue('on', { save: false, repoll: false, force: true });
filterToggle.addEventListener('click', () => {
    const nowOpen = filterPanel.style.display !== 'none';
    setFilterPanelOpen(!nowOpen);
});
filterTabButtons.forEach((button) => {
    button.addEventListener('click', () => {
        setFilterPanelTab(button.dataset.panelTab);
    });
    button.addEventListener('keydown', (event) => {
        const keyEvent = /** @type {KeyboardEvent} */ (event);
        if (keyEvent.key !== 'ArrowLeft' && keyEvent.key !== 'ArrowRight') {
            return;
        }
        keyEvent.preventDefault();
        const nextTab = filterState.activeFilterPanelTab === 'filters' ? 'legend' : 'filters';
        setFilterPanelTab(nextTab);
        const nextButton = filterTabButtons.find((candidate) => candidate.dataset.panelTab === nextTab);
        if (nextButton) {
            nextButton.focus();
        }
    });
});

function isMobileMapUi() {
    return window.matchMedia('(max-width: 700px) and (pointer: coarse)').matches;
}

function motionEnabled() {
    return filterState.activeMotion === 'on';
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

function threatFilterLabel(value) {
    switch (value) {
        case 'unknown': return 'Unknown';
        case 'clean': return 'Clean';
        case 'low': return 'Low';
        case 'medium': return 'Medium';
        case 'high': return 'High';
        default: return 'All';
    }
}

function isValidThreat(value) {
    return value === '' || value === 'unknown' || value === 'clean' ||
        value === 'low' || value === 'medium' || value === 'high';
}

function setMotionValue(value, { save = true, repoll = true, force = false } = {}) {
    const next = value === 'off' ? 'off' : 'on';
    const changed = next !== filterState.activeMotion;
    filterState.activeMotion = next;
    const onSelected = next === 'on';
    fMotionOn.classList.toggle('is-active', onSelected);
    fMotionOff.classList.toggle('is-active', !onSelected);
    fMotionOn.setAttribute('aria-pressed', onSelected ? 'true' : 'false');
    fMotionOff.setAttribute('aria-pressed', onSelected ? 'false' : 'true');
    fMotionOn.tabIndex = onSelected ? 0 : -1;
    fMotionOff.tabIndex = onSelected ? -1 : 0;
    if (save && (changed || force)) {
        try {
            if (next === 'off') {
                sessionStorage.setItem(MOTION_SESSION_KEY, 'off');
            } else {
                sessionStorage.removeItem(MOTION_SESSION_KEY);
            }
        } catch (_) {}
    }
    if (repoll && (changed || force)) {
        clearActiveArcs();
        refreshVisibleMarkerMotionState();
    }
}

function setThreatValue(value, { save = true, repoll = true, force = false } = {}) {
    const next = isValidThreat(value) ? value : DEFAULT_FILTERS.threat;
    const changed = next !== filterState.activeThreat;
    filterState.activeThreat = next;
    fThreatButtons.forEach((button) => {
        const selected = button.dataset.threat === next;
        button.classList.toggle('is-active', selected);
        button.setAttribute('aria-checked', selected ? 'true' : 'false');
        button.tabIndex = selected ? 0 : -1;
    });
    fThreatText.textContent = 'Threats: ' + threatFilterLabel(next);
    if (save && (changed || force)) {
        saveFilters();
    }
    if (repoll && (changed || force)) {
        pollNow();
    }
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
    return { valid, normalized: valid ? trimmed : filterState.appliedTextFilters.ip };
}

function validatePortValue(value) {
    const trimmed = value.trim();
    if (!trimmed) {
        return { valid: true, normalized: '' };
    }
    if (!/^\d+$/.test(trimmed)) {
        return { valid: false, normalized: filterState.appliedTextFilters.port };
    }
    const port = Number(trimmed);
    if (port < 1 || port > 65535) {
        return { valid: false, normalized: filterState.appliedTextFilters.port };
    }
    return { valid: true, normalized: String(port) };
}

function validateAsnValue(value) {
    const trimmed = value.trim();
    if (!trimmed) {
        return { valid: true, normalized: '' };
    }
    const asnPattern = /^[A-Za-z0-9 .,'()&/_:+-]+$/;
    const valid = trimmed.length >= 3 &&
        trimmed.length <= 64 &&
        asnPattern.test(trimmed);
    return { valid, normalized: valid ? trimmed : filterState.appliedTextFilters.asn };
}

function updateTextValidity() {
    const ip = validateIpValue(fIp.value);
    const port = validatePortValue(fPort.value);
    const asn = validateAsnValue(fAsn.value);
    setInputValidity(fIp, ip.valid);
    setInputValidity(fPort, port.valid);
    setInputValidity(fAsn, asn.valid);
    return { ip, port, asn };
}

function applyTextFilters() {
    const validation = updateTextValidity();
    let changed = false;

    if (validation.ip.valid && filterState.appliedTextFilters.ip !== validation.ip.normalized) {
        filterState.appliedTextFilters.ip = validation.ip.normalized;
        changed = true;
    }
    if (validation.port.valid && filterState.appliedTextFilters.port !== validation.port.normalized) {
        filterState.appliedTextFilters.port = validation.port.normalized;
        changed = true;
    }
    if (validation.asn.valid && filterState.appliedTextFilters.asn !== validation.asn.normalized) {
        filterState.appliedTextFilters.asn = validation.asn.normalized;
        changed = true;
    }

    if (validation.ip.valid) {
        fIp.value = validation.ip.normalized;
    }
    if (validation.port.valid) {
        fPort.value = validation.port.normalized;
    }
    if (validation.asn.valid) {
        fAsn.value = validation.asn.normalized;
    }

    if (changed) {
        saveFilters();
        pollNow();
    }
}

function scheduleTextApply() {
    if (filterState.textApplyTimer !== null) {
        clearTimeout(filterState.textApplyTimer);
    }
    filterState.textApplyTimer = setTimeout(() => {
        filterState.textApplyTimer = null;
        applyTextFilters();
    }, TEXT_FILTER_DEBOUNCE_MS);
}

function resetToDefaults() {
    if (filterState.textApplyTimer !== null) {
        clearTimeout(filterState.textApplyTimer);
        filterState.textApplyTimer = null;
    }
    fTime.value         = DEFAULT_FILTERS.time;
    fProto.value        = DEFAULT_FILTERS.proto;
    fIp.value           = DEFAULT_FILTERS.ip;
    fPort.value         = DEFAULT_FILTERS.port;
    fAsn.value          = DEFAULT_FILTERS.asn;
    setThreatValue(DEFAULT_FILTERS.threat, { save: false, repoll: false, force: true });
    setMotionValue('on', { save: true, repoll: false, force: true });

    filterState.appliedTextFilters.ip      = DEFAULT_FILTERS.ip;
    filterState.appliedTextFilters.port    = DEFAULT_FILTERS.port;
    filterState.appliedTextFilters.asn = DEFAULT_FILTERS.asn;
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

mustGetButton('f-defaults').addEventListener('click', resetToDefaults);
fTime.addEventListener('change', applyNonTextFilters);
fProto.addEventListener('change', applyNonTextFilters);
fMotionOn.addEventListener('click', () => {
    setMotionValue('on');
});
fMotionOff.addEventListener('click', () => {
    setMotionValue('off');
});
fThreatButtons.forEach((button, index) => {
    button.addEventListener('click', () => {
        setThreatValue(button.dataset.threat || '');
    });
    button.addEventListener('keydown', (event) => {
        const keyEvent = /** @type {KeyboardEvent} */ (event);
        if (keyEvent.key !== 'ArrowLeft' && keyEvent.key !== 'ArrowRight') {
            return;
        }
        keyEvent.preventDefault();
        const step = keyEvent.key === 'ArrowRight' ? 1 : -1;
        const nextIndex = (index + step + fThreatButtons.length) % fThreatButtons.length;
        const nextButton = fThreatButtons[nextIndex];
        nextButton.focus();
        setThreatValue(nextButton.dataset.threat || '');
    });
});

[fIp, fPort, fAsn].forEach((el) => {
    el.addEventListener('input', () => {
        updateTextValidity();
        scheduleTextApply();
    });
    el.addEventListener('blur', () => {
        if (filterState.textApplyTimer !== null) {
            clearTimeout(filterState.textApplyTimer);
            filterState.textApplyTimer = null;
        }
        applyTextFilters();
    });
    el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            if (filterState.textApplyTimer !== null) {
                clearTimeout(filterState.textApplyTimer);
                filterState.textApplyTimer = null;
            }
            applyTextFilters();
        }
    });
});

function fmtTs(ts) {
    return new Date(ts * 1000).toLocaleString();
}

function fmtTsCompact(ts) {
    return new Date(ts * 1000).toLocaleString(undefined, {
        month: 'numeric',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
    });
}

function buildResponsiveTimestamp(ts) {
    return '<span class="popup-time-full">' + escapeHtml(fmtTs(ts)) + '</span>' +
        '<span class="popup-time-compact">' + escapeHtml(fmtTsCompact(ts)) + '</span>';
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

function markerThreat(row) {
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

function threatScoreLabel(score) {
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

function detailRetryBlocked(state, nowMs = Date.now()) {
    return state.errorKind === 'temporary' && nowMs < state.retryAfterMs;
}

function parseRetryAfterMs(resp) {
    const raw = resp.headers.get('Retry-After');
    if (!raw) { return 0; }

    const deltaSecs = Number.parseInt(raw, 10);
    if (Number.isFinite(deltaSecs) && deltaSecs >= 0) {
        return deltaSecs * 1000;
    }

    const atMs = Date.parse(raw);
    if (!Number.isFinite(atMs)) { return 0; }
    return Math.max(0, atMs - Date.now());
}

function makeDetailError(kind, message, retryAfterMs = 0) {
    return { kind, message, retryAfterMs };
}

function clearDetailRetryTimer(state) {
    if (state.retryTimerId !== null) {
        clearTimeout(state.retryTimerId);
        state.retryTimerId = null;
    }
}

function scheduleDetailRetryUnlock(row, state, delayMs) {
    clearDetailRetryTimer(state);
    if (delayMs <= 0) { return; }
    state.retryTimerId = setTimeout(() => {
        state.retryTimerId = null;
        updatePopupContent(row);
    }, delayMs);
}

function setStatusCounts(mapped, total) {
    statMappedValue.textContent = mapped.toLocaleString();
    statTotalValue.textContent = total.toLocaleString();
}

function setStatusFreshness(text) {
    statTimeValue.textContent = text;
}

function formatMapFreshness(generatedAt, nowMs = Date.now()) {
    if (!Number.isFinite(generatedAt) || generatedAt <= 0) {
        return 'Updated';
    }

    const ageSecs = Math.max(0, Math.floor((nowMs / 1000) - generatedAt));
    if (ageSecs < 5) {
        return 'Updated just now';
    }
    if (ageSecs < 60) {
        return 'Updated ' + ageSecs + 's ago';
    }

    const ageMins = Math.floor(ageSecs / 60);
    if (ageMins < 60) {
        return 'Updated ' + ageMins + 'm ago';
    }

    const ageHours = Math.floor(ageMins / 60);
    return 'Updated ' + ageHours + 'h ago';
}

function formatCompactCount(value) {
    return new Intl.NumberFormat(undefined, {
        notation: 'compact',
        maximumFractionDigits: 1,
    }).format(value);
}

function formatCountdownUntil(targetSec, nowSec) {
    if (!Number.isFinite(targetSec) || !Number.isFinite(nowSec) || nowSec < 0) {
        return null;
    }
    if (targetSec <= nowSec) {
        return 'pending';
    }
    const remainingSec = Math.max(0, targetSec - nowSec);
    const remainingMins = Math.ceil(remainingSec / 60);
    if (remainingMins <= 1) {
        return '~<1m';
    }

    const hours = Math.floor(remainingMins / 60);
    const mins = remainingMins % 60;
    if (hours <= 0) {
        return '~' + mins + 'm';
    }
    return '~' + hours + 'h' + mins + 'm';
}

function formatUtcMidnightCountdown(nowSec) {
    if (!Number.isFinite(nowSec) || nowSec < 0) {
        return null;
    }
    const secondsPerDay = 24 * 60 * 60;
    const nextMidnightSec = (Math.floor(nowSec / secondsPerDay) + 1) * secondsPerDay;
    return formatCountdownUntil(nextMidnightSec, nowSec);
}

function setOperatorStatus(status) {
    if (!status || status.ok !== true) {
        statEvents.style.display = 'none';
        statSources.style.display = 'none';
        statIntel.style.display = 'none';
        statAbuse.style.display = 'none';
        statusOpSeparators.forEach((el) => {
            el.style.display = 'none';
        });
        return;
    }

    statEvents.style.display = '';
    statSources.style.display = '';
    statIntel.style.display = '';
    statAbuse.style.display = '';
    statusOpSeparators.forEach((el) => {
        el.style.display = '';
    });

    statEventsValue.textContent = formatCompactCount(status.rows_24h ?? 0);
    statSourcesValue.textContent = formatCompactCount(status.distinct_sources_24h ?? 0);

    statIntelValue.classList.remove('status-state-ok', 'status-state-stale', 'status-state-off', 'status-state-syncing');
    statAbuseValue.classList.remove('status-state-ok', 'status-state-stale', 'status-state-off', 'status-state-syncing');
    if (status.intel_enabled !== true) {
        statIntelValue.textContent = 'off';
        statIntelValue.classList.add('status-state-off');
        statIntel.dataset.tooltip = 'Threat intel feeds are disabled.';
    } else {
        const now = Number.isFinite(status.now) ? status.now : Math.floor(Date.now() / 1000);
        const refreshTs = Number.isFinite(status.intel_last_refresh_ts) ? status.intel_last_refresh_ts : 0;
        if (refreshTs <= 0) {
            if (status.intel_refresh_attempted === true) {
                statIntelValue.textContent = 'stale';
                statIntelValue.classList.add('status-state-stale');
                statIntel.dataset.tooltip = 'Threat intel feeds have not completed a successful refresh yet.';
            } else {
                statIntelValue.textContent = 'syncing';
                statIntelValue.classList.add('status-state-syncing');
                statIntel.dataset.tooltip = 'Threat intel feeds are still initializing.';
            }
        } else if ((now - refreshTs) <= (12 * 3600)) {
            statIntelValue.textContent = 'ok';
            statIntelValue.classList.add('status-state-ok');
            statIntel.dataset.tooltip = 'Threat intel feeds are current.';
        } else {
            statIntelValue.textContent = 'stale';
            statIntelValue.classList.add('status-state-stale');
            statIntel.dataset.tooltip = 'Threat intel feeds are stale.';
        }
    }

    if (status.abuse_enabled !== true) {
        statAbuseValue.textContent = 'off';
        statAbuseValue.classList.add('status-state-off');
        statAbuse.dataset.tooltip = 'AbuseIPDB lookups are disabled. Cached threat data may still be shown.';
        return;
    }

    const abuseRemaining = Number.isFinite(status.abuse_rate_remaining) ? status.abuse_rate_remaining : null;
    if (abuseRemaining === null && status.abuse_quota_exhausted !== true) {
        if (status.abuse_can_accept_new_lookups === false) {
            statAbuseValue.textContent = 'quota';
            statAbuseValue.classList.add('status-state-stale');
            statAbuse.dataset.tooltip =
                'AbuseIPDB request budget is currently exhausted. New lookups are paused until reset.';
        } else if (status.abuse_has_pending_work === true) {
            statAbuseValue.textContent = 'syncing';
            statAbuseValue.classList.add('status-state-syncing');
            statAbuse.dataset.tooltip =
                'Waiting for the first live AbuseIPDB response to confirm current requests remaining.';
        } else {
            statAbuseValue.textContent = 'ok';
            statAbuseValue.classList.add('status-state-ok');
            statAbuse.dataset.tooltip =
                'AbuseIPDB can accept new lookups. Quota has not yet been confirmed by a live response.';
        }
    } else if (status.abuse_quota_exhausted === true) {
        statAbuseValue.textContent = 'quota';
        statAbuseValue.classList.add('status-state-stale');
        const now = Number.isFinite(status.now) ? status.now : Math.floor(Date.now() / 1000);
        const retryAfterTs = Number.isFinite(status.abuse_quota_retry_after_ts)
            ? status.abuse_quota_retry_after_ts
            : null;
        const retryCountdown = retryAfterTs !== null
            ? formatCountdownUntil(retryAfterTs, now)
            : null;
        if (retryCountdown !== null) {
            if (retryCountdown === 'pending') {
                statAbuse.dataset.tooltip =
                    'AbuseIPDB daily quota is exhausted. Next automatic retry is pending.';
            } else {
                statAbuse.dataset.tooltip =
                    'AbuseIPDB daily quota is exhausted. Next automatic retry in ' +
                    retryCountdown + '.';
            }
        } else {
            const quotaResetCountdown = formatUtcMidnightCountdown(now);
            statAbuse.dataset.tooltip = quotaResetCountdown
                ? ('AbuseIPDB daily quota is exhausted. Quota refresh in ' + quotaResetCountdown + '.')
                : 'AbuseIPDB daily quota is exhausted. New lookups will resume after the UTC midnight reset.';
        }
    } else {
        statAbuseValue.textContent = 'ok';
        statAbuseValue.classList.add('status-state-ok');
        statAbuse.dataset.tooltip = abuseRemaining !== null
            ? ('AbuseIPDB can accept new lookups. ' + abuseRemaining + ' requests remaining today.')
            : 'AbuseIPDB can accept new lookups.';
    }
}

function setMapFeedState(nextState) {
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

function clearHomeState() {
    clearActiveArcs();
    homeState.homePt = null;
    if (homeState.homeMarker) {
        homeState.homeMarker.remove();
        homeState.homeMarker = null;
    }
    setHomeLegendVisible(false);
}

function readHomeUpdatedAt(status) {
    return Number.isFinite(status?.home_updated_at)
        ? Math.trunc(status.home_updated_at)
        : null;
}

function syncHomeStateFromStatus(status) {
    const wasExpectedValid = homeState.homeStatusExpectedValid;
    const homeConfigured = status?.home_configured === true;
    const homeValid = status?.home_valid === true;
    const nextUpdatedAt = readHomeUpdatedAt(status);

    homeState.homeStatusExpectedValid = homeConfigured && homeValid;
    if (!homeState.homeStatusExpectedValid) {
        homeState.homeRetryAfterMs = 0;
        homeState.lastHomeUpdatedAt = nextUpdatedAt;
        clearHomeState();
        return;
    }

    let shouldFetch = false;
    if (!wasExpectedValid) {
        shouldFetch = true;
    }
    if (!homeState.homePt) {
        shouldFetch = true;
    }
    if (homeState.lastHomeUpdatedAt !== nextUpdatedAt) {
        shouldFetch = true;
    }
    if (homeState.homeRetryAfterMs > 0 && Date.now() >= homeState.homeRetryAfterMs) {
        shouldFetch = true;
    }
    homeState.lastHomeUpdatedAt = nextUpdatedAt;
    if (shouldFetch) {
        void fetchHome({ ignoreRetryGate: true });
    }
}

async function fetchStatus() {
    if (statusState.statusInFlight) {
        return;
    }
    statusState.statusInFlight = true;
    try {
        const resp = await fetch('/api/status', { cache: 'no-store' });
        if (!resp.ok) {
            setOperatorStatus(null);
            return;
        }
        const body = await resp.json();
        setOperatorStatus(body);
        syncHomeStateFromStatus(body);
    } catch (_) {
        setOperatorStatus(null);
    } finally {
        statusState.statusInFlight = false;
    }
}

function scheduleStatusPoll(delayMs = STATUS_REFRESH_MS) {
    if (document.visibilityState === 'hidden') {
        if (statusState.statusPollTimer !== null) {
            clearTimeout(statusState.statusPollTimer);
            statusState.statusPollTimer = null;
        }
        return;
    }
    if (statusState.statusPollTimer !== null) {
        clearTimeout(statusState.statusPollTimer);
    }
    statusState.statusPollTimer = setTimeout(() => {
        statusState.statusPollTimer = null;
        void fetchStatus().then(() => {
            if (document.visibilityState === 'visible') {
                scheduleStatusPoll(STATUS_REFRESH_MS);
            }
        });
    }, delayMs);
}

function updateMapFeedIndicator(now = Date.now()) {
    if (mapState.lastMapSuccessAt === 0) {
        setMapFeedState('unknown');
        return;
    }
    const staleAfterMs = NORMAL_REFRESH_MS * 2;
    setMapFeedState((now - mapState.lastMapSuccessAt) <= staleAfterMs ? 'healthy' : 'stale');
}

function ensureDetailState(srcIp) {
    const windowSecs = currentWindowSecs();
    const existing = popupState.detailStateByIp.get(srcIp);
    if (existing && existing.windowSecs === windowSecs) {
        touchDetailState(srcIp, existing);
        return existing;
    }
    if (existing && existing.retryTimerId !== null) {
        clearTimeout(existing.retryTimerId);
    }

    const fresh = {
        rows: [],
        selectedIndex: 0,
        nextCursor: '',
        loading: false,
        error: '',
        errorKind: '',
        retryAfterMs: 0,
        retryTimerId: null,
        loaded: false,
        windowSecs: windowSecs,
        anchorTs: 0,
    };
    touchDetailState(srcIp, fresh);
    return fresh;
}

function touchDetailState(srcIp, state) {
    if (popupState.detailStateByIp.has(srcIp)) {
        popupState.detailStateByIp.delete(srcIp);
    }
    popupState.detailStateByIp.set(srcIp, state);
    trimDetailStateCache();
}

function trimDetailStateCache() {
    while (popupState.detailStateByIp.size > DETAIL_STATE_CACHE_MAX) {
        const oldest = popupState.detailStateByIp.entries().next().value;
        if (!oldest) {
            return;
        }
        const [oldestIp, oldestState] = oldest;
        clearDetailRetryTimer(oldestState);
        popupState.detailStateByIp.delete(oldestIp);
    }
}

function currentDetailAnchorTs() {
    if (Number.isFinite(mapState.lastMapGeneratedAt) && mapState.lastMapGeneratedAt > 0) {
        return mapState.lastMapGeneratedAt;
    }
    return Math.floor(Date.now() / 1000);
}

function ensureDetailAnchor(state) {
    if (!Number.isFinite(state.anchorTs) || state.anchorTs <= 0) {
        state.anchorTs = currentDetailAnchorTs();
    }
    return state.anchorTs;
}

function buildMapQueryString() {
    const params = new URLSearchParams();
    params.set('window', String(currentWindowSecs()));
    if (fProto.value)               { params.set('proto', fProto.value); }
    if (filterState.appliedTextFilters.ip)      { params.set('ip', filterState.appliedTextFilters.ip); }
    if (filterState.appliedTextFilters.port)    { params.set('port', filterState.appliedTextFilters.port); }
    if (filterState.appliedTextFilters.asn)     { params.set('asn', filterState.appliedTextFilters.asn); }
    if (filterState.activeThreat)               { params.set('threat', filterState.activeThreat); }
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

function buildSummaryItem(label, value) {
    if (value === null || value === undefined || value === '') { return ''; }
    return [
        '<div class="popup-meta-item">',
        '<span class="popup-meta-label">', label, '</span>',
        '<span class="popup-meta-value">', value, '</span>',
        '</div>',
    ].join('');
}

function buildAggregateSummary(r) {
    const metaItems = [
        buildSummaryItem('Hits', escapeHtml(String(r.count))),
        buildSummaryItem('Country', r.country ? escapeHtml(r.country) : ''),
        buildSummaryItem('First', buildResponsiveTimestamp(r.first_ts)),
        buildSummaryItem('Last', buildResponsiveTimestamp(r.last_ts)),
        buildSummaryItem('ASN', r.asn ? escapeHtml(r.asn) : ''),
    ].filter(Boolean).join('');
    const intel = buildIntelBadges(r);
    const usage = r.usage_type
        ? '<div class="popup-usage"><span class="popup-usage-label">type</span><span class="popup-usage-value">' +
            escapeHtml(r.usage_type) + '</span></div>'
        : '';

    return [
        '<div class="popup-summary">',
        '<div class="popup-summary-top">',
        '<div class="popup-header">',
        '<div class="popup-kicker">Source</div>',
        '<button type="button" class="popup-ip-copy" data-copy-ip="' + escapeHtml(r.src_ip) +
            '" aria-label="Copy source IP" title="Copy source IP">' +
            '<span class="ip">' + escapeHtml(r.src_ip) + '</span></button>',
        '</div>',
        buildLinkouts(r.src_ip),
        '</div>',
        intel || usage ? '<div class="popup-signal-strip">' + intel + usage + '</div>' : '',
        '<div class="popup-meta-grid">' + metaItems + '</div>',
        '</div>',
    ].join('');
}

function buildDetailCard(row) {
    return [
        '<div class="popup-detail-card">',
        '<div class="popup-detail-row">',
        '<span class="popup-detail-label">time</span>',
        '<span class="popup-detail-value">' + buildResponsiveTimestamp(row.ts) + '</span>',
        '</div>',
        '<div class="popup-detail-row popup-flow">',
        '<span class="popup-detail-label">flow</span>',
        '<div class="popup-flow-value"><span class="mono">' + escapeHtml(row.src_ip) + fmtPort(row.src_port) +
            '</span><span class="popup-flow-arrow" aria-hidden="true">&rarr;</span><span class="mono">' +
            escapeHtml(row.dst_ip) + fmtPort(row.dst_port) + '</span></div>',
        '</div>',
        '<div class="popup-detail-row">',
        '<span class="popup-detail-label">proto</span>',
        '<span class="popup-detail-value mono">' + escapeHtml(row.proto || '?') +
            (row.tcp_flags ? ' (' + escapeHtml(row.tcp_flags) + ')' : '') + '</span>',
        '</div>',
        '<div class="popup-detail-row popup-detail-row-rule">',
        '<span class="popup-detail-label">rule</span>',
        '<span class="popup-detail-value">' + escapeHtml(row.rule) + '</span>',
        '</div>',
        '</div>',
    ].join('');
}

function buildDetailPane(srcIp) {
    const state = ensureDetailState(srcIp);
    const slotId = detailSlotId(srcIp);
    const retryBlocked = detailRetryBlocked(state);

    if ((!state.loaded && !state.error) || (state.loading && state.rows.length === 0)) {
        return '<div id="' + slotId + '" class="popup-detail-state">Loading recent events...</div>';
    }

    if (state.error && state.rows.length === 0) {
        if (state.errorKind === 'temporary') {
            return [
                '<div id="' + slotId + '" class="popup-detail-state popup-detail-temporary">',
                '<div>' + escapeHtml(state.error) + '</div>',
                '<div class="popup-detail-hint">Try again in a few seconds.</div>',
                '</div>',
            ].join('');
        }
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
    const disablePrev = (atOldestLoaded && !state.nextCursor) || state.loading || retryBlocked
        ? ' disabled'
        : '';
    let detailHint = '';
    if (state.loading) {
        detailHint = '<div class="popup-detail-hint">Loading older events...</div>';
    } else if (state.error) {
        if (state.errorKind === 'temporary') {
            detailHint = '<div class="popup-detail-hint">Older events temporarily unavailable under load. Try again in a few seconds.</div>';
        } else {
            detailHint = '<div class="popup-detail-hint">Could not load older events.</div>';
        }
    }

    return [
        '<div id="' + slotId + '" class="popup-detail-wrap">',
        '<div class="popup-detail-bar">',
        '<div class="popup-detail-heading">Recent events</div>',
        '</div>',
        buildDetailCard(row),
        '<div class="popup-detail-footer">',
        '<span class="popup-detail-position">' + (state.selectedIndex + 1) + ' / ' +
            detailStateLabel(state) + '</span>',
        '<div class="popup-detail-nav">',
        '<button type="button" class="popup-detail-button" data-action="older" data-ip="' +
            escapeHtml(srcIp) + '"' + disablePrev + '>&larr;</button>',
        '<button type="button" class="popup-detail-button" data-action="newer" data-ip="' +
            escapeHtml(srcIp) + '"' + disableNewer + '>&rarr;</button>',
        '</div>',
        '</div>',
        detailHint,
        '</div>',
    ].join('');
}

function setError(msg) {
    statError.textContent   = msg;
    statError.style.display = msg ? '' : 'none';
}

async function fetchHome({ ignoreRetryGate = false } = {}) {
    if (homeState.homeFetchInFlight) {
        return;
    }
    if (!ignoreRetryGate && homeState.homeRetryAfterMs > 0 && Date.now() < homeState.homeRetryAfterMs) {
        return;
    }
    homeState.homeFetchInFlight = true;
    try {
        const resp = await fetch('/api/home', { cache: 'no-store' });
        if (!resp.ok) {
            if (resp.status === 404) {
                clearHomeState();
            }
            if (homeState.homeStatusExpectedValid) {
                homeState.homeRetryAfterMs = Date.now() + HOME_FETCH_RETRY_MS;
            }
            return;
        }
        const fresh = await resp.json();
        if (!fresh || !Number.isFinite(fresh.lat) || !Number.isFinite(fresh.lon)) {
            if (homeState.homeStatusExpectedValid) {
                homeState.homeRetryAfterMs = Date.now() + HOME_FETCH_RETRY_MS;
            }
            return;
        }
        homeState.homeRetryAfterMs = 0;

        const changed = !homeState.homePt || homeState.homePt.lat !== fresh.lat || homeState.homePt.lon !== fresh.lon;
        if (changed) {
            clearActiveArcs();
            homeState.homePt = fresh;
            if (homeState.homeMarker) { homeState.homeMarker.remove(); homeState.homeMarker = null; }
            addHomeMarker();
        }
    } catch (_) {
        if (homeState.homeStatusExpectedValid) {
            homeState.homeRetryAfterMs = Date.now() + HOME_FETCH_RETRY_MS;
        }
    } finally {
        homeState.homeFetchInFlight = false;
    }
}

function addHomeMarker() {
    if (!homeState.homePt || homeState.homeMarker) { return; }
    setHomeLegendVisible(true);
    homeState.homeMarker = L.circleMarker([homeState.homePt.lat, homeState.homePt.lon], {
        radius:      8,
        color:       '#58a6ff',
        fillColor:   '#58a6ff',
        fillOpacity: 0.10,
        weight:      2.5,
        interactive: true,
    });
    homeState.homeMarker.bindTooltip('Home', { direction: 'top', offset: [0, -8] });
    homeState.homeMarker.addTo(lmap);
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
    for (const activeArc of arcState.activeArcs) {
        if (activeArc.rafId !== null) {
            cancelAnimationFrame(activeArc.rafId);
        }
        if (activeArc.removeTimeoutId !== null) {
            clearTimeout(activeArc.removeTimeoutId);
        }
        activeArc.svg.remove();
    }
    arcState.activeArcs.clear();
}

function fireArc(srcLat, srcLon, color) {
    if (!homeState.homePt) { return; }

    const wrappedSrcLon = shortestWrappedLon(srcLon, homeState.homePt.lon);
    const src = lmap.latLngToLayerPoint([srcLat, wrappedSrcLon]);
    const dst = lmap.latLngToLayerPoint([homeState.homePt.lat, homeState.homePt.lon]);

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

    const activeArc = {
        svg: svg,
        rafId: null,
        removeTimeoutId: null,
    };
    arcState.activeArcs.add(activeArc);

    const totalLen = path.getTotalLength();
    path.style.strokeDasharray = String(totalLen);
    path.style.strokeDashoffset = String(totalLen);
    void path.getBoundingClientRect();
    path.style.transition = 'stroke-dashoffset ' + ARC_DRAW_MS + 'ms ease-in';
    path.style.strokeDashoffset = '0';

    const t0 = performance.now();
    function step(now) {
        if (!arcState.activeArcs.has(activeArc)) { return; }

        const frac = Math.min((now - t0) / ARC_DRAW_MS, 1.0);
        const pt = path.getPointAtLength(frac * totalLen);
        dot.setAttribute('cx', String(pt.x));
        dot.setAttribute('cy', String(pt.y));
        if (frac < 1.0) {
            activeArc.rafId = requestAnimationFrame(step);
            return;
        }
        activeArc.rafId = null;
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
        activeArc.removeTimeoutId = setTimeout(() => {
            svg.remove();
            arcState.activeArcs.delete(activeArc);
            activeArc.removeTimeoutId = null;
        }, ARC_FADE_MS + 50);
    }
    activeArc.rafId = requestAnimationFrame(step);
}

lmap.on('zoomstart', clearActiveArcs);

function shouldCandidateArc(row) {
    return !mapState.isInitialLoad &&
        homeState.homePt &&
        motionEnabled() &&
        typeof row.last_ts === 'number' &&
        row.last_ts > mapState.lastMapTs &&
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
    const detail = isMobileMapUi() ? '' : buildDetailPane(r.src_ip);
    return [
        '<div class="popup-row">',
        buildAggregateSummary(r),
        detail,
        '</div>',
    ].join('');
}

function createPopupOptions() {
    const mobileUi = isMobileMapUi();
    return {
        maxWidth: 360,
        autoPan: true,
        keepInView: true,
        autoPanPaddingTopLeft: L.point(16, 16),
        autoPanPaddingBottomRight: L.point(16, mobileUi ? 24 : 16),
    };
}

function updatePopupContent(row, latlng = null) {
    if (!popupState.activePopup || popupState.activePopupIp !== row.src_ip) { return; }
    popupState.activePopupRow = row;
    if (latlng) {
        popupState.activePopup.setLatLng(latlng);
    }
    popupState.activePopup.setContent(buildAggregatePopup(row));
    popupState.activePopup.update();
    bindPopupControls();
}

function openAggregatePopup(marker, row) {
    popupState.activePopupIp = row.src_ip;
    popupState.activePopupRow = row;
    if (!popupState.activePopup) {
        popupState.activePopup = L.popup(createPopupOptions());
    } else {
        Object.assign(popupState.activePopup.options, createPopupOptions());
    }
    popupState.activePopup.setLatLng(marker.getLatLng());
    popupState.activePopup.setContent(buildAggregatePopup(row));
    popupState.activePopup.openOn(lmap);
    bindPopupControls();

    if (isMobileMapUi()) {
        return;
    }

    const state = ensureDetailState(row.src_ip);
    if (!state.rows.length && !state.loading) {
        if (detailRetryBlocked(state)) {
            updatePopupContent(row, marker.getLatLng());
            return;
        }
        if (!state.rows.length) {
            state.anchorTs = 0;
        }
        ensureDetailAnchor(state);
        void loadDetail(row, '');
        return;
    }
    updatePopupContent(row, marker.getLatLng());
}

async function fetchDetailPage(srcIp, cursor, anchorTs, windowSecs) {
    const since = Math.max(0, anchorTs - windowSecs);
    const params = new URLSearchParams({
        ip: srcIp,
        since: String(since),
        limit: String(DETAIL_PAGE_SIZE),
    });
    if (cursor) { params.set('cursor', cursor); }

    let resp;
    try {
        resp = await fetch('/api/detail?' + params.toString(), { cache: 'no-store' });
    } catch (_) {
        throw makeDetailError('temporary',
            'Recent events temporarily unavailable under load.',
            DETAIL_RETRY_COOLDOWN_MS);
    }

    if (!resp.ok) {
        if (resp.status === 429 || resp.status === 502 || resp.status === 503 || resp.status === 504) {
            const retryAfterMs = parseRetryAfterMs(resp) || DETAIL_RETRY_COOLDOWN_MS;
            throw makeDetailError('temporary',
                'Recent events temporarily unavailable under load.',
                retryAfterMs);
        }
        throw makeDetailError('generic', 'Could not load recent events.');
    }

    let body;
    try {
        body = await resp.json();
    } catch (_) {
        throw makeDetailError('generic', 'Could not load recent events.');
    }
    if (!body || !Array.isArray(body.rows)) {
        throw makeDetailError('generic', 'Could not load recent events.');
    }
    return body;
}

async function loadDetail(row, cursor) {
    const state = ensureDetailState(row.src_ip);
    if (state.loading) { return; }
    const anchorTs = ensureDetailAnchor(state);

    state.loading = true;
    clearDetailRetryTimer(state);
    state.error = '';
    state.errorKind = '';
    state.retryAfterMs = 0;
    updatePopupContent(row);
    try {
        const body = await fetchDetailPage(row.src_ip, cursor, anchorTs, state.windowSecs);
        const rows = body.rows;
        if (cursor) {
            state.rows = state.rows.concat(rows);
        } else {
            state.rows = rows;
            state.selectedIndex = 0;
        }
        state.nextCursor = typeof body.next_cursor === 'string' ? body.next_cursor : '';
        clearDetailRetryTimer(state);
        state.loaded = true;
        state.error = '';
        state.errorKind = '';
        state.retryAfterMs = 0;
    } catch (err) {
        state.error = err && typeof err.message === 'string'
            ? err.message
            : 'Could not load recent events.';
        state.errorKind = err && err.kind === 'temporary' ? 'temporary' : 'generic';
        state.retryAfterMs = state.errorKind === 'temporary' && Number.isFinite(err.retryAfterMs)
            ? (Date.now() + Math.max(0, err.retryAfterMs))
            : 0;
        if (state.errorKind === 'temporary') {
            scheduleDetailRetryUnlock(row, state, Math.max(0, state.retryAfterMs - Date.now()));
        } else {
            clearDetailRetryTimer(state);
        }
        state.loaded = true;
    } finally {
        state.loading = false;
        updatePopupContent(row);
    }
}

async function showOlderDetail(row) {
    const state = ensureDetailState(row.src_ip);
    if (state.loading) { return; }
    if (detailRetryBlocked(state)) { return; }
    if (state.selectedIndex < state.rows.length - 1) {
        state.selectedIndex++;
        updatePopupContent(row);
        return;
    }
    if (!state.nextCursor) { return; }

    const priorLength = state.rows.length;
    await loadDetail(row, state.nextCursor);
    if (state.rows.length > priorLength) {
        state.selectedIndex = priorLength;
        updatePopupContent(row);
    }
}

function showNewerDetail(row) {
    const state = ensureDetailState(row.src_ip);
    if (state.loading || state.selectedIndex === 0) { return; }
    state.selectedIndex--;
    updatePopupContent(row);
}

function bindPopupControls() {
    const popupEl = popupState.activePopup ? popupState.activePopup.getElement() : null;
    if (!popupEl) { return; }

    if (popupEl.dataset.mmPopupControlsBound === '1') { return; }

    popupEl.dataset.mmPopupControlsBound = '1';
    L.DomEvent.disableClickPropagation(popupEl);
    L.DomEvent.disableScrollPropagation(popupEl);

    ['mousedown', 'pointerdown', 'dblclick'].forEach((eventName) => {
        popupEl.addEventListener(eventName, (event) => {
            if (!event.target.closest('[data-action], [data-copy-ip]')) { return; }
            event.stopPropagation();
        });
    });

    popupEl.addEventListener('click', (event) => {
        const popupRow = popupState.activePopupRow;
        if (!popupRow || popupRow.src_ip !== popupState.activePopupIp) {
            return;
        }
        const copyButton = event.target.closest('[data-copy-ip]');
        if (copyButton && popupEl.contains(copyButton)) {
            event.preventDefault();
            event.stopPropagation();
            void copyPopupIp(copyButton);
            return;
        }

        const button = event.target.closest('[data-action]');
        if (!button || !popupEl.contains(button)) { return; }

        event.preventDefault();
        event.stopPropagation();

        const action = button.getAttribute('data-action');
        if (button.getAttribute('data-ip') !== popupRow.src_ip) {
            return;
        }
        if (action === 'retry') {
            const state = ensureDetailState(popupRow.src_ip);
            clearDetailRetryTimer(state);
            state.rows = [];
            state.selectedIndex = 0;
            state.nextCursor = '';
            state.error = '';
            state.errorKind = '';
            state.retryAfterMs = 0;
            state.anchorTs = 0;
            state.loaded = false;
            void loadDetail(popupRow, '');
            return;
        }
        if (action === 'older') {
            void showOlderDetail(popupRow);
            return;
        }
        if (action === 'newer') {
            showNewerDetail(popupRow);
        }
    });
}

async function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
    }

    const probe = document.createElement('textarea');
    probe.value = text;
    probe.setAttribute('readonly', '');
    probe.style.position = 'fixed';
    probe.style.top = '-1000px';
    probe.style.left = '-1000px';
    document.body.appendChild(probe);
    probe.select();
    let ok = false;
    try {
        ok = document.execCommand('copy');
    } catch (_) {
        ok = false;
    }
    probe.remove();
    if (!ok) {
        throw new Error('copy failed');
    }
}

function showPopupCopyState(button, state) {
    button.classList.remove('is-copied', 'is-copy-failed');
    button.classList.add(state === 'copied' ? 'is-copied' : 'is-copy-failed');
    const header = button.closest('.popup-header');
    const kicker = header ? header.querySelector('.popup-kicker') : null;
    if (kicker) {
        kicker.textContent = state === 'copied' ? 'Copied' : 'Copy failed';
    }
    window.setTimeout(() => {
        if (!button.isConnected) { return; }
        button.classList.remove('is-copied', 'is-copy-failed');
        if (kicker && kicker.isConnected) {
            kicker.textContent = 'Source';
        }
    }, state === 'copied' ? 1200 : 1600);
}

async function copyPopupIp(button) {
    const ip = button.getAttribute('data-copy-ip');
    if (!ip) { return; }
    try {
        await copyText(ip);
        showPopupCopyState(button, 'copied');
    } catch (_) {
        showPopupCopyState(button, 'failed');
    }
}

function isSpikeMarker(row) {
    const windowSecs = currentWindowSecs();
    if (windowSecs !== 900 && windowSecs !== 3600) { return false; }
    if (!Number.isFinite(row.count) || !Number.isFinite(row.first_ts) || !Number.isFinite(row.last_ts)) {
        return false;
    }

    const now = Number.isFinite(mapState.lastMapGeneratedAt) && mapState.lastMapGeneratedAt > 0
        ? mapState.lastMapGeneratedAt
        : Math.floor(Date.now() / 1000);
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
    el.classList.toggle('marker-spike', spiking && motionEnabled());

    const tooltip = marker.getTooltip();
    if (spiking) {
        if (!tooltip) {
            marker.bindTooltip('!', {
                permanent: true,
                direction: 'center',
                offset: [0, 0],
                className: 'spike-node-badge',
                opacity: 1,
                interactive: false,
            });
        }
        marker.openTooltip();
        return;
    }

    if (tooltip) {
        marker.closeTooltip();
        marker.unbindTooltip();
    }
}

function refreshVisibleMarkerMotionState() {
    cluster.eachLayer((layer) => {
        if (!(layer instanceof L.CircleMarker)) {
            return;
        }
        applySpikeMarkerState(layer, layer.options.spiking === true);
    });
}

function renderMap(rows) {
    const reopenIp = popupState.activePopupIp;
    let reopenMarker = null;
    let reopenRow = null;
    const mobileUi = isMobileMapUi();

    cluster.clearLayers();
    mapState.mappedCount = 0;
    mapState.totalSeen = 0;
    const arcCandidates = [];

    for (const r of rows) {
        if (r.lat === null || r.lon === null || r.lat === undefined || r.lon === undefined) {
            continue;
        }
        mapState.totalSeen += Number.isFinite(r.count) ? r.count : 0;

        const threat = markerThreat(r);
        const spiking = isSpikeMarker(r);
        const color = threat === 'high'
            ? '#f85149'
            : markerColor((r.threat_max !== undefined) ? r.threat_max : null);
        const marker = L.circleMarker([r.lat, r.lon], {
            radius:      mobileUi ? (spiking ? 8 : 7) : (spiking ? 6 : 5),
            color:       color,
            fillColor:   color,
            fillOpacity: 0.75,
            weight:      mobileUi ? (spiking ? 2.5 : 2) : (spiking ? 2 : 1),
            threat:      threat,
            spiking:     spiking,
            srcIp:       r.src_ip,
        });
        marker.on('add', () => {
            setTimeout(() => {
                applySpikeMarkerState(marker, spiking);
            }, 0);
        });
        marker.on('click', () => {
            openAggregatePopup(marker, r);
        });
        cluster.addLayer(marker);
        mapState.mappedCount++;
        if (reopenIp && r.src_ip === reopenIp) {
            reopenMarker = marker;
            reopenRow = r;
        }

        if (shouldCandidateArc(r)) {
            arcCandidates.push(makeArcCandidate(r, color));
        }
    }

    if (!reopenMarker && reopenIp) {
        popupState.activePopupIp = '';
    }

    renderArcBatch(arcCandidates);
    if (reopenMarker && reopenRow) {
        updatePopupContent(reopenRow, reopenMarker.getLatLng());
    } else if (popupState.activePopup) {
        lmap.closePopup(popupState.activePopup);
    }
}

function scheduleNextPoll(delayMs) {
    if (mapState.pollTimer !== null) {
        clearTimeout(mapState.pollTimer);
    }
    mapState.pollTimer = setTimeout(() => {
        mapState.pollTimer = null;
        void poll();
    }, delayMs);
}

function requestPollNow() {
    if (mapState.pollTimer !== null) {
        clearTimeout(mapState.pollTimer);
        mapState.pollTimer = null;
    }
    // Keep one queued refresh rather than overlapping fetch/render cycles.
    if (mapState.pollInFlight) {
        mapState.pollQueued = true;
        return;
    }
    void poll();
}

async function poll() {
    if (mapState.pollInFlight) {
        mapState.pollQueued = true;
        return;
    }
    mapState.pollInFlight = true;
    updateMapFeedIndicator();
    try {
        const resp = await fetch('/api/map' + buildMapQueryString(), { cache: 'no-store' });
        if (!resp.ok) {
            setError('API ' + resp.status);
            updateMapFeedIndicator(Date.now() + (NORMAL_REFRESH_MS * 3));
            scheduleNextPoll(ERROR_REFRESH_MS);
            return;
        }

        const body = await resp.json();
        const rows = Array.isArray(body.rows) ? body.rows : [];
        mapState.lastMapGeneratedAt = Number.isFinite(body.generated_at)
            ? body.generated_at
            : Math.floor(Date.now() / 1000);
        setError('');
        renderMap(rows);

        let newestTs = 0;
        for (const r of rows) {
            if (typeof r.last_ts === 'number' && r.last_ts > newestTs) {
                newestTs = r.last_ts;
            }
        }
        mapState.lastMapTs = newestTs;
        mapState.lastMapSuccessAt = Date.now();
        updateMapFeedIndicator(mapState.lastMapSuccessAt);
        setStatusCounts(mapState.mappedCount, mapState.totalSeen);
        setStatusFreshness(formatMapFreshness(body.generated_at, mapState.lastMapSuccessAt));
        mapState.isInitialLoad = false;

        scheduleNextPoll(document.visibilityState === 'hidden' ? HIDDEN_REFRESH_MS : NORMAL_REFRESH_MS);
    } catch (err) {
        setError(err.message);
        updateMapFeedIndicator(Date.now() + (NORMAL_REFRESH_MS * 3));
        scheduleNextPoll(ERROR_REFRESH_MS);
    } finally {
        mapState.pollInFlight = false;
        if (mapState.pollQueued) {
            mapState.pollQueued = false;
            requestPollNow();
        }
    }
}

function pollNow() {
    clearActiveArcs();
    mapState.isInitialLoad = true;
    mapState.lastMapTs = 0;
    mapState.lastMapGeneratedAt = 0;
    setStatusCounts(0, 0);
    setStatusFreshness('Refreshing...');
    requestPollNow();
}

document.addEventListener('visibilitychange', () => {
    updateMapFeedIndicator();
    if (document.visibilityState === 'visible') {
        void fetchStatus();
        scheduleStatusPoll();
        if (!mapState.pollInFlight) {
            requestPollNow();
        }
        return;
    }
    if (statusState.statusPollTimer !== null) {
        clearTimeout(statusState.statusPollTimer);
        statusState.statusPollTimer = null;
    }
    scheduleNextPoll(HIDDEN_REFRESH_MS);
});

loadFilters();
filterState.appliedTextFilters.ip      = validateIpValue(fIp.value).normalized;
filterState.appliedTextFilters.port    = validatePortValue(fPort.value).normalized;
filterState.appliedTextFilters.asn = validateAsnValue(fAsn.value).normalized;
fIp.value = filterState.appliedTextFilters.ip;
fPort.value = filterState.appliedTextFilters.port;
fAsn.value = filterState.appliedTextFilters.asn;
updateTextValidity();
saveFilters();
setOperatorStatus(null);
setHomeLegendVisible(false);
updateMapFeedIndicator();
void fetchStatus();
scheduleStatusPoll();
pollNow();

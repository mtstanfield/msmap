/* msmap – shared frontend state, constants, and core handles */
// @ts-check
'use strict';

/** @typedef {import('./types.js').FilterPersistedState} FilterPersistedState */
/** @typedef {import('./types.js').FilterRuntimeState} FilterRuntimeState */
/** @typedef {import('./types.js').MapRuntimeState} MapRuntimeState */
/** @typedef {import('./types.js').PopupRuntimeState} PopupRuntimeState */
/** @typedef {import('./types.js').StatusRuntimeState} StatusRuntimeState */
/** @typedef {import('./types.js').HomeRuntimeState} HomeRuntimeState */
/** @typedef {import('./types.js').ArcRuntimeState} ArcRuntimeState */

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
/** @type {Readonly<FilterPersistedState>} */
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

/** @type {FilterRuntimeState} */
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

/** @type {MapRuntimeState} */
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

/** @type {PopupRuntimeState} */
const popupState = {
    activePopupIp: '',
    activePopup: null,
    activePopupRow: null,
    detailStateByIp: new Map(),
};

/** @type {StatusRuntimeState} */
const statusState = {
    statusPollTimer: null,
    statusInFlight: false,
};

/** @type {HomeRuntimeState} */
const homeState = {
    homePt: null,
    homeMarker: null,
    homeFetchInFlight: false,
    homeRetryAfterMs: 0,
    homeStatusExpectedValid: false,
    lastHomeUpdatedAt: null,
};

/** @type {ArcRuntimeState} */
const arcState = {
    activeArcs: new Set(),
};

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
    /** @param {any} clusterMarker */
    iconCreateFunction(clusterMarker) {
        /** @type {any[]} */
        const children = clusterMarker.getAllChildMarkers();
        const total = children.length;
        let hasHigh = false;
        let hasMedium = false;
        let hasLow = false;
        let hasSpike = false;
        for (const child of children) {
            if (child?.options?.threat === 'high') { hasHigh = true; }
            if (child?.options?.threat === 'medium') { hasMedium = true; }
            if (child?.options?.threat === 'low') { hasLow = true; }
            if (child?.options?.spiking === true) { hasSpike = true; }
        }
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

const msmapDeps = {
    NORMAL_REFRESH_MS,
    HIDDEN_REFRESH_MS,
    ERROR_REFRESH_MS,
    STATUS_REFRESH_MS,
    HOME_FETCH_RETRY_MS,
    DETAIL_PAGE_SIZE,
    DETAIL_RETRY_COOLDOWN_MS,
    DETAIL_STATE_CACHE_MAX,
    TEXT_FILTER_DEBOUNCE_MS,
    ARC_DRAW_MS,
    ARC_FADE_MS,
    MAX_ARCS_POLL,
    STORAGE_KEY,
    MOTION_SESSION_KEY,
    DEFAULT_FILTERS,
    filterState,
    mapState,
    popupState,
    statusState,
    homeState,
    arcState,
    lmap,
    cluster,
    statMapped,
    statTotal,
    statTime,
    statEvents,
    statSources,
    statIntel,
    statAbuse,
    statMappedValue,
    statTotalValue,
    statTimeValue,
    statEventsValue,
    statSourcesValue,
    statIntelValue,
    statAbuseValue,
    statError,
    filterPanel,
    filterToggle,
    filterTabButtons,
    filterTabFilters,
    filterTabLegend,
    fTime,
    fProto,
    fIp,
    fPort,
    fAsn,
    fThreatButtons,
    fThreatText,
    fMotionOn,
    fMotionOff,
    legendHome,
    statDot,
    statusOpSeparators,
};

window.msmapDeps = msmapDeps;
Object.assign(window, msmapDeps);

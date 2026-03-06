/* msmap – map rendering, popups, polling, and status UI */
// @ts-check
'use strict';

/** @typedef {import('./types.js').MapRow} MapRow */
/** @typedef {import('./types.js').DetailRow} DetailRow */
/** @typedef {import('./types.js').DetailEntryState} DetailEntryState */
/** @typedef {import('./types.js').StatusPayload} StatusPayload */
/** @typedef {import('./types.js').DetailError} DetailError */

/**
 * @param {number} ts
 * @returns {string}
 */
function fmtTs(ts) {
    return new Date(ts * 1000).toLocaleString();
}

/**
 * @param {number} ts
 * @returns {string}
 */
function fmtTsCompact(ts) {
    return new Date(ts * 1000).toLocaleString(undefined, {
        month: 'numeric',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
    });
}

/**
 * @param {number} ts
 * @returns {string}
 */
function buildResponsiveTimestamp(ts) {
    return '<span class="popup-time-full">' + escapeHtml(fmtTs(ts)) + '</span>' +
        '<span class="popup-time-compact">' + escapeHtml(fmtTsCompact(ts)) + '</span>';
}

/**
 * @param {number|null|undefined} p
 * @returns {string}
 */
function fmtPort(p) {
    return (p !== null && p !== undefined) ? ':' + p : '';
}

/**
 * @param {number|null|undefined} threat
 * @returns {string}
 */
function markerColor(threat) {
    if (threat === null || threat === undefined) { return '#adbac7'; }
    if (threat === 0)   { return '#3fb950'; }
    if (threat <= 33)   { return '#d29922'; }
    if (threat <= 66)   { return '#f0883e'; }
    return '#f85149';
}

/**
 * @param {MapRow} row
 * @returns {import('./types.js').ThreatLevel}
 */
function markerThreat(row) {
    if (row.spamhaus_drop === true) { return 'high'; }
    const threat = row.threat_max;
    if (threat === null || threat === undefined) { return 'unknown'; }
    if (threat === 0)   { return 'clean'; }
    if (threat <= 33)   { return 'low'; }
    if (threat <= 66)   { return 'medium'; }
    return 'high';
}

/**
 * @param {number|null|undefined} score
 * @returns {string}
 */
function threatClass(score) {
    if (score === null || score === undefined) { return 'threat-unknown'; }
    if (score === 0)   { return 'threat-clean'; }
    if (score <= 33)   { return 'threat-low'; }
    if (score <= 66)   { return 'threat-medium'; }
    return 'threat-high';
}

/**
 * @param {string} s
 * @returns {string}
 */
function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * @param {string} srcIp
 * @returns {string}
 */
function detailSlotId(srcIp) {
    return 'detail-' + srcIp.replace(/[^A-Za-z0-9_-]/g, '-');
}

/**
 * @param {DetailEntryState} state
 * @returns {string}
 */
function detailStateLabel(state) {
    const total = state.rows.length;
    if (!state.nextCursor) {
        return String(total);
    }
    return total + '+';
}

/**
 * @param {DetailEntryState} state
 * @param {number} [nowMs]
 * @returns {boolean}
 */
function detailRetryBlocked(state, nowMs = Date.now()) {
    return state.errorKind === 'temporary' && nowMs < state.retryAfterMs;
}

/**
 * @param {'temporary'|'generic'} kind
 * @param {string} message
 * @param {number} [retryAfterMs]
 * @returns {DetailError}
 */
function makeDetailError(kind, message, retryAfterMs = 0) {
    return { kind, message, retryAfterMs };
}

/**
 * @param {DetailEntryState} state
 */
function clearDetailRetryTimer(state) {
    if (state.retryTimerId !== null) {
        clearTimeout(state.retryTimerId);
        state.retryTimerId = null;
    }
}

/**
 * @param {MapRow} row
 * @param {DetailEntryState} state
 * @param {number} delayMs
 */
function scheduleDetailRetryUnlock(row, state, delayMs) {
    clearDetailRetryTimer(state);
    if (delayMs <= 0) { return; }
    state.retryTimerId = setTimeout(() => {
        state.retryTimerId = null;
        updatePopupContent(row);
    }, delayMs);
}

/**
 * @param {number} mapped
 * @param {number} total
 */
function setStatusCounts(mapped, total) {
    statMappedValue.textContent = mapped.toLocaleString();
    statTotalValue.textContent = total.toLocaleString();
}

/**
 * @param {string} text
 */
function setStatusFreshness(text) {
    statTimeValue.textContent = text;
}

/**
 * @param {number} generatedAt
 * @param {number} [nowMs]
 * @returns {string}
 */
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

/**
 * @param {number} value
 * @returns {string}
 */
function formatCompactCount(value) {
    return new Intl.NumberFormat(undefined, {
        notation: 'compact',
        maximumFractionDigits: 1,
    }).format(value);
}

/**
 * @param {number} targetSec
 * @param {number} nowSec
 * @returns {string|null}
 */
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

/**
 * @param {number} nowSec
 * @returns {string|null}
 */
function formatUtcMidnightCountdown(nowSec) {
    if (!Number.isFinite(nowSec) || nowSec < 0) {
        return null;
    }
    const secondsPerDay = 24 * 60 * 60;
    const nextMidnightSec = (Math.floor(nowSec / secondsPerDay) + 1) * secondsPerDay;
    return formatCountdownUntil(nextMidnightSec, nowSec);
}

/** @type {HTMLElement|null} */
let activeStatusTooltipTarget = null;

const statusTooltipEl = /** @type {HTMLElement} */ (window.msmapDeps.statusTooltip);

let statusTooltipRaf = 0;

/**
 * @param {HTMLElement} target
 */
function showStatusTooltip(target) {
    const text = target.dataset.tooltip || '';
    if (!text) {
        hideStatusTooltip();
        return;
    }

    activeStatusTooltipTarget = target;
    statusTooltipEl.textContent = text;
    statusTooltipEl.dataset.size = target.classList.contains('status-tooltip-compact') ? 'compact' : 'normal';
    if (target.classList.contains('status-tooltip-nowrap')) {
        statusTooltipEl.dataset.nowrap = 'true';
    } else {
        delete statusTooltipEl.dataset.nowrap;
    }
    statusTooltipEl.classList.add('is-visible');
    scheduleStatusTooltipReposition();
}

function hideStatusTooltip() {
    activeStatusTooltipTarget = null;
    if (statusTooltipRaf) {
        cancelAnimationFrame(statusTooltipRaf);
        statusTooltipRaf = 0;
    }
    statusTooltipEl.classList.remove('is-visible');
}

function repositionStatusTooltip() {
    statusTooltipRaf = 0;
    if (!activeStatusTooltipTarget || !statusTooltipEl.classList.contains('is-visible')) {
        return;
    }

    const targetRect = activeStatusTooltipTarget.getBoundingClientRect();
    const tooltipRect = statusTooltipEl.getBoundingClientRect();
    if (!tooltipRect.width || !tooltipRect.height) {
        return;
    }

    const viewportPad = 8;
    const offset = 10;
    let left = targetRect.left + ((targetRect.width - tooltipRect.width) / 2);
    if (activeStatusTooltipTarget.classList.contains('status-tooltip-align-left')) {
        left = targetRect.left;
    } else if (activeStatusTooltipTarget.classList.contains('status-tooltip-align-right')) {
        left = targetRect.right - tooltipRect.width;
    }
    left = Math.max(viewportPad, Math.min(left, window.innerWidth - tooltipRect.width - viewportPad));

    let top = targetRect.top - tooltipRect.height - offset;
    if (top < viewportPad) {
        top = Math.min(window.innerHeight - tooltipRect.height - viewportPad, targetRect.bottom + offset);
    }

    statusTooltipEl.style.left = Math.round(left) + 'px';
    statusTooltipEl.style.top = Math.round(top) + 'px';
}

function scheduleStatusTooltipReposition() {
    if (statusTooltipRaf) {
        return;
    }
    statusTooltipRaf = requestAnimationFrame(repositionStatusTooltip);
}

/**
 * @param {HTMLElement} target
 */
function syncActiveStatusTooltip(target) {
    if (activeStatusTooltipTarget === target) {
        showStatusTooltip(target);
    }
}

function initStatusTooltips() {
    /** @type {HTMLElement[]} */
    const targets = Array.from(document.querySelectorAll('#status-bar .status-tooltip-target'));
    targets.forEach((target) => {
        target.addEventListener('mouseenter', () => showStatusTooltip(target));
        target.addEventListener('mouseleave', () => {
            if (activeStatusTooltipTarget === target) {
                hideStatusTooltip();
            }
        });
        target.addEventListener('focusin', () => showStatusTooltip(target));
        target.addEventListener('focusout', () => {
            if (activeStatusTooltipTarget === target) {
                hideStatusTooltip();
            }
        });
    });

    window.addEventListener('resize', scheduleStatusTooltipReposition);
    window.addEventListener('scroll', scheduleStatusTooltipReposition, true);
}

/**
 * @param {StatusPayload|null} status
 */
function setOperatorStatus(status) {
    if (!status || status.ok !== true) {
        statEvents.style.display = 'none';
        statSources.style.display = 'none';
        statIntel.style.display = 'none';
        statAbuse.style.display = 'none';
        statusOpSeparators.forEach((el) => {
            el.style.display = 'none';
        });
        syncActiveStatusTooltip(statIntel);
        syncActiveStatusTooltip(statAbuse);
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
        statIntel.dataset.tooltip = 'Threat intel feeds: off.';
    } else {
        const now = typeof status.now === 'number' ? status.now : Math.floor(Date.now() / 1000);
        const refreshTs = typeof status.intel_last_refresh_ts === 'number' ? status.intel_last_refresh_ts : 0;
        if (refreshTs <= 0) {
            if (status.intel_refresh_attempted === true) {
                statIntelValue.textContent = 'stale';
                statIntelValue.classList.add('status-state-stale');
                statIntel.dataset.tooltip = 'Threat intel feeds: stale.';
            } else {
                statIntelValue.textContent = 'syncing';
                statIntelValue.classList.add('status-state-syncing');
                statIntel.dataset.tooltip = 'Threat intel feeds: syncing.';
            }
        } else if ((now - refreshTs) <= (12 * 3600)) {
            statIntelValue.textContent = 'ok';
            statIntelValue.classList.add('status-state-ok');
            statIntel.dataset.tooltip = 'Threat intel feeds: ok.';
        } else {
            statIntelValue.textContent = 'stale';
            statIntelValue.classList.add('status-state-stale');
            statIntel.dataset.tooltip = 'Threat intel feeds: stale.';
        }
    }

    if (status.abuse_enabled !== true) {
        statAbuseValue.textContent = 'off';
        statAbuseValue.classList.add('status-state-off');
        statAbuse.dataset.tooltip = 'AbuseIPDB lookups disabled.\nCached results shown.';
        return;
    }

    const abuseRemaining = Number.isFinite(status.abuse_rate_remaining) ? status.abuse_rate_remaining : null;
    if (abuseRemaining === null && status.abuse_quota_exhausted !== true) {
        if (status.abuse_can_accept_new_lookups === false) {
            statAbuseValue.textContent = 'quota';
            statAbuseValue.classList.add('status-state-stale');
            statAbuse.dataset.tooltip = 'AbuseIPDB quota exhausted.\nNew lookups paused.';
        } else if (status.abuse_has_pending_work === true) {
            statAbuseValue.textContent = 'syncing';
            statAbuseValue.classList.add('status-state-syncing');
            statAbuse.dataset.tooltip = 'Waiting for first\nAbuseIPDB quota response.';
        } else {
            statAbuseValue.textContent = 'ok';
            statAbuseValue.classList.add('status-state-ok');
            statAbuse.dataset.tooltip = 'AbuseIPDB lookups enabled.\nQuota pending.';
        }
    } else if (status.abuse_quota_exhausted === true) {
        statAbuseValue.textContent = 'quota';
        statAbuseValue.classList.add('status-state-stale');
        const now = typeof status.now === 'number' ? status.now : Math.floor(Date.now() / 1000);
        const retryAfterTs = typeof status.abuse_quota_retry_after_ts === 'number'
            ? status.abuse_quota_retry_after_ts
            : null;
        const retryCountdown = retryAfterTs !== null
            ? formatCountdownUntil(retryAfterTs, now)
            : null;
        if (retryCountdown !== null) {
            if (retryCountdown === 'pending') {
                statAbuse.dataset.tooltip = 'AbuseIPDB quota exhausted.\nNext retry pending.';
            } else {
                statAbuse.dataset.tooltip = 'AbuseIPDB quota exhausted.\nNext retry in ' + retryCountdown + '.';
            }
        } else {
            const quotaResetCountdown = formatUtcMidnightCountdown(now);
            statAbuse.dataset.tooltip = quotaResetCountdown
                ? ('AbuseIPDB quota exhausted.\nRefresh in ' + quotaResetCountdown + '.')
                : 'AbuseIPDB quota exhausted.\nRefresh pending.';
        }
    } else {
        statAbuseValue.textContent = 'ok';
        statAbuseValue.classList.add('status-state-ok');
        statAbuse.dataset.tooltip = abuseRemaining !== null
            ? ('AbuseIPDB can accept new lookups.\nRequests remaining: ' + abuseRemaining + '.')
            : 'AbuseIPDB can accept new lookups.';
    }
    syncActiveStatusTooltip(statIntel);
    syncActiveStatusTooltip(statAbuse);
}

/**
 * @param {'healthy'|'stale'|'unknown'} nextState
 */
function setMapFeedState(nextState) {
    statDot.classList.remove('is-unknown', 'is-healthy', 'is-stale');
    statDot.classList.add(
        nextState === 'healthy' ? 'is-healthy' :
        nextState === 'stale' ? 'is-stale' :
        'is-unknown'
    );
}

/**
 * @param {boolean} visible
 */
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

/**
 * @param {StatusPayload|null|undefined} status
 * @returns {number|null}
 */
function readHomeUpdatedAt(status) {
    const value = status?.home_updated_at;
    return typeof value === 'number' ? Math.trunc(value) : null;
}

/**
 * @param {StatusPayload|null|undefined} status
 */
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
        const result = await window.msmapApi.fetchStatusApi();
        if (!result.ok) {
            setOperatorStatus(null);
            return;
        }
        setOperatorStatus(result.data);
        syncHomeStateFromStatus(result.data);
    } catch (_) {
        setOperatorStatus(null);
    } finally {
        statusState.statusInFlight = false;
    }
}

/**
 * @param {number} [delayMs]
 */
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

/**
 * @param {number} [now]
 */
function updateMapFeedIndicator(now = Date.now()) {
    if (mapState.lastMapSuccessAt === 0) {
        setMapFeedState('unknown');
        return;
    }
    const staleAfterMs = NORMAL_REFRESH_MS * 2;
    setMapFeedState((now - mapState.lastMapSuccessAt) <= staleAfterMs ? 'healthy' : 'stale');
}

/**
 * @param {string} srcIp
 * @returns {DetailEntryState}
 */
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

    /** @type {DetailEntryState} */
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

/**
 * @param {string} srcIp
 * @param {DetailEntryState} state
 */
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

/**
 * @param {DetailEntryState} state
 * @returns {number}
 */
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

/**
 * @param {number|null|undefined} score
 * @returns {string}
 */
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

/**
 * @param {MapRow} r
 * @returns {string}
 */
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

/**
 * @param {string} srcIp
 * @returns {string}
 */
function buildLinkouts(srcIp) {
    const safeIp = encodeURIComponent(srcIp);
    const links = [
        { href: 'https://viz.greynoise.io/ip/' + safeIp, icon: greyNoiseIconSvg(), title: 'Open GreyNoise' },
        { href: 'https://www.shodan.io/host/' + safeIp, icon: shodanIconSvg(), title: 'Open Shodan' },
        { href: 'https://www.abuseipdb.com/check/' + safeIp, icon: abuseIpdbIconSvg(), title: 'Open AbuseIPDB' },
        { href: 'https://otx.alienvault.com/indicator/ip/' + safeIp, icon: otxIconSvg(), title: 'Open AlienVault OTX' },
    ];
    return '<div class="popup-linkouts">' + links.map((link) =>
        '<a class="popup-linkout" href="' + link.href + '" target="_blank" rel="noopener noreferrer" title="' +
        link.title + '" aria-label="' + link.title + '">' + link.icon + '</a>'
    ).join('') + '</div>';
}

/**
 * @param {string} label
 * @param {string} value
 * @returns {string}
 */
function buildSummaryItem(label, value) {
    if (value === null || value === undefined || value === '') { return ''; }
    return [
        '<div class="popup-meta-item">',
        '<span class="popup-meta-label">', label, '</span>',
        '<span class="popup-meta-value">', value, '</span>',
        '</div>',
    ].join('');
}

/**
 * @param {MapRow} r
 * @returns {string}
 */
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

/**
 * @param {DetailRow} row
 * @returns {string}
 */
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

/**
 * @param {string} srcIp
 * @returns {string}
 */
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
        '<span class="popup-detail-position">' + (state.selectedIndex + 1) + ' / ' + detailStateLabel(state) + '</span>',
        '<div class="popup-detail-nav">',
        '<button type="button" class="popup-detail-button" data-action="older" data-ip="' + escapeHtml(srcIp) + '"' + disablePrev + '>&larr;</button>',
        '<button type="button" class="popup-detail-button" data-action="newer" data-ip="' + escapeHtml(srcIp) + '"' + disableNewer + '>&rarr;</button>',
        '</div>',
        '</div>',
        detailHint,
        '</div>',
    ].join('');
}

/**
 * @param {string} msg
 */
function setError(msg) {
    statError.textContent = msg;
    statError.style.display = msg ? '' : 'none';
}

/**
 * @param {{ignoreRetryGate?: boolean}} [opts]
 */
async function fetchHome(opts = {}) {
    const { ignoreRetryGate = false } = opts;
    if (homeState.homeFetchInFlight) {
        return;
    }
    if (!ignoreRetryGate && homeState.homeRetryAfterMs > 0 && Date.now() < homeState.homeRetryAfterMs) {
        return;
    }
    homeState.homeFetchInFlight = true;
    try {
        const result = await window.msmapApi.fetchHomeApi();
        if (!result.ok) {
            if (result.status === 404) {
                clearHomeState();
            }
            if (homeState.homeStatusExpectedValid) {
                homeState.homeRetryAfterMs = Date.now() + HOME_FETCH_RETRY_MS;
            }
            return;
        }
        const fresh = result.data;
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

/**
 * @param {number} srcLon
 * @param {number} dstLon
 * @returns {number}
 */
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

/**
 * @param {number} srcLat
 * @param {number} srcLon
 * @param {string} color
 */
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
    path.setAttribute('d', 'M ' + src.x + ' ' + src.y + ' Q ' + cpx + ' ' + cpy + ' ' + dst.x + ' ' + dst.y);
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

    /** @type {import('./types.js').ArcHandle} */
    const activeArc = { svg: svg, rafId: null, removeTimeoutId: null };
    arcState.activeArcs.add(activeArc);

    const totalLen = path.getTotalLength();
    path.style.strokeDasharray = String(totalLen);
    path.style.strokeDashoffset = String(totalLen);
    void path.getBoundingClientRect();
    path.style.transition = 'stroke-dashoffset ' + ARC_DRAW_MS + 'ms ease-in';
    path.style.strokeDashoffset = '0';

    const t0 = performance.now();
    /**
     * @param {number} now
     */
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

/**
 * @param {MapRow} row
 * @returns {boolean}
 */
function shouldCandidateArc(row) {
    return !mapState.isInitialLoad &&
        homeState.homePt !== null &&
        motionEnabled() &&
        typeof row.last_ts === 'number' &&
        row.last_ts > mapState.lastMapTs &&
        Number.isFinite(row.lat) &&
        Number.isFinite(row.lon);
}

/**
 * @param {number} lat
 * @param {number} lon
 * @returns {string}
 */
function arcOriginKey(lat, lon) {
    const roundedLat = Math.round(lat * 2) / 2;
    const roundedLon = Math.round(lon * 2) / 2;
    return String(roundedLat) + ':' + String(roundedLon);
}

/**
 * @param {MapRow} row
 * @param {string} color
 * @returns {{srcIp: string, lat: number, lon: number, lastTs: number, threat: number, count: number, color: string, dedupeKey: string}}
 */
function makeArcCandidate(row, color) {
    const lat = typeof row.lat === 'number' ? row.lat : 0;
    const lon = typeof row.lon === 'number' ? row.lon : 0;
    return {
        srcIp: row.src_ip,
        lat,
        lon,
        lastTs: row.last_ts,
        threat: (row.threat_max !== null && row.threat_max !== undefined) ? row.threat_max : -1,
        count: Number.isFinite(row.count) ? row.count : 0,
        color: color,
        dedupeKey: arcOriginKey(lat, lon),
    };
}

/**
 * @param {{srcIp: string, lat: number, lon: number, lastTs: number, threat: number, count: number, color: string, dedupeKey: string}} left
 * @param {{srcIp: string, lat: number, lon: number, lastTs: number, threat: number, count: number, color: string, dedupeKey: string}} right
 * @returns {number}
 */
function compareArcCandidates(left, right) {
    if (left.lastTs !== right.lastTs) { return right.lastTs - left.lastTs; }
    if (left.threat !== right.threat) { return right.threat - left.threat; }
    return left.srcIp.localeCompare(right.srcIp);
}

/**
 * @param {Array<{srcIp: string, lat: number, lon: number, lastTs: number, threat: number, count: number, color: string, dedupeKey: string}>} candidates
 */
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

/**
 * @param {Array<{srcIp: string, lat: number, lon: number, lastTs: number, threat: number, count: number, color: string, dedupeKey: string}>} candidates
 */
function renderArcBatch(candidates) {
    const ranked = candidates.slice().sort(compareArcCandidates);
    for (const candidate of dedupeArcCandidates(ranked).slice(0, MAX_ARCS_POLL)) {
        fireArc(candidate.lat, candidate.lon, candidate.color);
    }
}

/**
 * @param {MapRow} r
 * @returns {string}
 */
function buildAggregatePopup(r) {
    const detail = isMobileMapUi() ? '' : buildDetailPane(r.src_ip);
    return ['<div class="popup-row">', buildAggregateSummary(r), detail, '</div>'].join('');
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

/**
 * @param {MapRow} row
 * @param {any|null} [latlng]
 */
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

/**
 * @param {any} marker
 * @param {MapRow} row
 */
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

/**
 * @param {string} srcIp
 * @param {string} cursor
 * @param {number} anchorTs
 * @param {number} windowSecs
 * @returns {Promise<import('./types.js').DetailResponseBody>}
 */
async function fetchDetailPage(srcIp, cursor, anchorTs, windowSecs) {
    const since = Math.max(0, anchorTs - windowSecs);
    const params = new URLSearchParams({
        ip: srcIp,
        since: String(since),
        limit: String(DETAIL_PAGE_SIZE),
    });
    if (cursor) { params.set('cursor', cursor); }

    const result = await window.msmapApi.fetchDetailApi(params.toString());
    if (!result.ok) {
        if (result.status === 429 || result.status === 502 || result.status === 503 || result.status === 504 ||
            result.kind === 'timeout' || result.kind === 'network') {
            throw makeDetailError('temporary', 'Recent events temporarily unavailable under load.', result.retryAfterMs || DETAIL_RETRY_COOLDOWN_MS);
        }
        throw makeDetailError('generic', 'Could not load recent events.');
    }
    const body = result.data;
    if (!body || !Array.isArray(body.rows)) {
        throw makeDetailError('generic', 'Could not load recent events.');
    }
    return body;
}

/**
 * @param {MapRow} row
 * @param {string} cursor
 */
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
        state.error = err && typeof err.message === 'string' ? err.message : 'Could not load recent events.';
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

/**
 * @param {MapRow} row
 */
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

/**
 * @param {MapRow} row
 */
function showNewerDetail(row) {
    const state = ensureDetailState(row.src_ip);
    if (state.loading || state.selectedIndex === 0) { return; }
    state.selectedIndex--;
    updatePopupContent(row);
}

function bindPopupControls() {
    const popupEl = /** @type {HTMLElement|null} */ (
        popupState.activePopup ? popupState.activePopup.getElement() : null
    );
    if (!popupEl) { return; }
    if (popupEl.dataset.mmPopupControlsBound === '1') { return; }

    popupEl.dataset.mmPopupControlsBound = '1';
    L.DomEvent.disableClickPropagation(popupEl);
    L.DomEvent.disableScrollPropagation(popupEl);

    ['mousedown', 'pointerdown', 'dblclick'].forEach((eventName) => {
        popupEl.addEventListener(eventName, (event) => {
            const target = /** @type {Element|null} */ (event.target instanceof Element ? event.target : null);
            if (!target || !target.closest('[data-action], [data-copy-ip]')) { return; }
            event.stopPropagation();
        });
    });

    popupEl.addEventListener('click', (event) => {
        const popupRow = popupState.activePopupRow;
        if (!popupRow || popupRow.src_ip !== popupState.activePopupIp) {
            return;
        }
        const target = /** @type {Element|null} */ (event.target instanceof Element ? event.target : null);
        if (!target) {
            return;
        }
        const copyButton = target.closest('[data-copy-ip]');
        if (copyButton && popupEl.contains(copyButton)) {
            event.preventDefault();
            event.stopPropagation();
            void copyPopupIp(copyButton);
            return;
        }

        const button = target.closest('[data-action]');
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

/**
 * @param {string} text
 * @returns {Promise<void>}
 */
async function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return;
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

/**
 * @param {Element} button
 * @param {'copied'|'failed'} state
 */
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

/**
 * @param {Element} button
 */
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

/**
 * @param {MapRow} row
 * @returns {boolean}
 */
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

/**
 * @param {any} marker
 * @param {boolean} spiking
 */
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
    /**
     * @param {any} layer
     */
    const updateLayer = (layer) => {
        if (!(layer instanceof L.CircleMarker)) {
            return;
        }
        applySpikeMarkerState(layer, layer.options.spiking === true);
    };
    cluster.eachLayer(updateLayer);
}

/**
 * @param {MapRow[]} rows
 */
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
        const color = threat === 'high' ? '#f85149' : markerColor((r.threat_max !== undefined) ? r.threat_max : null);
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

/**
 * @param {number} delayMs
 */
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
        const result = await window.msmapApi.fetchMapApi(buildMapQueryString());
        if (!result.ok) {
            setError('API ' + result.status);
            updateMapFeedIndicator(Date.now() + (NORMAL_REFRESH_MS * 3));
            scheduleNextPoll(ERROR_REFRESH_MS);
            return;
        }

        const body = result.data;
        const rows = Array.isArray(body.rows) ? body.rows : [];
        mapState.lastMapGeneratedAt = Number.isFinite(body.generated_at) ? body.generated_at : Math.floor(Date.now() / 1000);
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
        setError(err && err.message ? err.message : 'Map poll failed');
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

function initMapUi() {
    lmap.on('popupclose', (/** @type {any} */ event) => {
        if (popupState.activePopup && event.popup === popupState.activePopup) {
            popupState.activePopup = null;
            popupState.activePopupIp = '';
            popupState.activePopupRow = null;
        }
    });
    lmap.on('zoomstart', clearActiveArcs);
}

function startMsmap() {
    initFilterUi();
    initMapUi();
    initStatusTooltips();

    loadFilters();
    filterState.appliedTextFilters.ip = validateIpValue(fIp.value).normalized;
    filterState.appliedTextFilters.port = validatePortValue(fPort.value).normalized;
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
}

Object.assign(window.msmapDeps, {
    clearActiveArcs,
    refreshVisibleMarkerMotionState,
    pollNow,
    startMsmap,
});

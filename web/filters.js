/* msmap – filters, validation, and persistence */
// @ts-check
'use strict';

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

    filterState.appliedTextFilters.ip = DEFAULT_FILTERS.ip;
    filterState.appliedTextFilters.port = DEFAULT_FILTERS.port;
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

function initFilterUi() {
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
}

Object.assign(window, {
    currentFilterState,
    saveFilters,
    loadFilters,
    motionEnabled,
    currentWindowSecs,
    setThreatValue,
    setMotionValue,
    validateIpValue,
    validatePortValue,
    validateAsnValue,
    updateTextValidity,
    isMobileMapUi,
    initFilterUi,
});

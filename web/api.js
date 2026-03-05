/* msmap – API transport helpers */
// @ts-check
'use strict';

/** @typedef {import('./types.js').ApiFailure} ApiFailure */
/** @typedef {import('./types.js').ApiResult<import('./types.js').StatusPayload>} StatusApiResult */
/** @typedef {import('./types.js').ApiResult<import('./types.js').HomePayload>} HomeApiResult */
/** @typedef {import('./types.js').ApiResult<import('./types.js').MapResponseBody>} MapApiResult */
/** @typedef {import('./types.js').ApiResult<import('./types.js').DetailResponseBody>} DetailApiResult */

/**
 * @param {Response} resp
 * @returns {number}
 */
function parseRetryAfterMsFromHeader(resp) {
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

/**
 * @template T
 * @param {string} path
 * @param {number} timeoutMs
 * @returns {Promise<import('./types.js').ApiResult<T>>}
 */
async function requestJson(path, timeoutMs) {
    const controller = new AbortController();
    const timerId = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const resp = await fetch(path, { cache: 'no-store', signal: controller.signal });
        if (!resp.ok) {
            return {
                ok: false,
                status: resp.status,
                retryAfterMs: parseRetryAfterMsFromHeader(resp),
                kind: 'http',
                message: 'HTTP ' + resp.status,
            };
        }
        let body;
        try {
            body = await resp.json();
        } catch (_) {
            return { ok: false, status: 0, retryAfterMs: 0, kind: 'parse', message: 'Invalid JSON response' };
        }
        return { ok: true, data: body };
    } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') {
            return { ok: false, status: 0, retryAfterMs: 0, kind: 'timeout', message: 'Request timed out' };
        }
        return { ok: false, status: 0, retryAfterMs: 0, kind: 'network', message: 'Network request failed' };
    } finally {
        clearTimeout(timerId);
    }
}

/**
 * @returns {Promise<StatusApiResult>}
 */
async function fetchStatusApi() {
    return requestJson('/api/status', 8000);
}

/**
 * @returns {Promise<HomeApiResult>}
 */
async function fetchHomeApi() {
    return requestJson('/api/home', 8000);
}

/**
 * @param {string} queryString
 * @returns {Promise<MapApiResult>}
 */
async function fetchMapApi(queryString) {
    return requestJson('/api/map' + queryString, 12000);
}

/**
 * @param {string} queryString
 * @returns {Promise<DetailApiResult>}
 */
async function fetchDetailApi(queryString) {
    return requestJson('/api/detail?' + queryString, 10000);
}

window.msmapApi = {
    fetchStatusApi,
    fetchHomeApi,
    fetchMapApi,
    fetchDetailApi,
};

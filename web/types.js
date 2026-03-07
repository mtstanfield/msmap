/* msmap – shared frontend typedefs */
// @ts-check
'use strict';

/**
 * @typedef {'unknown'|'clean'|'low'|'medium'|'high'} ThreatLevel
 */

/**
 * @typedef {{
 *   src_ip: string,
 *   lat: number|null|undefined,
 *   lon: number|null|undefined,
 *   count: number,
 *   first_ts: number,
 *   last_ts: number,
 *   threat_max: number|null|undefined,
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
 *   next_cursor?: string
 * }} DetailResponseBody
 */

/**
 * @typedef {{
 *   lat: number,
 *   lon: number
 * }} HomePayload
 */

/**
 * @typedef {{
 *   rows: MapRow[],
 *   generated_at?: number
 * }} MapResponseBody
 */

/**
 * @typedef {'http'|'parse'|'timeout'|'network'} ApiErrorKind
 */

/**
 * @typedef {{
 *   ok: false,
 *   status: number,
 *   retryAfterMs: number,
 *   kind: ApiErrorKind,
 *   message: string
 * }} ApiFailure
 */

/**
 * @template T
 * @typedef {{
 *   ok: true,
 *   data: T
 * }} ApiSuccess
 */

/**
 * @template T
 * @typedef {ApiSuccess<T>|ApiFailure} ApiResult
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

/**
 * @typedef {'temporary'|'generic'} DetailErrorKind
 */

/**
 * @typedef {{
 *   kind: DetailErrorKind,
 *   message: string,
 *   retryAfterMs: number
 * }} DetailError
 */

/**
 * @typedef {{
 *   rows: DetailRow[],
 *   selectedIndex: number,
 *   nextCursor: string,
 *   loading: boolean,
 *   error: string,
 *   errorKind: ''|DetailErrorKind,
 *   retryAfterMs: number,
 *   retryTimerId: ReturnType<typeof setTimeout>|null,
 *   loaded: boolean,
 *   windowSecs: number,
 *   anchorTs: number
 * }} DetailEntryState
 */

/**
 * @typedef {{
 *   time: string,
 *   proto: string,
 *   ip: string,
 *   port: string,
 *   asn: string,
 *   threat: string
 * }} FilterPersistedState
 */

/**
 * @typedef {'filters'|'legend'} FilterPanelTab
 */

/**
 * @typedef {'on'|'off'} MotionSetting
 */

/**
 * @typedef {{
 *   appliedTextFilters: Pick<FilterPersistedState, 'ip'|'port'|'asn'>,
 *   textApplyTimer: ReturnType<typeof setTimeout>|null,
 *   activeFilterPanelTab: FilterPanelTab,
 *   activeThreat: string,
 *   activeMotion: MotionSetting
 * }} FilterRuntimeState
 */

/**
 * @typedef {{
 *   mappedCount: number,
 *   totalSeen: number,
 *   lastMapTs: number,
 *   lastMapGeneratedAt: number,
 *   isInitialLoad: boolean,
 *   pollTimer: ReturnType<typeof setTimeout>|null,
 *   pollInFlight: boolean,
 *   pollQueued: boolean,
 *   lastMapSuccessAt: number
 * }} MapRuntimeState
 */

/**
 * @typedef {{
 *   activePopupIp: string,
 *   activePopup: any|null,
 *   activePopupRow: MapRow|null,
 *   detailStateByIp: Map<string, DetailEntryState>
 * }} PopupRuntimeState
 */

/**
 * @typedef {{
 *   statusPollTimer: ReturnType<typeof setTimeout>|null,
 *   statusInFlight: boolean
 * }} StatusRuntimeState
 */

/**
 * @typedef {{
 *   homePt: HomePayload|null,
 *   homeMarker: any|null,
 *   homeFetchInFlight: boolean,
 *   homeRetryAfterMs: number,
 *   homeStatusExpectedValid: boolean,
 *   lastHomeUpdatedAt: number|null
 * }} HomeRuntimeState
 */

/**
 * @typedef {{
 *   svg: SVGSVGElement,
 *   rafId: number|null,
 *   removeTimeoutId: ReturnType<typeof setTimeout>|null
 * }} ArcHandle
 */

/**
 * @typedef {{
 *   activeArcs: Set<ArcHandle>
 * }} ArcRuntimeState
 */

export {};

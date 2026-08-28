# Self-Hosted Basemap (PMTiles) — Design

**Date:** 2026-08-28
**Status:** Approved (design review in chat)
**Replaces:** CARTO raster basemap (`basemaps.cartocdn.com/dark_all`)

## Background

On 2026-08-28 the live map at map.thetaxi.space began showing "API KEY
REQUIRED" watermarks. CARTO now requires an API key for its raster
basemaps and is retiring the raster service entirely. The CARTO tile
layer was msmap's last external runtime dependency; this design removes
it by self-hosting the basemap, consistent with the project's
"self-contained binary, no CDN, no external JS" convention.

## Decisions (from design review)

- **Detail level:** z0–6 extract (~50–100 MB). Overview detail —
  countries, major cities, coastlines — is enough because GeoIP
  clusters at city granularity anyway.
- **Display zoom:** map allows zoom to z9. z7–9 render overzoomed z6
  vector data (crisp, but no new detail). Hard cap at z9.
- **Missing basemap file:** msmap **refuses to start** with a clear
  error naming the path and the fetch script.
- **Approach:** serve the raw `.pmtiles` file over HTTP with byte-range
  support; all tile logic lives client-side in vendored JS
  (protomaps-leaflet). No PMTiles parsing in C++ beyond a magic-byte
  check.
- **Deliberate strictness:** malformed or multipart `Range` headers get
  `416` (stricter than RFC 9110's SHOULD-ignore) because the only
  intended client sends well-formed single ranges. `If-Range` is not
  implemented because the archive only changes across a restart (the
  ETag changes atomically with it).

## Architecture

```
scripts/fetch_basemap.sh          (operator, one-time, networked)
        │  pmtiles extract → basemap.pmtiles (z0–6)
        ▼
/var/lib/msmap/basemap/basemap.pmtiles   (mounted, like GeoIP mmdbs)
        │
        ▼
GET /basemap.pmtiles  (msmap HTTP server, Range requests, 206)
        │
        ▼
protomaps-leaflet (vendored, canvas renderer, built-in dark theme)
  reads PMTiles directory once, then fetches only visible tiles'
  byte ranges. Leaflet + markercluster stack unchanged.
```

After the one-time fetch, the map works fully offline. No third party
can break it by policy change.

## Server changes

### Configuration (`src/main.cpp`)

- New env var `MSMAP_BASEMAP_PMTILES`, default
  `/var/lib/msmap/basemap/basemap.pmtiles` (mirrors
  `MSMAP_CITY_MMDB` convention).
- Startup validation: open the file, verify readability and the
  PMTiles v3 magic (bytes 0–6 = `PMTiles`, byte 7 = `3`). On failure:
  log an error that names the resolved path and points at
  `scripts/fetch_basemap.sh`, then exit non-zero.
- Capture file size and mtime once at startup for the ETag.

### New route (`src/http.cpp`)

`GET /basemap.pmtiles` in `handle_request`:

- `Accept-Ranges: bytes` on all responses.
- `Range: bytes=a-b` (single range) → `206 Partial Content` via
  `MHD_create_response_from_fd_at_offset64`, with `Content-Range`.
  Open-ended `bytes=a-` is served to EOF.
- Malformed or multipart ranges, or ranges beyond EOF → `416` with
  `Content-Range: bytes */<size>`.
- No `Range` header → `200` with the full file (same fd-backed
  response, offset 0).
- Each request opens its own fd; MHD closes it on response
  destruction (thread-pool safe).
- `Content-Type: application/octet-stream`;
  `Cache-Control: public, max-age=86400`; ETag from size+mtime
  captured at startup (file changes only via operator re-fetch, which
  implies a restart). `If-None-Match` → `304`.
- `HandlerCtx` gains: basemap path, file size, ETag string.

## Frontend changes

- Vendor `protomaps-leaflet` (BSD-3, single dist file) into
  `web/vendor/`. First implementation step verifies whether its dist
  build bundles the `pmtiles` reader; if not, also vendor `pmtiles.js`
  (~30 KB, BSD-3). Either outcome fits this design.
- `web/state.js`: replace the `L.tileLayer(...)` CARTO layer with
  `protomapsL.leafletLayer({ url: '/basemap.pmtiles', theme: 'dark',
  maxDataZoom: 6 })`; set map `maxZoom: 9`.
- Attribution: `© OpenStreetMap contributors, © Protomaps` (ODbL —
  the Protomaps daily builds are OSM-derived).
- `web/bundle.py`: add vendor file token(s) to `_PLACEHOLDERS`;
  matching `{{...}}` tokens in `web/index.html`.

## Basemap acquisition

New `scripts/fetch_basemap.sh`:

1. Download the `pmtiles` CLI (go-pmtiles) if absent — pinned release
   version, sha256-verified. Dev-container tool, not an app
   dependency.
2. `pmtiles extract https://build.protomaps.com/<YYYYMMDD>.pmtiles
   basemap.pmtiles --maxzoom=6` into the mount directory (path
   argument, default `/var/lib/msmap/basemap/`). `<YYYYMMDD>` is the
   most recent daily build, discovered via the builds index at
   build.protomaps.com (with a documented manual override argument).

Operator-initiated, network-touching, one-time. Documented in
README/CLAUDE.md. `scripts/smoke_test.sh` mounts the file and fails
fast with a pointer to the fetch script when it is absent.

## Testing

- **Catch2 unit tests**
  - Range-header parser: valid `a-b`, open-ended `a-`, malformed,
    multipart, out-of-bounds → correct status/headers.
  - Startup validation: valid tiny fixture passes; truncated file,
    wrong magic, missing path fail with the expected error.
  - Fixture: minimal valid `.pmtiles` (~1 KB) checked into
    `tests/fixtures/` so tests are hermetic.
- **Fuzzing:** Range-header parser added to libFuzzer scope if cheap;
  otherwise recorded in FINDINGS.md as follow-up.
- **Manual smoke:** real z0–6 extract renders dark theme; overzoom to
  z9 works; cluster-click zoom works; DevTools network tab shows only
  same-origin requests.
- Standard quality gates: clean build, clang-tidy, cppcheck, all
  tests green.

## Risks

- protomaps-leaflet renders labels with canvas + system fonts; the
  default dark theme will not look pixel-identical to CARTO
  `dark_all`. Cosmetic tuning is available via its theme/paint-rules
  API if desired.
- If the protomaps-leaflet dist build lacks a bundled PMTiles reader,
  one extra vendored file (`pmtiles.js`) is required — resolved in the
  first implementation step.

## Out of scope

- Raster fallback of any kind (no CARTO, no OSM fallback).
- Zoom levels beyond 9 / extracts beyond z6.
- Server-side PMTiles decoding or per-tile endpoints.

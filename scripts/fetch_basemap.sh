#!/usr/bin/env bash
# fetch_basemap.sh — produce the z0–6 PMTiles basemap extract msmap serves at
# /basemap.pmtiles. One-time, ~50–100 MB download; the result works offline.
#
# Run inside the msmap-dev container:
#
#   MSYS_NO_PATHCONV=1 docker run --rm \
#     -v "C:/Users/ms/projects/msmap:/workspace" \
#     msmap-dev bash -c "bash /workspace/scripts/fetch_basemap.sh"
#
# Usage: fetch_basemap.sh [output.pmtiles] [YYYYMMDD]
#   output  default: /workspace/data/basemap/basemap.pmtiles
#   build   default: newest daily build at build.protomaps.com (probes back 3 days)

set -euo pipefail

PMTILES_VERSION="1.31.2"
PMTILES_TAR="go-pmtiles_${PMTILES_VERSION}_Linux_x86_64.tar.gz"
PMTILES_URL="https://github.com/protomaps/go-pmtiles/releases/download/v${PMTILES_VERSION}/${PMTILES_TAR}"
PMTILES_SHA256="3ed7dbf4ec2e6dfe5e25b6f70d1ffc932729f93c86db353bf514dd71010a312f"
MAXZOOM=6

OUT="${1:-/workspace/data/basemap/basemap.pmtiles}"
BUILD="${2:-}"

# ── ensure the pmtiles CLI ────────────────────────────────────────────────────
if ! command -v pmtiles >/dev/null 2>&1; then
    echo "[INFO] downloading go-pmtiles v${PMTILES_VERSION}…"
    tmp="$(mktemp -d)"
    curl -fsSL -o "${tmp}/${PMTILES_TAR}" "${PMTILES_URL}"
    echo "${PMTILES_SHA256}  ${tmp}/${PMTILES_TAR}" | sha256sum -c -
    tar -xzf "${tmp}/${PMTILES_TAR}" -C "${tmp}" pmtiles
    install -m 0755 "${tmp}/pmtiles" /usr/local/bin/pmtiles
    rm -rf "${tmp}"
fi

# ── pick the newest available daily build ─────────────────────────────────────
if [[ -z "${BUILD}" ]]; then
    for d in 0 1 2 3; do
        cand="$(date -u -d "-${d} day" +%Y%m%d)"
        if curl -fsI "https://build.protomaps.com/${cand}.pmtiles" >/dev/null 2>&1; then
            BUILD="${cand}"
            break
        fi
    done
    if [[ -z "${BUILD}" ]]; then
        echo "[FATAL] no recent daily build found at build.protomaps.com" >&2
        exit 1
    fi
fi

mkdir -p "$(dirname "${OUT}")"
echo "[INFO] extracting z0-${MAXZOOM} from build ${BUILD} → ${OUT}"
pmtiles extract "https://build.protomaps.com/${BUILD}.pmtiles" "${OUT}" \
    --maxzoom="${MAXZOOM}"
echo "[OK] wrote ${OUT} ($(du -h "${OUT}" | cut -f1))"

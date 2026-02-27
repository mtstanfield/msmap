-- msmap SQLite schema
-- Timestamps stored as Unix epoch (INTEGER, UTC).
-- Indexes defined separately (SQLite does not support inline INDEX in CREATE TABLE).

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── Main connection log ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS connections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,           -- Unix epoch, UTC
    src_ip      TEXT    NOT NULL,           -- v4 or v6 string
    src_port    INTEGER,                    -- NULL for ICMP
    dst_ip      TEXT    NOT NULL,
    dst_port    INTEGER,                    -- NULL for ICMP
    proto       TEXT    NOT NULL,           -- TCP | UDP | ICMP
    tcp_flags   TEXT,                       -- NULL for non-TCP (e.g. "SYN", "ACK", "SYN,ACK")
    chain       TEXT    NOT NULL,           -- input | forward
    in_iface    TEXT    NOT NULL,           -- e.g. ether1
    rule        TEXT    NOT NULL,           -- log-prefix value e.g. FW_INPUT_NEW
    conn_state  TEXT    NOT NULL,           -- new | established | related | invalid
    pkt_len     INTEGER NOT NULL,
    -- GeoIP enrichment (filled after insert by enrichment thread)
    country     TEXT,
    lat         REAL,
    lon         REAL,
    asn         TEXT,
    -- OSINT enrichment (filled from abuse_cache by enrichment thread)
    threat      INTEGER                     -- AbuseIPDB confidence score 0-100
);

CREATE INDEX IF NOT EXISTS idx_conn_ts      ON connections (ts);
CREATE INDEX IF NOT EXISTS idx_conn_src_ip  ON connections (src_ip);
CREATE INDEX IF NOT EXISTS idx_conn_dst_port ON connections (dst_port);
CREATE INDEX IF NOT EXISTS idx_conn_country ON connections (country);

-- ── AbuseIPDB OSINT cache ──────────────────────────────────────────────────
-- Keyed by IP. Refreshed by background thread when last_checked is stale.
CREATE TABLE IF NOT EXISTS abuse_cache (
    ip            TEXT    PRIMARY KEY,
    score         INTEGER NOT NULL,         -- 0-100
    last_checked  INTEGER NOT NULL          -- Unix epoch, UTC
);

-- ── Retention view ──────────────────────────────────────────────────────────
-- Convenience view; actual pruning is done by the retention thread.
-- DELETE FROM connections WHERE ts < strftime('%s', 'now', '-1 year');

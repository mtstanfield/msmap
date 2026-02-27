# FINDINGS.md

Issues discovered during development and code review.
Reviewed before each new feature increment. Resolved findings kept for regression history.

## Format

```
### FIND-NNN: Title
**Severity**: High | Medium | Low
**Status**:   Open | Fixed (commit abc1234) | Deferred
**File(s)**:  path/to/file.cpp
**Found**:    YYYY-MM-DD

Description of the problem.

**Resolution**: What was done / what to do instead.
```

Severity guide:
- **High**: security issue, data loss, crash, or silent data corruption
- **Medium**: correctness issue, missing validation, non-compliant with our standards
- **Low**: code quality, maintainability, style

---

## Findings from Prototype Review (2026-02-27)

The following were identified by reviewing the discarded prototype in the main repo
working tree. They are recorded here as reminders of what NOT to carry forward.
All are closed — none of this code enters the branch.

---

### FIND-001: Parser uses std::regex
**Severity**: Medium
**Status**:   Closed (not carried forward)
**File(s)**:  prototype/src/parser.cpp
**Found**:    2026-02-27

Used `std::regex` for log parsing. Problems: regex is CPU-intensive and hard to fuzz,
the pattern was malformed (doubled backslash escapes in raw string literals),
and it would not handle UDP or ICMP variants (no ports / no flags).

**Resolution**: Hand-written linear tokenizer. Two-phase: RFC 3339 header strip,
then Mikrotik body field-by-field. Fuzz with libFuzzer against
`parse_log(std::span<const char>)` entry point.

---

### FIND-002: Parser leaves most LogEntry fields unpopulated
**Severity**: High
**Status**:   Closed (not carried forward)
**File(s)**:  prototype/src/parser.cpp, prototype/src/parser.h
**Found**:    2026-02-27

`LogEntry` had no `chain`, `rule`, `conn_state`, `tcp_flags`, or `proto_family` fields.
The regex only captured src_mac, proto, src_ip:port, dst_ip:port, len — skipping
timestamp, hostname, chain, rule, connection-state, and all UDP/ICMP variants.

**Resolution**: Define `LogEntry` struct with all fields from the agreed schema before
writing the parser. Parser must handle all three protocol variants.

---

### FIND-003: UDP listener bound directly to port 514
**Severity**: Medium
**Status**:   Closed (not carried forward)
**File(s)**:  prototype/src/udp_listener.cpp
**Found**:    2026-02-27

Opened a raw UDP socket on port 514, bypassing rsyslog entirely. This meant:
- Received raw BSD syslog (ambiguous year, no timezone)
- No timestamp reformatting
- Listening on a privileged port (<1024) requires root or CAP_NET_BIND_SERVICE

**Resolution**: rsyslog receives on UDP 514, reformats timestamp to RFC 3339,
forwards to msmap on TCP 5140 (loopback, unprivileged). msmap never touches port 514.

---

### FIND-004: Raw socket HTTP server
**Severity**: High
**Status**:   Closed (not carried forward)
**File(s)**:  prototype/src/server.cpp
**Found**:    2026-02-27

Hand-rolled HTTP/1.1 over raw TCP socket. Issues:
- Single-threaded `accept()` loop — one connection at a time
- Fixed 1024-byte read buffer — truncates large requests silently
- No `Content-Length` header in responses — clients may hang
- HTTP path parsing via `find("GET ") + 4` — unsafe, no validation
- Reads web assets from disk at request time — broken in distroless

**Resolution**: `libmicrohttpd` handles HTTP correctly. Web assets embedded in
binary at compile time via `xxd -i` CMake step — no disk reads at runtime.

---

### FIND-005: Database schema incomplete; no WAL mode
**Severity**: High
**Status**:   Closed (not carried forward)
**File(s)**:  prototype/src/database.cpp
**Found**:    2026-02-27

`init()` created a table with only `(id, src_ip)` — none of the other agreed columns.
`get_logs_json()` was declared in the header but never defined (linker error).
No WAL mode pragma, so concurrent reads from the HTTP server would block on writes.

**Resolution**: Schema defined in `schema.sql`, applied in `Database::init()`.
Enable WAL: `PRAGMA journal_mode=WAL`. All fields in agreed schema must be present.

---

### FIND-006: schema.sql uses MySQL INDEX syntax (invalid in SQLite)
**Severity**: Medium
**Status**:   Closed (not carried forward)
**File(s)**:  prototype/schema.sql
**Found**:    2026-02-27

```sql
CREATE TABLE IF NOT EXISTS firewall_logs (
    ...
    INDEX idx_timestamp (timestamp),   -- ← MySQL syntax, not valid SQLite
    ...
);
```

SQLite requires `CREATE INDEX` as a separate statement outside `CREATE TABLE`.
Also `timestamp DATETIME` stores a text string — should be `ts INTEGER` (Unix epoch).

**Resolution**: Use separate `CREATE INDEX` statements. Store timestamp as
`ts INTEGER NOT NULL` (Unix epoch, UTC). See `schema.sql` in this branch.

---

### FIND-007: rsyslog.conf uses BSD timestamp and logs to file only
**Severity**: Medium
**Status**:   Closed (not carried forward)
**File(s)**:  prototype/rsyslog.conf
**Found**:    2026-02-27

Template used `%TIMESTAMP%` (BSD format, no year) and wrote to a flat log file.
No forwarding to the application. If condition had a comment inline in the filter
expression (`/* Mikrotik IP */`) which may cause parse errors in rsyslog.

**Resolution**: Use `%TIMESTAMP:::date-rfc3339%` template. Forward to msmap via
`omfwd` TCP on loopback port 5140. See `rsyslog.conf` in this branch.

---

### FIND-008: No error checking on socket calls
**Severity**: High
**Status**:   Closed (not carried forward)
**File(s)**:  prototype/src/server.cpp, prototype/src/udp_listener.cpp
**Found**:    2026-02-27

`socket()`, `bind()`, `listen()`, `accept()` return values were all unchecked.
A bind failure would silently continue and the accept loop would spin on -1.

**Resolution**: All system call return values must be checked. Use RAII wrappers
for file descriptors. libmicrohttpd handles this internally for the HTTP server.

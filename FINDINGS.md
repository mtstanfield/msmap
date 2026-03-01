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

---

## Findings from Static Release Build Debugging (2026-03-01)

---

### FIND-009: pkg_check_modules STATIC keyword is not supported in any cmake version
**Severity**: High
**Status**:   Fixed (CMakeLists.txt)
**File(s)**:  CMakeLists.txt
**Found**:    2026-03-01

`pkg_check_modules(FOO REQUIRED STATIC IMPORTED_TARGET libfoo)` treats `STATIC` as a
module name, not a keyword. cmake 3.x and 4.x both fail with:
`Package 'STATIC', required by 'virtual:world', not found`.

**Resolution**: Never pass `STATIC` to `pkg_check_modules`. Instead call with
`IMPORTED_TARGET` only (for include paths and compile flags), then — if static
linking is wanted — resolve each entry of `<PREFIX>_STATIC_LIBRARIES` to its `.a`
path via `find_library` and override `INTERFACE_LINK_LIBRARIES` on the target.

---

### FIND-010: find_library(VAR … NO_CACHE) reuses stale value if VAR is already set
**Severity**: High
**Status**:   Fixed (CMakeLists.txt)
**File(s)**:  CMakeLists.txt
**Found**:    2026-03-01

When `find_library(VAR name NO_CACHE)` is called in a loop and `VAR` already holds
a value from a previous iteration, cmake silently returns the old value instead of
re-searching. Effect: every library in every package resolved to the first `.a` found,
causing all other symbols to be missing at link time.

**Resolution**: Always `unset(VAR)` immediately before each `find_library(VAR …)` call
inside a loop.

---

### FIND-011: Glibc sub-libraries must not be statically linked (IFUNC / _dl_x86_cpu_features)
**Severity**: High
**Status**:   Fixed (CMakeLists.txt)
**File(s)**:  CMakeLists.txt
**Found**:    2026-03-01

`libm.a`, `libpthread.a`, `libdl.a`, `librt.a` from glibc use GNU indirect functions
(IFUNCs) that reference `_dl_x86_cpu_features`, a symbol that exists only in the
dynamic linker (`ld.so`). Statically linking them causes:
`undefined reference to '_dl_x86_cpu_features'`

**Resolution**: Exclude `m pthread dl rt c resolv` from the static library resolution
loop using an `_IN_LIST` guard. These fall back to `-lm`, `-lpthread`, etc. which are
dynamically resolved from glibc, and glibc IS present in `distroless/cc-debian12`.

---

### FIND-012: Debian bookworm's system libcurl4-openssl-dev has unresolvable static deps
**Severity**: Medium
**Status**:   Fixed (Dockerfile — build minimal libcurl from source)
**File(s)**:  Dockerfile
**Found**:    2026-03-01

`libcurl4-openssl-dev` on bookworm is compiled with nghttp2, rtmp, ssh2, psl, gssapi,
ldap, zstd, and brotli support. None of these have `.a` files on bookworm, making a
fully static curl impossible without the system package.

**Resolution**: Build a minimal libcurl from source in the builder stage with only
`-DHTTP_ONLY=ON -DCURL_USE_OPENSSL=ON` and all optional components disabled.
Install to `/opt/curl-static`; pass `-DCMAKE_PREFIX_PATH=/opt/curl-static` to cmake.
The only static deps are `libssl.a` and `libcrypto.a` which are available from
`libssl-dev`.

---

### FIND-013: libmicrohttpd.a pulls in libp11-kit + libffi at runtime (not in distroless)
**Severity**: Medium
**Status**:   Fixed (Dockerfile — COPY missing .so files into runtime stage)
**File(s)**:  Dockerfile
**Found**:    2026-03-01

`libmicrohttpd.a` links `libgnutls.a` (GnuTLS compiled in on Debian). GnuTLS references
`libp11-kit.so.0` (PKCS#11 provider) at runtime; p11-kit in turn requires `libffi.so.8`.
Neither is in `distroless/cc-debian12:nonroot`.
`libatomic.so.1` (GCC runtime) is also required by gnutls on some code paths but is
also absent from distroless.

**Resolution**: COPY the three versioned `.so` files from the builder stage into the
runtime stage:
```
COPY --from=builder /lib/x86_64-linux-gnu/libatomic.so.1.2.0  /lib/x86_64-linux-gnu/libatomic.so.1
COPY --from=builder /lib/x86_64-linux-gnu/libffi.so.8.1.2     /lib/x86_64-linux-gnu/libffi.so.8
COPY --from=builder /lib/x86_64-linux-gnu/libp11-kit.so.0.3.0 /lib/x86_64-linux-gnu/libp11-kit.so.0
```
All three only depend on `libc.so.6` which distroless already provides.
Final image size: ~56 MB.

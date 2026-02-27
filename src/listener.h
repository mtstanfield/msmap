#pragma once

namespace msmap {

/// Block on TCP 127.0.0.1:port, parse each received syslog line via
/// parse_log(), and print parsed entries to stdout.
///
/// One connection at a time; rsyslog opens a single persistent connection.
/// On disconnection, waits for the next connect (no busy-loop).
/// Parse warnings go to stderr. Fatal socket errors go to stderr and return.
///
/// Placeholder: stdout output will be replaced by SQLite inserts once the
/// storage layer is added.
void run_listener(int port);

} // namespace msmap

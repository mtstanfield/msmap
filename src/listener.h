#pragma once

namespace msmap {

class Database;

/// Block on TCP 127.0.0.1:port, parse each received syslog line via
/// parse_log(), and insert successful entries into `db`.
///
/// One connection at a time; rsyslog opens a single persistent connection.
/// On disconnection, waits for the next connect (no busy-loop).
/// Parse warnings and socket errors go to stderr.
/// This function does not return under normal operation.
void run_listener(int port, Database& db);

} // namespace msmap

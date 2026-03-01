#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace msmap {

/// All fields extracted from a single Mikrotik firewall log line.
/// Populated by parse_log(); in an unspecified state on parse failure.
struct LogEntry {
    std::int64_t ts{0};        ///< Unix epoch, UTC
    std::string  hostname;
    std::string  topic;        ///< e.g. "firewall"
    std::string  level;        ///< e.g. "info"
    std::string  rule;         ///< log-prefix value, e.g. "FW_INPUT_NEW"; empty if absent
    std::string  chain;        ///< "input" | "forward" | "output"
    std::string  in_iface;     ///< e.g. "ether1"
    std::string  out_iface;    ///< e.g. "ether2" or "(unknown 0)"
    std::string  conn_state;   ///< "new" | "established" | "related" | "invalid"
    std::string  proto;        ///< "TCP" | "UDP" | "ICMP"
    std::string  tcp_flags;    ///< e.g. "ACK", "SYN,ACK"; empty for non-TCP
    std::string  src_ip;
    std::int32_t src_port{-1}; ///< -1 for ICMP
    std::string  dst_ip;
    std::int32_t dst_port{-1}; ///< -1 for ICMP
    std::int32_t pkt_len{0};
};

/// Result of a parse attempt.
/// ok() returns true when error is empty.
struct ParseResult {
    LogEntry    entry;
    std::string error; ///< Non-empty string describes the failure; empty → success.

    [[nodiscard]] bool ok() const noexcept { return error.empty(); }
};

/// Parse one log line from Mikrotik.
///
/// Accepts two formats (auto-detected by the leading character):
///
///   BSD syslog  — sent directly from Mikrotik (native format):
///     <PRI>Mmm DD HH:MM:SS HOSTNAME TOPIC,LEVEL [RULE] CHAIN: ...
///     Timestamp treated as UTC; year inferred from system clock.
///
///   RFC 3339    — produced by rsyslog with %TIMESTAMP:::date-rfc3339%:
///     YYYY-MM-DDTHH:MM:SS±HH:MM HOSTNAME TOPIC,LEVEL [RULE] CHAIN: ...
///
/// The Mikrotik body is identical for both:
///   [RULE ' '] CHAIN ': in:' IFACE ' out:' IFACE
///   ', connection-state:' STATE [' src-mac ' MAC ',']
///   ' proto ' PROTO proto_variant ', len ' INT
///
/// On failure, result.ok() is false and result.error describes the problem.
[[nodiscard]] ParseResult parse_log(std::string_view line);

} // namespace msmap

#include "parser.h"

#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <string_view>
#include <system_error>

namespace msmap {
namespace {

// ── Tokenizer ────────────────────────────────────────────────────────────────

/// Lightweight, non-owning tokenizer over a string_view.
/// All read_* methods advance an internal position cursor.
class Tok {
public:
    explicit Tok(std::string_view src) noexcept : src_(src) {}

    [[nodiscard]] bool at_end() const noexcept { return pos_ >= src_.size(); }

    /// Advance past `lit` if it matches at the current position.
    /// Returns true and advances pos_ on match; false otherwise (pos_ unchanged).
    [[nodiscard]] bool consume(std::string_view lit) noexcept {
        if (src_.substr(pos_, lit.size()) == lit) {
            pos_ += lit.size();
            return true;
        }
        return false;
    }

    /// Read exactly n characters (or fewer if src_ is exhausted).
    std::string_view read_n(std::size_t n) noexcept {
        const std::size_t start = pos_;
        const std::size_t avail = src_.size() - pos_;
        const std::size_t take  = (n < avail) ? n : avail;
        pos_ += take;
        return src_.substr(start, take);
    }

    /// Read chars up to (but not including) `delim`, then skip the delimiter.
    /// If delimiter is not found, returns the rest and sets pos_ to end.
    std::string_view read_until(char delim) noexcept {
        const std::size_t start = pos_;
        while (pos_ < src_.size() && src_[pos_] != delim) {
            ++pos_;
        }
        const std::string_view span = src_.substr(start, pos_ - start);
        if (pos_ < src_.size()) {
            ++pos_; // skip delimiter
        }
        return span;
    }

    /// Multi-char delimiter variant.
    std::string_view read_until(std::string_view delim) noexcept {
        const std::size_t found = src_.find(delim, pos_);
        if (found == std::string_view::npos) {
            const std::string_view span = src_.substr(pos_);
            pos_ = src_.size();
            return span;
        }
        const std::string_view span = src_.substr(pos_, found - pos_);
        pos_ = found + delim.size();
        return span;
    }

    /// Read consecutive alpha characters; stop at first non-alpha (not consumed).
    std::string_view read_alpha() noexcept {
        const std::size_t start = pos_;
        while (pos_ < src_.size() &&
               std::isalpha(static_cast<unsigned char>(src_[pos_])) != 0) {
            ++pos_;
        }
        return src_.substr(start, pos_ - start);
    }

    /// Return remaining input, stripping trailing CR/LF.
    std::string_view rest_trimmed() noexcept {
        std::string_view span = src_.substr(pos_);
        pos_ = src_.size();
        while (!span.empty() && (span.back() == '\n' || span.back() == '\r')) {
            span.remove_suffix(1);
        }
        return span;
    }

private:
    std::string_view src_;
    std::size_t      pos_{0};
};

// ── Timestamp parsing ─────────────────────────────────────────────────────────

/// Parse a fixed-width decimal integer from ts.substr(start, len).
[[nodiscard]] bool parse_field(std::string_view ts, std::size_t start,
                               std::size_t len, int& out) noexcept {
    if (start + len > ts.size()) {
        return false;
    }
    const char* beg    = ts.data() + start;
    const char* end    = beg + len;
    auto        result = std::from_chars(beg, end, out);
    return result.ec == std::errc{} && result.ptr == end;
}

/// Parse RFC 3339 timestamp → UTC Unix epoch via timegm(3).
/// Accepted formats: 2026-02-27T08:14:23Z | ..+HH:MM | ..-HH:MM
[[nodiscard]] bool parse_rfc3339(std::string_view ts, std::int64_t& epoch) noexcept {
    // Minimum: "2026-02-27T08:14:23Z" = 20 chars
    if (ts.size() < 20) {
        return false;
    }
    // Validate fixed separators: YYYY-MM-DDTHH:MM:SS
    if (ts[4] != '-' || ts[7] != '-' || ts[10] != 'T' ||
        ts[13] != ':' || ts[16] != ':') {
        return false;
    }

    int year{};
    int mon{};
    int mday{};
    int hour{};
    int min{};
    int sec{};
    if (!parse_field(ts, 0, 4, year)  || !parse_field(ts, 5, 2, mon) ||
        !parse_field(ts, 8, 2, mday)  || !parse_field(ts, 11, 2, hour) ||
        !parse_field(ts, 14, 2, min)  || !parse_field(ts, 17, 2, sec)) {
        return false;
    }

    // Timezone suffix at position 19: 'Z' | '+HH:MM' | '-HH:MM'
    int tz_sec = 0;
    if (ts[19] == 'Z') {
        // UTC, nothing to do.
    } else if ((ts[19] == '+' || ts[19] == '-') && ts.size() >= 25 && ts[22] == ':') {
        int tz_h{};
        int tz_m{};
        if (!parse_field(ts, 20, 2, tz_h) || !parse_field(ts, 23, 2, tz_m)) {
            return false;
        }
        const int sign = (ts[19] == '+') ? 1 : -1;
        tz_sec         = sign * (tz_h * 3600 + tz_m * 60);
    } else {
        return false;
    }

    std::tm broken{};
    broken.tm_year  = year - 1900;
    broken.tm_mon   = mon - 1;
    broken.tm_mday  = mday;
    broken.tm_hour  = hour;
    broken.tm_min   = min;
    broken.tm_sec   = sec;
    broken.tm_isdst = 0;

    // timegm: treats broken as UTC, returns UTC epoch (glibc/POSIX extension).
    const auto raw = static_cast<std::int64_t>(timegm(&broken));
    if (raw == static_cast<std::int64_t>(-1)) {
        return false;
    }
    // Subtract offset: e.g. +05:00 means local is 5 h ahead, so UTC = local - 5 h.
    epoch = raw - tz_sec;
    return true;
}

/// Parse BSD syslog timestamp: "Mmm DD HH:MM:SS" (exactly 15 chars).
/// Assumes UTC (router must be configured with timezone = UTC).
/// Year is inferred from the system clock; if the parsed time would be more
/// than 24 h in the future, the previous year is used (Dec → Jan rollover).
[[nodiscard]] bool parse_bsd_timestamp(std::string_view ts,
                                        std::int64_t& epoch) noexcept {
    if (ts.size() != 15) { return false; }

    // Month name (first 3 chars) → 1-based index
    constexpr std::array<std::string_view, 12> months = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    int mon = 0;
    {
        int idx = 1;
        for (const auto& m : months) {
            if (ts.substr(0, 3) == m) { mon = idx; break; }
            ++idx;
        }
    }
    if (mon == 0) { return false; }

    if (ts[3] != ' ') { return false; }

    // Day: "DD" or " D" (space-padded single digit)
    int mday = 0;
    if (ts[4] == ' ') {
        if (std::isdigit(static_cast<unsigned char>(ts[5])) == 0) { return false; }
        mday = ts[5] - '0';
    } else {
        if (std::isdigit(static_cast<unsigned char>(ts[4])) == 0) { return false; }
        if (std::isdigit(static_cast<unsigned char>(ts[5])) == 0) { return false; }
        mday = (ts[4] - '0') * 10 + (ts[5] - '0');
    }
    if (mday < 1 || mday > 31) { return false; }

    // "HH:MM:SS" at positions 6-14 — space at [6], colon at [9] and [12]
    if (ts[6] != ' ' || ts[9] != ':' || ts[12] != ':') { return false; }
    int hour{};
    int min{};
    int sec{};
    if (!parse_field(ts, 7, 2, hour) ||
        !parse_field(ts, 10, 2, min) ||
        !parse_field(ts, 13, 2, sec)) { return false; }

    // Infer year from UTC system clock.
    const std::time_t now_t = std::time(nullptr);
    std::tm now_utc{};
    gmtime_r(&now_t, &now_utc);
    const int cur_year = now_utc.tm_year + 1900;

    const auto make_epoch = [&](int y) -> std::int64_t {
        std::tm broken{};
        broken.tm_year  = y - 1900;
        broken.tm_mon   = mon - 1;
        broken.tm_mday  = mday;
        broken.tm_hour  = hour;
        broken.tm_min   = min;
        broken.tm_sec   = sec;
        broken.tm_isdst = 0;
        return static_cast<std::int64_t>(timegm(&broken));
    };

    const std::int64_t candidate = make_epoch(cur_year);
    // If > 24 h in the future, assume Dec → Jan rollover and use previous year.
    epoch = (candidate > static_cast<std::int64_t>(now_t) + 86400LL)
                ? make_epoch(cur_year - 1)
                : candidate;
    return epoch != static_cast<std::int64_t>(-1);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

[[nodiscard]] bool sv_to_i32(std::string_view sv, std::int32_t& out) noexcept {
    if (sv.empty()) {
        return false;
    }
    auto result = std::from_chars(sv.data(), sv.data() + sv.size(), out);
    return result.ec == std::errc{} && result.ptr == sv.data() + sv.size();
}

[[nodiscard]] bool is_chain(std::string_view sv) noexcept {
    return sv == "input" || sv == "forward" || sv == "output";
}

// ── Per-phase parse functions ─────────────────────────────────────────────────
// Each returns an empty string on success or an error string on failure.
// They advance `tok` as they consume input.

[[nodiscard]] std::string parse_header(Tok& tok, LogEntry& entry) {
    if (tok.consume("<")) {
        // BSD syslog format: <PRI>Mmm DD HH:MM:SS HOSTNAME ...
        // Strip the numeric priority and closing '>'.
        tok.read_until('>');
        // Timestamp is always exactly 15 chars: "Mmm DD HH:MM:SS"
        const std::string_view ts_sv = tok.read_n(15);
        if (!parse_bsd_timestamp(ts_sv, entry.ts)) {
            std::string err = "bad BSD timestamp: ";
            err += ts_sv;
            return err;
        }
        if (!tok.consume(" ")) { return "expected space after BSD timestamp"; }
    } else {
        // RFC 3339 format (e.g. from rsyslog with %TIMESTAMP:::date-rfc3339%)
        const std::string_view ts_sv = tok.read_until(' ');
        if (!parse_rfc3339(ts_sv, entry.ts)) {
            std::string err = "bad timestamp: ";
            err += ts_sv;
            return err;
        }
    }
    entry.hostname = tok.read_until(' ');
    if (entry.hostname.empty()) { return "missing hostname"; }
    entry.topic = tok.read_until(',');
    if (entry.topic.empty()) { return "missing topic"; }
    entry.level = tok.read_until(' ');
    if (entry.level.empty()) { return "missing level"; }
    return {};
}

[[nodiscard]] std::string parse_rule_and_chain(Tok& tok, LogEntry& entry) {
    std::string_view word = tok.read_until(' ');
    if (word.empty()) { return "missing rule/chain token"; }

    if (word.back() == ':') {
        // No explicit rule; word IS the chain keyword (with trailing ':').
        word.remove_suffix(1);
        if (!is_chain(word)) {
            std::string err = "unknown chain (no rule): ";
            err += word;
            return err;
        }
        entry.chain = std::string(word);
    } else {
        // word is the rule name; next token must be CHAIN ':'.
        entry.rule = std::string(word);
        std::string_view chain_word = tok.read_until(' ');
        if (chain_word.empty() || chain_word.back() != ':') {
            std::string err = "expected CHAIN: after rule name, got: ";
            err += chain_word;
            return err;
        }
        chain_word.remove_suffix(1);
        if (!is_chain(chain_word)) {
            std::string err = "unknown chain: ";
            err += chain_word;
            return err;
        }
        entry.chain = std::string(chain_word);
    }
    return {};
}

[[nodiscard]] std::string parse_ifaces(Tok& tok, LogEntry& entry) {
    if (!tok.consume("in:"))  { return "expected 'in:'"; }
    entry.in_iface = tok.read_until(' ');
    if (entry.in_iface.empty()) { return "missing in_iface"; }
    if (!tok.consume("out:")) { return "expected 'out:'"; }
    // out_iface may contain spaces, e.g. "(unknown 0)"; read until ", "
    entry.out_iface = tok.read_until(", ");
    if (entry.out_iface.empty()) { return "missing out_iface"; }
    return {};
}

[[nodiscard]] std::string parse_conn_state(Tok& tok, LogEntry& entry) {
    if (!tok.consume("connection-state:")) { return "expected 'connection-state:'"; }
    entry.conn_state = tok.read_until(' ');
    if (entry.conn_state.empty()) { return "missing connection-state value"; }
    // Optional src-mac: parse and discard — it is always the gateway MAC.
    if (tok.consume("src-mac ")) {
        tok.read_until(", "); // discard MAC address + ", " delimiter
    }
    return {};
}

/// Parse "IP:PORT->IP:PORT" after proto-specific prefix has been consumed.
[[nodiscard]] std::string parse_ported_addrs(Tok& tok, LogEntry& entry) {
    entry.src_ip = tok.read_until(':');
    const std::string_view sport = tok.read_until('-');
    if (!tok.consume(">")) { return "expected '>' in address pair"; }
    if (!sv_to_i32(sport, entry.src_port)) {
        std::string err = "bad src_port: ";
        err += sport;
        return err;
    }
    entry.dst_ip = tok.read_until(':');
    const std::string_view dport = tok.read_until(',');
    if (!sv_to_i32(dport, entry.dst_port)) {
        std::string err = "bad dst_port: ";
        err += dport;
        return err;
    }
    return {};
}

[[nodiscard]] std::string parse_tcp(Tok& tok, LogEntry& entry) {
    // TCP: optional " (FLAGS)" then ", " then address pair.
    if (tok.consume(" (")) {
        entry.tcp_flags = tok.read_until(')');
        if (!tok.consume(", ")) { return "expected ', ' after TCP flags"; }
    } else if (!tok.consume(", ")) {
        return "expected ' (FLAGS)' or ', ' after TCP";
    }
    return parse_ported_addrs(tok, entry);
}

[[nodiscard]] std::string parse_udp(Tok& tok, LogEntry& entry) {
    if (!tok.consume(", ")) { return "expected ', ' after UDP"; }
    return parse_ported_addrs(tok, entry);
}

[[nodiscard]] std::string parse_icmp(Tok& tok, LogEntry& entry) {
    // ICMP: ", " then "IP->IP" (no ports).
    if (!tok.consume(", ")) { return "expected ', ' after ICMP"; }
    entry.src_ip = tok.read_until('-');
    if (!tok.consume(">")) { return "expected '>' in ICMP src->dst"; }
    entry.dst_ip = tok.read_until(',');
    // src_port / dst_port remain -1 (LogEntry defaults).
    return {};
}

[[nodiscard]] std::string parse_proto_and_len(Tok& tok, LogEntry& entry) {
    if (!tok.consume("proto ")) { return "expected 'proto '"; }
    entry.proto = tok.read_alpha();
    if (entry.proto.empty()) { return "missing protocol"; }

    std::string err;
    if (entry.proto == "TCP")       { err = parse_tcp(tok, entry); }
    else if (entry.proto == "UDP")  { err = parse_udp(tok, entry); }
    else if (entry.proto == "ICMP") { err = parse_icmp(tok, entry); }
    else {
        std::string bad = "unsupported protocol: ";
        bad += entry.proto;
        return bad;
    }
    if (!err.empty()) { return err; }

    if (!tok.consume(" len ")) { return "expected ' len '"; }
    const std::string_view len_sv = tok.rest_trimmed();
    if (!sv_to_i32(len_sv, entry.pkt_len)) {
        std::string e = "bad pkt_len: ";
        e += len_sv;
        return e;
    }
    return {};
}

} // anonymous namespace

// ── Public API ────────────────────────────────────────────────────────────────

ParseResult parse_log(std::string_view line) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.remove_suffix(1);
    }

    ParseResult result;
    if (line.empty()) {
        result.error = "empty line";
        return result;
    }

    LogEntry& entry = result.entry;
    Tok       tok(line);

    if (const std::string err = parse_header(tok, entry); !err.empty()) {
        result.error = err;
        return result;
    }
    if (const std::string err = parse_rule_and_chain(tok, entry); !err.empty()) {
        result.error = err;
        return result;
    }
    if (const std::string err = parse_ifaces(tok, entry); !err.empty()) {
        result.error = err;
        return result;
    }
    if (const std::string err = parse_conn_state(tok, entry); !err.empty()) {
        result.error = err;
        return result;
    }
    if (const std::string err = parse_proto_and_len(tok, entry); !err.empty()) {
        result.error = err;
        return result;
    }

    return result;
}

} // namespace msmap

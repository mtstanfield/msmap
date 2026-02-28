#pragma once

#include <array>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>

/// Minimal hand-rolled JSON serialisation helpers (see PLAN.md §Stack Decisions).
/// All functions append to an existing std::string to avoid per-call allocations.
namespace msmap::json {

/// Append a JSON string literal: surrounds `sv` with double-quotes and escapes
/// the seven ECMA-404 special characters plus control code-points < 0x20.
inline void append_string(std::string& out, std::string_view sv)
{
    out += '"';
    for (const char raw_ch : sv) {
        // Cast to unsigned char before the switch to avoid sign-extension on
        // negative char values (e.g. UTF-8 high bytes) and satisfy -Wsign-conversion.
        const auto ch = static_cast<unsigned char>(raw_ch);
        switch (ch) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (ch < 0x20) {
                    // Control character — encode as \u00XX.
                    // Indices are always 0-15; .at() enforces this with a
                    // terminate (not throw) when -fno-exceptions is active.
                    constexpr std::string_view k_hex{"0123456789abcdef"};
                    out += "\\u00";
                    out += k_hex.at(ch >> 4U);
                    out += k_hex.at(ch & 0x0fU);
                } else {
                    out += static_cast<char>(ch);
                }
                break;
        }
    }
    out += '"';
}

/// Append a quoted JSON string, or the literal `null` if `sv` is empty.
inline void append_string_or_null(std::string& out, std::string_view sv)
{
    if (sv.empty()) {
        out += "null";
    } else {
        append_string(out, sv);
    }
}

/// Append an integer value, or the literal `null` if the optional is empty.
inline void append_int_or_null(std::string& out, std::optional<int> v)
{
    if (v.has_value()) {
        out += std::to_string(*v);
    } else {
        out += "null";
    }
}

/// Append a double formatted to six decimal places, or the literal `null`.
/// Six decimal places gives sub-metre precision for lat/lon coordinates.
inline void append_double_or_null(std::string& out, std::optional<double> v)
{
    if (!v.has_value()) {
        out += "null";
        return;
    }
    std::array<char, 32> buf{};
    // snprintf is safe here: buf is large enough for any finite double at %.6f.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg) — snprintf is the right tool
    const int n = std::snprintf(buf.data(), buf.size(), "%.6f", *v);
    if (n > 0 && n < static_cast<int>(buf.size())) {
        out.append(buf.data(), static_cast<std::size_t>(n));
    } else {
        out += "null"; // unreachable for finite doubles in [-180, 180]
    }
}

} // namespace msmap::json

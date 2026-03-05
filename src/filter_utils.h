#pragma once

#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace msmap {

inline bool is_allowed_asn_filter_char(unsigned char ch) noexcept
{
    return std::isalnum(ch) != 0 ||
           ch == ' ' || ch == '.' || ch == ',' || ch == '\'' ||
           ch == '(' || ch == ')' || ch == '&' || ch == '/' ||
           ch == '_' || ch == '-' || ch == '+' || ch == ':';
}

inline std::optional<std::string> normalize_asn_filter(std::string_view raw)
{
    if (raw.empty() || raw.size() > 64) {
        return std::nullopt;
    }

    std::size_t start = 0;
    while (start < raw.size() &&
           std::isspace(static_cast<unsigned char>(raw[start])) != 0) {
        ++start;
    }

    std::size_t end = raw.size();
    while (end > start &&
           std::isspace(static_cast<unsigned char>(raw[end - 1])) != 0) {
        --end;
    }
    if (end <= start) {
        return std::nullopt;
    }

    std::string trimmed{raw.substr(start, end - start)};
    if (trimmed.size() < 3 || trimmed.size() > 64) {
        return std::nullopt;
    }
    for (const char ch : trimmed) {
        const auto uch = static_cast<unsigned char>(ch);
        if (!is_allowed_asn_filter_char(uch)) {
            return std::nullopt;
        }
    }
    return trimmed;
}

inline std::optional<std::int64_t> parse_positive_i64_exact(std::string_view raw) noexcept
{
    if (raw.empty()) {
        return std::nullopt;
    }

    std::int64_t value = 0;
    for (const char ch : raw) {
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
        constexpr std::int64_t k_max_div10 = std::numeric_limits<std::int64_t>::max() / 10;
        if (value > k_max_div10) {
            return std::nullopt;
        }
        value *= 10;
        const auto digit = static_cast<std::int64_t>(ch - '0');
        if (value > std::numeric_limits<std::int64_t>::max() - digit) {
            return std::nullopt;
        }
        value += digit;
    }

    return (value > 0) ? std::optional<std::int64_t>{value} : std::nullopt;
}

} // namespace msmap

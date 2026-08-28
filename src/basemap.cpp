#include "basemap.h"

#include <algorithm>
#include <limits>
#include <optional>

namespace {

/// Consume a decimal uint64 from the front of `sv`, advancing it.
/// Returns nullopt when the front is not a digit or the value overflows.
std::optional<std::uint64_t> take_uint(std::string_view& sv) noexcept
{
    if (sv.empty() || sv.front() < '0' || sv.front() > '9') {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    std::size_t   i     = 0;
    while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') {
        const auto digit = static_cast<std::uint64_t>(sv[i] - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10ULL) {
            return std::nullopt;
        }
        value = value * 10ULL + digit;
        ++i;
    }
    sv.remove_prefix(i);
    return value;
}

constexpr msmap::RangeSpec kInvalid{.valid = false, .offset = 0, .length = 0};

} // namespace

namespace msmap {

RangeSpec parse_range_header(std::string_view value,
                             std::uint64_t    file_size) noexcept
{
    constexpr std::string_view k_prefix{"bytes="};
    if (file_size == 0 || !value.starts_with(k_prefix)) {
        return kInvalid;
    }
    value.remove_prefix(k_prefix.size());

    if (value.starts_with('-')) {
        // Suffix form: bytes=-n → the last n bytes.
        value.remove_prefix(1);
        const auto n = take_uint(value);
        if (!n.has_value() || *n == 0 || !value.empty()) {
            return kInvalid;
        }
        const std::uint64_t len = std::min(*n, file_size);
        return {.valid = true, .offset = file_size - len, .length = len};
    }

    const auto first = take_uint(value);
    if (!first.has_value() || !value.starts_with('-')) {
        return kInvalid;
    }
    value.remove_prefix(1);

    if (*first >= file_size) {
        return kInvalid;
    }

    if (value.empty()) {
        // Open-ended form: bytes=a- → a through EOF.
        return {.valid = true, .offset = *first, .length = file_size - *first};
    }

    const auto last = take_uint(value);
    if (!last.has_value() || !value.empty() || *last < *first) {
        return kInvalid;
    }
    const std::uint64_t end = std::min(*last, file_size - 1);
    return {.valid = true, .offset = *first, .length = end - *first + 1};
}

} // namespace msmap

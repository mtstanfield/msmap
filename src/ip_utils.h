#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <arpa/inet.h>

namespace msmap {

inline std::optional<std::array<std::uint8_t, 4>>
parse_ipv4_literal(std::string_view ip) noexcept
{
    if (ip.empty() || ip.size() > 15) {
        return std::nullopt;
    }

    in_addr addr{};
    const std::string ip_copy{ip};
    if (inet_pton(AF_INET, ip_copy.c_str(), &addr) != 1) {
        return std::nullopt;
    }

    const auto* bytes =
        reinterpret_cast<const std::uint8_t*>(&addr.s_addr); // NOLINT(*-reinterpret-cast)
    return std::array<std::uint8_t, 4>{bytes[0], bytes[1], bytes[2], bytes[3]};
}

inline bool is_private_rfc1918_ipv4(std::string_view ip) noexcept
{
    const auto parsed = parse_ipv4_literal(ip);
    if (!parsed.has_value()) {
        return false;
    }

    const auto& bytes = *parsed;
    return bytes[0] == 10 ||
           (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
           (bytes[0] == 192 && bytes[1] == 168);
}

} // namespace msmap

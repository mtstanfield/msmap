#pragma once

#include <cstdint>
#include <string_view>

namespace msmap {

/// Result of parsing an HTTP `Range` header against a known file size.
/// When `valid` is false the request must be answered with 416.
struct RangeSpec {
    bool          valid;
    std::uint64_t offset;  ///< first byte to serve
    std::uint64_t length;  ///< number of bytes to serve
};

/// Parse a single-range `Range` header value (`bytes=a-b`, `bytes=a-`,
/// `bytes=-n`). Multipart ranges and any malformed input yield valid=false.
/// A range whose end lies past EOF is clamped to `file_size`.
[[nodiscard]] RangeSpec parse_range_header(std::string_view value,
                                           std::uint64_t    file_size) noexcept;

} // namespace msmap

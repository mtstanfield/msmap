#pragma once

#include <cstdint>
#include <optional>
#include <string>
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

/// Metadata for the basemap archive served at /basemap.pmtiles,
/// captured once at startup.
struct BasemapInfo {
    std::string   path;
    std::uint64_t size;
    std::string   etag;  ///< derived from size + mtime; includes quotes
};

/// Open and sanity-check the PMTiles archive at `path` (readable, PMTiles v3
/// magic). Returns std::nullopt when the file is missing, unreadable,
/// truncated, or not a v3 archive.
[[nodiscard]] std::optional<BasemapInfo> load_basemap_info(const std::string& path);

} // namespace msmap

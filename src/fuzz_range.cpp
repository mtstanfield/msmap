#include "basemap.h"

#include <cstdint>
#include <cstring>
#include <string_view>

/// libFuzzer entry point: first 8 bytes are the file size, the rest is the
/// Range header value. The parser must never crash, overflow, or return a
/// range that reaches past EOF.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size < 8) {
        return 0;
    }
    std::uint64_t file_size = 0;
    std::memcpy(&file_size, data, sizeof(file_size));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const std::string_view header{reinterpret_cast<const char*>(data + 8),
                                  size - 8};
    const msmap::RangeSpec spec = msmap::parse_range_header(header, file_size);
    if (spec.valid) {
        // Invariants the HTTP layer relies on.
        if (spec.length == 0 || spec.offset >= file_size ||
            file_size - spec.offset < spec.length) {
            __builtin_trap();
        }
    }
    return 0;
}

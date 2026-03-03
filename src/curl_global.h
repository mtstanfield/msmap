#pragma once

namespace msmap {

/// Process-wide one-time libcurl initialiser shared by all background workers.
/// Safe to call repeatedly; returns false only if the first global init failed.
[[nodiscard]] bool ensure_curl_global_init() noexcept;

} // namespace msmap

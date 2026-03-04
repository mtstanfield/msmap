#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

// Opaque handle; full definition only needed in geoip.cpp.
struct MMDB_s; // NOLINT(readability-identifier-naming) — third-party C name

namespace msmap {

// ── Result type ───────────────────────────────────────────────────────────────

struct GeoIpResult {
    std::string country; // ISO 3166-1 alpha-2 code, empty if not found
    double      lat{0.0};
    double      lon{0.0};
    std::string asn;     // e.g. "AS12345 Some ISP", empty if not found
    bool        has_coords{false};

    /// True only when a country code was resolved.
    [[nodiscard]] bool found() const noexcept { return !country.empty(); }

    /// True when the lookup has coordinates suitable for map placement.
    [[nodiscard]] bool renderable() const noexcept
    {
        return found() && has_coords;
    }
};

// ── MMDB handle deleter ───────────────────────────────────────────────────────

/// Calls MMDB_close then deletes the heap-allocated MMDB_s.
/// Defined in geoip.cpp where the full MMDB_s type is visible.
struct MmdbCloser { void operator()(MMDB_s* p) const noexcept; };

// ── GeoIp class ───────────────────────────────────────────────────────────────

class GeoIp {
public:
    /// Open the GeoLite2-City mmdb at city_path, and optionally the
    /// GeoLite2-ASN mmdb at asn_path (pass empty string to skip ASN).
    /// If the City file is absent or invalid, city_ready() returns false and
    /// lookups return an empty GeoIpResult.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    GeoIp(std::string_view city_path, std::string_view asn_path) noexcept;

    // Destructor defined in geoip.cpp so the unique_ptr can see MMDB_s.
    ~GeoIp() noexcept;

    GeoIp(const GeoIp&)            = delete;
    GeoIp& operator=(const GeoIp&) = delete;
    GeoIp(GeoIp&&)                 = delete;
    GeoIp& operator=(GeoIp&&)      = delete;

    /// True if the City database was opened successfully.
    [[nodiscard]] bool city_ready() const noexcept { return city_open_; }

    /// Backward-compatible alias for city_ready().
    [[nodiscard]] bool valid() const noexcept { return city_ready(); }

    /// True if the ASN database is currently loaded.
    [[nodiscard]] bool asn_ready() const noexcept { return asn_db_ != nullptr; }

    /// Look up src_ip and return country/lat/lon/asn.
    /// Returns an empty GeoIpResult if not found or not valid.
    [[nodiscard]] GeoIpResult lookup(const std::string& ip) const noexcept;

    /// Check whether either mmdb file has changed on disk since the last
    /// load (throttled to at most one stat() pair per kCheckIntervalSecs).
    /// Reloads and returns true if a change is detected; false otherwise.
    /// Safe to call on every recv() iteration — the fast path is just
    /// a time() call and an integer comparison.
    bool reload_if_changed() noexcept;

    /// Test hook: seed City reload state without requiring a real .mmdb.
    void set_city_state_for_test(bool city_ready, std::int64_t city_mtime) noexcept;

    /// Test hook: apply the City commit policy and report whether the new City
    /// database would replace the current one.
    bool apply_city_reload_result_for_test(bool new_city_ok,
                                           std::int64_t new_city_mtime) noexcept;

    /// Test hook: expose the current City mtime tracked by the reload logic.
    [[nodiscard]] std::int64_t city_mtime_for_test() const noexcept { return city_mtime_; }

private:
    /// (Re-)open mmdb files using the stored paths. City reload is
    /// transactional: on failure, the last good loaded City DB remains active.
    bool open() noexcept;

    /// Fill result.asn from the ASN database if it is open and has data.
    void lookup_asn(const std::string& ip, GeoIpResult& result) const noexcept;

    std::string city_path_;
    std::string asn_path_;

    std::unique_ptr<MMDB_s, MmdbCloser> city_db_;
    std::unique_ptr<MMDB_s, MmdbCloser> asn_db_;

    bool         city_open_{false};
    std::int64_t city_mtime_{0};
    std::int64_t asn_mtime_{0};
    std::int64_t last_check_{0};
};

} // namespace msmap

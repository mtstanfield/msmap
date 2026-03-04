#include "geoip.h"

#include <cstdint>
#include <ctime>
#include <iostream>
#include <maxminddb.h>
#include <memory>
#include <string_view>
#include <sys/stat.h>

namespace msmap {

// ── MmdbCloser ────────────────────────────────────────────────────────────────

void MmdbCloser::operator()(MMDB_s* p) const noexcept
{
    if (p != nullptr) {
        MMDB_close(p);
        delete p; // NOLINT(cppcoreguidelines-owning-memory)
    }
}

// ── Module helpers ────────────────────────────────────────────────────────────

namespace {

// How often to stat() the mmdb files and check for changes.
constexpr std::int64_t kCheckIntervalSecs{60};

/// Return the mtime of path as a Unix timestamp, or 0 on any error.
std::int64_t file_mtime(const std::string& path) noexcept
{
    if (path.empty()) {
        return 0;
    }
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) {
        return 0;
    }
    return static_cast<std::int64_t>(st.st_mtime);
}

/// Open one mmdb file into a fresh heap-allocated MMDB_s.
/// Returns a null unique_ptr and logs a warning on failure.
std::unique_ptr<MMDB_s, MmdbCloser>
open_mmdb(const std::string& path, const char* label) noexcept
{
    auto raw = std::make_unique<MMDB_s>();
    const int status = MMDB_open(path.c_str(), MMDB_MODE_MMAP, raw.get());
    if (status != MMDB_SUCCESS) {
        std::clog << "[WARN] MMDB_open(" << label << "=" << path << "): "
                  << MMDB_strerror(status) << '\n';
        // raw is destroyed here via default_delete (correct: MMDB_open failed,
        // so MMDB_close must NOT be called per MaxMind docs).
        return nullptr;
    }
    // Transfer ownership to the MmdbCloser-aware unique_ptr.
    return std::unique_ptr<MMDB_s, MmdbCloser>{raw.release()};
}

} // anonymous namespace

// ── GeoIp implementation ──────────────────────────────────────────────────────

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
GeoIp::GeoIp(std::string_view city_path, std::string_view asn_path) noexcept
    : city_path_(city_path), asn_path_(asn_path)
{
    (void)open();
}

GeoIp::~GeoIp() noexcept = default;

bool GeoIp::open() noexcept
{
    if (city_path_.empty()) {
        std::clog << "[WARN] GeoIP: no city mmdb path set; "
                     "map lookups unavailable\n";
        return false;
    }

    auto new_city_db = open_mmdb(city_path_, "city");
    if (!new_city_db) {
        return false;
    }

    const std::int64_t new_city_mtime = file_mtime(city_path_);

    std::unique_ptr<MMDB_s, MmdbCloser> new_asn_db;
    std::int64_t new_asn_mtime = asn_mtime_;

    if (!asn_path_.empty()) {
        if (auto candidate_asn_db = open_mmdb(asn_path_, "asn")) {
            new_asn_db = std::move(candidate_asn_db);
            new_asn_mtime = file_mtime(asn_path_);
        } else if (!asn_db_) {
            new_asn_mtime = 0;
        }
    }

    city_db_ = std::move(new_city_db);
    city_open_ = true;
    city_mtime_ = new_city_mtime;

    if (!asn_path_.empty()) {
        if (new_asn_db) {
            asn_db_ = std::move(new_asn_db);
            asn_mtime_ = new_asn_mtime;
        } else if (!asn_db_) {
            asn_mtime_ = new_asn_mtime;
        }
    } else {
        asn_db_.reset();
        asn_mtime_ = 0;
    }

    std::clog << "[INFO] GeoIP loaded: city=" << city_path_
              << (asn_db_ ? " asn=" + asn_path_ : " (no ASN)") << '\n';
    return true;
}

GeoIpResult GeoIp::lookup(const std::string& ip) const noexcept
{
    if (!city_open_ || !city_db_) {
        return {};
    }

    int gai_error{0};
    int mmdb_error{0};
    MMDB_lookup_result_s city_res =
        MMDB_lookup_string(city_db_.get(), ip.c_str(), &gai_error, &mmdb_error);

    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !city_res.found_entry) {
        return {};
    }

    GeoIpResult result;
    MMDB_entry_data_s data{};

    // ── Country ISO code ──────────────────────────────────────────────────────
    if (MMDB_get_value(&city_res.entry, &data,
                       "country", "iso_code",
                       static_cast<const char*>(nullptr)) == MMDB_SUCCESS
        && data.has_data
        && data.type == MMDB_DATA_TYPE_UTF8_STRING) {
        result.country.assign(data.utf8_string, // NOLINT(cppcoreguidelines-pro-type-union-access)
                              data.data_size);
    }

    if (result.country.empty()) {
        return result; // no country → lat/lon meaningless
    }

    bool has_lat{false};
    bool has_lon{false};

    // ── Latitude ──────────────────────────────────────────────────────────────
    if (MMDB_get_value(&city_res.entry, &data,
                       "location", "latitude",
                       static_cast<const char*>(nullptr)) == MMDB_SUCCESS
        && data.has_data
        && data.type == MMDB_DATA_TYPE_DOUBLE) {
        result.lat = data.double_value; // NOLINT(cppcoreguidelines-pro-type-union-access)
        has_lat = true;
    }

    // ── Longitude ─────────────────────────────────────────────────────────────
    if (MMDB_get_value(&city_res.entry, &data,
                       "location", "longitude",
                       static_cast<const char*>(nullptr)) == MMDB_SUCCESS
        && data.has_data
        && data.type == MMDB_DATA_TYPE_DOUBLE) {
        result.lon = data.double_value; // NOLINT(cppcoreguidelines-pro-type-union-access)
        has_lon = true;
    }

    result.has_coords = has_lat && has_lon;

    // ── ASN (separate database, optional) ─────────────────────────────────────
    lookup_asn(ip, result);

    return result;
}

void GeoIp::lookup_asn(const std::string& ip, GeoIpResult& result) const noexcept
{
    if (!asn_db_) {
        return;
    }

    int asn_gai{0};
    int asn_err{0};
    MMDB_lookup_result_s asn_res =
        MMDB_lookup_string(asn_db_.get(), ip.c_str(), &asn_gai, &asn_err);

    if (asn_gai != 0 || asn_err != MMDB_SUCCESS || !asn_res.found_entry) {
        return;
    }

    MMDB_entry_data_s asn_data{};
    std::uint32_t     asn_num{0};
    std::string       asn_org;

    if (MMDB_get_value(&asn_res.entry, &asn_data,
                       "autonomous_system_number",
                       static_cast<const char*>(nullptr)) == MMDB_SUCCESS
        && asn_data.has_data
        && asn_data.type == MMDB_DATA_TYPE_UINT32) {
        asn_num = asn_data.uint32; // NOLINT(cppcoreguidelines-pro-type-union-access)
    }

    if (MMDB_get_value(&asn_res.entry, &asn_data,
                       "autonomous_system_organization",
                       static_cast<const char*>(nullptr)) == MMDB_SUCCESS
        && asn_data.has_data
        && asn_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
        asn_org.assign(asn_data.utf8_string, // NOLINT(cppcoreguidelines-pro-type-union-access)
                       asn_data.data_size);
    }

    if (asn_num > 0) {
        result.asn = "AS" + std::to_string(asn_num);
        if (!asn_org.empty()) {
            result.asn += ' ';
            result.asn += asn_org;
        }
    }
}

bool GeoIp::reload_if_changed() noexcept
{
    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    if (now - last_check_ < kCheckIntervalSecs) {
        return false; // fast path: nothing to check yet
    }
    last_check_ = now;

    const std::int64_t new_city_mtime = file_mtime(city_path_);
    const std::int64_t new_asn_mtime  = file_mtime(asn_path_);

    if (new_city_mtime == city_mtime_ && new_asn_mtime == asn_mtime_) {
        return false;
    }

    std::clog << "[INFO] GeoIP mmdb changed on disk, reloading\n";
    return open();
}

void GeoIp::set_city_state_for_test(bool city_ready, std::int64_t city_mtime) noexcept
{
    city_open_ = city_ready;
    city_mtime_ = city_mtime;
}

bool GeoIp::apply_city_reload_result_for_test(bool new_city_ok,
                                              std::int64_t new_city_mtime) noexcept
{
    if (!new_city_ok) {
        return false;
    }
    city_open_ = true;
    city_mtime_ = new_city_mtime;
    return true;
}

} // namespace msmap

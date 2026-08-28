#include "basemap.h"

#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <fstream>
#include <string>

// ── parse_range_header ────────────────────────────────────────────────────────

TEST_CASE("range: closed range a-b", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=100-199", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 100);
    REQUIRE(r.length == 100);
}

TEST_CASE("range: single first byte", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=0-0", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 0);
    REQUIRE(r.length == 1);
}

TEST_CASE("range: open-ended a- runs to EOF", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=100-", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 100);
    REQUIRE(r.length == 900);
}

TEST_CASE("range: suffix -n takes last n bytes", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=-200", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 800);
    REQUIRE(r.length == 200);
}

TEST_CASE("range: suffix larger than file clamps to whole file", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=-5000", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 0);
    REQUIRE(r.length == 1000);
}

TEST_CASE("range: end past EOF is clamped", "[range]")
{
    const auto r = msmap::parse_range_header("bytes=900-1999", 1000);
    REQUIRE(r.valid);
    REQUIRE(r.offset == 900);
    REQUIRE(r.length == 100);
}

TEST_CASE("range: start at or past EOF is invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("bytes=1000-", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=5000-5999", 1000).valid);
}

TEST_CASE("range: reversed bounds are invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("bytes=200-100", 1000).valid);
}

TEST_CASE("range: multipart is invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("bytes=0-1,5-9", 1000).valid);
}

TEST_CASE("range: non-bytes unit is invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("items=0-1", 1000).valid);
}

TEST_CASE("range: malformed values are invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=-", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=abc-def", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=1x-5", 1000).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes= 0-1", 1000).valid);
}

TEST_CASE("range: uint64 overflow is invalid", "[range]")
{
    REQUIRE_FALSE(
        msmap::parse_range_header("bytes=99999999999999999999-", 1000).valid);
}

TEST_CASE("range: zero-size file rejects all ranges", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("bytes=0-0", 0).valid);
    REQUIRE_FALSE(msmap::parse_range_header("bytes=-1", 0).valid);
}

TEST_CASE("range: suffix of zero bytes is invalid", "[range]")
{
    REQUIRE_FALSE(msmap::parse_range_header("bytes=-0", 1000).valid);
}

// ── load_basemap_info ─────────────────────────────────────────────────────────

namespace {

/// Write `bytes` to a uniquely named temp file and return its path.
std::filesystem::path write_temp(const std::string& name, std::string_view bytes)
{
    const auto p = std::filesystem::temp_directory_path() / name;
    std::ofstream out{p, std::ios::binary | std::ios::trunc};
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return p;
}

constexpr std::string_view kMagic{"PMTiles\x03", 8};

} // namespace

TEST_CASE("basemap: valid v3 magic yields info with size and quoted etag", "[basemap]")
{
    std::string content{kMagic};
    content += "trailing archive bytes";
    const auto p    = write_temp("msmap_test_valid.pmtiles", content);
    const auto info = msmap::load_basemap_info(p.string());
    REQUIRE(info.has_value());
    REQUIRE(info->path == p.string());
    REQUIRE(info->size == content.size());
    REQUIRE(info->etag.size() >= 3);
    REQUIRE(info->etag.front() == '"');
    REQUIRE(info->etag.back() == '"');
    std::filesystem::remove(p);
}

TEST_CASE("basemap: wrong magic is rejected", "[basemap]")
{
    const auto p = write_temp("msmap_test_badmagic.pmtiles",
                              "NOTTILES this is not a pmtiles archive");
    REQUIRE_FALSE(msmap::load_basemap_info(p.string()).has_value());
    std::filesystem::remove(p);
}

TEST_CASE("basemap: wrong version byte is rejected", "[basemap]")
{
    const auto p = write_temp("msmap_test_badver.pmtiles",
                              std::string_view{"PMTiles\x02........", 16});
    REQUIRE_FALSE(msmap::load_basemap_info(p.string()).has_value());
    std::filesystem::remove(p);
}

TEST_CASE("basemap: truncated file is rejected", "[basemap]")
{
    const auto p = write_temp("msmap_test_trunc.pmtiles", "PM");
    REQUIRE_FALSE(msmap::load_basemap_info(p.string()).has_value());
    std::filesystem::remove(p);
}

TEST_CASE("basemap: missing file is rejected", "[basemap]")
{
    REQUIRE_FALSE(
        msmap::load_basemap_info("/nonexistent/msmap_no_such.pmtiles").has_value());
}

TEST_CASE("basemap: etag changes when file size changes", "[basemap]")
{
    std::string content{kMagic};
    const auto p  = write_temp("msmap_test_etag.pmtiles", content);
    const auto a  = msmap::load_basemap_info(p.string());
    content += "more bytes";
    (void)write_temp("msmap_test_etag.pmtiles", content);
    const auto b  = msmap::load_basemap_info(p.string());
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(a->etag != b->etag);
    std::filesystem::remove(p);
}

#include "basemap.h"

#include <catch2/catch_test_macros.hpp>

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

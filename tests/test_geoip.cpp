#include "geoip.h"

#include <catch2/catch_test_macros.hpp>

// GeoIP unit tests do not require real .mmdb files.
// They verify graceful degradation when the files are absent and that
// the mtime-polling logic is safe on an invalid instance.

TEST_CASE("GeoIpResult::found() is false when country is empty")
{
    const msmap::GeoIpResult r;
    REQUIRE_FALSE(r.found());
}

TEST_CASE("GeoIpResult::found() is true when country is set")
{
    msmap::GeoIpResult r;
    r.country = "US";
    REQUIRE(r.found());
}

TEST_CASE("GeoIp with empty city path is not valid")
{
    const msmap::GeoIp geoip{"", ""};
    REQUIRE_FALSE(geoip.valid());
}

TEST_CASE("GeoIp with nonexistent city path is not valid")
{
    const msmap::GeoIp geoip{"/nonexistent/GeoLite2-City.mmdb", ""};
    REQUIRE_FALSE(geoip.valid());
}

TEST_CASE("lookup() on invalid GeoIp returns empty result without crashing")
{
    const msmap::GeoIp geoip{"/nonexistent/GeoLite2-City.mmdb", ""};
    REQUIRE_FALSE(geoip.valid());

    const msmap::GeoIpResult r = geoip.lookup("1.2.3.4");
    REQUIRE_FALSE(r.found());
    REQUIRE(r.country.empty());
    REQUIRE(r.asn.empty());
}

TEST_CASE("reload_if_changed() on invalid GeoIp is a safe no-op")
{
    msmap::GeoIp geoip{"/nonexistent/GeoLite2-City.mmdb", ""};
    REQUIRE_FALSE(geoip.valid());
    // Should not crash or throw regardless of how many times called.
    REQUIRE_FALSE(geoip.reload_if_changed());
    REQUIRE_FALSE(geoip.reload_if_changed());
}

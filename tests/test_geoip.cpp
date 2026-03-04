#include "geoip.h"

#include <catch2/catch_test_macros.hpp>

// GeoIP unit tests do not require real .mmdb files.
// They verify graceful degradation when the files are absent and that
// the mtime-polling logic is safe on an invalid instance.

TEST_CASE("GeoIpResult::found() is false when country is empty")
{
    const msmap::GeoIpResult r;
    REQUIRE_FALSE(r.found());
    REQUIRE_FALSE(r.renderable());
}

TEST_CASE("GeoIpResult::found() is true when country is set")
{
    msmap::GeoIpResult r;
    r.country = "US";
    REQUIRE(r.found());
    REQUIRE_FALSE(r.renderable());
}

TEST_CASE("GeoIpResult::renderable() requires coordinates")
{
    msmap::GeoIpResult r;
    r.country = "US";
    r.lat = 37.751;
    r.lon = -97.822;
    r.has_coords = true;
    REQUIRE(r.renderable());
}

TEST_CASE("GeoIp with empty city path is not valid")
{
    const msmap::GeoIp geoip{"", ""};
    REQUIRE_FALSE(geoip.city_ready());
    REQUIRE_FALSE(geoip.valid());
    REQUIRE_FALSE(geoip.asn_ready());
}

TEST_CASE("GeoIp with nonexistent city path is not valid")
{
    const msmap::GeoIp geoip{"/nonexistent/GeoLite2-City.mmdb", ""};
    REQUIRE_FALSE(geoip.city_ready());
    REQUIRE_FALSE(geoip.valid());
    REQUIRE_FALSE(geoip.asn_ready());
}

TEST_CASE("lookup() on invalid GeoIp returns empty result without crashing")
{
    const msmap::GeoIp geoip{"/nonexistent/GeoLite2-City.mmdb", ""};
    REQUIRE_FALSE(geoip.city_ready());

    const msmap::GeoIpResult r = geoip.lookup("1.2.3.4");
    REQUIRE_FALSE(r.found());
    REQUIRE_FALSE(r.renderable());
    REQUIRE(r.country.empty());
    REQUIRE(r.asn.empty());
}

TEST_CASE("reload_if_changed() on invalid GeoIp is a safe no-op")
{
    msmap::GeoIp geoip{"/nonexistent/GeoLite2-City.mmdb", ""};
    REQUIRE_FALSE(geoip.city_ready());
    // Should not crash or throw regardless of how many times called.
    REQUIRE_FALSE(geoip.reload_if_changed());
    REQUIRE_FALSE(geoip.reload_if_changed());
}

TEST_CASE("failed City reload keeps the last good City state active")
{
    msmap::GeoIp geoip{"/nonexistent/GeoLite2-City.mmdb", ""};
    geoip.set_city_state_for_test(true, 123);

    REQUIRE_FALSE(geoip.apply_city_reload_result_for_test(false, 456));
    REQUIRE(geoip.city_ready());
    REQUIRE(geoip.city_mtime_for_test() == 123);
}

TEST_CASE("successful City reload replaces the tracked City state")
{
    msmap::GeoIp geoip{"/nonexistent/GeoLite2-City.mmdb", ""};
    geoip.set_city_state_for_test(true, 123);

    REQUIRE(geoip.apply_city_reload_result_for_test(true, 456));
    REQUIRE(geoip.city_ready());
    REQUIRE(geoip.city_mtime_for_test() == 456);
}

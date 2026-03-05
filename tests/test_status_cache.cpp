#include "abuse_cache.h"
#include "db.h"
#include "geoip.h"
#include "status_cache.h"

#include <catch2/catch_test_macros.hpp>

namespace {

msmap::GeoIpResult make_renderable_geo()
{
    msmap::GeoIpResult geo;
    geo.country = "US";
    geo.lat = 37.751;
    geo.lon = -97.822;
    geo.has_coords = true;
    return geo;
}

} // namespace

TEST_CASE("status cache: empty database snapshot is available", "[status]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::StatusCache status{db, nullptr, nullptr, nullptr, false, false, 60};
    REQUIRE(status.valid());

    const auto snapshot = status.snapshot();
    REQUIRE(snapshot.has_value());
    REQUIRE(snapshot->ok);
    REQUIRE(snapshot->rows_24h == 0);
    REQUIRE(snapshot->distinct_sources_24h == 0);
    REQUIRE_FALSE(snapshot->latest_event_ts.has_value());
    REQUIRE(snapshot->abuse_enabled == false);
    REQUIRE_FALSE(snapshot->abuse_rate_remaining.has_value());
    REQUIRE_FALSE(snapshot->abuse_can_accept_new_lookups);
    REQUIRE_FALSE(snapshot->abuse_quota_exhausted);
    REQUIRE_FALSE(snapshot->abuse_quota_retry_after_ts.has_value());
    REQUIRE_FALSE(snapshot->abuse_has_pending_work);
    REQUIRE_FALSE(snapshot->intel_refresh_attempted);
    REQUIRE(snapshot->generated_at >= snapshot->now);
}

TEST_CASE("status cache: populated database snapshot includes counts", "[status]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::LogEntry base{};
    base.ts = 1000;
    base.src_ip = "1.2.3.4";
    base.src_port = 1234;
    base.dst_ip = "10.0.0.1";
    base.dst_port = 443;
    base.proto = "TCP";
    base.tcp_flags = "SYN";
    base.rule = "FW_INPUT_NEW";
    base.chain = "input";
    base.in_iface = "ether1";
    base.conn_state = "new";
    base.pkt_len = 52;

    msmap::LogEntry other = base;
    other.ts = 1500;
    other.src_ip = "5.6.7.8";

    const auto geo = make_renderable_geo();
    db.insert(base, geo);
    db.insert(other, geo);

    msmap::StatusCache status{db, nullptr, nullptr, nullptr, false, false, 60};
    const auto snapshot = status.snapshot();
    REQUIRE(snapshot.has_value());
    REQUIRE(snapshot->rows_24h == 2);
    REQUIRE(snapshot->distinct_sources_24h == 2);
    REQUIRE(snapshot->latest_event_ts == 1500);
    REQUIRE(snapshot->abuse_enabled == false);
    REQUIRE_FALSE(snapshot->abuse_rate_remaining.has_value());
    REQUIRE_FALSE(snapshot->abuse_can_accept_new_lookups);
    REQUIRE_FALSE(snapshot->abuse_quota_exhausted);
    REQUIRE_FALSE(snapshot->abuse_quota_retry_after_ts.has_value());
    REQUIRE_FALSE(snapshot->abuse_has_pending_work);
    REQUIRE_FALSE(snapshot->intel_refresh_attempted);
}

TEST_CASE("status cache: invalid database publishes an unhealthy snapshot", "[status]")
{
    msmap::Database db{"/nonexistent/path/msmap.db"};
    REQUIRE_FALSE(db.valid());

    msmap::StatusCache status{db, nullptr, nullptr, nullptr, false, false, 60};
    REQUIRE(status.valid());

    const auto snapshot = status.snapshot();
    REQUIRE(snapshot.has_value());
    REQUIRE_FALSE(snapshot->ok);
    REQUIRE(snapshot->rows_24h == 0);
    REQUIRE(snapshot->distinct_sources_24h == 0);
    REQUIRE_FALSE(snapshot->latest_event_ts.has_value());
    REQUIRE(snapshot->abuse_enabled == false);
    REQUIRE_FALSE(snapshot->abuse_rate_remaining.has_value());
    REQUIRE_FALSE(snapshot->abuse_can_accept_new_lookups);
    REQUIRE_FALSE(snapshot->abuse_quota_exhausted);
    REQUIRE_FALSE(snapshot->abuse_quota_retry_after_ts.has_value());
    REQUIRE_FALSE(snapshot->abuse_has_pending_work);
    REQUIRE_FALSE(snapshot->intel_refresh_attempted);
    REQUIRE(snapshot->generated_at == snapshot->now);
}

TEST_CASE("status cache: abuse cache exposes remaining quota", "[status]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::AbuseCache abuse{":memory:", "dummy_key"};
    REQUIRE(abuse.valid());
    abuse.set_rate_remaining_for_test(742);

    msmap::StatusCache status{db, nullptr, &abuse, nullptr, true, false, 60};
    const auto snapshot = status.snapshot();
    REQUIRE(snapshot.has_value());
    REQUIRE(snapshot->abuse_enabled);
    REQUIRE(snapshot->abuse_rate_remaining.has_value());
    REQUIRE(*snapshot->abuse_rate_remaining == 742);
    REQUIRE(snapshot->abuse_can_accept_new_lookups);
    REQUIRE_FALSE(snapshot->abuse_quota_exhausted);
    REQUIRE_FALSE(snapshot->abuse_quota_retry_after_ts.has_value());
    REQUIRE_FALSE(snapshot->abuse_has_pending_work);
}

TEST_CASE("status cache: abuse cache remains unknown before first live confirmation", "[status]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::AbuseCache abuse{":memory:", "dummy_key"};
    REQUIRE(abuse.valid());

    msmap::StatusCache status{db, nullptr, &abuse, nullptr, true, false, 60};
    const auto snapshot = status.snapshot();
    REQUIRE(snapshot.has_value());
    REQUIRE(snapshot->abuse_enabled);
    REQUIRE_FALSE(snapshot->abuse_rate_remaining.has_value());
    REQUIRE(snapshot->abuse_can_accept_new_lookups);
    REQUIRE_FALSE(snapshot->abuse_quota_exhausted);
    REQUIRE_FALSE(snapshot->abuse_quota_retry_after_ts.has_value());
    REQUIRE_FALSE(snapshot->abuse_has_pending_work);
}

TEST_CASE("status cache: abuse cache exposes exhausted quota", "[status]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::AbuseCache abuse{":memory:", "dummy_key"};
    REQUIRE(abuse.valid());
    abuse.set_rate_remaining_for_test(0);

    msmap::StatusCache status{db, nullptr, &abuse, nullptr, true, false, 60};
    const auto snapshot = status.snapshot();
    REQUIRE(snapshot.has_value());
    REQUIRE(snapshot->abuse_enabled);
    REQUIRE(snapshot->abuse_rate_remaining.has_value());
    REQUIRE(*snapshot->abuse_rate_remaining == 0);
    REQUIRE_FALSE(snapshot->abuse_can_accept_new_lookups);
    REQUIRE(snapshot->abuse_quota_exhausted);
    REQUIRE_FALSE(snapshot->abuse_quota_retry_after_ts.has_value());
    REQUIRE_FALSE(snapshot->abuse_has_pending_work);
}

TEST_CASE("status cache: exposes abuse quota retry ETA when armed", "[status]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::AbuseCache abuse{":memory:", "dummy_key"};
    REQUIRE(abuse.valid());
    abuse.set_rate_remaining_for_test(0);
    abuse.arm_quota_retry_for_test(1700000000, true);

    msmap::StatusCache status{db, nullptr, &abuse, nullptr, true, false, 60};
    const auto snapshot = status.snapshot();
    REQUIRE(snapshot.has_value());
    REQUIRE(snapshot->abuse_enabled);
    REQUIRE(snapshot->abuse_quota_exhausted);
    REQUIRE_FALSE(snapshot->abuse_can_accept_new_lookups);
    REQUIRE(snapshot->abuse_quota_retry_after_ts.has_value());
    REQUIRE(*snapshot->abuse_quota_retry_after_ts == 1700000000);
    REQUIRE_FALSE(snapshot->abuse_has_pending_work);
}

TEST_CASE("status cache: abuse syncing reflects pending background work", "[status]")
{
    msmap::Database db{":memory:"};
    REQUIRE(db.valid());

    msmap::AbuseCache abuse{":memory:", "dummy_key"};
    REQUIRE(abuse.valid());
    abuse.mark_in_flight_for_test("1.2.3.4");

    msmap::StatusCache status{db, nullptr, &abuse, nullptr, true, false, 60};
    const auto snapshot = status.snapshot();
    REQUIRE(snapshot.has_value());
    REQUIRE(snapshot->abuse_enabled);
    REQUIRE(snapshot->abuse_has_pending_work);
    REQUIRE_FALSE(snapshot->abuse_rate_remaining.has_value());
    REQUIRE(snapshot->abuse_can_accept_new_lookups);
}

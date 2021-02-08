#include "catch.hpp"

#include "hostname_cache.hpp"
#include "irods_at_scope_exit.hpp"

#include <string_view>
#include <chrono>
#include <thread>

namespace net = irods::experimental::net;

using namespace std::chrono_literals;

TEST_CASE("hostname_cache")
{
    net::hnc_init("irods_hostname_cache_test", 100'000);
    irods::at_scope_exit cleanup{[] { net::hnc_deinit(); }};

    SECTION("insert / update / expiration")
    {
        REQUIRE(net::hnc_insert_or_assign("foo", "foo.irods.org", 3s));
        auto alias = net::hnc_lookup("foo");
        REQUIRE(alias);
        REQUIRE(alias.value() == "foo.irods.org");

        REQUIRE_FALSE(net::hnc_insert_or_assign("foo", "foobar.irods.org", 3s));
        alias = net::hnc_lookup("foo");
        REQUIRE(alias);
        REQUIRE(alias.value() == "foobar.irods.org");

        std::this_thread::sleep_for(3s);
        REQUIRE_FALSE(net::hnc_lookup("foo"));
    }

    SECTION("erasure operations")
    {
        REQUIRE(net::hnc_insert_or_assign("foo", "foo.irods.org", 3s));
        REQUIRE(net::hnc_insert_or_assign("bar", "bar.irods.org", 3s));
        REQUIRE(net::hnc_insert_or_assign("baz", "baz.irods.org", 3s));
        REQUIRE(net::hnc_insert_or_assign("jar", "jar.irods.org", 3s));

        // Erase the "baz" entry.
        const char* key = "baz";
        REQUIRE(net::hnc_lookup(key));
        net::hnc_erase(key);
        REQUIRE_FALSE(net::hnc_lookup(key));

        // Show that the other entries still exist.
        REQUIRE(net::hnc_lookup("foo"));
        REQUIRE(net::hnc_lookup("bar"));
        REQUIRE(net::hnc_lookup("jar"));

        // Show that all expired entries were erased from the cache.
        std::this_thread::sleep_for(3s);
        net::hnc_erase_expired_entries();
        REQUIRE_FALSE(net::hnc_lookup("foo"));
        REQUIRE_FALSE(net::hnc_lookup("bar"));
        REQUIRE_FALSE(net::hnc_lookup("jar"));
    }
}


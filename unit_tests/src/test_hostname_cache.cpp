#include "catch.hpp"

#include "hostname_cache.hpp"
#include "irods_at_scope_exit.hpp"

#include <string_view>
#include <chrono>
#include <thread>

namespace net = irods::experimental::net;

TEST_CASE("hostname_cache")
{
#if 0
    std::string_view hosts_config = R"({
        "host_entries": [
            {
                "address_type" : "local",
                "addresses" : [
                    {"address" : "xx.yy.nn.zz"},
                    {"address" : "longname.example.org"}
                ]
            },
            {
                "address_type" : "remote",
                "addresses" : [
                    {"address" : "aa.bb.cc.dd"},
                    {"address" : "fqdn.example.org"},
                    {"address" : "morefqdn.example.org"}
                ]
            },
            {
                "address_type" : "remote",
                "addresses" : [
                    {"address" : "ddd.eee.fff.xxx"},
                    {"address" : "another.example.org"}
                ]
            }
        ]
    })";

    net::hnc_init();
    irods::at_scope_exit cleanup{[] { net::hnc_deinit(); }};

    // clang-format off
    REQUIRE(*irods::get_hostname_from_cache("localhost", hosts_config)            == "longname.example.org");
    REQUIRE(*irods::get_hostname_from_cache("morefqdn.example.org", hosts_config) == "morefqdn.example.org");
    REQUIRE(*irods::get_hostname_from_cache("fqdn.example.org", hosts_config)     == "morefqdn.example.org");
    REQUIRE(*irods::get_hostname_from_cache("ddd.eee.fff.xxx", hosts_config)      == "another.example.org");
    // clang-format on

    REQUIRE_FALSE(irods::get_hostname_from_cache("does.not.exist.irods.org", hosts_config));
#else
    net::hnc_init("irods_hostname_cache_test", 100'000);
    irods::at_scope_exit cleanup{[] { net::hnc_deinit(); }};

    using namespace std::chrono_literals;

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
        REQUIRE(net::hnc_insert_or_assign("foo", "foo.irods.org", 2s));
        REQUIRE(net::hnc_insert_or_assign("bar", "bar.irods.org", 2s));
        REQUIRE(net::hnc_insert_or_assign("baz", "baz.irods.org", 2s));
        REQUIRE(net::hnc_insert_or_assign("jar", "jar.irods.org", 2s));

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
#endif
}


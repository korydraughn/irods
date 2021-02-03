#include "catch.hpp"

#include "network_utilities.hpp"
#include "irods_at_scope_exit.hpp"

#include <string_view>

TEST_CASE("hostname_cache")
{
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

    irods::init_hostname_cache();
    irods::at_scope_exit cleanup{[] { irods::deinit_hostname_cache(); }};

    // clang-format off
    REQUIRE(*irods::get_hostname_from_cache("localhost", hosts_config)            == "longname.example.org");
    REQUIRE(*irods::get_hostname_from_cache("morefqdn.example.org", hosts_config) == "morefqdn.example.org");
    REQUIRE(*irods::get_hostname_from_cache("fqdn.example.org", hosts_config)     == "morefqdn.example.org");
    REQUIRE(*irods::get_hostname_from_cache("ddd.eee.fff.xxx", hosts_config)      == "another.example.org");
    // clang-format on

    REQUIRE_FALSE(irods::get_hostname_from_cache("does.not.exist.irods.org", hosts_config));
}


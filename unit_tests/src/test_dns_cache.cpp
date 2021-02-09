#include "catch.hpp"

#include "dns_cache.hpp"
#include "irods_at_scope_exit.hpp"

#include <string_view>
#include <chrono>
#include <thread>
#include <iostream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

namespace net = irods::experimental::net;

using namespace std::chrono_literals;

using gai_deleter = void (*)(addrinfo*);

auto resolve_canonical_hostname(const std::string_view _node) -> std::unique_ptr<addrinfo, gai_deleter>;
auto resolve_ip(const std::string_view _node) -> std::unique_ptr<addrinfo, gai_deleter>;

TEST_CASE("dns_cache")
{
    net::dnsc_init("irods_dns_cache_test", 100'000);
    irods::at_scope_exit cleanup{[] { net::dnsc_deinit(); }};

    SECTION("insert / update / expiration")
    {
        const char* google = "google.com";
        auto cname = resolve_canonical_hostname(google);
        REQUIRE(cname);
        REQUIRE(net::dnsc_insert_or_assign(google, *cname, 3s));
        auto gai_info = net::dnsc_lookup(google);
        REQUIRE(gai_info);

        const char* yahoo = "yahoo.com";
        auto ip = resolve_ip(yahoo);
        REQUIRE(ip);
        REQUIRE(net::dnsc_insert_or_assign(yahoo, *ip, 3s));
        gai_info = net::dnsc_lookup(yahoo);
        REQUIRE(gai_info);
        const auto* src = &reinterpret_cast<sockaddr_in*>(gai_info->ai_addr)->sin_addr;
        char dst[INET_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET, src, dst, sizeof(dst))) {
            std::cout << dst << '\n';
        }

        std::this_thread::sleep_for(4s);
        REQUIRE_FALSE(net::dnsc_lookup(google));
        REQUIRE_FALSE(net::dnsc_lookup(yahoo));
    }
}

auto resolve_canonical_hostname(const std::string_view _node) -> std::unique_ptr<addrinfo, gai_deleter>
{
    addrinfo hints{};
    hints.ai_flags = AI_CANONNAME;
    addrinfo* res{};
    const auto ec = getaddrinfo(_node.data(), nullptr, &hints, &res);
    REQUIRE(ec == 0);
    return {res, freeaddrinfo};
}

auto resolve_ip(const std::string_view _node) -> std::unique_ptr<addrinfo, gai_deleter>
{
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* res{};
    const auto ec = getaddrinfo(_node.data(), nullptr, &hints, &res);
    REQUIRE(ec == 0);
    return {res, freeaddrinfo};
}


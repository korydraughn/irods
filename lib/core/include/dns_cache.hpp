#ifndef IRODS_DNS_CACHE_HPP
#define IRODS_DNS_CACHE_HPP

/// \file

#include <string>
#include <string_view>
#include <memory>
#include <chrono>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

namespace irods::experimental::net
{
    using address_info_deleter_type = void(*)(addrinfo*);

    /// Initializes the dns cache.
    ///
    /// \since 4.2.9
    auto dnsc_init(const std::string_view _shm_name = "irods_dns_cache",
                   std::size_t _shm_size = 5'000'000) -> void;

    /// \since 4.2.9
    auto dnsc_deinit() -> void;

    /// \since 4.2.9
    auto dnsc_insert_or_assign(const std::string_view _hostname,
                               const addrinfo& _info,
                               std::chrono::seconds _expires_after) -> bool;

    /// \since 4.2.9
    auto dnsc_lookup(const std::string_view _hostname) -> std::unique_ptr<addrinfo, address_info_deleter_type>;

    /// \since 4.2.9
    auto dnsc_erase(const std::string_view _hostname) -> void;

    /// \since 4.2.9
    auto dnsc_erase_expired_entries() -> void;

    /// \since 4.2.9
    auto dnsc_clear_cache() -> void;
} // namespace irods::experimental::net

#endif // IRODS_DNS_CACHE_HPP


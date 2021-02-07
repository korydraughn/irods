#ifndef IRODS_DNS_CACHE_HPP
#define IRODS_DNS_CACHE_HPP

/// \file

#include <string>
#include <string_view>
#include <optional>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// In order to store the results of getaddrinfo() in shared memory,
// the addrinfo structure will need to be flatten or use offset_ptr<T>'s
// due to the member pointers.

namespace irods::experimental::net
{
    /// Initializes the dns cache.
    ///
    /// \since 4.2.9
    auto dnsc_init() -> void;

    /// Initializes the dns cache.
    ///
    /// \since 4.2.9
    auto dnsc_insert_or_assign(const std::string_view _hostname, const addrinfo& _info) -> bool;

    /// Initializes the dns cache.
    ///
    /// \since 4.2.9
    auto dnsc_lookup() -> std::optional<addrinfo*>;

    /// Initializes the dns cache.
    ///
    /// \since 4.2.9
    auto dnsc_erase() -> void;

    /// Initializes the dns cache.
    ///
    /// \since 4.2.9
    auto dnsc_erase_expired_entries() -> void;

    /// Initializes the dns cache.
    ///
    /// \since 4.2.9
    auto dnsc_clear_cache() -> void;
} // namespace irods::experimental::net

#endif // IRODS_DNS_CACHE_HPP


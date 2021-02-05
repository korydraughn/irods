#ifndef IRODS_HOSTNAME_CACHE_HPP
#define IRODS_HOSTNAME_CACHE_HPP

/// \file

#include <chrono>
#include <string>
#include <string_view>
#include <optional>

namespace irods::experimental::net
{
    /// Initializes the hostname cache.
    ///
    /// This function should only be called on startup of the server.
    ///
    /// \since 4.2.9
    auto hnc_init() -> void;

    /// Cleans up any resources created via hnc_init().
    ///
    /// This function must be called from the same process that called hnc_init().
    ///
    /// \since 4.2.9
    auto hnc_deinit() -> void;

    /// Erases all hostname entries from the hostname cache.
    ///
    /// \since 4.2.9
    auto hnc_clear_cache() -> void;

    /// Inserts a new mapping or updates an existing mapping within the hostname cache.
    ///
    /// \param[in] _hostname      The key that will be mapped to \p _alias.
    /// \param[in] _alias         The value that will be mapped to \p _hostname.
    /// \param[in] _expires_after The number of seconds from the time of insertion before
    ///                           the entry becomes invalid.
    ///
    /// \return A boolean value.
    /// \retval true  If a new entry was inserted.
    /// \retval false If an existing entry was updated.
    ///
    /// \since 4.2.9
    auto hnc_insert_or_assign(const std::string_view _hostname,
                              const std::string_view _alias,
                              std::chrono::seconds _expires_after) -> bool;

    /// Removes an entry from the hostname cache.
    ///
    /// \param[in] _hostname The key associated with the entry to remove.
    ///
    /// \since 4.2.9
    auto hnc_erase(const std::string_view _hostname) -> void;

    /// Removes all expired entries from the hostname cache.
    ///
    /// \since 4.2.9
    auto hnc_erase_expired_entries() -> void;

    /// Returns a hostname alias for \p _hostname if available.
    ///
    /// \param[in] _hostname The hostname to find an alias for.
    ///
    /// \return An optional string.
    /// \retval std::string  If the an alias was found.
    /// \retval std::nullopt Otherwise.
    ///
    /// \since 4.2.9
    auto hnc_lookup(const std::string_view _hostname) -> std::optional<std::string>;
} // namespace irods::experimental::net

#endif // IRODS_HOSTNAME_CACHE_HPP


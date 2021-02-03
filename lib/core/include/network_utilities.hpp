#ifndef IRODS_NETWORK_UTILITIES_HPP
#define IRODS_NETWORK_UTILITIES_HPP

/// \file

#include <string>
#include <string_view>
#include <optional>

namespace irods
{
    /// Initializes the hostname cache.
    ///
    /// This function should only be called on startup of the server.
    ///
    /// \since 4.2.9
    auto init_hostname_cache() -> void;

    /// Cleans up any resources created via init_hostname_cache().
    ///
    /// This function is provided for test purposes. It should not be called by any production code.
    ///
    /// \since 4.2.9
    auto deinit_hostname_cache() -> void;

    /// Returns the longest hostname alias for \p _hostname.
    ///
    /// \param[in] _hostname     The hostname to find an alias for. If "localhost" is passed,
    ///                          then the first entry with an address_type of "local" will be
    ///                          searched.
    /// \param[in] _hosts_config A string containing JSON matching the format of the hosts_config.json
    ///                          file. If \p _hosts_config is empty, the hosts_config.json file will be
    ///                          used if available.
    ///
    /// \return An optional string.
    /// \retval std::string  If the an alias was found.
    /// \retval std::nullopt Otherwise.
    ///
    /// \since 4.2.9
    auto get_hostname_from_cache(const std::string_view _hostname, const std::string_view _hosts_config = {})
        -> std::optional<std::string>;
} // namespace irods

#endif // IRODS_NETWORK_UTILITIES_HPP


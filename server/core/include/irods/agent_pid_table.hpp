#ifndef IRODS_AGENT_PID_TABLE_HPP
#define IRODS_AGENT_PID_TABLE_HPP

/// \file

#include <ctime>
#include <string_view>
#include <vector>

#include <sys/types.h>

namespace irods::experimental::agent_pid_table
{
    /// TODO
    ///
    /// \since 5.0.0
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init)
    struct agent_pid_info
    {
        pid_t pid;
        std::time_t created_at;
        char client_addr[40]; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
        char client_username[64]; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
        char client_zone[64]; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
    }; // struct agent_pid_info

    /// Initializes the PID table.
    ///
    /// This function should only be called on startup of the server.
    ///
    /// \param[in] _shm_name The name of the shared memory to create.
    /// \param[in] _count    TODO
    ///
    /// \since 5.0.0
    auto init(const std::string_view _shm_name = "irods_agent_pid_table", std::size_t _count = 2000) -> void;

    /// Cleans up any resources created via init().
    ///
    /// This function must be called from the same process that called init().
    ///
    /// \since 5.0.0
    auto deinit() noexcept -> void;

    /// TODO Inserts a new mapping or updates an existing mapping within the DNS cache.
    ///
    /// \param[in] _info The value that will be mapped to \p _key.
    ///
    /// \since 5.0.0
    auto insert(const agent_pid_info& _info) -> void;

    /// TODO Returns a heap allocated addrinfo object for \p _key if available.
    ///
    /// Successful lookups do not extend the lifetime of the cached entry.
    ///
    /// \param[in] _key The key value of the addrinfo to search for.
    ///
    /// \return A unique_ptr to an addrinfo.
    /// \retval addrinfo The element with a key equivalent to \p _key.
    /// \retval nullptr  Otherwise.
    ///
    /// \since 5.0.0
    auto copy_table() -> std::vector<agent_pid_info>;

    /// TODO Removes an entry from the agent pid table.
    ///
    /// \param[in] _pid The PID of the entry to remove.
    ///
    /// \since 5.0.0
    auto erase(const pid_t _pid) -> void;

    /// TODO Erases all entries from the agent pid table.
    ///
    /// \since 5.0.0
    auto clear() -> void;

    /// TODO Returns the number of entries in the agent pid table.
    ///
    /// \since 5.0.0
    auto size() -> std::size_t;
} // namespace irods::experimental::agent_pid_table

#endif // IRODS_AGENT_PID_TABLE_HPP

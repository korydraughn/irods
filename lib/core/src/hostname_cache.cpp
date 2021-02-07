#include "hostname_cache.hpp"

#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/sync/named_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include <fmt/format.h>

#include <cstring>

#include <sys/types.h>
#include <unistd.h>

namespace
{
    namespace bi = boost::interprocess;

    struct alias;

    // clang-format off
    using segment_manager_type = bi::managed_shared_memory::segment_manager;
    using void_allocator_type  = bi::allocator<void, segment_manager_type>;
    using char_allocator_type  = bi::allocator<char, segment_manager_type>;
    using key_type             = bi::basic_string<char, std::char_traits<char>, char_allocator_type>;
    using mapped_type          = alias;
    using value_type           = std::pair<const key_type, mapped_type>;
    using value_allocator_type = bi::allocator<value_type, segment_manager_type>;
    using map_type             = bi::map<key_type, mapped_type, std::less<key_type>, value_allocator_type>;
    using clock_type           = std::chrono::system_clock;
    // clang-format on

    // The value type mapped to a specific hostname key.
    struct alias
    {
        alias(const std::string_view _hostname,
              std::int64_t _expiration,
              std::int64_t _expires_after)
            : hostname{}
            , expiration{_expiration}
            , expires_after{_expires_after}
        {
            std::strncpy(hostname, _hostname.data(), _hostname.size());
        }

        char hostname[256];         // FQDN are 253 characters long.
        std::int64_t expiration;    // The seconds since epoch representing when this alias expires.
        std::int64_t expires_after; // The number of seconds to apply to expiration after successful lookup.
    }; // struct alias

    //
    // Global Variables
    //

    // clang-format off
    // The following variables define the names of shared memory objects and other properties.
    const char* const g_segment_name = "irods_hostname_cache";
    const std::size_t g_segment_size = 1'000'000; // TODO This could be a knob.
    const char* const g_mutex_name   = "irods_hostname_cache_mutex";
    const char* const g_map_name     = "irods_hostname_cache_map";
    // clang-format on

    // A flag used to indicate whether the hostname cache has been initialized or not.
    bool g_initialized = false;

    // On initialization, holds the PID of the process that initialized the hostname cache.
    // This ensures that only the process that initialized the system can deinitialize it.
    pid_t g_owner_pid;

    // The following are pointers to the shared memory objects and allocator.
    // Allocating on the heap allows us to know when the hostname cache is constructed/destructed.
    std::unique_ptr<bi::managed_shared_memory> g_segment;
    std::unique_ptr<void_allocator_type> g_allocator;
    std::unique_ptr<bi::named_mutex> g_mutex;
    map_type* g_map;
} // anonymous namespace

namespace irods::experimental::net
{
    auto hnc_init() -> void
    {
        if (g_initialized) {
            return;
        }

        g_initialized = true;

        bi::named_mutex::remove(g_mutex_name);
        bi::shared_memory_object::remove(g_segment_name);

        g_owner_pid = getpid();
        g_segment = std::make_unique<bi::managed_shared_memory>(bi::create_only, g_segment_name, g_segment_size);
        g_allocator = std::make_unique<void_allocator_type>(g_segment->get_segment_manager());
        g_mutex = std::make_unique<bi::named_mutex>(bi::create_only, g_mutex_name);
        g_map = g_segment->construct<map_type>(g_map_name)(std::less<key_type>{}, *g_allocator);
    } // hnc_init

    auto hnc_deinit() -> void
    {
        if (!g_initialized || getpid() != g_owner_pid) {
            return;
        }

        try {
            // clang-format off
            if (g_map)       { g_map = nullptr; }
            if (g_mutex)     { g_mutex.reset(); }
            if (g_allocator) { g_allocator.reset(); }
            if (g_segment)   { g_segment.reset(); }
            // clang-format on

            bi::named_mutex::remove(g_mutex_name);
            bi::shared_memory_object::remove(g_segment_name);
        }
        catch (...) {}
    } // hnc_deinit

    auto hnc_clear_cache() -> void
    {
        bi::scoped_lock lk{*g_mutex};
        g_map->clear();
    } // hnc_clear_cache

    auto hnc_insert_or_assign(const std::string_view _hostname,
                              const std::string_view _alias,
                              std::chrono::seconds _expires_after) -> bool
    {
        bi::scoped_lock lk{*g_mutex};
        key_type key{_hostname.data(), *g_allocator};
        const auto expiration = clock_type::now() + _expires_after;
        mapped_type value{_alias, expiration.time_since_epoch().count(), _expires_after.count()};
        const auto [iter, inserted] = g_map->insert_or_assign(key, value);
        return inserted;
    } // hnc_insert_or_assign

    auto hnc_erase(const std::string_view _hostname) -> void
    {
        bi::scoped_lock lk{*g_mutex};
        g_map->erase(key_type{_hostname.data(), *g_allocator});
    } // hnc_erase

    auto hnc_erase_expired_entries() -> void
    {
        bi::scoped_lock lk{*g_mutex};

        const auto p = [now = clock_type::now()](const value_type& _v) {
            return now.time_since_epoch().count() >= _v.second.expiration;
        };

        g_map->erase(std::remove_if(g_map->begin(), g_map->end(), p), g_map->end());
    } // hnc_erase_expired_entries

    auto hnc_lookup(const std::string_view _hostname) -> std::optional<std::string>
    {
        bi::scoped_lock lk{*g_mutex};

        if (auto iter = g_map->find(key_type{_hostname.data(), *g_allocator}); iter != g_map->end()) {
            if (clock_type::now().time_since_epoch().count() < iter->second.expiration) {
                iter->second.expiration += iter->second.expires_after;
                return iter->second.hostname;
            }
        }

        return std::nullopt;
    } // hnc_lookup
} // namespace irods::experimental::net


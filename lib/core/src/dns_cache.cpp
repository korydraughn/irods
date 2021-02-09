#include "dns_cache.hpp"

#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/sync/named_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include <cstring>
#include <utility>
#include <algorithm>

#include <sys/types.h>
#include <unistd.h>

namespace
{
    namespace bi = boost::interprocess;

    using std::chrono::duration_cast;
    using std::chrono::seconds;

    struct address_info;

    // clang-format off
    using segment_manager_type = bi::managed_shared_memory::segment_manager;
    using void_allocator_type  = bi::allocator<void, segment_manager_type>;
    using char_allocator_type  = bi::allocator<char, segment_manager_type>;
    using key_type             = bi::basic_string<char, std::char_traits<char>, char_allocator_type>;
    using mapped_type          = bi::offset_ptr<address_info>;
    using value_type           = std::pair<const key_type, mapped_type>;
    using value_allocator_type = bi::allocator<value_type, segment_manager_type>;
    using map_type             = bi::map<key_type, mapped_type, std::less<key_type>, value_allocator_type>;
    using clock_type           = std::chrono::system_clock;
    // clang-format on

    // The value type mapped to a specific hostname key.
    struct address_info
    {
        int flags;
        int family;
        int socktype;
        int protocol;
        socklen_t addrlen;
        bi::offset_ptr<sockaddr> addr;
        bi::offset_ptr<char> canonname;
        bi::offset_ptr<address_info> next;

        std::int64_t expiration;
        std::int64_t expires_after;
    }; // struct address_info

    //
    // Global Variables
    //

    // The following variables define the names of shared memory objects and other properties.
    std::string g_segment_name;
    std::size_t g_segment_size;
    std::string g_mutex_name;
    std::string g_map_name;

    // On initialization, holds the PID of the process that initialized the hostname cache.
    // This ensures that only the process that initialized the system can deinitialize it.
    pid_t g_owner_pid;

    // The following are pointers to the shared memory objects and allocator.
    // Allocating on the heap allows us to know when the hostname cache is constructed/destructed.
    std::unique_ptr<bi::managed_shared_memory> g_segment;
    std::unique_ptr<void_allocator_type> g_allocator;
    std::unique_ptr<bi::named_mutex> g_mutex;
    map_type* g_map;

    auto free_address_info(addrinfo* _p) -> void
    {
        for (addrinfo* current = _p, *prev = nullptr; current;) {
            if (current->ai_addr)      { std::free(current->ai_addr); }
            if (current->ai_canonname) { std::free(current->ai_canonname); }

            prev = current;
            current = current->ai_next;

            std::free(prev);
        }
    }

    auto current_timestamp_in_seconds() noexcept -> std::int64_t
    {
        return duration_cast<seconds>(clock_type::now().time_since_epoch()).count();
    }
} // anonymous namespace

namespace irods::experimental::net
{
    auto dnsc_init(const std::string_view _shm_name, std::size_t _shm_size) -> void
    {
        if (getpid() == g_owner_pid) {
            return;
        }

        g_segment_name = _shm_name.data();
        g_segment_size = _shm_size;
        g_mutex_name = g_segment_name + "_mutex";
        g_map_name = g_segment_name + "_map";

        bi::named_mutex::remove(g_mutex_name.data());
        bi::shared_memory_object::remove(g_segment_name.data());

        g_owner_pid = getpid();
        g_segment = std::make_unique<bi::managed_shared_memory>(bi::create_only, g_segment_name.data(), g_segment_size);
        g_allocator = std::make_unique<void_allocator_type>(g_segment->get_segment_manager());
        g_mutex = std::make_unique<bi::named_mutex>(bi::create_only, g_mutex_name.data());
        g_map = g_segment->construct<map_type>(g_map_name.data())(std::less<key_type>{}, *g_allocator);
    } // dnsc_init

    auto dnsc_deinit() -> void
    {
        if (getpid() != g_owner_pid) {
            return;
        }

        try {
            g_owner_pid = 0;

            // clang-format off
            if (g_map)       { g_map = nullptr; }
            if (g_mutex)     { g_mutex.reset(); }
            if (g_allocator) { g_allocator.reset(); }
            if (g_segment)   { g_segment.reset(); }
            // clang-format on

            bi::named_mutex::remove(g_mutex_name.data());
            bi::shared_memory_object::remove(g_segment_name.data());
        }
        catch (...) {}
    } // dnsc_deinit

    auto dnsc_insert_or_assign(const std::string_view _hostname,
                               const addrinfo& _info,
                               seconds _expires_after) -> bool
    {
        bi::scoped_lock lk{*g_mutex};

        bi::offset_ptr<address_info> first{};
        bi::offset_ptr<address_info> prev{};
        bi::offset_ptr<address_info> current{};

        for (const auto* p = &_info; p; p = p->ai_next) {
            current = static_cast<address_info*>(g_segment->allocate(sizeof(address_info)));

            std::memset(current.get(), 0, sizeof(address_info));

            // clang-format off
            current->flags         = p->ai_flags;
            current->family        = p->ai_family;
            current->socktype      = p->ai_socktype;
            current->protocol      = p->ai_protocol;
            current->addrlen       = p->ai_addrlen;
            current->addr          = nullptr;
            current->canonname     = nullptr;
            current->next          = nullptr;
            current->expiration    = 0;
            current->expires_after = _expires_after.count();
            // clang-format on

            if (p->ai_addr) {
                current->addr = static_cast<sockaddr*>(g_segment->allocate(sizeof(sockaddr)));
                std::memcpy(current->addr.get(), p->ai_addr, sizeof(sockaddr));
            }

            if (p->ai_canonname) {
                const auto size = std::strlen(p->ai_canonname);
                current->canonname = static_cast<char*>(g_segment->allocate(sizeof(char) * size + 1));
                std::strncpy(current->canonname.get(), p->ai_canonname, size);
                current->canonname[size] = 0;
            }

            if (!prev) {
                first = current;
            }
            else {
                prev->next = current;
            }

            prev = current;
        }

        key_type key{_hostname.data(), *g_allocator};
        first->expiration = duration_cast<seconds>((clock_type::now() + _expires_after).time_since_epoch()).count();
        const auto [iter, inserted] = g_map->insert_or_assign(std::move(key), std::move(first));

        return inserted;
    } // dnsc_insert_or_assign

    auto dnsc_erase(const std::string_view _hostname) -> void
    {
        bi::scoped_lock lk{*g_mutex};
        g_map->erase(key_type{_hostname.data(), *g_allocator});
    } // dnsc_erase

    auto dnsc_lookup(const std::string_view _hostname) -> std::unique_ptr<addrinfo, address_info_deleter_type>
    {
        bi::scoped_lock lk{*g_mutex};

        if (auto iter = g_map->find(key_type{_hostname.data(), *g_allocator}); iter != g_map->end()) {
            if (auto& [k, v] = *iter; current_timestamp_in_seconds() < v->expiration) {
                addrinfo* current{};
                addrinfo* first{};
                addrinfo* prev{};

                for (auto p = v; p; p = p->next) {
                    current = static_cast<addrinfo*>(std::malloc(sizeof(addrinfo)));

                    std::memset(current, 0, sizeof(addrinfo));

                    // clang-format off
                    current->ai_flags     = p->flags;
                    current->ai_family    = p->family;
                    current->ai_socktype  = p->socktype;
                    current->ai_protocol  = p->protocol;
                    current->ai_addrlen   = p->addrlen;
                    current->ai_addr      = nullptr;
                    current->ai_canonname = nullptr;
                    current->ai_next      = nullptr;
                    // clang-format on

                    if (p->addr) {
                        current->ai_addr = static_cast<sockaddr*>(std::malloc(sizeof(sockaddr)));
                        std::memcpy(current->ai_addr, p->addr.get(), sizeof(sockaddr));
                    }

                    if (p->canonname) {
                        const auto size = std::strlen(p->canonname.get());
                        current->ai_canonname = static_cast<char*>(std::malloc(sizeof(char) * size + 1));
                        std::strncpy(current->ai_canonname, p->canonname.get(), size);
                        current->ai_canonname[size] = 0;
                    }

                    if (!prev) {
                        first = current;
                    }
                    else {
                        prev->ai_next = current;
                    }

                    prev = current;
                }

                v->expiration = current_timestamp_in_seconds() + v->expires_after;

                return {first, free_address_info};
            }
        }

        return {nullptr, nullptr};
    } // dnsc_lookup

    auto dnsc_erase_expired_entries() -> void
    {
        bi::scoped_lock lk{*g_mutex};

        const auto now = current_timestamp_in_seconds();

        for (auto iter = g_map->begin(), end = g_map->end(); iter != end;) {
            if (now >= iter->second->expiration) {
                bi::offset_ptr<address_info> current;
                bi::offset_ptr<address_info> prev;

                for (current = iter->second; current;) {
                    if (current->addr) {
                        g_segment->deallocate(current->addr.get());
                    }

                    if (current->canonname) {
                        g_segment->deallocate(current->canonname.get());
                    }

                    prev = current;
                    current = current->next;

                    g_segment->deallocate(prev.get());

                    iter = g_map->erase(iter);
                }
            }
            else {
                ++iter;
            }
        }
    } // dnsc_erase_expired_entries

    auto dnsc_clear_cache() -> void
    {
        bi::scoped_lock lk{*g_mutex};

        for (auto& [k, v] : *g_map) {
            bi::offset_ptr<address_info> current;
            bi::offset_ptr<address_info> prev;

            for (current = v; current;) {
                if (current->addr) {
                    g_segment->deallocate(current->addr.get());
                }

                if (current->canonname) {
                    g_segment->deallocate(current->canonname.get());
                }

                prev = current;
                current = current->next;

                g_segment->deallocate(prev.get());
            }
        }

        g_map->clear();
    } // dnsc_clear_cache
} // namespace irods::experimental::net


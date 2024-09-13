#include "irods/agent_pid_table.hpp"

#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/sync/named_sharable_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <boost/interprocess/sync/sharable_lock.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>

#include <unistd.h>

namespace
{
    // clang-format off
    namespace bi  = boost::interprocess;
    namespace apt = irods::experimental::agent_pid_table;
    // clang-format on

    // clang-format off
    using segment_manager_type = bi::managed_shared_memory::segment_manager;
    using shmem_allocator_type = bi::allocator<apt::agent_pid_info, segment_manager_type>;
    using vector_type          = bi::vector<apt::agent_pid_info, shmem_allocator_type>;
    // clang-format on

    //
    // Global Variables
    //

    // The following variables define the names of shared memory objects and other properties.
    std::string g_segment_name; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    std::size_t g_segment_size; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    std::string g_mutex_name; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    // On initialization, holds the PID of the process that initialized the agent pid table.
    // This ensures that only the process that initialized the system can deinitialize it.
    pid_t g_owner_pid; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    // The following are pointers to the shared memory objects and allocator.
    // Allocating on the heap allows us to know when the agent pid table is constructed/destructed.
    std::unique_ptr<bi::managed_shared_memory> g_segment; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    std::unique_ptr<shmem_allocator_type> g_allocator; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    std::unique_ptr<bi::named_sharable_mutex> g_mutex; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    vector_type* g_pids; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
} // anonymous namespace

namespace irods::experimental::agent_pid_table
{
    auto init(const std::string_view _shm_name, std::size_t _count) -> void
    {
        if (getpid() == g_owner_pid) {
            return;
        }

        using std::chrono::seconds;
        using std::chrono::system_clock;

        const auto now = std::chrono::duration_cast<seconds>(system_clock::now().time_since_epoch()).count();

        g_segment_name = fmt::format("{}_{}_{}", _shm_name, getpid(), now);
        g_segment_size = sizeof(agent_pid_info) * _count;
        g_mutex_name = g_segment_name + "_mutex";

        bi::named_sharable_mutex::remove(g_mutex_name.data());
        bi::shared_memory_object::remove(g_segment_name.data());

        g_owner_pid = getpid();
        g_segment = std::make_unique<bi::managed_shared_memory>(bi::create_only, g_segment_name.data(), g_segment_size);
        g_allocator = std::make_unique<shmem_allocator_type>(g_segment->get_segment_manager());
        g_mutex = std::make_unique<bi::named_sharable_mutex>(bi::create_only, g_mutex_name.data());
        g_pids = g_segment->construct<vector_type>(bi::anonymous_instance)(*g_allocator);
    } // init

    auto deinit() noexcept -> void
    {
        if (getpid() != g_owner_pid) {
            return;
        }

        try {
            g_owner_pid = 0;

            if (g_segment && g_pids) {
                g_segment->destroy_ptr(g_pids);
                g_pids = nullptr;
            }

            // clang-format off
            if (g_mutex)     { g_mutex.reset(); }
            if (g_allocator) { g_allocator.reset(); }
            if (g_segment)   { g_segment.reset(); }
            // clang-format on

            bi::named_sharable_mutex::remove(g_mutex_name.data());
            bi::shared_memory_object::remove(g_segment_name.data());
        }
        catch (...) {}
    } // deinit

    auto shared_memory_name() -> std::string_view
    {
        return g_segment_name;
    } // shared_memory_name

    auto insert(const agent_pid_info& _info) -> void
    {
        bi::scoped_lock lk{*g_mutex};
        g_pids->push_back(_info);
    } // insert

    auto copy_table() -> std::vector<agent_pid_info>
    {
        bi::sharable_lock lk{*g_mutex};
        return {std::begin(*g_pids), std::end(*g_pids)};
    } // copy_table

    auto erase(const pid_t _pid) -> void
    {
        bi::scoped_lock lk{*g_mutex};
        auto e = std::end(*g_pids);
        auto iter = std::remove_if(std::begin(*g_pids), e, [_pid](const agent_pid_info& _info) {
            return _info.pid == _pid;
        });
        g_pids->erase(iter, e);
    } // erase

    auto clear() -> void
    {
        bi::scoped_lock lk{*g_mutex};
        g_pids->clear();
    } // clear

    auto size() -> std::size_t
    {
        bi::sharable_lock lk{*g_mutex};
        return g_pids->size();
    } // size
} // namespace irods::experimental::agent_pid_table

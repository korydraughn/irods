#include "irods/irods_server_state.hpp"

#include "irods/rodsErrorTable.h"
#include "irods/shared_memory_object.hpp"

#include <fmt/format.h>

#include <memory>

namespace ipc = irods::experimental::interprocess;

using ipc_object_type = ipc::shared_memory_object<irods::server_state::server_state>;

std::unique_ptr<ipc_object_type> g_state;

const char* const g_shared_memory_name = "irods_server_state";

namespace irods::server_state
{
    auto init(bool _init_shared_memory) -> void 
    {
        if (_init_shared_memory) {
            g_state.reset(new ipc_object_type{g_shared_memory_name});

            // Due to the implementation of shared_memory_object, we have to manually
            // set the value. Relying on the constructor to do this is incorrect because
            // shared_memory_object only initializes the object when allocating shared
            // memory for the first time. If the shared memory exists, the values passed
            // to the shared_memory_object will be ignored.
            g_state->atomic_exec([](server_state& _value) {
                _value = server_state::running;
            });
        }
        else {
            g_state.reset(new ipc_object_type{ipc::no_init, g_shared_memory_name});
        }
    } // init

    auto get_state() -> server_state 
    {
        return g_state->atomic_exec([](server_state _value) {
            return _value;
        });
    } // get_state

    auto set_state(server_state _new_state) -> irods::error 
    {
        return g_state->atomic_exec([_new_state](server_state& _value) {
            _value = _new_state;
            return SUCCESS();
        });
    } // set_state

    auto to_string(server_state _state) -> std::string_view
    {
        switch (_state) {
            // clang-format off
            case server_state::running: return "server_state_running";
            case server_state::paused:  return "server_state_paused";
            case server_state::stopped: return "server_state_stopped";
            case server_state::exited:  return "server_state_exited";
            // clang-format on
        }

        throw std::invalid_argument{"Server state not supported"};
    } // to_string
} // namespace irods::server_state


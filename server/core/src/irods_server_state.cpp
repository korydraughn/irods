#include "irods/irods_server_state.hpp"

#include "irods/rodsErrorTable.h"

#include <fmt/format.h>

namespace irods
{
    // clang-format off
    const std::string server_state::RUNNING = "server_state_running";
    const std::string server_state::PAUSED  = "server_state_paused";
    const std::string server_state::STOPPED = "server_state_stopped";
    const std::string server_state::EXITED  = "server_state_exited";

    const server_state::int_type server_state::INT_RUNNING = 0;
    const server_state::int_type server_state::INT_PAUSED  = 1;
    const server_state::int_type server_state::INT_STOPPED = 2;
    const server_state::int_type server_state::INT_EXITED  = 3;
    // clang-format on

    server_state& server_state::instance()
    {
        static server_state instance_;
        return instance_;
    }

    const std::string& server_state::operator()()
    {
        return to_string(ipc_state_.atomic_exec([](int_type _value) {
            return _value;
        }));
    }

    error server_state::operator()(const std::string& _new_state)
    {
        const auto new_ipc_state = to_int(_new_state);

        return ipc_state_.atomic_exec([new_ipc_state, &_new_state](int_type& _value) {
            if (new_ipc_state < 0 || new_ipc_state > 3) {
                auto msg = fmt::format("Invalid state [{}]", _new_state);
                return ERROR(SYS_INVALID_INPUT_PARAM, std::move(msg));
            }

            _value = new_ipc_state;

            return SUCCESS();
        });
    }

    server_state::server_state()
        : ipc_state_{"irods_server_state", to_int(RUNNING)}
        , state_{RUNNING}
    {
    }

    server_state::int_type server_state::to_int(const std::string_view _state)
    {
        if (_state == RUNNING) { return 0; }
        if (_state == PAUSED)  { return 1; }
        if (_state == STOPPED) { return 2; }
        if (_state == EXITED)  { return 3; }

        throw std::invalid_argument{fmt::format("No server state mapped to string: {}", _state)};
    }

    const std::string& server_state::to_string(server_state::int_type _state)
    {
        switch (_state) {
            case 0: return RUNNING;
            case 1: return PAUSED;
            case 2: return STOPPED;
            case 3: return EXITED;
        }

        throw std::invalid_argument{fmt::format("No server state mapped to integer: {}", _state)};
    }
} // namespace irods


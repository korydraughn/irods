#include "irods/irods_server_state.hpp"

#include "irods/rodsErrorTable.h"

namespace irods
{
    const std::string server_state::RUNNING = "server_state_running";
    const std::string server_state::PAUSED  = "server_state_paused";
    const std::string server_state::STOPPED = "server_state_stopped";
    const std::string server_state::EXITED  = "server_state_exited";

    server_state& server_state::instance()
    {
        static server_state instance_;
        return instance_;
    }

    const std::string& server_state::operator()()
    {
        std::lock_guard lock{mutex_};
        return state_;
    }

    error server_state::operator()(const std::string& _new_state)
    {
        std::lock_guard lock{mutex_};

        if (RUNNING != _new_state &&
            PAUSED  != _new_state &&
            STOPPED != _new_state &&
            EXITED  != _new_state)
        {
            std::string msg("invalid state [");
            msg += _new_state;
            msg += "]";
            return ERROR(SYS_INVALID_INPUT_PARAM, msg);
        }

        state_ = _new_state;

        return SUCCESS();
    }

    server_state::server_state()
        : mutex_{}
        , state_{RUNNING}
    {
    }
} // namespace irods


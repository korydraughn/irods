#ifndef IRODS_SERVER_STATE_HPP
#define IRODS_SERVER_STATE_HPP

#include "irods/irods_error.hpp"

#include <string>
#include <mutex>

namespace irods
{
    class server_state
    {
    public:
        static const std::string RUNNING;
        static const std::string PAUSED;
        static const std::string STOPPED;
        static const std::string EXITED;

        static server_state& instance();

        const std::string& operator()();

        error operator()(const std::string& _new_state);

    private:
        server_state();
        server_state(const server_state&) = delete;
        server_state& operator=(const server_state&) = delete;

        std::mutex mutex_;
        std::string state_;
    }; // class server_state
} // namespace irods

#endif // IRODS_SERVER_STATE_HPP


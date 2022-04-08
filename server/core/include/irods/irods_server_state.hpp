#ifndef IRODS_SERVER_STATE_HPP
#define IRODS_SERVER_STATE_HPP

#include "irods/irods_error.hpp"
#include "irods/shared_memory_object.hpp"

#include <cstddef>
#include <string>
#include <string_view>

namespace irods
{
    class server_state
    {
    public:
        using int_type = std::int8_t;

        static const std::string RUNNING;
        static const std::string PAUSED;
        static const std::string STOPPED;
        static const std::string EXITED;

        static const int_type INT_RUNNING;
        static const int_type INT_PAUSED;
        static const int_type INT_STOPPED;
        static const int_type INT_EXITED;

        static server_state& instance();

        const std::string& operator()();

        error operator()(const std::string& _new_state);

    private:
        server_state();
        server_state(const server_state&) = delete;
        server_state& operator=(const server_state&) = delete;

        int_type to_int(const std::string_view _state);
        const std::string& to_string(int_type _state);

        experimental::interprocess::shared_memory_object<int_type> ipc_state_;
        std::string state_;
    }; // class server_state
} // namespace irods

#endif // IRODS_SERVER_STATE_HPP


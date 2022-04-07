#ifndef IRODS_SERVER_CONTROL_PLANE_HPP
#define IRODS_SERVER_CONTROL_PLANE_HPP

/// \file

namespace irods
{
    inline const std::string SERVER_CONTROL_OPTION_KW( "server_control_option" );
    inline const std::string SERVER_CONTROL_HOST_KW( "server_control_host" );
    inline const std::string SERVER_CONTROL_FORCE_AFTER_KW( "server_control_force_after" );
    inline const std::string SERVER_CONTROL_WAIT_FOREVER_KW( "server_control_wait_forever" );

    inline const std::string SERVER_CONTROL_SHUTDOWN( "server_control_shutdown" );
    inline const std::string SERVER_CONTROL_PAUSE( "server_control_pause" );
    inline const std::string SERVER_CONTROL_RESUME( "server_control_resume" );
    inline const std::string SERVER_CONTROL_STATUS( "server_control_status" );
    inline const std::string SERVER_CONTROL_PING( "server_control_ping" );

    inline const std::string SERVER_CONTROL_ALL_OPT( "all" );
    inline const std::string SERVER_CONTROL_HOSTS_OPT( "hosts" );
    inline const std::string SERVER_CONTROL_SUCCESS( "server_control_success" );

    inline const std::string SERVER_PAUSED_ERROR( "The server is Paused, resume before issuing any other commands" );

    // This is a hand-chosen polling time for the control plane.
    inline const std::size_t SERVER_CONTROL_POLLING_TIME_MILLI_SEC = 500;

    // Derived from above - used to wait for the server to shut down or resume.
    inline const std::size_t SERVER_CONTROL_FWD_SLEEP_TIME_MILLI_SEC = SERVER_CONTROL_POLLING_TIME_MILLI_SEC / 4.0;
} // namespace irods

#endif // IRODS_SERVER_CONTROL_PLANE_HPP


#ifndef IRODS_UDT_SERVER_HPP
#define IRODS_UDT_SERVER_HPP

#include <udt.h>

namespace irods::experimental
{
    class udt_server
    {
    public:
        explicit udt_server(int _port = 9000);

        udt_server(const udt_server&) = delete;
        udt_server& operator=(const udt_server&) = delete;

        void stop();

    private:
        UDTSOCKET server_socket_;

    };
} // namespace irods::experimental

#endif // IRODS_UDT_SERVER_HPP


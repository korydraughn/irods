#ifndef IRODS_UDT_SERVER_HPP
#define IRODS_UDT_SERVER_HPP

#include "thread_pool.hpp"

#include <udt/udt.h>
#include <arpa/inet.h>

#include <atomic>

namespace irods::experimental
{
    class udt_server
    {
    public:
        explicit udt_server(int _port = 9000, int _max_pending_connections = 10);

        udt_server(const udt_server&) = delete;
        udt_server& operator=(const udt_server&) = delete;

        ~udt_server();

        void start();
        void stop() noexcept;

    private:
        void bind_and_listen();

        sockaddr_in sock_addr_;
        UDTSOCKET server_socket_;
        std::atomic<bool> stop_;
        int port_;
        int max_pending_conns_;
        irods::thread_pool thread_pool_;
    };
} // namespace irods::experimental

#endif // IRODS_UDT_SERVER_HPP


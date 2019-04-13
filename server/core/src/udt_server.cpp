#include "udt_server.hpp"

#include "irods_logger.hpp"
#include "thread_pool.hpp"

#include <memory>
#include <string>
#include <stdexcept>

namespace irods::experimental
{
    udt_server::udt_server(int _port, int _max_pending_connections)
        : sock_addr_{}
        , server_socket_{UDT::socket(AF_INET, SOCK_STREAM, 0)}
        , stop_{}
        , port_{_port}
        , max_pending_conns_{_max_pending_connections}
    {
        sock_addr_.sin_family = AF_INET;
        sock_addr_.sin_port = htons(port_);
        sock_addr_.sin_addr.s_addr = INADDR_ANY;
    }

    udt_server::~udt_server()
    {
        stop();
        UDT::close(server_socket_);
        using log = irods::experimental::log;
        log::server::info("UDT server has stopped.");
    }

    void udt_server::start()
    {
        using log = irods::experimental::log;

        bind_and_listen();

        //std::string accept_msg = "Waiting for UDT client to connect on port ";
        //accept_msg += std::to_string(port_);
        //accept_msg += " ...";

        while (!stop_) {
            int name_length;
            auto client_info = std::make_shared<sockaddr_in>(); 
            auto ptr = reinterpret_cast<sockaddr*>(client_info.get());
            
            //log::server::info(accept_msg);

            auto client_socket = UDT::accept(server_socket_, ptr, &name_length);

            if (stop_) {
                if (UDT::INVALID_SOCK != client_socket) {
                    UDT::close(client_socket);
                }

                break;
            }

            if (UDT::INVALID_SOCK == client_socket) {
                continue;
            }

            // TODO The server must support the following operations:
            // - read
            // - write
            // - seek

            log::server::info({{"log_message", "New UDT client connected."},
                               {"udt_client_ip", inet_ntoa(client_info->sin_addr)},
                               {"udt_client_port", std::to_string(ntohs(client_info->sin_port))}});

            UDT::close(client_socket);
        }
    }

    void udt_server::stop() noexcept
    {
        stop_ = true;
    }

    void udt_server::bind_and_listen()
    {
        // Do not block on UDT::accept.
        bool block = false;
        UDT::setsockopt(server_socket_, 0, UDT_RCVSYN, &block, sizeof(bool));

        if (auto ptr = reinterpret_cast<sockaddr*>(&sock_addr_);
            UDT::ERROR == UDT::bind(server_socket_, ptr, sizeof(sockaddr_in)))
        {
            throw std::runtime_error{UDT::getlasterror().getErrorMessage()};
        }

        if (UDT::ERROR == UDT::listen(server_socket_, max_pending_conns_)) {
            throw std::runtime_error{UDT::getlasterror().getErrorMessage()};
        }
    }
} // namespace irods::experimental


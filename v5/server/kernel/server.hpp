#ifndef IRODS_SERVER_HPP
#define IRODS_SERVER_HPP

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace irods::v5
{
    class server
    {
    public:
        explicit server(boost::asio::io_context& _io_context);

        server(const server&) = delete;
        auto operator=(const server&) -> server& = delete;

    private:
        auto wait_for_signals() -> void;
        auto accept() -> void;
        auto read() -> void;
        auto write() -> void;

        boost::asio::io_context& io_context_;
        boost::asio::signal_set signals_;
        boost::asio::ip::tcp::acceptor acceptor_;
        boost::asio::ip::tcp::socket socket_;
    };
} // namespace irods::v5

#endif // IRODS_SERVER_HPP

#include "udt_server.hpp"

#include "irods_logger.hpp"

#include "json.hpp"

#include <memory>
#include <string>
#include <stdexcept>
#include <tuple>
#include <array>
#include <unordered_map>
#include <functional>

namespace
{
    enum class op_code : int
    {
        open = 1,
        close,
        read,
        write,
        seek
    };

    auto read_header(UDTSOCKET _socket) -> std::tuple<int, op_code, nlohmann::json> 
    {
        using log = irods::experimental::log;

        std::array<char, 2000> buf{};
        std::streamsize total_bytes_received = 0;

        while (total_bytes_received < static_cast<std::streamsize>(buf.size())) {
            char* buf_pos = &buf[0]+ total_bytes_received;
            const auto bytes_remaining = buf.size() - total_bytes_received;

            const auto bytes_received = UDT::recv(_socket, buf_pos, bytes_remaining, 0);

            if (UDT::ERROR == bytes_received) {
                log::server::error({{"log_message", "XXXX UDT server - recv."},
                                    {"total_bytes_received", std::to_string(total_bytes_received)}});
                return {UDT::getlasterror().getErrorCode(), {}, {}};
            }

            total_bytes_received += bytes_received;
            log::server::info("XXXX UDT server - total bytes received = " + std::to_string(total_bytes_received));
        }

        using json = nlohmann::json;

        try {
            auto json_data = json::parse(&buf[0]);
            return {0, op_code{json_data["op_code"].get<int>()}, json_data};
        }
        catch (const json::parse_error& e) {
        }
        
        return {-1, {}, {}};
    }

    namespace handler
    {
        auto open(UDTSOCKET _socket, const nlohmann::json& _json_req) -> void
        {
        }

        auto read(UDTSOCKET _socket, const nlohmann::json& _json_req) -> void
        {
        }

        auto write(UDTSOCKET _socket, const nlohmann::json& _json_req) -> void
        {
        }

        auto seek(UDTSOCKET _socket, const nlohmann::json& _json_req) -> void
        {
        }
    } // namespace handler

    using op_handler = std::function<void(UDTSOCKET _socket, const nlohmann::json&)>;

    const std::unordered_map<op_code, op_handler> op_handlers{
        {op_code::open,  handler::open},
        {op_code::read,  handler::read},
        {op_code::write, handler::write},
        {op_code::seek,  handler::seek}
    };
} // anonymous namespace

namespace irods::experimental
{
    udt_server::udt_server(int _port, int _max_pending_connections)
        : sock_addr_{}
        , server_socket_{UDT::socket(AF_INET, SOCK_STREAM, 0)}
        , stop_{}
        , port_{_port}
        , max_pending_conns_{_max_pending_connections}
        , thread_pool_{static_cast<int>(std::thread::hardware_concurrency())}
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

            // Block on the new socket.
            // This call is required because the accept socket has been
            // configured to be non-blocking and all sockets created through
            // the accept socket inherit the properties of it.
            bool block = true;
            UDT::setsockopt(client_socket, 0, UDT_RCVSYN, &block, sizeof(bool));

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
            // - open
            // - close
            // - read
            // - write
            // - seek

            log::server::info({{"log_message", "New UDT client connected."},
                               {"udt_client_ip", inet_ntoa(client_info->sin_addr)},
                               {"udt_client_port", std::to_string(ntohs(client_info->sin_port))}});

            irods::thread_pool::post(thread_pool_, [client_socket] {
                while (true) {
                    const auto [ec, op_code, req] = read_header(client_socket);

                    if (ec) {
                        // TODO Handle error. Send error response.
                        log::server::error("Could not read header.");
                        break;
                    }

                    log::server::info({{"json_request_data", req.dump()}});

                    if (op_code::close == op_code) {
                        break;
                    }

                    if (auto it = op_handlers.find(op_code); std::end(op_handlers) != it) {
                        (it->second)(client_socket, req);
                    }
                    else {
                        log::server::error({{"log_message", "Invalid Op Code."},
                                            {"op_code", std::to_string(static_cast<int>(op_code))}});
                    }
                }

                UDT::close(client_socket);

                log::server::info("UDT client connection closed.");
            });
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


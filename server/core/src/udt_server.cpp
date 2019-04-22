#include "udt_server.hpp"

#include "getRodsEnv.h"
#include "modDataObjMeta.h"

#include "transport/udt_transport_common.hpp"
#include "irods_logger.hpp"
#include "connection_pool.hpp"

#include "json.hpp"

#include <boost/filesystem.hpp>

#include <memory>
#include <string>
#include <stdexcept>
#include <tuple>
#include <array>
#include <unordered_map>
#include <functional>
#include <fstream>

namespace common = irods::experimental::io::common;

using op_code    = common::op_code;
using error_code = common::error_code;

namespace
{
    struct request_context
    {
        int data_id;
        std::string resource;
        std::string resource_hierarchy;
        std::string logical_path;
        std::string physical_path;
        int replica_number;
        std::fstream file;
        bool update_catalog;
        std::atomic<bool> close_connection;

        void reset()
        {
            data_id = -1;
            resource.clear();
            resource_hierarchy.clear();
            logical_path.clear();
            physical_path.clear();
            replica_number = -1;
            file.close();
            update_catalog = false;
            close_connection = false;
        }
    };

    thread_local request_context req_ctx;

    auto read_header(UDTSOCKET _socket) -> std::tuple<int, op_code, nlohmann::json> 
    {
        using log = irods::experimental::log;

        std::array<char, 2000> buf{};

        const auto received = common::receive_buffer(_socket, buf.data(), buf.size());

        log::server::info("XXXX UDT server - total bytes received = " + std::to_string(received));

        using json = nlohmann::json;

        try {
            auto json_data = json::parse(&buf[0]);
            return {0, op_code{json_data["op_code"].get<int>()}, json_data};
        }
        catch (const json::parse_error& e) {
        }

        return {-1, {}, {}};
    }

    auto send_error_response(UDTSOCKET _socket, error_code _ec, const std::string& _msg = "") -> void
    {
        using log = irods::experimental::log;
        using json = nlohmann::json;

        const auto msg = json{
            {"error_code", static_cast<int>(_ec)},
            {"error_message", _msg}
        }.dump();

        std::array<char, 2000> buf{};
        std::copy(std::begin(msg), std::end(msg), std::begin(buf));

        const auto sent = common::send_buffer(_socket, buf.data(), buf.size());

        log::server::info("XXXX UDT server - total bytes sent = " + std::to_string(sent));
    }

    namespace handler
    {
        auto open(UDTSOCKET _socket, const nlohmann::json& _req) -> void
        {
            using log = irods::experimental::log;

            if (_req.count("open_mode") == 0) {
                log::server::error("Missing argument [open_mode].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [open_mode]");
                return;
            }

            if (_req.count("data_id") == 0) {
                log::server::error("Missing argument [data_id].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [data_id]");
                return;
            }

            if (_req.count("resource") == 0) {
                log::server::error("Missing argument [resource].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [resource]");
                return;
            }

            if (_req.count("resource_hierarchy") == 0) {
                log::server::error("Missing argument [resource_hierarchy].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [resource_hierarchy]");
                return;
            }

            if (_req.count("replica_number") == 0) {
                log::server::error("Missing argument [replica_number].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [replica_number]");
                return;
            }

            if (_req.count("logical_path") == 0) {
                log::server::error("Missing argument [logical_path].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [logical_path]");
                return;
            }

            if (_req.count("physical_path") == 0) {
                log::server::error("Missing argument [physical_path].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [physical_path]");
                return;
            }

            req_ctx.data_id = _req["data_id"].get<int>();
            req_ctx.resource = _req["resource"].get<std::string>();
            req_ctx.resource_hierarchy = _req["resource_hierarchy"].get<std::string>();
            req_ctx.replica_number = _req["replica_number"].get<int>();
            req_ctx.logical_path = _req["logical_path"].get<std::string>();
            req_ctx.physical_path = _req["physical_path"].get<std::string>();

            // Open file.
            req_ctx.file.open(req_ctx.physical_path, common::to_openmode(_req["open_mode"].get<int>())); 

            if (!req_ctx.file) {
                send_error_response(_socket, error_code::file_open, "Could not open file");
                return;
            }

            send_error_response(_socket, error_code::ok);
        }

        auto update_catalog() -> void;

        auto close(UDTSOCKET _socket, const nlohmann::json& _req) -> void
        {
            using log = irods::experimental::log;

            log::server::info("Close connection request received. Shutting down connection ...");

            req_ctx.file.close();

            if (req_ctx.update_catalog) {
                update_catalog();
            }

            send_error_response(_socket, error_code::ok);
            req_ctx.close_connection = true;
        }

        auto read(UDTSOCKET _socket, const nlohmann::json& _req) -> void
        {
            send_error_response(_socket, error_code::ok);

            using log = irods::experimental::log;

            if (_req.count("buffer_size") == 0) {
                log::server::error("Missing argument [buffer_size].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [buffer_size]");
                return;
            }

            const auto buffer_size = _req["buffer_size"].get<std::streamsize>();
            std::array<char, 15> expected_size_buf{};
            std::array<char, 8192> buf{};
            std::streamsize total_sent = 0;

            while (total_sent < buffer_size) {
                if (!req_ctx.file) {
                    expected_size_buf= {'0'};
                    common::send_buffer(_socket, expected_size_buf.data(), expected_size_buf.size());
                    break;
                }

                req_ctx.file.read(&buf[0], std::min<std::streamsize>(buf.size(), buffer_size));

                const int count = req_ctx.file.gcount();
                const std::string expected_size = std::to_string(count);

                std::copy(std::begin(expected_size), std::end(expected_size), std::begin(expected_size_buf));

                common::send_buffer(_socket, expected_size_buf.data(), expected_size_buf.size());
                total_sent += common::send_buffer(_socket, buf.data(), count);
            }

            log::server::info("XXXX UDT server - total bytes sent = " + std::to_string(total_sent));
        }

        auto write(UDTSOCKET _socket, const nlohmann::json& _req) -> void
        {
            send_error_response(_socket, error_code::ok);

            using log = irods::experimental::log;

            if (_req.count("buffer_size") == 0) {
                log::server::error("Missing argument [buffer_size].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [buffer_size]");
                return;
            }

            const auto buffer_size = _req["buffer_size"].get<std::streamsize>();
            std::array<char, 8192> buf{};
            std::streamsize total_received = 0;

            while (total_received < buffer_size) {
                const auto received = common::receive_buffer(_socket, buf.data(), buf.size());

                req_ctx.file.write(buf.data(), received);
                req_ctx.update_catalog = true;

                total_received += received;
            }

            log::server::info("XXXX UDT server - total bytes received = " + std::to_string(total_received));

            send_error_response(_socket, error_code::ok);
        }

        auto seek(UDTSOCKET _socket, const nlohmann::json& _req) -> void
        {
            using log = irods::experimental::log;

            if (_req.count("seek_from") == 0) {
                log::server::error("Missing argument [seek_from].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [seek_from]");
                return;
            }

            if (_req.count("offset") == 0) {
                log::server::error("Missing argument [offset].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [offset]");
                return;
            }

            const auto seek_dir = common::to_seekdir(_req["seek_from"].get<int>());
            const auto offset = _req["offset"].get<int>();

            // XXX THESE TWO FUNCTIONS ARE UPDATING THE SAME FILE POINTER!!!
            // Should only use one of them.
            //req_ctx.file.seekg(offset, seek_dir);
            req_ctx.file.seekp(offset, seek_dir);

            // TODO Needs to return the new position in the file.
            send_error_response(_socket, error_code::ok);
        }

        auto update_catalog() -> void
        {
            using log = irods::experimental::log;

            dataObjInfo_t info{};

            info.dataId = req_ctx.data_id;
            std::strncpy(info.objPath, req_ctx.logical_path.c_str(), req_ctx.logical_path.size());
            std::strncpy(info.rescHier, req_ctx.resource_hierarchy.c_str(), req_ctx.resource_hierarchy.size());
            info.replNum = req_ctx.replica_number;

            namespace fs = boost::filesystem;

            const auto file_size = std::to_string(fs::file_size(req_ctx.physical_path));

            log::server::info("XXXXXXXXXXXXXX FINAL DATA OBJECT SIZE = " + file_size);

            keyValPair_t kvp{};

            addKeyVal(&kvp, DATA_SIZE_KW, file_size.c_str());

            rodsEnv env;

            if (const auto ec = getRodsEnv(&env); ec != 0) {
                log::server::error({{"log_message", "Could not get iRODS environment for data object size update."},
                                    {"logical_path", req_ctx.logical_path},
                                    {"error_code", std::to_string(ec)}});
                return;
            }

            irods::connection_pool cpool{1, env.rodsHost, env.rodsPort, env.rodsUserName, env.rodsZone, 600};
            modDataObjMeta_t input{&info, &kvp};
            auto conn = cpool.get_connection();

            if (const auto ec = rcModDataObjMeta(&static_cast<rcComm_t&>(conn), &input); ec != 0) {
                log::server::error({{"log_message", "Could not update data object size in catalog."},
                                    {"logical_path", req_ctx.logical_path},
                                    {"error_code", std::to_string(ec)}});
            }
        }
    } // namespace handler

    using op_handler = std::function<void(UDTSOCKET _socket, const nlohmann::json&)>;

    const std::unordered_map<op_code, op_handler> op_handlers{
        {op_code::open,  handler::open},
        {op_code::close, handler::close},
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

            log::server::info({{"log_message", "New UDT client connected."},
                               {"udt_client_ip", inet_ntoa(client_info->sin_addr)},
                               {"udt_client_port", std::to_string(ntohs(client_info->sin_port))}});

            irods::thread_pool::post(thread_pool_, [client_socket] {
                req_ctx.reset();

                while (!req_ctx.close_connection) {
                    const auto [ec, op_code, req] = read_header(client_socket);

                    if (ec) {
                        log::server::error("Could not read header.");
                        send_error_response(client_socket, error_code::bad_header, "Bad request header");
                        break;
                    }

                    log::server::info({{"XXXXX JSON_REQUEST_DATA", req.dump()}});

                    if (auto it = op_handlers.find(op_code); std::end(op_handlers) != it) {
                        (it->second)(client_socket, req);
                    }
                    else {
                        log::server::error({{"log_message", "Invalid Op Code."},
                                            {"op_code", std::to_string(static_cast<int>(op_code))}});
                    }

                    std::this_thread::yield();
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


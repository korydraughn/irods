#include "udt_server.hpp"

#include "getRodsEnv.h"
#include "modDataObjMeta.h"

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

    enum class error_code : int
    {
        ok = 0,
        bad_header = 1000,
        missing_arg,
        file_open,
        network_udt
    };

    struct request_context
    {
        int data_id;
        std::string resource;
        std::string resource_hierarchy;
        std::string logical_path;
        std::string physical_path;
        int replica_number;
        std::fstream file;
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
            close_connection = false;
        }
    };

    thread_local request_context req_ctx;

    auto read_header(UDTSOCKET _socket) -> std::tuple<int, op_code, nlohmann::json> 
    {
        using log = irods::experimental::log;

        std::array<char, 2000> buf{};
        std::streamsize total_bytes_received = 0;

        while (total_bytes_received < static_cast<std::streamsize>(buf.size())) {
            char* buf_pos = &buf[0] + total_bytes_received;
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

        std::streamsize total_bytes_sent = 0;

        while (total_bytes_sent < static_cast<std::streamsize>(buf.size())) {
            const auto* buf_pos = &buf[0] + total_bytes_sent;
            const auto bytes_remaining = buf.size() - total_bytes_sent;

            const auto bytes_sent = UDT::send(_socket, buf_pos, bytes_remaining, 0);

            if (UDT::ERROR == bytes_sent) {
                // TODO Should probably throw
            }

            total_bytes_sent += bytes_sent;
            log::server::info("XXXX UDT server - total bytes sent = " + std::to_string(total_bytes_sent));
        }
    }

    namespace handler
    {
        auto open(UDTSOCKET _socket, const nlohmann::json& _req) -> void
        {
            using log = irods::experimental::log;

            // Check input.
            if (_req.count("open_mode") == 0) {
                log::server::error("Missing argument [open_mode].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [open_mode]");
                return;
            }

            if (_req.count("create_mode") == 0) {
                log::server::error("Missing argument [create_mode].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [create_mode]");
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

            const auto to_openmode = [](int _safe_mode) -> std::ios_base::openmode
            {
                // clang-format off
                int in    = 1 << 0;
                int out   = 1 << 1;
                int trunc = 1 << 2;
                int app   = 1 << 3;
                int ate   = 1 << 4;
                // clang-format on

                using std::ios_base;
                
                ios_base::openmode m{};

                if (_safe_mode & out) {
                    m |= ios_base::out;
                }

                if (_safe_mode & in) {
                    m |= ios_base::in;
                }

                if (_safe_mode & trunc) {
                    m |= ios_base::trunc;
                }

                if (_safe_mode & app) {
                    m |= ios_base::app;
                }

                if (_safe_mode & ate) {
                    m |= ios_base::ate;
                }

                return m;
            };

            // Open file.
            req_ctx.file.open(req_ctx.physical_path, to_openmode(_req["open_mode"].get<int>())); 

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
            update_catalog();
            send_error_response(_socket, error_code::ok);
            req_ctx.close_connection = true;
        }

        auto read(UDTSOCKET _socket, const nlohmann::json& _req) -> void
        {
            send_error_response(_socket, error_code::ok);

            using log = irods::experimental::log;

            // Check input.
            if (_req.count("buffer_size") == 0) {
                log::server::error("Missing argument [buffer_size].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [buffer_size]");
                return;
            }

            const auto buffer_size = _req["buffer_size"].get<std::streamsize>();
            std::array<char, 8192> buf{};
            std::streamsize total_bytes_sent = 0;

            // Steps to handle all read cases:
            // Loop:
            // 1. Send client a flag indicating whether more data is coming.
            //    1a. If there is data to send, provide the expected size.
            // 2. If there is no more data, send flag indicating that so that
            //    the client can stop gracefully.

            if (!req_ctx.file) {
                
            }

            while (true) {

            }

            while (req_ctx.file && total_bytes_sent < buffer_size) {
                req_ctx.file.read(&buf[0], std::min<std::streamsize>(buf.size(), buffer_size));

                const auto count = req_ctx.file.gcount();
                int total = 0;

                while (total < count) {
                    const auto* buf_pos = &buf[0] + total;
                    const auto bytes_remaining = count - total;
                    const auto bytes_sent = UDT::send(_socket, buf_pos, bytes_remaining, 0);

                    if (UDT::ERROR == bytes_sent) {
                        log::server::error({{"log_message", "XXXX UDT server - send."},
                                            {"total_bytes_sent", std::to_string(total_bytes_sent)}});
                        return;
                    }

                    total += bytes_sent;
                }

                total_bytes_sent += total;
            }

            /*
            if (auto empty_bytes = buffer_size - total_bytes_sent; empty_bytes > 0) {
                buf = {};

                while (empty_bytes > 0) {
                    const auto bytes_sent = UDT::send(_socket, &buf[0], std::min<int>(buf.size(), empty_bytes), 0);

                    if (UDT::ERROR == bytes_sent) {
                        log::server::error({{"log_message", "XXXX UDT server - send."},
                                            {"total_bytes_sent", std::to_string(total_bytes_sent)}});
                        return;
                    }

                    total_bytes_sent += bytes_sent;
                    empty_bytes -= bytes_sent;
                }
            }
            */

            log::server::info("XXXX UDT server - total bytes sent = " + std::to_string(total_bytes_sent));

            /*
            //namespace fs = boost::filesystem;

            //const auto file_size = fs::file_size(req_ctx.physical_path) - req_ctx.file.tellp();

            const auto buffer_size = _req["buffer_size"].get<std::streamsize>();
            constexpr int read_buf_size = 8192;
            const int chunks = buffer_size / read_buf_size;
            const int bytes_remaining = buffer_size % read_buf_size;
            std::streamsize total_bytes_sent = 0;
            std::array<char, read_buf_size> buf{};

            for (int i = 0; i < chunks; ++i) {
                log::server::info("XXXX UDT SERVER READ - READING CHUNK ...");

                if (!req_ctx.file) {
                    log::server::info("XXXX UDT SERVER READ - EOF REACHED OR FILE ERROR!!!");
                    log::server::info("XXXX UDT server - total bytes sent = " + std::to_string(total_bytes_sent));
                    return;
                }

                req_ctx.file.read(&buf[0], read_buf_size);

                const auto bytes_sent = UDT::send(_socket, &buf[0], req_ctx.file.gcount(), 0);

                if (UDT::ERROR == bytes_sent) {
                    log::server::error({{"log_message", "XXXX UDT server - send."},
                                        {"total_bytes_sent", std::to_string(total_bytes_sent)}});
                    return;
                }

                total_bytes_sent += bytes_sent;
            }

            if (bytes_remaining == 0 || !req_ctx.file) {
                log::server::info("XXXX UDT SERVER READ - EOF REACHED OR NO MORE BYTES TO READ!!!");
                log::server::info("XXXX UDT server - total bytes sent = " + std::to_string(total_bytes_sent));
                return;
            }

            log::server::info("XXXX UDT SERVER READ - READING REMAINING BYTES!!!");

            req_ctx.file.read(&buf[0], bytes_remaining);

            const auto bytes_sent = UDT::send(_socket, &buf[0], req_ctx.file.gcount(), 0);

            if (UDT::ERROR == bytes_sent) {
                log::server::error({{"log_message", "XXXX UDT server - send."},
                                    {"total_bytes_sent", std::to_string(total_bytes_sent)}});
                return;
            }

            total_bytes_sent += bytes_sent;

            log::server::info("XXXX UDT server - total bytes sent = " + std::to_string(total_bytes_sent));
            */

            /*
            const auto buffer_size = _req["buffer_size"].get<std::streamsize>();
            std::array<char, 8192> buf{};
            std::streamsize total_bytes_sent = 0;

            while (total_bytes_sent < buffer_size) {
                req_ctx.file.read(&buf[0], std::min<std::streamsize>(buf.size(), buffer_size));

                const auto bytes_sent = UDT::send(_socket, &buf[0], req_ctx.file.gcount(), 0);

                if (UDT::ERROR == bytes_sent) {
                    log::server::error({{"log_message", "XXXX UDT server - send."},
                                        {"total_bytes_sent", std::to_string(total_bytes_sent)}});
                    send_error_response(_socket, error_code::network_udt, "Network::UDT send failed");
                    return;
                }

                total_bytes_sent += bytes_sent;
                log::server::info("XXXX UDT server - total bytes sent = " + std::to_string(total_bytes_sent));
            }
            */
        }

        auto write(UDTSOCKET _socket, const nlohmann::json& _req) -> void
        {
            send_error_response(_socket, error_code::ok);

            using log = irods::experimental::log;

            // Check input.
            if (_req.count("buffer_size") == 0) {
                log::server::error("Missing argument [buffer_size].");
                send_error_response(_socket, error_code::missing_arg, "Missing argument [buffer_size]");
                return;
            }

            const auto buffer_size = _req["buffer_size"].get<std::streamsize>();
            std::array<char, 8192> buf{};
            std::streamsize total_bytes_received = 0;

            while (total_bytes_received < buffer_size) {
                const auto bytes_received = UDT::recv(_socket, &buf[0], static_cast<int>(buf.size()), 0);

                if (UDT::ERROR == bytes_received) {
                    log::server::error({{"log_message", "XXXX UDT server - recv."},
                                        {"total_bytes_received", std::to_string(total_bytes_received)}});
                    send_error_response(_socket, error_code::network_udt, "Network::UDT recv failed");
                    return;
                }

                // Write the bytes to the file.
                req_ctx.file.write(&buf[0], bytes_received);

                total_bytes_received += bytes_received;
                log::server::info("XXXX UDT server - total bytes received = " + std::to_string(total_bytes_received));
            }

            send_error_response(_socket, error_code::ok);
        }

        auto seek(UDTSOCKET _socket, const nlohmann::json& _req) -> void
        {
            using log = irods::experimental::log;

            // Check input.
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

            const auto to_seekdir = [](int _dir) -> std::ios_base::seekdir
            {
                constexpr int seek_beg = 1;
                constexpr int seek_cur = 2;
                constexpr int seek_end = 3;

                switch (_dir) {
                    case seek_beg:
                        return std::ios_base::beg;

                    case seek_cur:
                        return std::ios_base::cur;

                    case seek_end:
                        return std::ios_base::end;

                    default:
                        return std::ios_base::cur;
                        // TODO Should throw an exception.
                }
            };

            const auto seek_dir = to_seekdir(_req["seek_from"].get<int>());
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


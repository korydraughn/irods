#ifndef IRODS_IO_UDT_TRANSPORT_HPP
#define IRODS_IO_UDT_TRANSPORT_HPP

#undef NAMESPACE_IMPL
#undef rxComm
#undef rxDataObjOpen
#undef rxDataObjClose
#undef rx_get_file_descriptor_info

// clang-format off
#ifdef IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
    #define RODS_SERVER

    #include "rsDataObjOpen.hpp"
    #include "rsDataObjClose.hpp"

    #define NAMESPACE_IMPL                  server

    #define rxComm                          rsComm_t

    #define rxDataObjOpen                   rsDataObjOpen
    #define rxDataObjClose                  rsDataObjClose
    #define rx_get_file_descriptor_info     rs_get_file_descriptor_info
#else
    #include "dataObjOpen.h"
    #include "dataObjClose.h"

    #define NAMESPACE_IMPL                  client

    #define rxComm                          rcComm_t

    #define rxDataObjOpen                   rcDataObjOpen
    #define rxDataObjClose                  rcDataObjClose
    #define rx_get_file_descriptor_info     rc_get_file_descriptor_info
#endif // IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
// clang-format on

#include "rcMisc.h"
#include "api_plugin_number.h"
#include "get_file_descriptor_info.h"
#include "rsGlobalExtern.hpp" // Declares resc_mgr
#include "transport/transport.hpp"
#include "transport/udt_transport_common.hpp"
#include "irods_logger.hpp"
#include "irods_server_api_call.hpp"

#include "json.hpp"

#include <udt/udt.h>
#include <arpa/inet.h>

#include <string>
#include <array>
#include <tuple>

namespace irods::experimental::io::NAMESPACE_IMPL
{
    template <typename CharT>
    class basic_udt_transport : public transport<CharT>
    {
    public:
        // clang-format off
        using char_type   = typename transport<CharT>::char_type;
        using traits_type = typename transport<CharT>::traits_type;
        using int_type    = typename traits_type::int_type;
        using pos_type    = typename traits_type::pos_type;
        using off_type    = typename traits_type::off_type;
        // clang-format on

    private:
        // clang-format off
        inline static constexpr auto uninitialized_file_descriptor = -1;
        inline static constexpr auto minimum_valid_file_descriptor = 3;

        // Errors
        inline static constexpr auto translation_error             = -1;
        inline static const     auto seek_error                    = pos_type{off_type{-1}};
        // clang-format on

        struct data_object_info
        {
            int data_id;
            std::string logical_path;
            std::string physical_path;
            std::string resource;
            std::string resource_hierarchy;
            int repl_number;
        };

    public:
        explicit basic_udt_transport(rxComm& _comm)
            : transport<CharT>{}
            , server_addr_{}
            , socket_{UDT::socket(AF_INET, SOCK_STREAM, 0)}
            , comm_{&_comm}
            , fd_{uninitialized_file_descriptor}
            , connected_{}
        {
            server_addr_.sin_family = AF_INET;
            server_addr_.sin_port = htons(9000);
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  std::ios_base::openmode _mode) override
        {
            return !is_open()
                ? open_impl(_p, _mode, [](auto&) {})
                : false;
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  int _replica_number,
                  std::ios_base::openmode _mode) override
        {
            if (is_open()) {
                return false;
            }

            return open_impl(_p, _mode, [_replica_number](auto& _input) {
                const auto replica = std::to_string(_replica_number);
                addKeyVal(&_input.condInput, REPL_NUM_KW, replica.c_str());
            });
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  const std::string& _resource_name,
                  std::ios_base::openmode _mode) override
        {
            if (is_open()) {
                return false;
            }

            return open_impl(_p, _mode, [&_resource_name](auto& _input) {
                addKeyVal(&_input.condInput, RESC_NAME_KW, _resource_name.c_str());
            });
        }

        bool close() override
        {
            namespace common = irods::experimental::io::common;

            using log = irods::experimental::log;

            if (const auto sent = send_header({{"op_code", static_cast<int>(common::op_code::close)}}); !sent) {
                log::server::error("XXXX UDT client - close socket");
            }

            using json = nlohmann::json;

            if (const json resp = read_error_response(); resp["error_code"].get<int>() != 0) {
                log::server::error("XXXX UDT client - " + resp["error_message"].get<std::string>());
            }

            UDT::close(socket_);

            return true;
        }

        std::streamsize receive(char_type* _buffer, std::streamsize _buffer_size) override
        {
            namespace common = irods::experimental::io::common;

            using log  = irods::experimental::log;
            using json = nlohmann::json;

            // Send header.

            {
                const auto sent = send_header({
                    {"op_code", static_cast<int>(common::op_code::read)},
                    {"buffer_size", _buffer_size}
                });

                if (!sent) {
                    log::server::error("XXXX UDT client - could not send header.");
                    return -1;
                }

                const json resp = read_error_response();

                if (resp["error_code"].get<int>() != 0) {
                    log::server::error("XXXX UDT client - " + resp["error_message"].get<std::string>());
                    return -1;
                }
            }

            // Read buffer data.

            std::streamsize total_received = 0;

            while (total_received < _buffer_size) {
                log::server::info("UDT CLIENT READ - Reading incoming buffer size ...");

                // Read header (get incoming buffer size).
                std::array<char, 15> expected_size_buf{};

                common::receive_buffer(socket_, expected_size_buf.data(), expected_size_buf.size());

                const int expected_size = std::stoi(std::string(std::begin(expected_size_buf), std::end(expected_size_buf)));

                log::server::info("UDT CLIENT READ - incoming buffer size = " + std::to_string(expected_size));

                if (expected_size == 0) {
                    return total_received;
                }

                log::server::info("UDT CLIENT READ - Reading incoming buffer data ...");

                total_received += common::receive_buffer(socket_, _buffer, expected_size);
            }

            log::server::info("UDT CLIENT READ - total bytes received = " + std::to_string(total_received));

            return total_received;
        }

        std::streamsize send(const char_type* _buffer, std::streamsize _buffer_size) override
        {
            namespace common = irods::experimental::io::common;

            using log  = irods::experimental::log;
            using json = nlohmann::json;

            // Send header.

            {
                const auto sent = send_header({
                    {"op_code", static_cast<int>(common::op_code::write)},
                    {"buffer_size", _buffer_size}
                });

                if (!sent) {
                    log::server::error("XXXX UDT client - could not send header.");
                    return -1;
                }

                const json resp = read_error_response();

                if (resp["error_code"].get<int>() != 0) {
                    log::server::error("XXXX UDT client - " + resp["error_message"].get<std::string>());
                    return -1;
                }
            }

            // Send buffer data.

            const auto total_sent = common::send_buffer(socket_, _buffer, _buffer_size);

            log::server::info("XXXX UDT client - total bytes sent = " + std::to_string(total_sent));

            const json resp = read_error_response();

            if (resp["error_code"].get<int>() != 0) {
                log::server::error("XXXX UDT client - " + resp["error_message"].get<std::string>());
                return -1;
            }

            return total_sent;
        }

        pos_type seekpos(off_type _offset, std::ios_base::seekdir _dir) override
        {
            namespace common = irods::experimental::io::common;

            if (!is_open()) {
                return seek_error;
            }

            const auto sent = send_header({
                {"op_code", static_cast<int>(common::op_code::seek)},
                {"seek_from", common::to_safe_transport_format(_dir)},
                {"offset", _offset}
            });

            if (!sent) {
                return seek_error;
            }

            using json = nlohmann::json;

            if (const json resp = read_error_response(); resp["error_code"].get<int>() != 0) {
                return seek_error;
            }

            // TODO Needs to return the new position!
            return 0;
        }

        bool is_open() const noexcept override
        {
            return connected_;
        }

        int file_descriptor() const noexcept override
        {
            return fd_;
        }

    private:
        int make_open_flags(std::ios_base::openmode _mode) noexcept
        {
            using std::ios_base;

            const auto m = _mode & ~(ios_base::ate | ios_base::binary);

            if (ios_base::in == m) {
                return O_RDONLY;
            }
            else if (ios_base::out == m || (ios_base::out | ios_base::trunc) == m) {
                return O_CREAT | O_WRONLY | O_TRUNC;
            }
            else if (ios_base::app == m || (ios_base::out | ios_base::app) == m) {
                return O_CREAT | O_WRONLY | O_APPEND;
            }
            else if ((ios_base::out | ios_base::in) == m) {
                return O_CREAT | O_RDWR;
            }
            else if ((ios_base::out | ios_base::in | ios_base::trunc) == m) {
                return O_CREAT | O_RDWR | O_TRUNC;
            }
            else if ((ios_base::out | ios_base::in | ios_base::app) == m ||
                     (ios_base::in | ios_base::app) == m)
            {
                return O_CREAT | O_RDWR | O_APPEND | O_TRUNC;
            }

            return translation_error;
        }

        bool seek_to_end_if_required(std::ios_base::openmode _mode)
        {
            if (std::ios_base::ate & _mode) {
                if (seek_error == seekpos(0, std::ios_base::end)) {
                    return false;
                }
            }

            return true;
        }

        template <typename Function>
        bool open_impl(const filesystem::path& _p, std::ios_base::openmode _mode, Function _func)
        {
            const auto flags = make_open_flags(_mode);

            if (flags == translation_error) {
                return false;
            }

            dataObjInp_t input{};

            input.createMode = 0600;
            input.openFlags = flags;
            rstrcpy(input.objPath, _p.c_str(), sizeof(input.objPath));

            _func(input);

            // TODO Modularize the block of code below.

            const auto fd = rxDataObjOpen(comm_, &input);

            if (fd < minimum_valid_file_descriptor) {
                return false;
            }

            fd_ = fd;

            if (!seek_to_end_if_required(_mode)) {
                close_rx_connection();
                return false;
            }

            // Fetch file descriptor information and resolve the
            // resource to the hostname/ip of the leaf resource server.

            const auto [info_captured, error_msg, hostname, info] = capture_file_descriptor_info();

            close_rx_connection();

            if (!info_captured) {
                return false;
            }

            // UDT specific initialization code.
            if (const auto ec = load_in_addr_from_hostname(hostname.c_str(), &server_addr_.sin_addr); ec != 0) {
                //throw std::runtime_error{"Cannot resolve hostname of destination resource to IP address"};
                return false;
            }

            // Connect to resource where the data object is stored.
            if (auto ptr = reinterpret_cast<sockaddr*>(&server_addr_);
                UDT::ERROR == UDT::connect(socket_, ptr, sizeof(sockaddr_in)))
            {
                //throw std::runtime_error{"UDT::connect - could not connect to server"};
                return false;
            }

            // Send command to open data object for UDT reads and/or writes.
            if (!open_for_udt(_mode, info)) {
                // TODO
            }

            connected_ = true;

            return true;
        }

        auto capture_file_descriptor_info() -> std::tuple<bool, std::string, std::string, data_object_info>
        {
            using log  = irods::experimental::log;
            using json = nlohmann::json;

            const auto json_input = json{{"fd", fd_}}.dump();
            char* json_output{};

            if (const auto ec = rx_get_file_descriptor_info(comm_, json_input.c_str(), &json_output); ec != 0) {
                std::string error_msg = "Cannot get file descriptor information [ec => ";
                error_msg += std::to_string(ec);
                error_msg += ']';

                return {false, error_msg, {}, {}};
            }

            log::server::trace("Got file descriptor info.");
            log::server::trace({{"file_descriptor_info", json_output}});

            std::string hostname;
            data_object_info info{};

            try {
                const auto fd_info = json::parse(json_output);
                const auto& data_obj_info = fd_info["data_object_info"];

                info.resource = data_obj_info["resource_name"].get<std::string>();
                info.resource_hierarchy = data_obj_info["resource_hierarchy"].get<std::string>();
                info.data_id = data_obj_info["data_id"].get<int>();
                info.logical_path = data_obj_info["object_path"].get<std::string>();
                info.physical_path = data_obj_info["file_path"].get<std::string>();
                info.repl_number = data_obj_info["replica_number"].get<int>();

                irods::resource_ptr resc_ptr;
                if (const auto err = resc_mgr.resolve(info.resource, resc_ptr); !err.ok()) {
                    std::string error_msg = "Cannot resolve resource name to hostname [ec => ";
                    error_msg += std::to_string(err.code());
                    error_msg += ']';

                    return {false, error_msg, {}, {}};
                }

                if (const auto err = resc_ptr->get_property(irods::RESOURCE_LOCATION, hostname); !err.ok()) {
                    std::string error_msg = "Cannot resolve resource name to hostname [ec => ";
                    error_msg += std::to_string(err.code());
                    error_msg += ']';

                    return {false, error_msg, {}, {}};
                }

                log::server::trace({{"log_message", "File Descriptor Info"},
                                    {"logical_path", info.logical_path},
                                    {"physical_path", info.physical_path},
                                    {"resource", info.resource},
                                    {"hostname", hostname}});
            }
            catch (const json::parse_error& e) {
                return {false, e.what(), {}, {}};
            }

            return {true, {}, hostname, info};
        }

        bool send_header(const nlohmann::json& _header)
        {
            namespace common = irods::experimental::io::common;

            using log = irods::experimental::log;

            const auto msg = _header.dump();

            std::array<char, 2000> buf{};
            std::copy(std::begin(msg), std::end(msg), std::begin(buf));

            const auto total_sent = common::send_buffer(socket_, buf.data(), buf.size());

            log::server::info("XXXX UDT client - total bytes sent = " + std::to_string(total_sent));

            return total_sent == buf.size();
        }

        nlohmann::json read_error_response()
        {
            namespace common = irods::experimental::io::common;

            using log = irods::experimental::log;

            std::array<char, 2000> buf{};

            const auto total_received = common::receive_buffer(socket_, buf.data(), buf.size());

            log::server::info("XXXX UDT client - total bytes received = " + std::to_string(total_received));

            using json = nlohmann::json;

            try {
                return json::parse(&buf[0]);
            }
            catch (const json::parse_error& e) {
            }

            return {}; // TODO Should probably throw instead.
        }

        bool open_for_udt(std::ios_base::openmode _mode, const data_object_info& _info)
        {
            namespace common = irods::experimental::io::common;

            using log  = irods::experimental::log;
            using json = nlohmann::json;

            const auto sent = send_header({
                {"op_code", static_cast<int>(common::op_code::open)},
                {"open_mode", common::to_safe_transport_format(_mode)},
                {"data_id", _info.data_id},
                {"logical_path", _info.logical_path},
                {"physical_path", _info.physical_path},
                {"resource", _info.resource},
                {"resource_hierarchy", _info.resource_hierarchy},
                {"replica_number", _info.repl_number}
            });

            if (!sent) {
                return false;
            }

            const json resp = read_error_response();

            if (resp["error_code"].get<int>() != 0) {
                log::server::error("XXXX UDT client - " + resp["error_message"].get<std::string>());
                return false;
            }

            return true;
        }

        bool close_rx_connection()
        {
            openedDataObjInp_t input{};
            input.l1descInx = fd_;

            if (const auto ec = rxDataObjClose(comm_, &input); ec < 0) {
                return false;
            }

            fd_ = uninitialized_file_descriptor;

            return true;
        }

        int rs_get_file_descriptor_info(rsComm_t* _comm, const char* _json_input, char** _json_output)
        {
            if (!_json_input) {
                return -1;
            }

            bytesBuf_t input_buf{};
            input_buf.len = static_cast<int>(std::strlen(_json_input));
            input_buf.buf = const_cast<char*>(_json_input);

            bytesBuf_t* output_buf{};

            const int ec = server_api_call(GET_FILE_DESCRIPTOR_INFO_APN, _comm, &input_buf, &output_buf);

            if (ec == 0) {
                *_json_output = static_cast<char*>(output_buf->buf);
            }

            return ec;
        }

        sockaddr_in server_addr_;
        UDTSOCKET socket_;
        rxComm* comm_;
        int fd_;
        bool connected_;
    }; // basic_udt_transport

    using udt_transport = basic_udt_transport<char>;
} // irods::experimental::io::NAMESPACE_IMPL

#ifdef IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
    #undef RODS_SERVER
#endif

#endif // IRODS_IO_UDT_TRANSPORT_HPP

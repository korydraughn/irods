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

#include <udt/udt.h>
#undef ERROR

#include "rcMisc.h"
#include "api_plugin_number.h"
#include "get_file_descriptor_info.h"
#include "rsGlobalExtern.hpp" // Declares resc_mgr
#include "transport/default_transport.hpp"
#include "transport/udt_transport_common.hpp"
#include "irods_server_api_call.hpp"
#include "irods_query.hpp"

#include "json.hpp"

#include <arpa/inet.h>

#include <string>
#include <array>
#include <tuple>

namespace irods::experimental::io::NAMESPACE_IMPL
{
    template <typename CharT>
    class basic_udt_transport : public basic_transport<CharT>
    {
    public:
        // clang-format off
        using char_type   = typename basic_transport<CharT>::char_type;
        using traits_type = typename basic_transport<CharT>::traits_type;
        using int_type    = typename traits_type::int_type;
        using pos_type    = typename traits_type::pos_type;
        using off_type    = typename traits_type::off_type;
        // clang-format on

    protected:
        inline static const auto seek_error = pos_type{off_type{-1}};

    public:
        explicit basic_udt_transport(rxComm& _comm)
            : basic_transport<char_type>{_comm}
            //, server_addr_{}
            , socket_{UDT::socket(AF_INET, SOCK_STREAM, 0)}
            , connected_{}
        {
            //server_addr_.sin_family = AF_INET;
            //server_addr_.sin_port = htons(9000);
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  std::ios_base::openmode _mode) override
        {
            if (!basic_transport<char_type>::open(_p, _mode)) {
                return false;
            }

            return connect_to_udt_server_and_open_data_object(_mode);
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  int _replica_number,
                  std::ios_base::openmode _mode) override
        {
            if (!basic_transport<char_type>::open(_p, _replica_number, _mode)) {
                return false;
            }

            return connect_to_udt_server_and_open_data_object(_mode);
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  const std::string& _resource_name,
                  std::ios_base::openmode _mode) override
        {
            if (!basic_transport<char_type>::open(_p, _resource_name, _mode)) {
                return false;
            }

            return connect_to_udt_server_and_open_data_object(_mode);
        }

        bool close() override
        {
            namespace common = irods::experimental::io::common;

            //using log = irods::experimental::log;

            if (!common::send_message(socket_, {{"op_code", static_cast<int>(common::op_code::close)}})) {
                //log::server::error("XXXX UDT client - close socket");
            }

            using json = nlohmann::json;

            if (const json resp = read_error_response(); resp["error_code"].get<int>() != 0) {
                //log::server::error("XXXX UDT client - " + resp["error_message"].get<std::string>());
            }

            UDT::close(socket_);

            return true;
        }

        std::streamsize receive(char_type* _buffer, std::streamsize _buffer_size) override
        {
            namespace common = irods::experimental::io::common;

            //using log  = irods::experimental::log;
            using json = nlohmann::json;

            // Send header.

            {
                const auto sent = common::send_message(socket_, {
                    {"op_code", static_cast<int>(common::op_code::read)},
                    {"buffer_size", _buffer_size}
                });

                if (!sent) {
                    //log::server::error("XXXX UDT client - could not send header.");
                    return -1;
                }

                const json resp = read_error_response();

                if (resp["error_code"].get<int>() != 0) {
                    //log::server::error("XXXX UDT client - " + resp["error_message"].get<std::string>());
                    return -1;
                }
            }

            // Read buffer data.

            std::streamsize total_received = 0;

            while (total_received < _buffer_size) {
                //log::server::info("UDT CLIENT READ - Reading incoming buffer size ...");

                // Read header (get incoming buffer size).
                std::array<char_type, 15> expected_size_buf{};

                common::receive_buffer(socket_, expected_size_buf.data(), expected_size_buf.size());

                const int expected_size = std::stoi(std::string(std::begin(expected_size_buf), std::end(expected_size_buf)));

                //log::server::info("UDT CLIENT READ - incoming buffer size = " + std::to_string(expected_size));

                if (expected_size == 0) {
                    return total_received;
                }

                //log::server::info("UDT CLIENT READ - Reading incoming buffer data ...");

                total_received += common::receive_buffer(socket_, _buffer, expected_size);
            }

            //log::server::info("UDT CLIENT READ - total bytes received = " + std::to_string(total_received));

            return total_received;
        }

        std::streamsize send(const char_type* _buffer, std::streamsize _buffer_size) override
        {
            namespace common = irods::experimental::io::common;

            //using log  = irods::experimental::log;
            using json = nlohmann::json;

            // Send header.

            {
                const auto sent = common::send_message(socket_, {
                    {"op_code", static_cast<int>(common::op_code::write)},
                    {"buffer_size", _buffer_size}
                });

                if (!sent) {
                    //log::server::error("XXXX UDT client - could not send header.");
                    return -1;
                }

                const json resp = read_error_response();

                if (resp["error_code"].get<int>() != 0) {
                    //log::server::error("XXXX UDT client - " + resp["error_message"].get<std::string>());
                    return -1;
                }
            }

            // Send buffer data.

            const auto total_sent = common::send_buffer(socket_, _buffer, _buffer_size);

            //log::server::info("XXXX UDT client - total bytes sent = " + std::to_string(total_sent));

            const json resp = read_error_response();

            if (resp["error_code"].get<int>() != 0) {
                //log::server::error("XXXX UDT client - " + resp["error_message"].get<std::string>());
                return -1;
            }

            return total_sent;
        }

        pos_type seekpos(off_type _offset, std::ios_base::seekdir _dir) override
        {
            namespace common = irods::experimental::io::common;

            const auto sent = common::send_message(socket_, {
                {"op_code", static_cast<int>(common::op_code::seek)},
                {"seek_from", common::to_safe_transport_format(_dir)},
                {"offset", _offset}
            });

            if (!sent) {
                return seek_error;
            }

            using json = nlohmann::json;

            const json resp = read_error_response();

            if (resp["error_code"].get<int>() != 0) {
                return seek_error;
            }

            return resp["position"].get<off_type>();
        }

        bool is_open() const noexcept override
        {
            return connected_;
        }

    private:
        struct data_object_info
        {
            int data_id;
            std::string logical_path;
            std::string physical_path;
            std::string resource;
            std::string resource_hierarchy;
            int repl_number;
        };

        auto connect_to_udt_server_and_open_data_object(std::ios_base::openmode _mode) -> bool
        {
            const auto [info_captured, error_msg, hostname, info] = capture_file_descriptor_info();

            basic_transport<char_type>::close();

            if (!info_captured) {
                return false;
            }

            sockaddr_in server_addr_{};
            server_addr_.sin_family = AF_INET;
            server_addr_.sin_port = htons(9000);

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
                return false;
            }

            connected_ = true;

            return true;
        }

        auto capture_file_descriptor_info() -> std::tuple<bool, std::string, std::string, data_object_info>
        {
            //using log  = irods::experimental::log;
            using json = nlohmann::json;

            const auto json_input = json{{"fd", basic_transport<char_type>::file_descriptor()}}.dump();
            char* json_output{};

            if (const auto ec = rx_get_file_descriptor_info(basic_transport<char_type>::connection(), json_input.c_str(), &json_output); ec != 0) {
                std::string error_msg = "Cannot get file descriptor information [ec => ";
                error_msg += std::to_string(ec);
                error_msg += ']';

                return {false, error_msg, {}, {}};
            }

            //log::server::trace("Got file descriptor info.");
            //log::server::trace({{"file_descriptor_info", json_output}});

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

                std::string sql = "select RESC_LOC where RESC_NAME = '";
                sql += info.resource;
                sql += "'";
                for (const auto&& row : irods::query<rxComm>{basic_transport<char_type>::connection(), sql}) {
                    hostname = row[0];
                }

                /*
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
                */

                /*
                log::server::trace({{"log_message", "File Descriptor Info"},
                                    {"logical_path", info.logical_path},
                                    {"physical_path", info.physical_path},
                                    {"resource", info.resource},
                                    {"hostname", hostname}});
                                    */
            }
            catch (const json::parse_error& e) {
                return {false, e.what(), {}, {}};
            }

            return {true, {}, hostname, info};
        }

        nlohmann::json read_error_response()
        {
            namespace common = irods::experimental::io::common;

            //using log = irods::experimental::log;

            std::array<char_type, 2000> buf{};

            const auto total_received = common::receive_buffer(socket_, buf.data(), buf.size());
            (void) total_received;

            //log::server::info("XXXX UDT client - total bytes received = " + std::to_string(total_received));

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

            //using log  = irods::experimental::log;
            using json = nlohmann::json;

            const auto sent = common::send_message(socket_, {
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
                //log::server::error("XXXX UDT client - " + resp["error_message"].get<std::string>());
                return false;
            }

            return true;
        }

#ifdef IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
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
#endif // IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API

        //sockaddr_in server_addr_;
        UDTSOCKET socket_;
        bool connected_;
    }; // basic_udt_transport

    using udt_transport = basic_udt_transport<char>;
} // irods::experimental::io::NAMESPACE_IMPL

#ifdef IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
    #undef RODS_SERVER
#endif

#endif // IRODS_IO_UDT_TRANSPORT_HPP

#ifndef IRODS_IO_DEFAULT_TRANSPORT_HPP
#define IRODS_IO_DEFAULT_TRANSPORT_HPP

#undef NAMESPACE_IMPL
#undef rxComm
#undef rxDataObjOpen
#undef rxDataObjClose
#undef rxDataObjLseek
#undef rx_get_file_descriptor_info

// clang-format off
#ifdef IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
    #define RODS_SERVER

    #include "rsDataObjOpen.hpp"
    #include "rsDataObjClose.hpp"
    #include "rsDataObjLseek.hpp"

    #define NAMESPACE_IMPL                  server

    #define rxComm                          rsComm_t

    #define rxDataObjOpen                   rsDataObjOpen
    #define rxDataObjClose                  rsDataObjClose
    #define rxDataObjLseek                  rsDataObjLseek
    #define rx_get_file_descriptor_info     rs_get_file_descriptor_info
#else
    #include "dataObjOpen.h"
    #include "dataObjClose.h"
    #include "dataObjLseek.h"

    #define NAMESPACE_IMPL                  client

    #define rxComm                          rcComm_t

    #define rxDataObjOpen                   rcDataObjOpen
    #define rxDataObjClose                  rcDataObjClose
    #define rxDataObjLseek                  rcDataObjLseek
    #define rx_get_file_descriptor_info     rc_get_file_descriptor_info
#endif // IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
// clang-format on

#include "rcMisc.h"
#include "api_plugin_number.h"
#include "get_file_descriptor_info.h"
#include "rsGlobalExtern.hpp" // Declares resc_mgr
#include "connection_pool.hpp"
#include "transport/transport.hpp"
#include "irods_logger.hpp"
#include "irods_query.hpp"
#include "filesystem/path.hpp"
#include "irods_server_api_call.hpp"

#include "json.hpp"

#include <udt/udt.h>
#include <arpa/inet.h>

#include <string>

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

    public:
        explicit basic_udt_transport(rxComm& _comm)
            : transport<CharT>{}
            , server_addr_{}
            , socket_{UDT::socket(AF_INET, SOCK_STREAM, 0)}
            , comm_{&_comm}
            , fd_{uninitialized_file_descriptor}
            , offset_{}
            , logical_path_{}
            , physical_path_{}
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
            close_rx_connection();
            UDT::close(socket_);
            return true;
        }

        std::streamsize receive(char_type* _buffer, std::streamsize _buffer_size) override
        {
            std::streamsize total_bytes_received = 0;

            while (total_bytes_received < _buffer_size) {
                auto* buf_pos = _buffer + total_bytes_received;
                const auto bytes_remaining = _buffer_size - total_bytes_received;

                const auto bytes_received = UDT::recv(socket_, buf_pos, bytes_remaining, 0);

                if (UDT::ERROR == bytes_received) {
                    break;
                }

                total_bytes_received += bytes_received;
            }

            return total_bytes_received;
        }

        std::streamsize send(const char_type* _buffer, std::streamsize _buffer_size) override
        {
            std::streamsize total_bytes_sent = 0;

            while (total_bytes_sent < _buffer_size) {
                auto* buf_pos = _buffer + total_bytes_sent;
                const auto bytes_remaining = _buffer_size - total_bytes_sent;

                const auto bytes_sent = UDT::send(socket_, buf_pos, bytes_remaining, 0);

                if (UDT::ERROR == bytes_sent) {
                    break;
                }

                total_bytes_sent += bytes_sent;
            }

            return total_bytes_sent;
        }

        pos_type seekpos(off_type _offset, std::ios_base::seekdir _dir) override
        {
            if (!is_open()) {
                return seek_error;
            }

            openedDataObjInp_t input{};

            input.l1descInx = fd_;
            input.offset = _offset;

            switch (_dir) {
                case std::ios_base::beg:
                    input.whence = SEEK_SET;
                    break;

                case std::ios_base::cur:
                    input.whence = SEEK_CUR;
                    break;

                case std::ios_base::end:
                    input.whence = SEEK_END;
                    break;

                default:
                    return seek_error;
            }

            fileLseekOut_t* output{};

            if (const auto ec = rxDataObjLseek(comm_, &input, &output); ec < 0) {
                return seek_error;
            }

            return output->offset;
        }

        bool is_open() const noexcept override
        {
            return fd_ >= minimum_valid_file_descriptor;
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
                close();
                return false;
            }

            // TODO Fetch file descriptor information and resolve the
            // resource to the hostname/ip of the leaf resource server.

            using log = irods::experimental::log;

#if 0
            std::string target_hostname;

            namespace fs = irods::experimental::filesystem;

            fs::path path = input.objPath;
            std::string sql = "select DATA_RESC_NAME, COLL_NAME, DATA_NAME, DATA_PATH where COLL_NAME = '";
            sql += path.parent_path().string();
            sql += "' and DATA_NAME = '";
            sql += path.object_name().string();
            sql += "'";

            for (auto&& row : irods::query{comm_, sql}) {
                log::server::info("Extracting resource name ...");
                auto target_resc = row[0];

                log::server::info("Extracting logical path ...");
                logical_path_ = (fs::path{row[1]} / row[2]).string();

                log::server::info("Extracting physical path ...");
                physical_path_ = row[3];

                irods::resource_ptr resc_ptr;
                if (const auto err = resc_mgr.resolve(target_resc, resc_ptr); !err.ok()) {
                    throw std::runtime_error{"Cannot resolve resource name to host [ec => " +
                                             std::to_string(err.code()) + ']'};
                }

                if (const auto err = resc_ptr->get_property(irods::RESOURCE_LOCATION, target_hostname);
                    !err.ok())
                {
                    throw std::runtime_error{"Cannot resolve resource name to hostname [ec => " +
                                             std::to_string(err.code()) + ']'};
                }

                log::server::info({{"log_message", "File Descriptor Info"},
                                   {"logical_path", logical_path_},
                                   {"physical_path", physical_path_},
                                   {"resource", target_resc},
                                   {"target_hostname", target_hostname}});
            }
#else
            using json = nlohmann::json;

            std::string json_input = R"_({"fd": )_";
            json_input += std::to_string(fd_);
            json_input += '}';

            log::server::info({{"JSON_INPUT", json_input}});

            //irods::connection_pool cpool{1, "kdd-ws", 1247, "rods", "tempZone", 600};
            //auto conn = cpool.get_connection();

            char* json_output{};

            if (const auto ec = rx_get_file_descriptor_info(comm_, json_input.c_str(), &json_output); ec != 0) {
                throw std::runtime_error{"Cannot get file descriptor information [ec => " + std::to_string(ec) + ']'};
            }

            log::server::info("Got file descriptor info.");
            log::server::info({{"file_descriptor_info", json_output}});

            std::string target_hostname;

            try {
                log::server::info("Parsing JSON string into JSON object ...");
                const auto fd_info = json::parse(json_output);

                log::server::info("Getting reference to data object info ...");
                const auto& data_obj_info = fd_info["data_object_info"];

                log::server::info("Extracting resource name ...");
                auto target_resc = data_obj_info["resource_name"].get<std::string>();

                log::server::info("Extracting logical path ...");
                logical_path_ = data_obj_info["object_path"].get<std::string>();

                log::server::info("Extracting physical path ...");
                physical_path_ = data_obj_info["file_path"].get<std::string>();

                irods::resource_ptr resc_ptr;
                if (const auto err = resc_mgr.resolve(target_resc, resc_ptr); !err.ok()) {
                    throw std::runtime_error{"Cannot resolve resource name to host [ec => " +
                                             std::to_string(err.code()) + ']'};
                }

                if (const auto err = resc_ptr->get_property(irods::RESOURCE_LOCATION, target_hostname);
                    !err.ok())
                {
                    throw std::runtime_error{"Cannot resolve resource name to hostname [ec => " +
                                             std::to_string(err.code()) + ']'};
                }

                log::server::info({{"log_message", "File Descriptor Info"},
                                   {"logical_path", logical_path_},
                                   {"physical_path", physical_path_},
                                   {"resource", target_resc},
                                   {"target_hostname", target_hostname}});
            }
            catch (const json::parse_error& e) {
                throw std::runtime_error{e.what()};
            }
#endif

            //close_rx_connection();

            // UDT specific initialization code.
            inet_pton(AF_INET, target_hostname.c_str(), &server_addr_.sin_addr);

            if (auto ptr = reinterpret_cast<sockaddr*>(&server_addr_);
                UDT::ERROR == UDT::connect(socket_, ptr, sizeof(sockaddr_in)))
            {
                throw std::runtime_error{"UDT::connect - could not connect to server"};
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
        off_type offset_;
        std::string logical_path_;
        std::string physical_path_;
    }; // basic_udt_transport

    using udt_transport = basic_udt_transport<char>;
} // irods::experimental::io::NAMESPACE_IMPL

#ifdef IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
    #undef RODS_SERVER
#endif

#endif // IRODS_IO_DEFAULT_TRANSPORT_HPP

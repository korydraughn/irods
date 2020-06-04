#ifndef IRODS_IO_SNAPPY_TRANSPORT_HPP
#define IRODS_IO_SNAPPY_TRANSPORT_HPP

#undef NAMESPACE_IMPL
#undef rxComm

#ifdef IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
    #include "rs_set_stream_compression.hpp"

    #define NAMESPACE_IMPL              server

    #define rxComm                      rsComm

    #define rx_set_stream_compression   rs_set_stream_compression

    // Forward declarations
    struct rsComm;
#else
    #include "set_stream_compression.h"

    #define NAMESPACE_IMPL              client

    #define rxComm                      rcComm

    #define rx_set_stream_compression   rc_set_stream_compression

    // Forward declarations
    struct rcComm;
#endif // IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API

#include "transport/transport.hpp"
#include "irods_at_scope_exit.hpp"

#include <snappy-c.h>

#include <ios>
#include <string>
#include <vector>

namespace irods::experimental::io::NAMESPACE_IMPL
{
    template <typename CharT>
    class basic_snappy_transport : public transport<CharT>
    {
    public:
        // clang-format off
        using char_type   = typename transport<CharT>::char_type;
        using traits_type = typename transport<CharT>::traits_type;
        using int_type    = typename traits_type::int_type;
        using pos_type    = typename traits_type::pos_type;
        using off_type    = typename traits_type::off_type;
        // clang-format on

        explicit basic_snappy_transport(rxComm& conn, transport<CharT>& tp)
            : transport<CharT>{}
            , conn_{&conn}
            , tp_{&tp}
        {
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  std::ios_base::openmode _mode) override
        {
            return tp_->open(_p, _mode) && set_compression_algo();
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  int _replica_number,
                  std::ios_base::openmode _mode) override
        {
            return tp_->open(_p, _replica_number, _mode) && set_compression_algo();
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  const std::string& _resource_name,
                  std::ios_base::openmode _mode) override
        {
            return tp_->open(_p, _resource_name, _mode) && set_compression_algo();
        }

        bool close() override
        {
            return tp_->close();
        }

        std::streamsize receive(char_type* _buffer, std::streamsize _buffer_size) override
        {
            const auto bytes_read = tp_->receive(_buffer, _buffer_size);

            // Uncompress the buffer if the buffer can be uncompressed.
            if (snappy_validate_compressed_buffer(_buffer, bytes_read) == SNAPPY_OK) {
                std::size_t output_length;
                snappy_uncompressed_length(_buffer, bytes_read, &output_length);

                std::vector<char_type> compressed(bytes_read);
                std::copy(_buffer, _buffer + bytes_read, std::begin(compressed));
                snappy_uncompress(compressed.data(), compressed.size(), _buffer, &output_length);

                return output_length;
            }

            return bytes_read;
        }

        std::streamsize send(const char_type* _buffer, std::streamsize _buffer_size) override
        {
            auto output_length = snappy_max_compressed_length(_buffer_size);
            std::vector<char> output(output_length);
            snappy_compress(_buffer, _buffer_size, output.data(), &output_length);
            return tp_->send(output.data(), output_length);
        }

        pos_type seekpos(off_type _offset, std::ios_base::seekdir _dir) override
        {
            return tp_->seekpos(_offset, _dir);
        }

        bool is_open() const noexcept override
        {
            return tp_->is_open();
        }

        int file_descriptor() const noexcept override
        {
            return tp_->file_descriptor();
        }

    private:
        bool set_compression_algo() const noexcept
        {
            const compression_input_t input{tp_->file_descriptor(), COMPRESSION_SNAPPY};

            if (rx_set_stream_compression(conn_, &input) != 0) {
                tp_->close();
                return false;
            }

            return true;
        }

        rxComm* conn_;
        transport<CharT>* tp_;
    };

    using snappy_transport = basic_snappy_transport<char>;
} // namespace irods::experimental::io::NAMESPACE_IMPL

#endif // IRODS_IO_SNAPPY_TRANSPORT_HPP


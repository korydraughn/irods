#ifndef IRODS_IO_SNAPPY_TRANSPORT_HPP
#define IRODS_IO_SNAPPY_TRANSPORT_HPP

#include "transport/transport.hpp"

#include "irods_at_scope_exit.hpp"

#include <snappy-c.h>

#include <cstdio>
#include <ios>
#include <string>
#include <vector>
#include <iostream>

namespace irods::experimental::io
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

        explicit basic_snappy_transport(transport<CharT>& tp)
            : transport<CharT>{}
            , tp_{&tp}
        {
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  std::ios_base::openmode _mode) override
        {
            return tp_->open(_p, _mode);
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  int _replica_number,
                  std::ios_base::openmode _mode) override
        {
            return tp_->open(_p, _replica_number, _mode);
        }

        bool open(const irods::experimental::filesystem::path& _p,
                  const std::string& _resource_name,
                  std::ios_base::openmode _mode) override
        {
            return tp_->open(_p, _resource_name, _mode);
        }

        bool close() override
        {
            return tp_->close();
        }

        std::streamsize receive(char_type* _buffer, std::streamsize _buffer_size) override
        {
            //return tp_->receive(_buffer, _buffer_size);

            const auto bytes_read = tp_->receive(_buffer, _buffer_size);
            std::cout << "transport :: bytes received = " << bytes_read << '\n';

            // Uncompress the buffer.
            if (snappy_validate_compressed_buffer(_buffer, bytes_read) == SNAPPY_OK) {
            //if (snappy_validate_compressed_buffer(_buffer, _buffer_size) == SNAPPY_OK) {
                std::cout << "transport :: buffer is compressed.  inflating ...\n";

                std::size_t output_length;
                snappy_uncompressed_length(_buffer, bytes_read, &output_length);

                std::vector<char_type> compressed(bytes_read);
                std::copy(_buffer, _buffer + bytes_read, std::begin(compressed));

                snappy_uncompress(compressed.data(), compressed.size(), _buffer, &output_length);

                std::cout << "transport :: uncompressed buffer size = " << output_length << '\n';
                return output_length;
            }

            std::cout << "transport :: buffer is NOT compressed.\n";
            std::cout << "transport :: buffer size = " << bytes_read << '\n';
            return bytes_read;
        }

        std::streamsize send(const char_type* _buffer, std::streamsize _buffer_size) override
        {
            return tp_->send(_buffer, _buffer_size);

            auto output_length = snappy_max_compressed_length(_buffer_size);
            auto* output = static_cast<char*>(std::malloc(output_length));
            irods::at_scope_exit release_mem{[output] { std::free(output); }};
            snappy_compress(_buffer, _buffer_size, output, &output_length);
            return tp_->send(output, output_length);
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
        transport<CharT>* tp_;
    };

    using snappy_transport = basic_snappy_transport<char>;
} // namespace irods::experimental::io

#endif // IRODS_IO_SNAPPY_TRANSPORT_HPP


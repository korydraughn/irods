#ifndef IRODS_IO_STATISTICAL_TRANSPORT_HPP
#define IRODS_IO_STATISTICAL_TRANSPORT_HPP

#include "transport/transport.hpp"

#include <ios>
#include <chrono>

namespace irods::experimental::io
{
    template <typename CharT>
    class basic_statistical_transport : public transport<CharT>
    {
    public:
        // clang-format off
        using char_type    = typename transport<CharT>::char_type;
        using traits_type  = typename transport<CharT>::traits_type;
        using int_type     = typename traits_type::int_type;
        using pos_type     = typename traits_type::pos_type;
        using off_type     = typename traits_type::off_type;

        using clock_type   = std::chrono::high_resolution_clock;
        using milliseconds = std::chrono::milliseconds;
        // clang-format on

        explicit basic_statistical_transport(transport<CharT>& tp)
            : transport<CharT>{}
            , tp_{&tp}
            , millis_{}
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
            const auto start = clock_type::now();
            const auto bytes = tp_->receive(_buffer, _buffer_size);
            millis_ += std::chrono::duration_cast<milliseconds>(clock_type::now() - start);
            return bytes;
        }

        std::streamsize send(const char_type* _buffer, std::streamsize _buffer_size) override
        {
            const auto start = clock_type::now();
            const auto bytes = tp_->send(_buffer, _buffer_size);
            millis_ += std::chrono::duration_cast<milliseconds>(clock_type::now() - start);
            return bytes;
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

        void reset() noexcept
        {
            millis_ = 0;
        }

        std::chrono::milliseconds total_time() const noexcept
        {
            return millis_;
        }

    private:
        transport<CharT>* tp_;
        std::chrono::milliseconds millis_;
    };

    using statistical_transport = basic_statistical_transport<char>;
} // namespace irods::experimental::io::NAMESPACE_IMPL

#endif // IRODS_IO_STATISTICAL_TRANSPORT_HPP


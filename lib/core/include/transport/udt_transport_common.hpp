#ifndef IRODS_IO_UDT_TRANSPORT_COMMON_HPP
#define IRODS_IO_UDT_TRANSPORT_COMMON_HPP

#include "json.hpp"

#include <udt/udt.h>

#include <array>

namespace irods::experimental::io::common
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
        network_udt,
        eof
    };

    struct openmode
    {
        // clang-format off
        static constexpr int in     = 1 << 0;
        static constexpr int out    = 1 << 1;
        static constexpr int trunc  = 1 << 2;
        static constexpr int app    = 1 << 3;
        static constexpr int ate    = 1 << 4;
        static constexpr int binary = 1 << 5;
        // clang-format on
    };

    struct seekdir
    {
        static constexpr int beg = 0;
        static constexpr int cur = 1;
        static constexpr int end = 2;
    };

    template <typename CharT>
    int send_buffer(UDTSOCKET _socket, const CharT* _buffer, int _buffer_size)
    {
        int total_sent = 0;

        while (total_sent < _buffer_size) {
            const auto sent = UDT::send(_socket, _buffer + total_sent, _buffer_size - total_sent, 0);

            if (UDT::ERROR == sent) {
                break;
            }

            total_sent += sent;
        }

        return total_sent;
    }

    template <typename CharT>
    int receive_buffer(UDTSOCKET _socket, CharT* _buffer, int _buffer_size)
    {
        int total_received = 0;

        while (total_received < _buffer_size) {
            const auto received = UDT::recv(_socket, _buffer + total_received, _buffer_size - total_received, 0);

            if (UDT::ERROR == received) {
                break;
            }

            total_received += received;
        }

        return total_received;
    }

    inline auto send_message(UDTSOCKET _socket, const nlohmann::json& _message) -> bool
    {
        const auto msg = _message.dump();

        std::array<char, 2000> buf{};
        std::copy(std::begin(msg), std::end(msg), std::begin(buf));

        const auto total_sent = send_buffer(_socket, buf.data(), buf.size());

        return total_sent == buf.size();
    }

    inline auto to_safe_transport_format(std::ios_base::openmode _mode) noexcept -> int
    {
        using std::ios_base;

        int m = 0;

        if (_mode & ios_base::out) {
            m |= openmode::out;
        }

        if (_mode & ios_base::in) {
            m |= openmode::in;
        }

        if (_mode & ios_base::trunc) {
            m |= openmode::trunc;
        }

        if (_mode & ios_base::app) {
            m |= openmode::app;
        }

        if (_mode & ios_base::ate) {
            m |= openmode::ate;
        }

        return m;
    }

    inline auto to_openmode(int _mode) -> std::ios_base::openmode
    {
        using std::ios_base;

        ios_base::openmode m{};

        if (_mode & openmode::out) {
            m |= ios_base::out;
        }

        if (_mode & openmode::in) {
            m |= ios_base::in;
        }

        if (_mode & openmode::trunc) {
            m |= ios_base::trunc;
        }

        if (_mode & openmode::app) {
            m |= ios_base::app;
        }

        if (_mode & openmode::binary) {
            m |= ios_base::binary;
        }

        if (_mode & openmode::ate) {
            m |= ios_base::ate;
        }

        return m;
    }

    inline auto to_safe_transport_format(std::ios_base::seekdir _dir) noexcept -> int
    {
        int dir = 0;

        switch (_dir) {
            case std::ios_base::beg:
                dir = seekdir::beg;
                break;

            case std::ios_base::cur:
                dir = seekdir::cur;
                break;

            case std::ios_base::end:
                dir = seekdir::end;
                break;

            default:
                return -1;
        }

        return dir;
    }

    inline auto to_seekdir(int _dir) -> std::ios_base::seekdir
    {
        switch (_dir) {
            case seekdir::beg:
                return std::ios_base::beg;

            case seekdir::cur:
                return std::ios_base::cur;

            case seekdir::end:
                return std::ios_base::end;

            default:
                return std::ios_base::cur;
                // TODO Should throw an exception.
        }
    }
} // namespace irods::experimental::io::utils

#endif // IRODS_IO_UDT_TRANSPORT_COMMON_HPP

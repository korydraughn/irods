#ifndef IRODS_NULL_COMPRESSION_HPP
#define IRODS_NULL_COMPRESSION_HPP

#include "compression.hpp"

#include <algorithm>

namespace irods::experimental::io
{
    class null_compression
        : public compression
    {
    public:
        auto compress(std::byte* buffer,
                      std::int64_t buffer_size,
                      std::byte* output_buffer) -> std::int64_t override
        {
            std::copy(buffer, buffer + buffer_size, output_buffer);
            return buffer_size;
        }

        auto uncompress(std::byte* buffer,
                        std::int64_t buffer_size,
                        std::byte* output_buffer) -> std::int64_t override
        {
            std::copy(buffer, buffer + buffer_size, output_buffer);
            return buffer_size;
        }
    };
} // namespace irods::experimental::io

#endif // IRODS_NULL_COMPRESSION_HPP

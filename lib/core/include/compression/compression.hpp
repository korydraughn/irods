#ifndef IRODS_COMPRESSION_HPP
#define IRODS_COMPRESSION_HPP

#include <cstddef>
#include <cstdint>

namespace irods::experimental::io
{
    class compression
    {
    public:
        virtual ~compression() {}

        virtual auto compress(std::byte* buffer,
                              std::int64_t buffer_size,
                              std::byte* output_buffer) -> std::int64_t = 0;

        virtual auto uncompress(std::byte* buffer,
                                std::int64_t buffer_size,
                                std::byte* output_buffer) -> std::int64_t = 0;
    };
} // namespace irods::experimental::io

#endif // IRODS_COMPRESSION_HPP

#ifndef IRODS_NONBLOCKING_STREAM_HPP
#define IRODS_NONBLOCKING_STREAM_HPP

#include "rodsErrorTable.h"
#include "circular_buffer.hpp"
#include "lock_and_wait_strategy.hpp"

#include <ios>
#include <exception>
#include <thread>
#include <chrono>
#include <future>
#include <atomic>
#include <stdexcept>
#include <memory>

namespace irods::experimental::io
{
    class nonblocking_stream_error
        : public std::runtime_error
    {
    public:
        nonblocking_stream_error(long long error_code, const char* msg)
            : std::runtime_error{msg}
            , ec_{error_code}
        {
        }

        auto error_code() -> long long
        {
            return ec_;
        }

    private:
        long long ec_;
    };

    struct io_result
    {
        std::streamsize bytes = 0;
        bool consumed = false;
    };

    template <typename Stream>
    class nonblocking_stream
    {
    public:
        // clang-format off
        using char_type = typename Stream::char_type;
        using pos_type  = typename Stream::pos_type;
        using off_type  = typename Stream::off_type;
        // clang-format on

        nonblocking_stream(Stream& stream, std::size_t backlog_size)
            : stream_{stream}
            , worker_thread_{}
            , io_requests_{backlog_size}
            , stop_worker_thread_{}
        {
            worker_thread_ = std::thread{[this] {
                std::shared_ptr<io_request> req;

                while (!stop_worker_thread_.load()) {
                    if (io_requests_.empty()) {
                        using namespace std::chrono_literals;
                        std::this_thread::sleep_for(1ms);
                        continue;
                    }

                    io_requests_.pop_front(req); // TODO circular_buffer needs a try_pop(T).

                    try {
                        switch (req->operation) {
                            case io_operation::read:
                                // FIXME This will fail if fewer bytes are returned than what was expected.
                                // This will happen if the data object being read does not divide evenly by the
                                // buffer size.
                                //
                                // FIXME Potential race condition.
                                // The reads must wait until the client processes the buffer results. If we
                                // don't wait until the filled buffer has been consumed, then we risk overwriting
                                // unconsumed data leading to data lost or incoreect results.
                                if (const auto count = stream_.rdbuf()->sgetn(req->buffer, req->buffer_size);
                                    count != req->buffer_size)
                                {
                                    throw nonblocking_stream_error{count, "read error"};
                                }
                                req->promise.set_value();
                                break;

                            case io_operation::write:
                                if (const auto count = stream_.rdbuf()->sputn(req->buffer, req->buffer_size);
                                    count != req->buffer_size)
                                {
                                    throw nonblocking_stream_error{count, "write error"};
                                }
                                req->promise.set_value();
                                break;

                            case io_operation::seek_position:
                                if (const auto pos = stream_.rdbuf()->pubseekpos(req->offset);
                                    pos == pos_type{off_type{-1}})
                                {
                                    throw nonblocking_stream_error{FILE_INDEX_LOOKUP_ERR, "seek position error"};
                                }
                                req->promise.set_value();
                                break;

                            case io_operation::seek_offset:
                                if (const auto pos = stream_.rdbuf()->pubseekoff(req->offset, req->seek_dir);
                                    pos == pos_type{off_type{-1}})
                                {
                                    throw nonblocking_stream_error{FILE_INDEX_LOOKUP_ERR, "seek offset error"};
                                }
                                req->promise.set_value();
                                break;

                            default:
                                break;
                        }
                    }
                    catch (...) {
                        // TODO Exception should contain information about the failed request.
                        // (e.g. the request arguments).
                        req->promise.set_exception(std::current_exception());
                        io_requests_.clear();
                    }
                }
            }};
        }

        nonblocking_stream(const nonblocking_stream&) = delete;
        auto operator=(const nonblocking_stream&) -> nonblocking_stream& = delete;

        ~nonblocking_stream()
        {
            stop_worker_thread_.store(true);
            worker_thread_.join();
        }

        auto read(char_type* buffer, std::streamsize count) -> std::future<void>
        {
            auto req = std::make_shared<io_request>();
            req->operation = io_operation::read;
            req->buffer = buffer;
            req->buffer_size = count;

            io_requests_.push_back(req);

            return req->promise.get_future();
        }

        auto write(const char_type* buffer, std::streamsize count) -> std::future<void>
        {
            auto req = std::make_shared<io_request>();
            req->operation = io_operation::write;
            req->buffer = const_cast<char_type*>(buffer);
            req->buffer_size = count;

            io_requests_.push_back(req);

            return req->promise.get_future();
        }

        auto seek(pos_type pos) -> std::future<void>
        {
            auto req = std::make_shared<io_request>();
            req->operation = io_operation::seek_position;
            req->offset = pos;

            io_requests_.push_back(req);

            return req->promise.get_future();
        }

        auto seek(off_type offset, std::ios_base::seekdir dir) -> std::future<void>
        {
            auto req = std::make_shared<io_request>();
            req->operation = io_operation::seek_offset;
            req->offset = offset;
            req->seek_dir = dir;

            io_requests_.push_back(req);

            return req->promise.get_future();
        }

        auto wait() -> void
        {

        }

        auto error() -> void
        {

        }

    private:
        enum class io_operation
        {
            read,
            write,
            seek_position,
            seek_offset
        };

        struct io_request
        {
            io_operation operation;
            char_type* buffer;
            std::streamsize buffer_size;
            std::ios_base::seekdir seek_dir;
            off_type offset;
            std::promise<void> promise;
        };

        Stream& stream_;
        std::thread worker_thread_;
        // TODO ring_buffer does not support move-only objects.
        irods::experimental::circular_buffer<std::shared_ptr<io_request>> io_requests_;
        std::atomic<bool> stop_worker_thread_;
    }; // nonblocking_stream
} // namespace irods::experimental::io

#endif // IRODS_NONBLOCKING_STREAM_HPP


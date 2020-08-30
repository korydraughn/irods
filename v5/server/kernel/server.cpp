#include "server.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <utility>

// clang-format off
namespace asio   = boost::asio;

using io_context = boost::asio::io_context;
using tcp        = boost::asio::ip::tcp;
using error_code = boost::system::error_code;
// clang-format on

namespace irods::v5
{
    server::server(asio::io_context& _io_context)
        : io_context_{_io_context}
        , signals_{_io_context, SIGCHLD}
        , acceptor_{_io_context, {tcp::v4(), 1247}}
        , socket_{_io_context}
    {
        wait_for_signals();
        accept();
    }

    auto server::wait_for_signals() -> void
    {
        signals_.async_wait([this](error_code _ec, int _signal)
        {
            // Only the parent process should check for this signal. We can
            // determine whether we are in the parent by checking if the acceptor
            // is still open.
            if (acceptor_.is_open()) {
                // Reap completed child processes so that we don't end up with
                // zombies.
                int status = 0;
                while (waitpid(-1, &status, WNOHANG) > 0);

                wait_for_signals();
            }
        });
    }

    auto server::accept() -> void
    {
        acceptor_.async_accept([this](error_code _ec, tcp::socket _new_socket)
        {
            if (_ec) {
                // TODO Log error.
                accept();
                return;
            }

            // Take ownership of the newly accepted socket.
            socket_ = std::move(_new_socket);

            // Inform the io_context that we are about to fork. The io_context
            // cleans up any internal resources, such as threads, that may
            // interfere with forking.
            io_context_.notify_fork(io_context::fork_prepare);

            if (const auto pid = fork(); pid > 0) {
                // Inform the io_context that the fork is finished and that this
                // is the parent process. The io_context uses this opportunity to
                // recreate any internal resources that were cleaned up during
                // preparation for the fork.
                io_context_.notify_fork(io_context::fork_parent);

                // The parent process can now close the newly accepted socket. It
                // remains open in the child.
                socket_.close();

                // TODO Record the PID for future processing.

                accept();
            }
            else if (pid == 0) {
                // Inform the io_context that the fork is finished and that this
                // is the child process. The io_context uses this opportunity to
                // create any internal file descriptors that must be private to
                // the new process.
                io_context_.notify_fork(io_context::fork_child);

                // The child won't be accepting new connections, so we can close
                // the acceptor. It remains open in the parent.
                acceptor_.close();

                // The child process is not interested in processing the SIGCHLD
                // signal.
                signals_.cancel();

                read();
            }
            else {
                // TODO Log error.
                accept();
            }
        });
    }

    auto server::read() -> void
    {
        // Parses the request header to determine what to do.
        // Possibly reads config files.
        // Loads the shared library that corresponds to the operation.

        // Instead of the server instructing the client to use a secure port,
        // the server could just serve a secure port and leave it up to the
        // client to use the correct one. The server then only tells the client
        // whether the request requires a secure port in order to carry it out.

        while (true) {
            try {
                /*
                    [First N bytes = length of request and encoding/compression algo]
                    {
                        "user": {
                            "name": "kory",
                            "session_id": "..."
                        },
                        "proxy_user": {
                            "name": "rods",
                            "session_id": "..."
                        },
                        "api_number": 1000,
                        "api_arguments": {
                            "path": "/tempZone/home/rods/foo",
                            "replica_number": 2,
                            "open_mode": bitwise_value,
                            "replica_token": "..."
                        }
                    }
                */
                const auto [ec, req] = read_request_header(socket_);

                // Verify that the API number is valid.
                if (!is_valid_api_number(req)) {

                }

                // Verify that the user is real and has the correct permission
                // to execute the operation.
                if (!is_authorized_user(req)) {

                }

                // Trigger the REPF and do the actual operation.
                const auto response = execute(socket_, req);

                write(response);
            }
            catch (const std::exception& e) {
                // TODO Log error and continue or shutdown handler.
            }
        }
    }

    auto server::write() -> void
    {

    }
} // namespace irods::v5

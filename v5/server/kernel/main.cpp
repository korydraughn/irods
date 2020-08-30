#include "server.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

#include <boost/program_options.hpp>

//#include <fmt/format.h>

#include <unistd.h>

#include <iostream>

auto parse_command_line(int _argc, char* _argv[]) -> std::tuple<bool, int>;

auto print_usage_info() noexcept -> void;

auto print_version_info() noexcept -> void;

auto daemonize(boost::asio::io_context& _io_context) -> int;

int main(int _argc, char* _argv[])
{
    if (const auto [terminate, ec] = parse_command_line(_argc, _argv); terminate) {
        return ec;
    }

    try {
        boost::asio::io_context io_context;

        if (const auto ec = daemonize(io_context); ec != 0) {
            // TODO Log error.
            return ec;
        }

        irods::v5::server server{io_context};

        io_context.run();
    }
    catch (const std::exception& e) {
        // TODO Log error.
        return 1;
    }
    
    return 0;
}

auto parse_command_line(int _argc, char* _argv[]) -> std::tuple<bool, int>
{
    namespace po = boost::program_options;

    try {
        po::options_description options{""};
        options.add_options()
            ("help,h", "")
            ("version,v", "");

        po::variables_map vm;
        po::store(po::command_line_parser(_argc, _argv).run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            print_usage_info();
            return {true, 0};
        }

        if (vm.count("version")) {
            print_version_info();
            return {true, 0};
        }
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return {true, 1};
    }
    
    return {false, 0};
}

auto print_usage_info() noexcept -> void
{

}

auto print_version_info() noexcept -> void
{

}

auto daemonize(boost::asio::io_context& _io_context) -> int
{
    // The implementation of this function is adapted from the following:
    //
    //   https://www.boost.org/doc/libs/1_67_0/doc/html/boost_asio/example/cpp11/fork/daemon.cpp

    namespace asio = boost::asio;

    // Register signal handlers so that the daemon may be shut down.
    // TODO Register SIGHUP to trigger re-read of configuration file.
    asio::signal_set signals{_io_context, SIGINT, SIGTERM};
    signals.async_wait([&_io_context](boost::system::error_code _ec, int _signal) {
        _io_context.stop();
    });

    // Inform the io_context that we are about to become a daemon. The
    // io_context cleans up any internal resources, such as threads, that
    // may interfere with forking.
    _io_context.notify_fork(asio::io_context::fork_prepare);

    // Fork the process and have the parent exit. If the process was started
    // from a shell, this returns control to the user. Forking a new process is
    // also a prerequisite for the subsequent call to setsid().
    if (const auto pid = fork(); pid > 0) {
        // We're in the parent process and need to exit.
        //
        // When the exit() function is used, the program terminates without
        // invoking local variables' destructors. Only global variables are
        // destroyed. As the io_context object is a local variable, this means
        // we do not have to call:
        //
        //   io_context.notify_fork(asio::io_context::fork_parent);
        // 
        // However, this line should be added before each call to exit() if
        // using a global io_context object. An additional call:
        //
        //   io_context.notify_fork(asio::io_context::fork_prepare);
        // 
        // should also precede the second fork().
        exit(0);
    }
    else {
        // TODO Log error.
        return 1;
    }

    // Make the process a new session leader. This detaches if from the terminal.
    setsid();

    // A process inherits its working directory from its parent. This could be
    // on a mounted filesystem, which means that the running daemon would prevent
    // this filesystem from being unmounted. Changing to the root directory avoids
    // this problem.
    chdir("/");

    // The file mode creation mask is also inherited from the parent process.
    // We don't want to restrict the permissions on files created by the daemon,
    // so the mask is cleared.
    umask(0);

    // A second fork ensures the process cannot acquire a controlling terminal.
    if (const auto pid = fork(); pid > 0) {
        exit(0);
    }
    else {
        // TODO Log error.
        return 1;
    }

    // Close the standard streams. This decouples the daemon from the terminal
    // that started it.
    close(0);
    close(1);
    close(2);

    // Disable all forms of input and output.
    if (open("/dev/null", O_RDONLY) < 0) {
        // TODO Log error.
        return 1;
    }

    if (open("/dev/null", O_WRONLY) < 0) {
        // TODO Log error.
        return 1;
    }

    if (open("/dev/null", O_RDWR) < 0) {
        // TODO Log error.
        return 1;
    }

    // Inform the io_context that we have finished becoming a daemon. The
    // io_context uses this opportunity to create any internal file descriptors
    // that need to be private to the new process.
    _io_context.notify_fork(asio::io_context::fork_child);

    return 0;
}


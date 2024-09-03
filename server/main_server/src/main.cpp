#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_logger.hpp>

#include <boost/asio.hpp>
#include <boost/interprocess/ipc/message_queue.hpp>
#include <boost/program_options.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <csignal>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>

namespace
{
    using log_server = irods::experimental::log::server;

    volatile std::sig_atomic_t g_terminate = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    volatile std::sig_atomic_t g_reload_config = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    auto print_usage() -> void;
    auto print_version_info() -> void;
    auto print_configuration_template() -> void;

    auto daemonize() -> void;
    auto create_pid_file(const std::string& _pid_file) -> int;
    auto init_logger(const nlohmann::json& _config) -> void;
    auto setup_signal_handlers() -> void;
} // anonymous namespace

int main(int _argc, char* _argv[])
{
    std::string config_path;

    namespace po = boost::program_options;

    po::options_description opts_desc{""};

    // clang-format off
    opts_desc.add_options()
        ("config-file,f", po::value<std::string>(), "")
        ("jsonschema-file", po::value<std::string>(), "")
        ("dump-config-template", "")
        ("dump-default-jsonschema", "")
        ("daemonize,d", "")
        ("pid-file,P", "")
        ("help,h", "")
        ("version,v", "");
    // clang-format on

    po::positional_options_description pod;
    pod.add("config-file", 1);

    try {
        po::variables_map vm;
        po::store(po::command_line_parser(_argc, _argv).options(opts_desc).positional(pod).run(), vm);
        po::notify(vm);

        if (vm.count("help") > 0) {
            print_usage();
            return 0;
        }

        if (vm.count("version") > 0) {
            print_version_info();
            return 0;
        }

        if (vm.count("dump-config-template") > 0) {
            print_configuration_template();
            return 0;
        }

        if (vm.count("dump-default-jsonschema") > 0) {
            //fmt::print(default_jsonschema());
            return 0;
        }

        if (auto iter = vm.find("config-file"); std::end(vm) != iter) {
            config_path = std::move(iter->second.as<std::string>());
        }
        else {
            fmt::print(stderr, "Error: Missing [CONFIG_FILE_PATH] parameter.");
            return 1;
        }

        if (vm.count("daemonize") > 0) {
            daemonize();
        }

        // TODO What does it mean to daemonize and use a unique pidfile name?
        // Perhaps daemonization means there's only one instance running on the machine?
        // What if the pidfile name was derived from the config file path? Only one instance can work.
        // But, what if redirection is disabled by the admin?
        std::string pid_file = "/var/run/irods.pid";
        if (const auto iter = vm.find("pid-file"); std::end(vm) != iter) {
            pid_file = std::move(iter->second.as<std::string>());
        }

        if (create_pid_file(pid_file) == -1) {
            fmt::print(stderr, "Error: could not create PID file [{}].", pid_file);
            return 1;
        }
    }
    catch (const std::exception& e) {
        fmt::print(stderr, "Error: {}\n", e.what());
        return 1;
    }

    using json = nlohmann::json;
    json config;

    try {
        // Load configuration.
        config = json::parse(std::ifstream{config_path});

        // TODO Validate configuration.
#if 0
        const auto config = json::parse(std::ifstream{vm["config-file"].as<std::string>()});
        irods::http::globals::set_configuration(config);

        {
            const auto schema_file = (vm.count("jsonschema-file") > 0) ? vm["jsonschema-file"].as<std::string>() : "";
            if (!is_valid_configuration(schema_file, vm["config-file"].as<std::string>())) {
                return 1;
            }
        }
#endif

        // TODO Init base systems for parent process.
        // - logger
        // - shared memory for replica access table, dns cache, hostname cache?
        // - delay server salt

        init_logger(config);
        
        // This message queue gives child processes a way to notify the parent process.
        // This will only be used by the agent factory because iRODS 5.0 won't have a control plane.
        // Or at least that's the plan.
        constexpr const auto* mq_name = "irodsd_mq"; // TODO Make this name unique.
        constexpr auto max_number_of_msg = 1; // Set to 1 to protect against duplicate/spamming of messages.
        constexpr auto max_msg_size = 512; 
        boost::interprocess::message_queue::remove(mq_name);
        boost::interprocess::message_queue pproc_mq{
            boost::interprocess::create_only, mq_name, max_number_of_msg, max_msg_size};

        // Launch agent factory.
        auto pid_af = fork();
        if (0 == pid_af) {
            char pname[] = "irodsAgent";
            char parent_mq_name[] = "irodsd_mq";
            char* args[] = {pname, parent_mq_name, nullptr};
            execv(pname, args);
            _exit(1);
        }
        else if (-1 == pid_af) {
            fmt::print(stderr, "Error: could not launch agent factory.\n");
            return 1;
        }
        fmt::print("agent factory pid = [{}]\n", pid_af);

        // Fork delay server if this server is the leader.
        auto pid_ds = fork();
        if (0 == pid_ds) {
            char pname[] = "irodsDelayServer";
            char* args[] = {pname, nullptr};
            execv(pname, args);
            _exit(1);
        }
        else if (-1 == pid_ds) {
            kill(pid_af, SIGTERM);
            fmt::print(stderr, "Error: could not launch delay server.\n");
            return 1;
        }
        fmt::print("delay server pid = [{}]\n", pid_ds);

        // Setting up signal handlers here removes the need for reacting to shutdown signals
        // such as SIGINT and SIGTERM during the startup sequence.
        setup_signal_handlers();

        // Enter parent process main loop.
        // 
        // This process should never introduce threads. Everything it cares about must be handled
        // within the loop. This keeps things simple and straight forward.
        //
        // THE PARENT PROCESS IS THE ONLY PROCESS THAT SHOULD/CAN REACT TO SIGNALS!
        // EVERYTHING IS PROPAGATED THROUGH/FROM THE PARENT PROCESS!

        std::array<char, max_msg_size> msg_buf{};
        boost::interprocess::message_queue::size_type recvd_size{};
        unsigned int priority{};

        while (true) {
            // TODO Handle messages from agent factory: shutdown
            msg_buf.fill(0);

            // TODO Change to try_receive() or equivalent.
            // This MUST NOT block.
            pproc_mq.receive(msg_buf.data(), msg_buf.size(), recvd_size, priority);

            std::string_view msg(msg_buf.data(), recvd_size);
            fmt::print("irodsd: received message: [{}], recvd_size: [{}]\n", msg, recvd_size);

            if (msg == "shutdown") {
                fmt::print("Received shutdown instruction from control plane.\n");
                break;
            }

            // TODO Reap child processes.
            // TODO Fork agent factory and/or delay server again if necessary.
        }

        // Start shutting everything down.

#ifdef IRODS_LAUNCH_CONTROL_PLANE
        kill(pid_cp, SIGTERM);
#endif
        kill(pid_af, SIGTERM);
        kill(pid_ds, SIGTERM);

#ifdef IRODS_LAUNCH_CONTROL_PLANE
        waitpid(pid_cp, nullptr, 0);
#endif
        waitpid(pid_ds, nullptr, 0);
        waitpid(pid_af, nullptr, 0);

        fmt::print("Shutdown complete.\n");

        return 0;
    }
    catch (const std::exception& e) {
        fmt::print(stderr, "Error: {}\n", e.what());
        return 1;
    }
} // main

namespace
{
    auto print_usage() -> void
    {
        fmt::print(
R"__(irodsServer - Launch an iRODS server

Usage: irodsServer [OPTION]... CONFIG_DIRECTORY_PATH

TODO More words ...

Mandatory arguments to long options are mandatory for short options too.

Options:
  -d, --daemonize
                TODO
  -P, --pid-file
                TODO
      --jsonschema-file
                TODO
      --dump-config-template
                TODO
      --dump-default-jsonschema
                TODO
  -h, --help    Display this help message and exit.
  -v, --version Display version information and exit.
)__");
    } // print_usage

    auto print_version_info() -> void
    {
        // TODO
    } // print_version_info

    auto print_configuration_template() -> void
    {
        // TODO
    } // print_configuration_template

    auto daemonize() -> void
    {
        // Become a background process.
        switch (fork()) {
            case -1: _exit(-1);
            case 0: break;
            default: _exit(0);
        }

        // Become session leader.
        if (setsid() == -1) {
            _exit(-1);
        }

        // Make sure we aren't the session leader.
        switch (fork()) {
            case -1: _exit(-1);
            case 0: break;
            default: _exit(0);
        }

        umask(0);
        chdir("/");

        // Get max number of open file descriptors.
        auto max_fd = sysconf(_SC_OPEN_MAX);
        if (-1 == max_fd) {
            // Indeterminate, so take a guess.
            max_fd = 8192;
        }

        // Close open file descriptors.
        for (auto fd = 0; fd < max_fd; ++fd) {
            close(fd);
        }

        constexpr auto fd_stdin  = 0;
        constexpr auto fd_stdout = 1;
        constexpr auto fd_stderr = 2;

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        auto fd = open("/dev/null", O_RDWR);
        if (fd_stdin != fd) {
            _exit(-1);
        }

        if (dup2(fd, fd_stdout) != fd_stdout) {
            _exit(-1);
        }

        if (dup2(fd, fd_stderr) != fd_stderr) {
            _exit(-1);
        }
    } // daemonize

    auto create_pid_file(const std::string& _pid_file) -> int
    {
        // Open the PID file. If it does not exist, create it and give the owner
        // permission to read and write to it.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-signed-bitwise)
        const auto fd = open(_pid_file.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd == -1) {
            //log_server::error("Could not open PID file.");
            return 1;
        }

        // Get the current open flags for the open file descriptor.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        const auto flags = fcntl(fd, F_GETFD);
        if (flags == -1) {
            //log_server::error("Could not retrieve open flags for PID file.");
            return 1;
        }

        // Enable the FD_CLOEXEC option for the open file descriptor.
        // This option will cause successful calls to exec() to close the file descriptor.
        // Keep in mind that record locks are NOT inherited by forked child processes.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-signed-bitwise)
        if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
            //log_server::error("Could not set FD_CLOEXEC on PID file.");
            return 1;
        }

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init)
        struct flock input;
        input.l_type = F_WRLCK;
        input.l_whence = SEEK_SET;
        input.l_start = 0;
        input.l_len = 0;

        // Try to acquire the write lock on the PID file. If we cannot get the lock,
        // another instance of the application must already be running or something
        // weird is going on.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        if (fcntl(fd, F_SETLK, &input) == -1) {
            if (EAGAIN == errno || EACCES == errno) {
                //log_server::error("Could not acquire write lock for PID file. Another instance "
                                  //"could be running already.");
                return 1;
            }
        }
        
        if (ftruncate(fd, 0) == -1) {
            //log_server::error("Could not truncate PID file's contents.");
            return 1;
        }

        const auto contents = fmt::format("{}\n", getpid());
        // NOLINTNEXTLINE(google-runtime-int)
        if (write(fd, contents.data(), contents.size()) != static_cast<long>(contents.size())) {
            //log_server::error("Could not write PID to PID file.");
            return 1;
        }

        return 0;
    } // create_pid_file

    auto init_logger(const nlohmann::json& _config) -> void
    {
        namespace logger = irods::experimental::log;

        logger::init(false, false);
        irods::server_properties::instance().capture(); // FIXME
        log_server::set_level(ix::log::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_SERVER)); // FIXME
        logger::set_server_type("server");
        logger::set_server_zone(_config.at(irods::KW_CFG_ZONE_NAME).get<std::string>()); // FIXME
        logger::set_server_hostname(hostname); // TODO Get hostname from config file.
    } // init_logger

    auto setup_signal_handlers() -> void
    {
        // SIGINT
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init)
        struct sigaction sa_terminate;
        sigemptyset(&sa_terminate.sa_mask);
        sa_terminate.sa_flags = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
        sa_terminate.sa_handler = [](int) { g_terminate = 1; };
        if (sigaction(SIGINT, &sa_terminate, nullptr) == -1) {
            // TODO Handle error.
        }

        // SIGTERM
        if (sigaction(SIGTERM, &sa_terminate, nullptr) == -1) {
            // TODO Handle error.
        }

        // SIGHUP
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init)
        struct sigaction sa_sighup;
        sigemptyset(&sa_sighup.sa_mask);
        sa_sighup.sa_flags = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
        sa_sighup.sa_handler = [](int) { g_reload_config = 1; };
        if (sigaction(SIGTERM, &sa_sighup, nullptr) == -1) {
            // TODO Handle error.
        }

        // TODO SIGCHLD
        // TODO SIGPIPE
    } // setup_signal_handlers
} // anonymous namespace

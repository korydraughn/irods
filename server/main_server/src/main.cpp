#include "irods/client_connection.hpp"
#include "irods/dns_cache.hpp"
#include "irods/get_grid_configuration_value.h"
#include "irods/hostname_cache.hpp"
#include "irods/irods_at_scope_exit.hpp"
#include "irods/irods_client_api_table.hpp"
#include "irods/irods_configuration_keywords.hpp"
#include "irods/irods_default_paths.hpp"
#include "irods/irods_environment_properties.hpp"
#include "irods/irods_logger.hpp"
#include "irods/irods_server_api_table.hpp"
#include "irods/irods_server_properties.hpp"
#include "irods/irods_signal.hpp"
#include "irods/irods_version.h"
#include "irods/plugins/api/delay_server_migration_types.h"
#include "irods/plugins/api/grid_configuration_types.h"
#include "irods/rcConnect.h" // For RcComm
#include "irods/rcGlobalExtern.h" // For ProcessType
#include "irods/rcMisc.h"
#include "irods/rodsClient.h"
#include "irods/rodsErrorTable.h"
#include "irods/set_delay_server_migration_info.h"

#include <boost/asio.hpp>
#include <boost/chrono.hpp>
#include <boost/interprocess/ipc/message_queue.hpp>
#include <boost/program_options.hpp>
#include <boost/stacktrace.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <jsoncons/json.hpp>
#include <jsoncons_ext/jsonschema/jsonschema.hpp>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

#ifdef __cpp_lib_filesystem
#  include <filesystem>
#else
#  include <boost/filesystem.hpp>
#endif

// __has_feature is a Clang specific feature.
// The preprocessor code below exists so that other compilers can be used (e.g. GCC).
#ifndef __has_feature
#  define __has_feature(feature) 0
#endif

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#  include <sanitizer/lsan_interface.h>

// Defines default options for running iRODS with Address Sanitizer enabled.
// This is a convenience function which allows the iRODS server to start without
// having to specify options via environment variables.
extern "C" const char* __asan_default_options()
{
    // See root CMakeLists.txt file for definition.
    return IRODS_ADDRESS_SANITIZER_DEFAULT_OPTIONS;
} // __asan_default_options
#endif

namespace
{
#ifdef __cpp_lib_filesystem
    namespace fs = std::filesystem;
#else
    namespace fs = boost::filesystem;
#endif

    namespace log_ns = irods::experimental::log;

    using log_server = irods::experimental::log::server;

    volatile std::sig_atomic_t g_terminate = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    volatile std::sig_atomic_t g_terminate_graceful = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    volatile std::sig_atomic_t g_reload_config = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    pid_t g_pid_af = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    pid_t g_pid_ds = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    auto print_usage() -> void;
    auto print_version_info() -> void;
    auto print_configuration_template() -> void;

    auto validate_configuration() -> bool;
    auto daemonize() -> void;
    auto create_pid_file(const std::string& _pid_file) -> int;
    auto init_logger() -> void;
    auto setup_signal_handlers() -> int;

    auto handle_shutdown() -> void;
    auto handle_shutdown_graceful() -> void;

    auto set_delay_server_migration_info(RcComm& _comm,
                                         std::string_view _leader,
                                         std::string_view _successor) -> void;
    auto get_delay_server_leader(RcComm& _comm) -> std::optional<std::string>;
    auto get_delay_server_successor(RcComm& _comm) -> std::optional<std::string>;
    auto launch_agent_factory(const char* _src_func) -> bool;
    auto handle_configuration_reload() -> void;
    auto launch_delay_server() -> void;
    auto migrate_and_launch_delay_server(bool& _first_boot,
                                         std::chrono::steady_clock::time_point& _time_start) -> void;
    auto log_stacktrace_files() -> void;
    auto remove_leftover_agent_info_files_for_ips() -> void;
} // anonymous namespace

auto main(int _argc, char* _argv[]) -> int
{
    // TODO Do something with this, eventually.
    [[maybe_unused]] const auto boot_time = std::chrono::system_clock::now();

    ProcessType = SERVER_PT; // This process identifies itself as a server.

    set_ips_display_name("irodsServer");

    namespace po = boost::program_options;

    po::options_description opts_desc{""};

    // clang-format off
    opts_desc.add_options()
        ("daemonize,d", "")
        ("pid-file,p", po::value<std::string>(), "")
        ("help,h", "")
        ("version,v", "");
    // clang-format on

    try {
        po::variables_map vm;
        po::store(po::command_line_parser(_argc, _argv).options(opts_desc).run(), vm);
        po::notify(vm);

        if (vm.count("help") > 0) {
            print_usage();
            return 0;
        }

        if (vm.count("version") > 0) {
            print_version_info();
            return 0;
        }

        if (vm.count("daemonize") > 0) {
            daemonize();
        }

        std::string pid_file = (irods::get_irods_runstate_directory() / "irods/irods-server.pid").string();
        if (const auto iter = vm.find("pid-file"); std::end(vm) != iter) {
            pid_file = std::move(iter->second.as<std::string>());
        }

        if (create_pid_file(pid_file) != 0) {
            fmt::print(stderr, "Error: could not create PID file [{}].\n", pid_file);
            return 1;
        }
    }
    catch (const std::exception& e) {
        fmt::print(stderr, "Error: {}\n", e.what());
        return 1;
    }

    try {
        if (!validate_configuration()) {
            return 1;
        }

        const auto config_file_path = irods::get_irods_config_directory() / "server_config.json";
        irods::server_properties::instance().init(config_file_path.c_str());
        irods::environment_properties::instance(); // Load the local environment file.

        // TODO Consider removing the need for these along with all options.
        // All logging should be controlled via the new logging system.
        rodsLogLevel(LOG_NOTICE);
    	rodsLogSqlReq(0);

        init_logger();

        // Setting up signal handlers here removes the need for reacting to shutdown signals
        // such as SIGINT and SIGTERM during the startup sequence.
        if (setup_signal_handlers() == -1) {
            log_server::error("{}: Error setting up signal handlers for main server process.", __func__);
            return 1;
        }

        log_server::info("{}: Initializing shared memory for main server process.", __func__);

        namespace hnc = irods::experimental::net::hostname_cache;
        hnc::init("irods_hostname_cache5", irods::get_hostname_cache_shared_memory_size()); // TODO Rename

        namespace dnsc = irods::experimental::net::dns_cache;
        dnsc::init("irods_dns_cache5", irods::get_dns_cache_shared_memory_size()); // TODO Rename

        // Load server API table so that API plugins which are needed to stand up the server are
        // available for use.
        auto& server_api_table = irods::get_server_api_table();
        auto& pack_table = irods::get_pack_table();
        if (const auto res = irods::init_api_table(server_api_table, pack_table, false); !res.ok()) {
            log_server::error("{}: {}", __func__, res.result());
            return 1;
        }

        // If this is a catalog service consumer, the client API table should be loaded so that
        // client calls can be made to the catalog service provider as part of the server
        // initialization process.
        auto& client_api_table = irods::get_client_api_table();
        if (const auto res = irods::init_api_table(client_api_table, pack_table, false); !res.ok()) {
            log_server::error("{}: {}", __func__, res.result());
            return 1;
        }

        if (!launch_agent_factory(__func__)) {
            return 1;
        }

        // Enter parent process main loop.
        // 
        // This process should never introduce threads. Everything it cares about must be handled
        // within the loop. This keeps things simple and straight forward.
        //
        // THE PARENT PROCESS IS THE ONLY PROCESS THAT SHOULD/CAN REACT TO SIGNALS!
        // EVERYTHING IS PROPAGATED THROUGH/FROM THE PARENT PROCESS!

        // dsm = Short for delay server migration
        // This is used to control the frequency of the delay server migration logic.
        auto dsm_time_start = std::chrono::steady_clock::now();

        // TODO Remove this and just delay the startup of the delay server. Even better if the delay server
        // only starts up after the agent factory is accepting connections.
        auto first_boot = true;

        while (true) {
            if (g_terminate) {
                log_server::info("{}: Received shutdown instruction. Exiting server main loop.", __func__);
                handle_shutdown();
                break;
            }

            if (g_terminate_graceful) {
                log_server::info("{}: Received graceful shutdown instruction. Exiting server main loop.", __func__);
                handle_shutdown_graceful();
                break;
            }

            if (g_reload_config) {
                handle_configuration_reload();
            }

            // Clean up any zombie child processes if they exist. These appear following a configuration
            // reload. We call waitpid() multiple times because the main server processes may have multiple
            // child processes.
            // TODO The number of iterations should always match the number of child processes.
            for (int i = 0, children = 2; i < children; ++i) {
                waitpid(-1, nullptr, WNOHANG);
            }

            // TODO Add logic to fork a new agent factory if not running.

            log_stacktrace_files();
            remove_leftover_agent_info_files_for_ips();
            migrate_and_launch_delay_server(first_boot, dsm_time_start);

            std::this_thread::sleep_for(std::chrono::seconds{1});
        }

        log_server::info("{}: Server shutdown complete.", __func__);

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
        // TODO Update help text.
        fmt::print(
R"__(irodsServer - Launch an iRODS server

Usage: irodsServer [OPTION]...

TODO More words ...

Mandatory arguments to long options are mandatory for short options too.

Options:
  -d, --daemonize
                Run server instance in the background as a service.
  -p, --pid-file FILE
                The absolute path to FILE, which will be used as the
                PID file for the server instance.
  -h, --help    Display this help message and exit.
  -v, --version Display version information and exit.
)__");
    } // print_usage

    auto print_version_info() -> void
    {
        constexpr const auto commit = std::string_view{IRODS_GIT_COMMIT}.substr(0, 7);
        fmt::print("irodsServer v{}.{}.{}-{}\n", IRODS_VERSION_MAJOR, IRODS_VERSION_MINOR, IRODS_VERSION_PATCHLEVEL, commit);
    } // print_version_info

    auto validate_configuration() -> bool
    {
        try {
            namespace jsonschema = jsoncons::jsonschema;

            std::ifstream config_file{irods::get_irods_config_directory() / "server_config.json"};
            if (!config_file) {
                return false;
            }
            const auto config = jsoncons::json::parse(config_file);

            // NOLINTNEXTLINE(bugprone-lambda-function-name)
            const auto do_validate = [fn = __func__](const auto& _config, const std::string& _schema_file) {
                fmt::print("{}: JSON schema file = [{}].\n", fn, _schema_file);
                std::ifstream in{_schema_file};
                const auto schema = jsoncons::json::parse(in); // The stream object cannot be instantiated inline.
                const auto compiled = jsonschema::make_json_schema(schema);

                jsoncons::json_decoder<jsoncons::ojson> decoder;
                compiled.validate(_config, decoder);
                const auto json_result = decoder.get_result();

                if (!json_result.empty()) {
                    std::ostringstream out;
                    out << pretty_print(json_result);
                    fmt::print("{}: {}\n", fn, out.str());
                    return false;
                }

                return true;
            };

            // Validate the server configuration. If that succeeds, move on to validating the
            // irods_environment.json file.
            if (do_validate(config, config.at("json_schema_file").as<std::string>())) {
                std::string env_file;
                std::string session_file;
                if (const auto err = irods::get_json_environment_file(env_file, session_file); !err.ok()) {
                    fmt::print("{}: {}\n", __func__, err.status());
                    return false;
                }

                // Validate the irods_environment.json file referenced by the server configuration.
                std::ifstream in{env_file};
                if (!in) {
                    return false;
                }
                const auto env_file_config = jsoncons::json::parse(in);
                return do_validate(env_file_config, config.at("environment_json_schema_file").as<std::string>());
            }
        }
        catch (const std::exception& e) {
            fmt::print("{}: {}\n", __func__, e.what());
        }

        return false;
    } // validate_configuration

    auto daemonize() -> void
    {
        // Become a background process.
        switch (fork()) {
            case -1: _exit(1);
            case  0: break;
            default: _exit(0);
        }

        // Become session leader.
        if (setsid() == -1) {
            _exit(1);
        }

        // Make sure we aren't the session leader.
        switch (fork()) {
            case -1: _exit(1);
            case  0: break;
            default: _exit(0);
        }

        umask(0);
        chdir("/"); // TODO Should we keep this? Need to refresh my memory on why this is important.

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

        // clang-format off
        constexpr auto fd_stdin  = 0;
        constexpr auto fd_stdout = 1;
        constexpr auto fd_stderr = 2;
        // clang-format on

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        auto fd = open("/dev/null", O_RDWR);
        if (fd_stdin != fd) {
            _exit(1);
        }

        if (dup2(fd, fd_stdout) != fd_stdout) {
            _exit(1);
        }

        if (dup2(fd, fd_stderr) != fd_stderr) {
            _exit(1);
        }
    } // daemonize

    auto create_pid_file(const std::string& _pid_file) -> int
    {
        // Open the PID file. If it does not exist, create it and give the owner
        // permission to read and write to it.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-signed-bitwise)
        const auto fd = open(_pid_file.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd == -1) {
            fmt::print("Could not open PID file.\n");
            return 1;
        }

        // Get the current open flags for the open file descriptor.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        const auto flags = fcntl(fd, F_GETFD);
        if (flags == -1) {
            fmt::print("Could not retrieve open flags for PID file.\n");
            return 1;
        }

        // Enable the FD_CLOEXEC option for the open file descriptor.
        // This option will cause successful calls to exec() to close the file descriptor.
        // Keep in mind that record locks are NOT inherited by forked child processes.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-signed-bitwise)
        if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
            fmt::print("Could not set FD_CLOEXEC on PID file.\n");
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
                fmt::print("Could not acquire write lock for PID file. Another instance "
                           "could be running already.\n");
                return 1;
            }
        }
        
        if (ftruncate(fd, 0) == -1) {
            fmt::print("Could not truncate PID file's contents.\n");
            return 1;
        }

        const auto contents = fmt::format("{}\n", getpid());
        // NOLINTNEXTLINE(google-runtime-int)
        if (write(fd, contents.data(), contents.size()) != static_cast<long>(contents.size())) {
            fmt::print("Could not write PID to PID file.\n");
            return 1;
        }

        return 0;
    } // create_pid_file

    auto init_logger() -> void
    {
        log_ns::init(false, false); // TODO Restore test mode. stdout requires synchronization so it may be dropped.
        log_server::set_level(log_ns::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_SERVER));
        log_ns::set_server_type("server");
        log_ns::set_server_zone(irods::get_server_property<std::string>(irods::KW_CFG_ZONE_NAME));
        log_ns::set_server_hostname(boost::asio::ip::host_name());
    } // init_logger

    auto setup_signal_handlers() -> int
    {
        // DO NOT memset sigaction structures!

        std::signal(SIGUSR1, SIG_IGN); // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)

        // SIGINT
        struct sigaction sa_terminate; // NOLINT(cppcoreguidelines-pro-type-member-init)
        sigemptyset(&sa_terminate.sa_mask);
        sa_terminate.sa_flags = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
        sa_terminate.sa_handler = [](int) {
            // Only respond if the server hasn't been instructed to terminate already.
            if (0 == g_terminate_graceful) {
                g_terminate = 1;
            }
        };
        if (sigaction(SIGINT, &sa_terminate, nullptr) == -1) {
            return -1;
        }

        // SIGTERM
        if (sigaction(SIGTERM, &sa_terminate, nullptr) == -1) {
            return -1;
        }

        // SIGQUIT (graceful shutdown)
        struct sigaction sa_terminate_graceful; // NOLINT(cppcoreguidelines-pro-type-member-init)
        sigemptyset(&sa_terminate_graceful.sa_mask);
        sa_terminate_graceful.sa_flags = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
        sa_terminate_graceful.sa_handler = [](int) {
            // Only respond if the server hasn't been instructed to terminate already.
            if (0 == g_terminate) {
                g_terminate_graceful = 1;
            }
        };
        if (sigaction(SIGQUIT, &sa_terminate_graceful, nullptr) == -1) {
            return -1;
        }

        // SIGHUP
        struct sigaction sa_sighup; // NOLINT(cppcoreguidelines-pro-type-member-init)
        sigemptyset(&sa_sighup.sa_mask);
        sa_sighup.sa_flags = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
        sa_sighup.sa_handler = [](int) { g_reload_config = 1; };
        if (sigaction(SIGHUP, &sa_sighup, nullptr) == -1) {
            return -1;
        }

        irods::setup_unrecoverable_signal_handlers();

        return 0;
    } // setup_signal_handlers

    auto handle_shutdown() -> void
    {
        kill(g_pid_af, SIGTERM);

        if (g_pid_ds > 0) {
            kill(g_pid_ds, SIGTERM);
        }

        waitpid(g_pid_af, nullptr, 0);
        log_server::info("{}: Agent Factory shutdown complete.", __func__);

        if (g_pid_ds > 0) {
            waitpid(g_pid_ds, nullptr, 0);
            log_server::info("{}: Delay Server shutdown complete.", __func__);
        }
    } // handle_shutdown

    auto handle_shutdown_graceful() -> void
    {
        kill(g_pid_af, SIGQUIT);

        if (g_pid_ds > 0) {
            kill(g_pid_ds, SIGTERM);
        }

        waitpid(g_pid_af, nullptr, 0);
        log_server::info("{}: Agent Factory shutdown complete.", __func__);

        if (g_pid_ds > 0) {
            waitpid(g_pid_ds, nullptr, 0);
            log_server::info("{}: Delay Server shutdown complete.", __func__);
        }
    } // handle_shutdown_graceful

    auto get_delay_server_leader(RcComm& _comm) -> std::optional<std::string>
    {
        GridConfigurationInput input{};
        std::strcpy(input.name_space, "delay_server");
        std::strcpy(input.option_name, "leader");

        GridConfigurationOutput* output{};
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory,cppcoreguidelines-no-malloc)
        irods::at_scope_exit free_output{[&output] { std::free(output); }};

        if (const auto ec = rc_get_grid_configuration_value(&_comm, &input, &output); ec < 0) {
            log_server::error(
                "Could not retrieve delay server migration information from catalog "
                "[error_code={}, namespace=delay_server, option_name=leader].",
                ec);
            return std::nullopt;
        }
        
        return output->option_value;
    } // get_delay_server_leader

    auto get_delay_server_successor(RcComm& _comm) -> std::optional<std::string>
    {
        GridConfigurationInput input{};
        std::strcpy(input.name_space, "delay_server");
        std::strcpy(input.option_name, "successor");

        GridConfigurationOutput* output{};
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory,cppcoreguidelines-no-malloc)
        irods::at_scope_exit free_output{[&output] { std::free(output); }};

        if (const auto ec = rc_get_grid_configuration_value(&_comm, &input, &output); ec < 0) {
            log_server::error(
                "Could not retrieve delay server migration information from catalog "
                "[error_code={}, namespace=delay_server, option_name=successor].",
                ec);
            return std::nullopt;
        }
        
        return output->option_value;
    } // get_delay_server_successor

    auto set_delay_server_migration_info(RcComm& _comm,
                                         std::string_view _leader,
                                         std::string_view _successor) -> void
    {
        DelayServerMigrationInput input{};
        _leader.copy(input.leader, sizeof(DelayServerMigrationInput::leader));
        _successor.copy(input.successor, sizeof(DelayServerMigrationInput::successor));

        if (const auto ec = rc_set_delay_server_migration_info(&_comm, &input); ec < 0) {
            log_server::error(
                "Failed to set delay server migration info in R_GRID_CONFIGURATION "
                "[error_code={}, leader={}, successor={}].",
                ec,
                _leader,
                _successor);
        }
    } // set_delay_server_migration_info

    auto launch_agent_factory(const char* _src_func) -> bool
    {
        log_server::info("{}: Launching Agent Factory.", _src_func);

        g_pid_af = fork();

        if (0 == g_pid_af) {
            std::string hn_shm_name{irods::experimental::net::hostname_cache::shared_memory_name()};
            std::string dns_shm_name{irods::experimental::net::dns_cache::shared_memory_name()};

            const auto binary = irods::get_irods_sbin_directory() / "irodsAgent";

            // NOLINTNEXTLINE(modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
            char* pname = strdup(binary.c_str());
            // NOLINTNEXTLINE(modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
            char boot_time_str[] = ""; // TODO Forward the boot time.
            // NOLINTNEXTLINE(modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
            char* args[] = {
                pname,
                hn_shm_name.data(),
                dns_shm_name.data(),
                boot_time_str,
                nullptr
            };

            execv(pname, args);
            _exit(1);
        }
        else if (-1 == g_pid_af) {
            log_server::error("{}: Could not launch agent factory.", __func__);
            return false;
        }

        log_server::info("{}: Agent Factory PID = [{}].", __func__, g_pid_af);
        return true;
    } // launch_agent_factory

    auto handle_configuration_reload() -> void
    {
        log_server::info("{}: Received configuration reload instruction. Reloading configuration.", __func__);

        if (!validate_configuration()) {
            log_server::error("{}: Invalid configuration. Continuing to run with previous configuration.", __func__);
            return;
        }

        if (g_pid_ds > 0) {
            log_server::info("{}: Sending SIGTERM to delay server.", __func__);
            kill(g_pid_ds, SIGTERM);
        }

        log_server::info("{}: Sending SIGQUIT to agent factory.", __func__);
        kill(g_pid_af, SIGQUIT);

        // Reset this variable so that the delay server migration logic can handle
        // the relaunching of the delay server for us.
        g_pid_ds = 0;

        try {
            log_server::info("{}: Reloading configuration for main server process.", __func__);
            irods::server_properties::instance().reload();
            irods::environment_properties::instance().capture();

            // Update the logger for the main server process.
            log_server::set_level(log_ns::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_SERVER));
            log_ns::set_server_zone(irods::get_server_property<std::string>(irods::KW_CFG_ZONE_NAME));
            log_ns::set_server_hostname(boost::asio::ip::host_name());
        }
        catch (const std::exception& e) {
            log_server::error("{}: Error reloading configuration for main server process: {}", __func__, e.what());
        }

        // Launch a new agent factory to serve client requests.
        // The previous agent factory is allowed to linger around until its children terminate.
        launch_agent_factory(__func__);

        // We do not need to manually launch the delay server because the delay server migration
        // logic will handle that for us.

        g_reload_config = 0;
    } // handle_configuration_reload

    auto launch_delay_server() -> void
    {
        auto launch = (0 == g_pid_ds);

        if (g_pid_ds > 0) {
            if (const auto ec = kill(g_pid_ds, 0); ec == -1) {
                if (EPERM == errno || ESRCH == errno) {
                    launch = true;
                    g_pid_ds = 0;
                }
            }
        }

        if (launch) {
            log_server::info("{}: Launching Delay Server.", __func__);
            g_pid_ds = fork();
            if (0 == g_pid_ds) {
                const auto binary = irods::get_irods_sbin_directory() / "irodsDelayServer";
                // NOLINTNEXTLINE(modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
                char* pname = strdup(binary.c_str());
                // NOLINTNEXTLINE(modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
                char* args[] = {pname, nullptr}; // TODO Restore test mode.
                execv(pname, args);
                _exit(1);
            }
            else if (g_pid_ds > 0) {
                log_server::info("{}: Delay Server PID = [{}].", __func__, g_pid_ds);
            }
            else {
                log_server::error("{}: Could not launch delay server [errno={}].", __func__, errno);
                g_pid_ds = 0;
            }
        }
    } // launch_delay_server

    auto migrate_and_launch_delay_server(bool& _first_boot,
                                         std::chrono::steady_clock::time_point& _time_start) -> void
    {
        using namespace std::chrono_literals;

        // By remembering the initial value of _first_boot, we can keep the initial connection
        // to the agent factory quiet. The reason for this is because the agent factory isn't guaranteed
        // to be accepting connections by the time the first client connection is made from the main server
        // process.
        const auto did_first_boot = _first_boot;

        // TODO Replace 10s with the configuration value from server_config.json.
        if (auto now = std::chrono::steady_clock::now(); _first_boot || (now - _time_start > 10s)) {
            _first_boot = false;
            _time_start = now;

            const auto hostname = boost::asio::ip::host_name();
            std::optional<std::string> leader;
            std::optional<std::string> successor;

            try {
                irods::experimental::client_connection conn;
                leader = get_delay_server_leader(conn);
                successor = get_delay_server_successor(conn);

                if (leader && successor) {
                    log_server::debug("{}: Delay server leader [{}] and successor [{}].", __func__, *leader, *successor);

                    // 4 cases:
                    // L  S
                    // ----
                    // 0  0 (invalid state / no-op)
                    // 1  0 (migration complete)
                    // 0  1 (leader has shut down ds, successor launching ds)
                    // 1  1 (leader running ds, admin requested migration)

                    // This server is the leader and may be running a delay server.
                    if (hostname == *leader) {
                        if (hostname == *successor) {
                            launch_delay_server();

                            // Clear successor entry in catalog. This isn't necessary, but helps
                            // keep the admin from becoming confused.
                            if (g_pid_ds > 0) {
                                set_delay_server_migration_info(conn, KW_DELAY_SERVER_MIGRATION_IGNORE, "");
                            }
                        }
                        else if (!successor->empty()) {
                            // Migration requested. Stop local delay server if running and clear the
                            // leader entry in the catalog.
                            if (g_pid_ds > 0) {
                                kill(g_pid_ds, SIGTERM);

                                // Wait for delay server to complete current tasks. Depending on the workload, this
                                // could take minutes, hours, days to complete.
                                int status = 0;
                                waitpid(g_pid_ds, &status, 0);
                                log_server::info("Delay server has completed shutdown [exit_code={}].", WEXITSTATUS(status));
                                g_pid_ds = 0;
                            }

                            // TODO This isn't necessary if we can get task locking working (i.e. delay servers
                            // lock tasks just before execution).
                            //
                            // TODO However, we can uncomment the following if the server can confirm the host
                            // doesn't exist in the zone.
                            //
                            // Clear the leader entry. This acts as a signal to the successor server
                            // that it is safe to launch the delay server.
                            //set_delay_server_migration_info(conn, "", KW_DELAY_SERVER_MIGRATION_IGNORE);
                        }
                        else {
                            launch_delay_server();
                        }
                    }
                    else if (hostname == *successor) {
                        // leader == successor is covered by first if-branch.
#if 0
                        if (leader->empty()) {
                            // The leader's delay server has been shut down. Launch the delay server if
                            // not running already.

                            log_server::info("{}: Launching Delay Server.", __func__);
                            g_pid_ds = fork();
                            if (0 == g_pid_ds) {
                                char pname[] = "/usr/sbin/irodsDelayServer"; // TODO This MUST NOT assume /usr/sbin.
                                char* args[] = {pname, nullptr}; // TODO Needs to take the config file path.
                                execv(pname, args);
                                _exit(1);
                            }
                            else if (g_pid_ds > 0) {
                                log_server::info("{}: Delay Server PID = [{}].", __func__, g_pid_ds);
                                set_delay_server_migration_info(conn, hostname, "");
                            }
                            else {
                                log_server::error("{}: Could not launch delay server [errno={}].", __func__, errno);
                            }
                        }
                        else {
                            // TODO
                            // Determine when it's safe to auto-promote the successor to the leader
                            // (i.e. the leader value is never cleared).

                            // 1. Connect to leader.
                            // 2. Use API to get the PID of the delay server.
                            // 3. If we find a PID for the delay server, try again later (because we're waiting for it to shutdown).
                            // 4. If we fail to reach the leader (due to network, etc), start counting failures.
                            // 5. If the successor fails to get the PID N times, auto-promote successor to leader.
                        }
#else
                        // Delay servers lock tasks before execution. This allows the successor server
                        // to launch a delay server without duplicating work.
                        launch_delay_server();

                        if (g_pid_ds > 0) {
                            set_delay_server_migration_info(conn, hostname, "");
                        }
#endif
                    }
                    else {
                        // TODO Reap child processes: agent factory, delay server
                        // TODO Fork agent factory and/or delay server again if necessary.
                    }
                }
            }
            catch (const irods::exception& e) {
                // It's possible the agent factory may not be ready for client requests.
                // This situation is most visible during startup, when the delay server migration
                // logic attempts to fetch the leader and successor hostnames from the catalog.
                //
                // If and when the connection from the main server process fails, log the error
                // silently. We want startup (i.e. first boot) to clean.
                if (did_first_boot && e.code() == USER_SOCK_CONNECT_ERR) {
                    log_server::trace("{}: {}", __func__, e.client_display_what());
                }
                else {
                    log_server::error("{}: {}", __func__, e.client_display_what());
                }
            }
            catch (const std::exception& e) {
                log_server::error("{}: {}", __func__, e.what());
            }
        }
    } // migrate_and_launch_delay_server

    auto log_stacktrace_files() -> void
    {
        for (auto&& entry : fs::directory_iterator{irods::get_irods_stacktrace_directory().c_str()}) {
            // Expected filename format:
            //
            //     <epoch_seconds>.<epoch_milliseconds>.<agent_pid>
            //
            // 1. Extract the timestamp from the filename and convert it to ISO8601 format.
            // 2. Extract the agent pid from the filename.
            const auto p = entry.path().generic_string();

            if (p.ends_with(irods::STACKTRACE_NOT_READY_FOR_LOGGING_SUFFIX)) {
                log_server::trace("Skipping [{}] ...", p);
                continue;
            }

            auto slash_pos = p.rfind("/");

            if (slash_pos == std::string::npos) {
                log_server::trace("Skipping [{}]. No forward slash separator found.", p);
                continue;
            }

            ++slash_pos;
            const auto first_dot_pos = p.find(".", slash_pos);

            if (first_dot_pos == std::string::npos) {
                log_server::trace("Skipping [{}]. No dot separator found.", p);
                continue;
            }

            const auto last_dot_pos = p.rfind(".");

            if (last_dot_pos == std::string::npos || last_dot_pos == first_dot_pos) {
                log_server::trace("Skipping [{}]. No dot separator found.", p);
                continue;
            }

            const auto epoch_seconds = p.substr(slash_pos, first_dot_pos - slash_pos);
            const auto remaining_millis = p.substr(first_dot_pos + 1, last_dot_pos - (first_dot_pos + 1));
            const auto pid = p.substr(last_dot_pos + 1);
            log_server::trace(
                "epoch seconds = [{}], remaining millis = [{}], agent pid = [{}]",
                epoch_seconds,
                remaining_millis,
                pid);

            try {
                // Convert the epoch value to ISO8601 format.
                log_server::trace("Converting epoch seconds to UTC timestamp.");
                using boost::chrono::system_clock;
                using boost::chrono::time_fmt;
                const auto tp = system_clock::from_time_t(std::stoll(epoch_seconds));
                std::ostringstream utc_ss;
                utc_ss << time_fmt(boost::chrono::timezone::utc, "%FT%T") << tp;

                // Read the contents of the file.
                std::ifstream file{p};
                const auto stacktrace = boost::stacktrace::stacktrace::from_dump(file);
                file.close();

                // 3. Write the contents of the stacktrace file to syslog.
                irods::experimental::log::server::critical({
                    {"log_message", boost::stacktrace::to_string(stacktrace)},
                    {"stacktrace_agent_pid", pid},
                    {"stacktrace_timestamp_utc", fmt::format("{}.{}Z", utc_ss.str(), remaining_millis)},
                    {"stacktrace_timestamp_epoch_seconds", epoch_seconds},
                    {"stacktrace_timestamp_epoch_milliseconds", remaining_millis}
                });

                // 4. Delete the stacktrace file.
                //
                // We don't want the stacktrace files to go away without making it into the log.
                // We can't rely on the log invocation above because of syslog.
                // We don't want these files to accumulate for long running servers.
                log_server::trace("Removing stacktrace file from disk.");
                fs::remove(entry);
            }
            catch (...) {
                // Something happened while logging the stacktrace file.
                // Leaving the stacktrace file in-place for processing later.
                log_server::trace("Caught exception while processing stacktrace file.");
            }
        }
    } // log_stacktrace_files

    auto remove_leftover_agent_info_files_for_ips() -> void
    {
        for (const auto& entry : fs::directory_iterator{irods::get_irods_proc_directory().c_str()}) {
            try {
                const auto agent_pid = std::stoi(entry.path().stem().string());

                // If the agent process does not exist or the main server process doesn't
                // have permission to send signals to the agent process, then remove the
                // agent file so that ips doesn't report it as an active agent.
                if (kill(agent_pid, 0) == -1 && (ESRCH == errno || EPERM == errno)) {
                    fs::remove(entry);
                }
            }
            catch (const std::exception& e) {
                log_server::error("{}: {}: {}", __func__, entry.path().c_str(), e.what());
            }
        };
    } // remove_leftover_agent_info_files_for_ips
} // anonymous namespace
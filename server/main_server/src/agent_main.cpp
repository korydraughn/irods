// Things we no longer need:
//
//      - get64RandomBytes() (func)
//      - resource_manager::print_local_resources() (member func)
//          - invoked inside initServer()
//      - recordServerProcess() (func)
//      - purge functions in rodsServer.cpp
//
// Things we need:
//
//      - initServer() (func)
//      - initServerMain() (func)
//      - createAndSetRECacheSalt() (func) ???
//          - NREP?
//      - 
//
// Things we need to make a decision about:
//
//      - shared memory originally initialized by the main server process
//      - stacktrace watcher

#include "irods/agent_globals.hpp"
#include "irods/agent_pid_table.hpp"
#include "irods/client_api_allowlist.hpp"
#include "irods/dns_cache.hpp"
#include "irods/hostname_cache.hpp"
#include "irods/initServer.hpp"
#include "irods/irods_at_scope_exit.hpp"
#include "irods/irods_buffer_encryption.hpp" // For RE cache salt
#include "irods/irods_client_api_table.hpp"
#include "irods/irods_client_server_negotiation.hpp"
#include "irods/irods_configuration_keywords.hpp"
#include "irods/irods_configuration_parser.hpp" // For key_path_t
#include "irods/irods_dynamic_cast.hpp"
#include "irods/irods_environment_properties.hpp"
#include "irods/irods_exception.hpp"
#include "irods/irods_logger.hpp"
#include "irods/irods_network_factory.hpp"
#include "irods/irods_network_object.hpp"
#include "irods/irods_re_plugin.hpp"
#include "irods/irods_server_api_table.hpp"
#include "irods/irods_server_properties.hpp"
#include "irods/irods_signal.hpp"
#include "irods/irods_threads.hpp"
#include "irods/locks.hpp" // For removeMutex TODO remove eventually
#include "irods/miscServerFunct.hpp" // For get_catalog_service_role
#include "irods/plugin_lifetime_manager.hpp"
#include "irods/rcConnect.h"
#include "irods/rcGlobalExtern.h" // For ProcessType
#include "irods/replica_access_table.hpp"
#include "irods/replica_state_table.hpp"
#include "irods/rodsConnect.h"
#include "irods/rodsErrorTable.h"
#include "irods/rsApiHandler.hpp"
#include "irods/rsGlobalExtern.hpp"
#include "irods/rsIcatOpr.hpp"
#include "irods/sharedmemory.hpp"
#include "irods/sockComm.h"
#include "irods/sockCommNetworkInterface.hpp"
#include "irods/sslSockComm.h"

#include <boost/asio.hpp>
#include <boost/interprocess/ipc/message_queue.hpp>
#include <boost/program_options.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <chrono>
#include <csignal>
#include <fstream>
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

    using log_af = irods::experimental::log::agent_factory;
    using log_agent = irods::experimental::log::agent;

    // TODO Remove
    //volatile std::sig_atomic_t g_terminate = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    const char* g_ips_data_directory{}; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    std::time_t g_graceful_shutdown_timeout{}; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    auto init_logger(const nlohmann::json& _config) -> void;
    auto load_log_levels_for_loggers() -> void;
    auto setup_signal_handlers() -> int;
    auto createAndSetRECacheSalt() -> irods::error;
    auto init_shared_memory_for_plugin(const nlohmann::json& _plugin_object) -> bool;
    auto init_shared_memory_for_plugins() -> irods::error;
    auto deinit_shared_memory_for_plugin(const nlohmann::json& _plugin_object) -> bool;
    auto deinit_shared_memory_for_plugins() -> irods::error;

    // TODO Refactor these functions.
    auto initServer(RsComm& _comm) -> int;
    auto initServerMain(RsComm& _comm, const bool _enable_test_mode, const bool _write_to_stdout) -> int;

    auto handle_client_request(int _socket_fd, std::time_t _created_at) -> int;
    auto cleanup() -> void;
    auto cleanupAndExit(int status) -> void;
    auto set_rule_engine_globals(RsComm& _comm) -> void;
    auto agentMain(RsComm& _comm) -> int;
    auto create_agent_pid_file_for_ips(const RsComm& _comm, std::time_t _created_at) -> void;

    auto reap_agent_processes(bool _shutting_down) -> void;
} // anonymous namespace

int main(int _argc, char* _argv[])
{
    ProcessType = AGENT_PT; // This process identifies itself as the agent factory or an agent.

    std::string config_file_path;
    std::string hostname_cache_shm_name;
    std::string dns_cache_shm_name;

    // TODO Boost.ProgramOptions isn't necessary.

    namespace po = boost::program_options;

    po::options_description opts_desc{""};

    // clang-format off
    opts_desc.add_options()
        ("config-file,f", po::value<std::string>(), "")
        ("hostname-cache-shm-name,x", po::value<std::string>(), "")
        ("dns-cache-shm-name,y", po::value<std::string>(), "")
        ("boot-time,b", po::value<std::string>(), "");
    // clang-format on

    po::positional_options_description pod;
    pod.add("config-file", 1);
    pod.add("hostname-cache-shm-name", 1);
    pod.add("dns-cache-shm-name", 1);
    pod.add("boot-time", 1);

    try {
        po::variables_map vm;
        po::store(po::command_line_parser(_argc, _argv).options(opts_desc).positional(pod).run(), vm);
        po::notify(vm);

        if (auto iter = vm.find("config-file"); std::end(vm) != iter) {
            config_file_path = std::move(iter->second.as<std::string>());
        }
        else {
            fmt::print(stderr, "Error: Missing [CONFIG_FILE_PATH] parameter.");
            return 1;
        }

        if (auto iter = vm.find("hostname-cache-shm-name"); std::end(vm) != iter) {
            hostname_cache_shm_name = std::move(iter->second.as<std::string>());
        }
        else {
            fmt::print(stderr, "Error: Missing [HOSTNAME_CACHE_SHM_NAME] parameter.");
            return 1;
        }

        if (auto iter = vm.find("dns-cache-shm-name"); std::end(vm) != iter) {
            dns_cache_shm_name = std::move(iter->second.as<std::string>());
        }
        else {
            fmt::print(stderr, "Error: Missing [DNS_CACHE_SHM_NAME] parameter.");
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
        // TODO Pick one of the following.
        config = json::parse(std::ifstream{config_file_path});
        irods::server_properties::instance().init(config_file_path.c_str());
        irods::environment_properties::instance().capture(); // TODO This MUST NOT assume /var/lib/irods.

        // Initialize global pointer to ips data directory for agent cleanup.
        // This is required so that the signal handler for reaping agents remains async-signal-safe.
        // TODO Need a better way to get this.
        g_ips_data_directory = config.at("ips_data_directory").get_ref<const std::string&>().c_str();

        // Capture the gracefule shutdown timeout value for agent cleanup.
        // This is required so that the signal handler for reaping agents remains async-signal-safe.
        // TODO Need a better way to get this.
        g_graceful_shutdown_timeout = config.at("graceful_shutdown_timeout_in_seconds").get<int>();

        // TODO Consider removing the need for these along with all options.
        // All logging should be controlled via the new logging system.
        rodsLogLevel(LOG_NOTICE);
    	rodsLogSqlReq(0);

        // To see log messages from rsyslog, you must add irodsAgent5 to /etc/rsyslog.d/00-irods.conf.
        init_logger(config);

        log_af::info("{}: Initializing loggers for agent factory.", __func__);
        // TODO These MUST NOT assume /etc/irods/server_config.json.
        load_log_levels_for_loggers();

        // We only need to inform the agent factory of where to write stacktrace files. The main
        // server process is responsible for reading and writing them to the log file.
        irods::set_stacktrace_directory(config.at("stacktrace_directory").get_ref<const std::string&>());

        log_af::info("{}: Initializing signal handlers for agent factory.", __func__);
        if (setup_signal_handlers() == -1) {
            log_af::error("{}: Error setting up signal handlers for agent factory process.", __func__);
            return 1;
        }

        log_af::info("{}: Initializing client allowlist for agent factory.", __func__);
        irods::client_api_allowlist::init();

        // TODO
        //remove_leftover_rulebase_pid_files(*server_config);

        // TODO Initialize shared memory systems.
        log_af::info("{}: Initializing shared memory for agent factory.", __func__);

        irods::experimental::agent_pid_table::init();
        irods::at_scope_exit deinit_agent_pid_table{[] { irods::experimental::agent_pid_table::deinit(); }};

        irods::experimental::net::hostname_cache::init_no_create(hostname_cache_shm_name);
        irods::experimental::net::dns_cache::init_no_create(dns_cache_shm_name);

        irods::experimental::replica_access_table::init();
        irods::at_scope_exit deinit_replica_access_table{[] { irods::experimental::replica_access_table::deinit(); }};

        log_af::info("{}: Initializing zone information for agent factory.", __func__);

        // Set the default value for evicting DNS cache entries.
        using key_path_t = irods::configuration_parser::key_path_t;
        irods::set_server_property(
            key_path_t{irods::KW_CFG_ADVANCED_SETTINGS, irods::KW_CFG_DNS_CACHE, irods::KW_CFG_EVICTION_AGE_IN_SECONDS},
            irods::get_dns_cache_eviction_age());
        // Set the default value for evicting hostname cache entries.
        irods::set_server_property(
            key_path_t{irods::KW_CFG_ADVANCED_SETTINGS, irods::KW_CFG_HOSTNAME_CACHE, irods::KW_CFG_EVICTION_AGE_IN_SECONDS},
            irods::get_hostname_cache_eviction_age());

        if (const auto res = createAndSetRECacheSalt(); !res.ok()) {
            log_af::error("{}: createAndSetRECacheSalt error.\n{}", __func__, res.result());
            return 1;
        }

        if (const auto res = init_shared_memory_for_plugins(); !res.ok()) {
            log_af::error("{}: Failed to initialize shared memory for plugins. [error code={}]", __func__, res.code());
            return 1;
        }
        irods::at_scope_exit remove_shared_memory{[pid_af = getpid()] {
            // Only the agent factory is allowed to deinit the shared memory associated
            // with plugins. This is especially important because the NREP's shared memory
            // is shared by all agents running on the server.
            //
            // TODO Should the agent factory always do this?
            // What happens if the agent factory terminates before a agent completes?
            // The agent could be running policy that relies on the shared memory.
            // Should the agent factory kill all agents immediately since the agents don't
            // respond to SIGINT / SIGTERM immediately?
            if (getpid() == pid_af) {
                deinit_shared_memory_for_plugins();
            }
        }};

        // TODO Why is this necessary?
        irods::re_plugin_globals = std::make_unique<irods::global_re_plugin_mgr>();

        // Initialize zone information for request processing.
        // initServerMain starts the listening socket and stores it in svrComm.
        // TODO initServerMain can likely be simplified.
        RsComm svrComm{}; // TODO RsComm contains a std::string, so never memset this type!
        if (const auto ec = initServerMain(svrComm, false, false); ec < 0) {
            log_af::error("{}: initServerMain error. [error code={}]", __func__, ec);
            return 1;
        }

        // Enter parent process main loop.
        // 
        // This process should never introduce threads. Everything it cares about must be handled
        // within the loop. This keeps things simple and straight forward.
        //
        // THE PARENT PROCESS IS THE ONLY PROCESS THAT SHOULD/CAN REACT TO SIGNALS!
        // EVERYTHING IS PROPAGATED THROUGH/FROM THE PARENT PROCESS!

        fd_set sockMask;
        FD_ZERO(&sockMask); // NOLINT(readability-isolate-declaration)

        log_af::info("{}: Waiting for client request.", __func__);
        while (true) {
            if (g_terminate) {
                log_af::info("{}: Received shutdown instruction. Exiting agent factory main loop.", __func__);
                break;
            }

            if (g_terminate_graceful) {
                log_af::info("{}: Received graceful shutdown instruction. Exiting agent factory main loop.", __func__);
                break;
            }

            // NOLINTNEXTLINE(hicpp-signed-bitwise, cppcoreguidelines-pro-bounds-constant-array-index)
            FD_SET(svrComm.sock, &sockMask);

            int numSock = 0;
            struct timeval time_out; // NOLINT(cppcoreguidelines-pro-type-member-init)
            time_out.tv_sec  = 0;
            time_out.tv_usec = 500 * 1000;

            // FIXME Replace use of select() with epoll() or Boost.Asio.
            while ((numSock = select(svrComm.sock + 1, &sockMask, nullptr, nullptr, &time_out)) == -1) {
                if (g_terminate) {
                    log_af::info("{}: Received shutdown instruction. Exiting agent factory select() loop.", __func__);
                    break;
                }

                if (g_terminate_graceful) {
                    log_af::info("{}: Received graceful shutdown instruction. Exiting agent factory select() loop.", __func__);
                    break;
                }

                // "select" modifies the timeval structure, so reset it.
                time_out.tv_sec  = 0;
                time_out.tv_usec = 500 * 1000;

                if (EINTR == errno) {
                    log_af::trace("{}: select() interrupted", __func__);
                    // NOLINTNEXTLINE(hicpp-signed-bitwise, cppcoreguidelines-pro-bounds-constant-array-index)
                    FD_SET(svrComm.sock, &sockMask);
                    continue;
                }

                log_af::error("{}: select() error, errno = {}", __func__, errno);
                return 1;
            }

            if (g_terminate) {
                log_af::info("{}: Received shutdown instruction. Exiting agent factory main loop.", __func__);
                break;
            }

            if (g_terminate_graceful) {
                log_af::info("{}: Received shutdown instruction. Exiting agent factory main loop.", __func__);
                break;
            }

            if (0 == numSock) {
                // "select" modifies the timeval structure, so reset it.
                time_out.tv_sec  = 0;
                time_out.tv_usec = 500 * 1000;
                continue;
            }

            const int newSock = rsAcceptConn(&svrComm);
            if (newSock < 0) {
                log_af::info("{}: rsAcceptConn() error, errno = {}", __func__, errno);
                continue;
            }

            // Fork agent to handle client request.

            const auto agent_pid = fork();
            if (agent_pid == 0) {
                close(svrComm.sock); // Close the listening socket.
                try {
                    return handle_client_request(newSock, std::time(nullptr));
                }
                catch (const std::exception& e) {
                    log_agent::critical("{}: Exception caught in outer most scope of request handler: {}", __func__, e.what());
                    return 1;
                }
            }

            if (agent_pid > 0) {
                close(newSock);
            }
            else {
                log_af::critical("Failed to fork agent. errno={}", errno);
            }
        }

        // Start shutting everything down.

        // Do not accept new client requests (i.e. close the listening socket).
        close(svrComm.sock);

        if (0 == g_terminate_graceful) {
            // Instruct all agents to shutdown gracefully.
            // To avoid unnecessary complexity, we use SIGUSR1 as the termination signal for agents.
            // Attempting to use SIGTERM would also notify the main server process, agent factory, and delay server.
            kill(0, SIGUSR1);
        }

        reap_agent_processes(true);

        log_af::info("{}: Shutdown complete.", __func__);

        return 0;
    }
    catch (const std::exception& e) {
        fmt::print(stderr, "Error: {}\n", e.what());
        return 1;
    }
} // main

namespace
{
    auto init_logger(const nlohmann::json& _config) -> void
    {
        namespace logger = irods::experimental::log;

        logger::init(false, false);
        log_af::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_AGENT_FACTORY));
        logger::set_server_type("agent_factory");
        logger::set_server_zone(_config.at(irods::KW_CFG_ZONE_NAME).get<std::string>());
        logger::set_server_hostname(boost::asio::ip::host_name());
    } // init_logger

    auto load_log_levels_for_loggers() -> void
    {
        namespace logger = irods::experimental::log;

        logger::agent::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_AGENT));
        logger::agent_factory::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_AGENT_FACTORY));
        logger::api::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_API));
        logger::authentication::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_AUTHENTICATION));
        logger::database::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_DATABASE));
        logger::genquery2::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_GENQUERY2));
        logger::legacy::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_LEGACY));
        logger::microservice::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_MICROSERVICE));
        logger::network::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_NETWORK));
        logger::resource::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_RESOURCE));
        logger::rule_engine::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_RULE_ENGINE));
        logger::sql::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_SQL));
    } // load_log_levels_for_loggers

    auto setup_signal_handlers() -> int
    {
        // DO NOT memset sigaction structures!

        std::signal(SIGINT, SIG_IGN);

        // SIGTERM
        struct sigaction sa_terminate; // NOLINT(cppcoreguidelines-pro-type-member-init)
        sigemptyset(&sa_terminate.sa_mask);
        sa_terminate.sa_flags = SA_SIGINFO;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
        sa_terminate.sa_sigaction = [](int, siginfo_t* _siginfo, void*) {
            const auto saved_errno = errno;

            // Only respond to SIGTERM if the main server process sent it.
            if (getppid() == _siginfo->si_pid && 0 == g_terminate_graceful) {
                g_terminate = 1;
            }

            errno = saved_errno;
        };
        if (sigaction(SIGTERM, &sa_terminate, nullptr) == -1) {
            return -1;
        }

        // SIGQUIT (graceful shutdown)
        struct sigaction sa_terminate_graceful; // NOLINT(cppcoreguidelines-pro-type-member-init)
        sigemptyset(&sa_terminate_graceful.sa_mask);
        sa_terminate_graceful.sa_flags = SA_SIGINFO;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
        sa_terminate_graceful.sa_sigaction = [](int, siginfo_t* _siginfo, void*) {
            const auto saved_errno = errno;

            // Only respond to SIGQUIT if the main server process sent it.
            if (getppid() == _siginfo->si_pid && 0 == g_terminate) {
                g_terminate_graceful = 1;
            }

            errno = saved_errno;
        };
        if (sigaction(SIGQUIT, &sa_terminate_graceful, nullptr) == -1) {
            return -1;
        }

        // SIGCHLD
        struct sigaction sa_sigchld; // NOLINT(cppcoreguidelines-pro-type-member-init)
        sigemptyset(&sa_sigchld.sa_mask);
        sa_sigchld.sa_flags = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access, cppcoreguidelines-pro-type-cstyle-cast)
        sa_sigchld.sa_handler = [](int) {
            const auto saved_errno = errno;
            reap_agent_processes(false);
            errno = saved_errno;
        };
        if (sigaction(SIGCHLD, &sa_sigchld, nullptr) == -1) {
            return -1;
        }

        irods::setup_unrecoverable_signal_handlers();

        return 0;
    } // setup_signal_handlers

    // We incorporate the cache salt into the rule engine's named_mutex and shared memory object.
    // This prevents (most of the time) an orphaned mutex from halting server standup. Issue most often seen
    // when a running iRODS installation is uncleanly killed (leaving the file system object used to implement
    // boost::named_mutex e.g. in /var/run/shm) and then the iRODS user account is recreated, yielding a different
    // UID. The new iRODS user account is then unable to unlock or remove the existing mutex, blocking the server.
    auto createAndSetRECacheSalt() -> irods::error
    {
        // Should only ever set the cache salt once.
        try {
            const auto& existing_salt = irods::get_server_property<const std::string>(irods::KW_CFG_RE_CACHE_SALT);
            log_af::debug("createAndSetRECacheSalt: Cache salt already set [{}]", existing_salt.c_str());
            return ERROR(SYS_ALREADY_INITIALIZED, "createAndSetRECacheSalt: Cache salt already set");
        }
        catch (const irods::exception&) {
            irods::buffer_crypt::array_t buf;
            irods::error ret = irods::buffer_crypt::generate_key(buf, /* RE_CACHE_SALT_NUM_RANDOM_BYTES */ 40);
            if (!ret.ok()) {
                log_af::critical("createAndSetRECacheSalt: failed to generate random bytes");
                return PASS(ret);
            }

            std::string cache_salt_random;
            ret = irods::buffer_crypt::hex_encode(buf, cache_salt_random);
            if (!ret.ok()) {
                log_af::critical("createAndSetRECacheSalt: failed to hex encode random bytes");
                return PASS(ret);
            }

            const auto cache_salt = fmt::format("pid{}_{}", static_cast<std::intmax_t>(getpid()), cache_salt_random);

            try {
                irods::set_server_property<std::string>(irods::KW_CFG_RE_CACHE_SALT, cache_salt);
            }
            catch (const nlohmann::json::exception& e) {
                log_af::critical("createAndSetRECacheSalt: failed to set server_properties");
                return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
            }
            catch (const std::exception&) {}

            if (setenv(SP_RE_CACHE_SALT, cache_salt.c_str(), 1) != 0) {
                log_af::critical("createAndSetRECacheSalt: failed to set environment variable");
                return ERROR(SYS_SETENV_ERR, "createAndSetRECacheSalt: failed to set environment variable");
            }

            return SUCCESS();
        }
    } // createAndSetRECacheSalt

    auto init_shared_memory_for_plugin(const nlohmann::json& _plugin_object) -> bool
    {
        const auto itr = _plugin_object.find(irods::KW_CFG_SHARED_MEMORY_INSTANCE);

        if (_plugin_object.end() != itr) {
            const auto& mem_name = itr->get_ref<const std::string&>();
            prepareServerSharedMemory(mem_name);
            return true;
        }

        return false;
    } // init_shared_memory_for_plugin

    auto init_shared_memory_for_plugins() -> irods::error
    {
        try {
            const auto config_handle{irods::server_properties::instance().map()};
            const auto& config{config_handle.get_json()};

            for (const auto& item : config.at(irods::KW_CFG_PLUGIN_CONFIGURATION).items()) {
                for (const auto& plugin : item.value().items()) {
                    init_shared_memory_for_plugin(plugin.value());
                }
            }
        }
        catch (const irods::exception& e) {
            return irods::error(e);
        }
        catch (const std::exception& e) {
            return ERROR(SYS_INTERNAL_ERR, e.what());
        }

        return SUCCESS();
    } // init_shared_memory_for_plugins

    auto deinit_shared_memory_for_plugin(const nlohmann::json& _plugin_object) -> bool
    {
        const auto itr = _plugin_object.find(irods::KW_CFG_SHARED_MEMORY_INSTANCE);

        if (_plugin_object.end() != itr) {
            const auto& mem_name = itr->get_ref<const std::string&>();
            removeSharedMemory(mem_name);
            resetMutex(mem_name.c_str());
            return true;
        }

        return false;
    } // deinit_shared_memory_for_plugin

    auto deinit_shared_memory_for_plugins() -> irods::error
    {
        try {
            const auto config_handle{irods::server_properties::instance().map()};
            const auto& config{config_handle.get_json()};

            for (const auto& item : config.at(irods::KW_CFG_PLUGIN_CONFIGURATION).items()) {
                for (const auto& plugin : item.value().items()) {
                    deinit_shared_memory_for_plugin(plugin.value());
                }
            }
        }
        catch (const irods::exception& e) {
            return irods::error(e);
        }
        catch (const std::exception& e) {
            return ERROR(SYS_INTERNAL_ERR, e.what());
        }

        return SUCCESS();
    } // deinit_shared_memory_for_plugins

    auto initServer(RsComm& _comm) -> int
    {
        if (const auto ec = initServerInfo(0, &_comm); ec < 0) {
            log_af::info("{}: initServerInfo error, status = {}", __func__, ec);
            return ec;
        }

        // TODO Unnecessary?
        //resc_mgr.print_local_resources();

        printZoneInfo();

        rodsServerHost_t* rodsServerHost{};
        if (const auto ec = getRcatHost(PRIMARY_RCAT, nullptr, &rodsServerHost); ec < 0 || !rodsServerHost) {
            return ec;
        }

        std::string svc_role;
        if (const auto res = get_catalog_service_role(svc_role); !res.ok()) {
            log_af::error("{}: Could not get server role. [error code={}]", __func__, res.code());
            return res.code();
        }

        if (LOCAL_HOST == rodsServerHost->localFlag) {
            if (irods::KW_CFG_SERVICE_ROLE_PROVIDER == svc_role) {
                disconnectRcat();
            }
        }
        else if (rodsServerHost->conn) {
            rcDisconnect(rodsServerHost->conn);
            rodsServerHost->conn = nullptr;
        }

        if (irods::KW_CFG_SERVICE_ROLE_PROVIDER == svc_role) {
            // TODO Why?
            //purgeLockFileDir(0);
        }

        return 0;
    } // initServer

    auto initServerMain(RsComm& _comm,
                        const bool enable_test_mode = false,
                        const bool write_to_stdout = false) -> int
    {
        std::memset(&_comm, 0, sizeof(RsComm));
        int status = getRodsEnv(&_comm.myEnv);
        if (status < 0) {
            log_af::error("{}: getRodsEnv error. status = {}", __func__, status);
            return status;
        }

        // TODO Verify this is reading from the correct location.
        // Consider non-pkg installs and pkg installs.
        setRsCommFromRodsEnv(&_comm);

#if 0
        // Load server API table so that API plugins which are needed to stand up the server are
        // available for use.
        irods::api_entry_table& RsApiTable = irods::get_server_api_table();
        irods::pack_entry_table& ApiPackTable = irods::get_pack_table();
        if (const auto err = irods::init_api_table(RsApiTable, ApiPackTable, false); !err.ok()) {
            irods::log(PASS(err));
            return err.code();
        }

        // If this is a catalog service consumer, the client API table should be loaded so that
        // client calls can be made to the catalog service provider as part of the server
        // initialization process.
        irods::api_entry_table& RcApiTable = irods::get_client_api_table();
        if (const auto err = irods::init_api_table(RcApiTable, ApiPackTable, false); !err.ok()) {
            irods::log(PASS(err));
            return err.code();
        }

        status = initServer(_comm);
        if (status < 0) {
            log_af::error("{}: initServer error. status = {}", __func__, status);
            return 1;
        }
#endif

        int zone_port;
        try {
            zone_port = irods::get_server_property<const int>(irods::KW_CFG_ZONE_PORT);
        }
        catch (const irods::exception& e) {
            irods::log(irods::error(e));
            return e.code();
        }

        _comm.sock = sockOpenForInConn(&_comm, &zone_port, nullptr, SOCK_STREAM);
        if (_comm.sock < 0) {
            log_af::error("{}: sockOpenForInConn error. status = {}", __func__, _comm.sock);
            return _comm.sock;
        }

        if (listen(_comm.sock, MAX_LISTEN_QUE) < 0) {
            log_af::error("{}: listen failed, errno: {}", __func__, errno);
            return SYS_SOCK_LISTEN_ERR;
        }

        log_af::info("{}: Server Release version {} - API Version {} is up", __func__, RODS_REL_VERSION, RODS_API_VERSION);

        return 0;
    } // initServerMain

    auto handle_client_request(int _socket_fd, std::time_t _created_at) -> int
    {
        // Setup signal handlers for agent.

        // SIGINT is ignored to protect the agents from being killed when running the
        // server in the foreground (i.e. no daemonization). The described behavior is
        // observed by running the server in the foreground, enabling the default behavior
        // of SIGINT, and entering CTRL-C in the bash terminal.
        std::signal(SIGINT, SIG_IGN);

        // SIGTERM is ignored to avoid unwanted termination of the agent during a full
        // shutdown of the iRODS server.
        std::signal(SIGTERM, SIG_IGN);

        // To avoid unnecessary complexity for configuration reload, shutdown, and signals,
        // we use SIGUSR1 as the signal for instructing the agents to shutdown.
        struct sigaction sa_terminate; // NOLINT(cppcoreguidelines-pro-type-member-init)
        sigemptyset(&sa_terminate.sa_mask);
        sa_terminate.sa_flags = SA_SIGINFO;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
        sa_terminate.sa_sigaction = [](int, siginfo_t* _siginfo, void*) {
            // Only respond to SIGUSR1 if the agent factory triggered it.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
            if (getppid() == _siginfo->si_pid) {
                g_terminate = 1;
            }
        };
        if (sigaction(SIGUSR1, &sa_terminate, nullptr) == -1) {
            return -1; // TODO Use a better error code or log instead.
        }

        // SIGPIPE is ignored so that agents can detect socket issues to other servers.
        std::signal(SIGPIPE, SIG_IGN);

        std::signal(SIGCHLD, SIG_DFL);

        std::signal(SIGHUP, SIG_IGN);

        //std::signal(SIGABRT, SIG_DFL);
        //std::signal(SIGUSR1, SIG_DFL);

        irods::experimental::log::set_server_type("agent");

        // Artificially create a conn object in order to create a network object.
        // This is gratuitous but necessary to maintain the consistent interface.
        RcComm tmp_comm{};

        irods::network_object_ptr net_obj;
        irods::error ret = irods::network_factory(&tmp_comm, net_obj);

        if (!ret.ok() || !net_obj.get()) {
            log_agent::error("{}: Failed to initialize network object for client request.", __func__);
            return 1;
        }

        net_obj->socket_handle(_socket_fd);
        startupPack_t* startupPack = nullptr;
        struct timeval tv;
        tv.tv_sec = READ_STARTUP_PACK_TOUT_SEC;
        tv.tv_usec = 0;

        if (const auto res = readStartupPack(net_obj, &startupPack, &tv); !res.ok()) {
            log_agent::error("{}: readStartupPack failed, [error code={}]", res.code());
            sendVersion(net_obj, res.code(), 0, nullptr, 0);
            mySockClose(net_obj->socket_handle());
            return 0;
        }

        if (startupPack->connectCnt > /* MAX_SVR_SVR_CONNECT_CNT */ 7) {
            sendVersion(net_obj, SYS_EXCEED_CONNECT_CNT, 0, nullptr, 0);
            mySockClose(net_obj->socket_handle());
            std::free(startupPack);
            return 0;
        }

        if (std::strcmp(startupPack->option, RODS_HEARTBEAT_T) == 0) {
            const char* heartbeat = RODS_HEARTBEAT_T;
            const int heartbeat_length = std::strlen(heartbeat);
            int bytes_to_send = heartbeat_length;

            while (bytes_to_send) {
                const int bytes_sent = send(net_obj->socket_handle(), &(heartbeat[heartbeat_length - bytes_to_send]), bytes_to_send, 0);
                const int errsav = errno;
                if (errsav != EINTR) {
                    log_agent::error("{}: Socket error encountered during heartbeat; socket returned {}",
                                      __func__, strerror(errsav));
                    break;
                }

                if (bytes_sent > 0) {
                    bytes_to_send -= bytes_sent;
                }
            }

            mySockClose(net_obj->socket_handle());
            std::free(startupPack);
            return 0;
        }

        if (startupPack->clientUser[0] != '\0') {
            if (const auto ec = chkAllowedUser(startupPack->clientUser, startupPack->clientRodsZone); ec < 0) {
                sendVersion(net_obj, ec, 0, nullptr, 0);
                mySockClose(net_obj->socket_handle());
                std::free(startupPack);
                return 0;
            }
        }

        //
        // This is where we return to iRODS 4.3 logic.
        //

        RsComm rsComm{};

        // Originally set via an environment variable in initRsCommWithStartupPack in iRODS 4.2+.
        rsComm.sock = _socket_fd;

        irods::experimental::log::set_error_object(&rsComm.rError);
        irods::at_scope_exit release_error_stack{[] { irods::experimental::log::set_error_object(nullptr); }};

        rsComm.thread_ctx = static_cast<thread_context*>(std::malloc(sizeof(thread_context)));

        bool require_cs_neg = false;
        int status = initRsCommWithStartupPack(&rsComm, startupPack, require_cs_neg); // This version just uses the startupPack.

        // manufacture a network object for comms
        ret = irods::network_factory(&rsComm, net_obj);
        if (!ret.ok()) {
            log_agent::error(PASS(ret).result());
        }

        if (status < 0) {
            log_agent::error("initRsCommWithStartupPack error: [{}]", status);
            sendVersion(net_obj, status, 0, nullptr, 0);
            cleanupAndExit(status);
        }

        irods::re_plugin_globals.reset(new irods::global_re_plugin_mgr);
        irods::re_plugin_globals->global_re_mgr.call_start_operations();

        // TODO Cannot assume /var/lib/irods.
        status = getRodsEnv(&rsComm.myEnv);

        if (status < 0) {
            log_agent::error("agentMain :: getRodsEnv failed");
            sendVersion(net_obj, SYS_AGENT_INIT_ERR, 0, nullptr, 0);
            cleanupAndExit(status);
        }

        // load server side pluggable api entries
        irods::api_entry_table&  RsApiTable   = irods::get_server_api_table();
        irods::pack_entry_table& ApiPackTable = irods::get_pack_table();
        ret = irods::init_api_table(RsApiTable, ApiPackTable, false);
        if (!ret.ok()) {
            log_agent::error(PASS(ret).result());
            return 1;
        }

        // load client side pluggable api entries
        irods::api_entry_table& RcApiTable = irods::get_client_api_table();
        ret = irods::init_api_table(RcApiTable, ApiPackTable, false);
        if (!ret.ok()) {
            log_agent::error(PASS(ret).result());
            return 1;
        }

        std::string svc_role;
        ret = get_catalog_service_role(svc_role);
        if (!ret.ok()) {
            log_agent::error(PASS(ret).result());
            return 1;
        }

        // TODO Huh?
#if 0
        if (irods::KW_CFG_SERVICE_ROLE_PROVIDER == svc_role) {
            if (std::strstr(rsComm.myEnv.rodsDebug, "CAT") != nullptr) {
                chlDebug(rsComm.myEnv.rodsDebug);
            }
        }
#endif

        status = initAgent(RULE_ENGINE_TRY_CACHE, &rsComm);

        if (status < 0) {
            log_agent::error("agentMain :: initAgent failed: {}", status);
            sendVersion(net_obj, SYS_AGENT_INIT_ERR, 0, nullptr, 0);
            cleanupAndExit(status);
        }

        if (rsComm.clientUser.userName[0] != '\0') {
            status = chkAllowedUser(rsComm.clientUser.userName, rsComm.clientUser.rodsZone);

            if (status < 0) {
                sendVersion(net_obj, status, 0, nullptr, 0);
                cleanupAndExit(status);
            }
        }

        // handle negotiations with the client regarding TLS if requested
        // this scope block makes valgrind happy
        {
            std::string neg_results;
            ret = irods::client_server_negotiation_for_server(net_obj, neg_results, require_cs_neg, &rsComm);
            if (!ret.ok() || irods::CS_NEG_FAILURE == neg_results) {
                // send a 'we failed to negotiate' message here??
                // or use the error stack rule engine thingie
                log_agent::error(PASS(ret).result());
                sendVersion(net_obj, SERVER_NEGOTIATION_ERROR, 0, nullptr, 0);
                cleanupAndExit(ret.code());
            }
            else {
                // copy negotiation results to comm for action by network objects
                std::snprintf(rsComm.negotiation_results, sizeof(rsComm.negotiation_results), "%s", neg_results.c_str());
            }
        }

        // send the server version and status as part of the protocol. Put
        // rsComm.reconnPort as the status
        ret = sendVersion(net_obj, status, rsComm.reconnPort, rsComm.reconnAddr, rsComm.cookie);

        if (!ret.ok()) {
            log_agent::error(PASS(ret).result());
            sendVersion(net_obj, SYS_AGENT_INIT_ERR, 0, nullptr, 0);
            cleanupAndExit(status);
        }

        create_agent_pid_file_for_ips(rsComm, _created_at);

        // call initialization for network plugin as negotiated
        irods::network_object_ptr new_net_obj;
        ret = irods::network_factory(&rsComm, new_net_obj);
        if (!ret.ok()) {
            log_agent::error(PASS(ret).result());
            return 1;
        }

        ret = sockAgentStart(new_net_obj);
        if (!ret.ok()) {
            log_agent::error(PASS(ret).result());
            return 1;
        }

        const auto cleanup_and_free_rsComm_members = [&rsComm] {
            cleanup();
            if (rsComm.thread_ctx) {
                std::free(rsComm.thread_ctx); // NOLINT(cppcoreguidelines-no-malloc, cppcoreguidelines-owning-memory)
            }
            if (rsComm.auth_scheme) {
                std::free(rsComm.auth_scheme); // NOLINT(cppcoreguidelines-no-malloc, cppcoreguidelines-owning-memory)
            }
        };

        new_net_obj->to_server(&rsComm);
        status = agentMain(rsComm);

        // call initialization for network plugin as negotiated
        ret = sockAgentStop( new_net_obj );
        if (!ret.ok()) {
            log_agent::error(PASS(ret).result());
            cleanup_and_free_rsComm_members();
            return 1;
        }

        new_net_obj->to_server(&rsComm);

        cleanup_and_free_rsComm_members();

        // clang-format off
        (0 == status)
            ? log_agent::debug("Agent [{}] exiting with status = {}", getpid(), status)
            : log_agent::error("Agent [{}] exiting with status = {}", getpid(), status);
        // clang-format on

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
        // This function must be called here due to the use of _exit() (just below). Address Sanitizer (ASan)
        // relies on std::atexit handlers to report its findings. _exit() does not trigger any of the handlers
        // registered by ASan, therefore, we manually run ASan just before the agent exits.
        __lsan_do_leak_check();
#endif

        return (0 == status) ? 0 : 1;
    } // handle_client_request

    auto cleanup() -> void
    {
        std::string svc_role;
        irods::error ret = get_catalog_service_role(svc_role);
        if (!ret.ok()) {
            log_agent::error(PASS(ret).result());
        }

        if (INITIAL_DONE == InitialState) {
            close_all_l1_descriptors(*ThisComm);

            // This agent's PID must be erased from all replica access table entries as it will soon no longer exist.
            irods::experimental::replica_access_table::erase_pid(getpid());

            irods::replica_state_table::deinit();

            disconnectAllSvrToSvrConn();
        }

        if (irods::KW_CFG_SERVICE_ROLE_PROVIDER == svc_role) {
            disconnectRcat();
        }

        irods::re_plugin_globals->global_re_mgr.call_stop_operations();
    } // cleanup

    auto cleanupAndExit(int status) -> void
    {
        cleanup();

        if (status >= 0) {
            std::exit(0); // NOLINT(concurrency-mt-unsafe)
        }

        std::exit(1); // NOLINT(concurrency-mt-unsafe)
    } // cleanupAndExit

    auto set_rule_engine_globals(RsComm& _comm) -> void
    {
        irods::set_server_property<std::string>(irods::CLIENT_USER_NAME_KW, _comm.clientUser.userName);
        irods::set_server_property<std::string>(irods::CLIENT_USER_ZONE_KW, _comm.clientUser.rodsZone);
        irods::set_server_property<int>(irods::CLIENT_USER_PRIV_KW, _comm.clientUser.authInfo.authFlag);
        irods::set_server_property<std::string>(irods::PROXY_USER_NAME_KW, _comm.proxyUser.userName);
        irods::set_server_property<std::string>(irods::PROXY_USER_ZONE_KW, _comm.proxyUser.rodsZone);
        irods::set_server_property<int>(irods::PROXY_USER_PRIV_KW, _comm.clientUser.authInfo.authFlag);
    } // set_rule_engine_globals

    auto agentMain(RsComm& _comm) -> int
    {
        int status = 0;

        // compiler backwards compatibility hack
        // see header file for more details
        irods::dynamic_cast_hack();

        while (status >= 0) {
            if (g_terminate) {
                log_agent::trace("{}: Received shutdown instruction. Agent is shutting down.", __func__);
                break;
            }

            // set default to the native auth scheme here.
            if (!_comm.auth_scheme) {
                _comm.auth_scheme = strdup("native");
            }

            // The following is an artifact of the legacy authentication plugins. This operation is
            // only useful for certain plugins which are not supported in 4.3.0, so it is being
            // left out of compilation for now. Once we have determined that this is safe to do in
            // general, this section can be removed.
#if 0
            // construct an auth object based on the scheme specified in the comm
            irods::auth_object_ptr auth_obj;
            if (const auto err = irods::auth_factory(_comm.auth_scheme, &_comm.rError, auth_obj); !err.ok()) {
                irods::experimental::api::plugin_lifetime_manager::destroy();

                irods::log(PASSMSG(fmt::format(
                    "Failed to factory an auth object for scheme: \"{}\".",
                    _comm.auth_scheme), err));

                return err.code();
            }

            irods::plugin_ptr ptr;
            if (const auto err = auth_obj->resolve(irods::AUTH_INTERFACE, ptr); !err.ok()) {
                irods::experimental::api::plugin_lifetime_manager::destroy();

                irods::log(PASSMSG(fmt::format(
                    "Failed to resolve the auth plugin for scheme: \"{}\".",
                    _comm.auth_scheme), err));

                return err.code();
            }

            irods::auth_ptr auth_plugin = boost::dynamic_pointer_cast<irods::auth>(ptr);

            // Call agent start
            if (const auto err = auth_plugin->call<const char*>(_comm, irods::AUTH_AGENT_START, auth_obj, ""); !err.ok()) {
                irods::experimental::api::plugin_lifetime_manager::destroy();

                irods::log(PASSMSG(fmt::format(
                    "Failed during auth plugin agent start for scheme: \"{}\".",
                    _comm.auth_scheme), err));

                return err.code();
            }
#endif

            // add the user info to the server properties for
            // reach by the operation wrapper for access by the
            // dynamic policy enforcement points
            try {
                set_rule_engine_globals(_comm);
            }
            catch (const irods::exception& e) {
                log_agent::error("set_rule_engine_globals failed:\n{}", e.what());
            }

            if (_comm.ssl_do_accept) {
                status = sslAccept(&_comm);
                if (status < 0) {
                    log_agent::error("sslAccept failed in agentMain with status {}", status);
                }
                _comm.ssl_do_accept = 0;
            }
            if (_comm.ssl_do_shutdown) {
                status = sslShutdown(&_comm);
                if (status < 0) {
                    log_agent::error("sslShutdown failed in agentMain with status {}", status);
                }
                _comm.ssl_do_shutdown = 0;
            }

            status = readAndProcClientMsg(&_comm, READ_HEADER_TIMEOUT);
            if (status < 0) {
                if (status == DISCONN_STATUS) {
                    status = 0;
                    break;
                }
            }
        }

        irods::experimental::api::plugin_lifetime_manager::destroy();

        // determine if we even need to connect, break the
        // infinite reconnect loop.
        if (!resc_mgr.need_maintenance_operations()) {
            return status;
        }

        // find the icat host
        rodsServerHost_t* rodsServerHost = 0;
        status = getRcatHost(PRIMARY_RCAT, 0, &rodsServerHost);
        if (status < 0) {
            log_agent::error(ERROR(status, "getRcatHost failed.").result());
            return status;
        }

        // connect to the icat host
        status = svrToSvrConnect(&_comm, rodsServerHost);
        if ( status < 0 ) {
            log_agent::error(ERROR(status, "svrToSvrConnect failed.").result());
            return status;
        }

        // call post disconnect maintenance operations before exit
        status = resc_mgr.call_maintenance_operations(rodsServerHost->conn);

        return status;
    } // agentMain

    auto create_agent_pid_file_for_ips(const RsComm& _comm, std::time_t _created_at) -> void
    {
        std::string_view local_zone = "UNKNOWN";
        if (const auto* lz = getLocalZoneName(); lz) {
            local_zone = lz;
        }

        std::string_view client_zone = _comm.clientUser.rodsZone;
        if (client_zone.empty()) {
            client_zone = local_zone;
        }

        std::string_view proxy_zone = _comm.proxyUser.rodsZone;
        if (proxy_zone.empty()) {
            proxy_zone = local_zone;
        }

        std::string_view client_program_name = _comm.option;
        if (client_program_name.empty()) {
            client_program_name = "UNKNOWN";
        }

        const auto ips_data_dir = irods::get_server_property<std::string>("ips_data_directory");
        const auto pid_file = fmt::format("{}/{}", ips_data_dir, getpid());

        if (std::ofstream out{pid_file}; out) {
            out << fmt::format("{} {} {} {} {} {} {}\n",
                // TODO The argument order is weird?
                _comm.proxyUser.userName,
                client_zone,
                _comm.clientUser.userName,
                proxy_zone,
                client_program_name,
                _comm.clientAddr,
                static_cast<unsigned int>(_created_at));
        }
        else {
            log_agent::error("{}: Could not open file [{}] for agent/ips data.", __func__, pid_file);
        }
    } // create_agent_pid_file_for_ips

    auto reap_agent_processes(bool _shutting_down) -> void
    {
        pid_t pid;
        int status;
        char agent_pid[16];
        char agent_pid_file_path[1024]; // TODO _POSIX_PATH_MAX?

        const auto unlink_agent_pid_file = [&](const pid_t _pid) {
            auto [p, ec] = std::to_chars(agent_pid, agent_pid + sizeof(agent_pid), _pid);
            if (std::errc{} != ec) {
                return;
            }

            // Add the null-terminating byte.
            *p = 0;

            std::memset(agent_pid_file_path, 0, sizeof(agent_pid_file_path));
            std::strcpy(agent_pid_file_path, g_ips_data_directory);
            std::strcat(agent_pid_file_path, agent_pid);

            unlink(agent_pid_file_path);
        };

        if (g_terminate_graceful && _shutting_down) {
            const auto start_time = std::time(nullptr);

            // Poll termination of agents until one of the following conditions is true.
            // - waitpid() returns -1 and errno is ECHILD
            // - The graceful timeout limit has been exceeded
            //
            // If all agents have exited, break out the loop (i.e. we're done).
            // If the graceful timeout limit has been exceeded, send SIGUSR1 signal to all agents
            // so they terminate immediately.
            while (true) {
                pid = waitpid(-1, &status, WNOHANG);

                // This branch is for when we're shutting down (i.e. not in a signal handler).
                // That is - continue to loop until all agents have terminated.
                if (-1 == pid && ECHILD == errno) {
                    // All agents have terminated.
                    return;
                }

                if (pid > 0) {
                    unlink_agent_pid_file(pid);
                }

                if ((std::time(nullptr) - start_time) >= g_graceful_shutdown_timeout) {
                    // Instruct agents to terminate. Breaking out the loop and going into the
                    // normal reaping of agents is necessary because the files generated for ips
                    // must be cleaned up.
                    kill(0, SIGUSR1);
                    break;
                }
            }
        }

        const auto flags = _shutting_down ? 0: WNOHANG;

        while (true) {
            pid = waitpid(-1, &status, flags);

            // This branch is for when we're shutting down (i.e. not in a signal handler).
            // That is - continue to loop until all agents have terminated.
            if (_shutting_down) {
                if (-1 == pid && ECHILD == errno) {
                    // All agents have terminated.
                    break;
                }
            }
            // This branch is for when we're in a signal handler.
            // That is - continue to loop as long as waitpid returns a valid pid.
            else if (pid <= 0) {
                break;
            }

            unlink_agent_pid_file(pid);
        }
    } // reap_agent_processes
} // anonymous namespace

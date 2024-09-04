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

#include "irods/client_api_allowlist.hpp"
#include "irods/dns_cache.hpp"
#include "irods/hostname_cache.hpp"
#include "irods/initServer.hpp"
#include "irods/irods_at_scope_exit.hpp"
#include "irods/irods_buffer_encryption.hpp" // For RE cache salt
#include "irods/irods_client_api_table.hpp"
#include "irods/irods_configuration_keywords.hpp"
#include "irods/irods_configuration_parser.hpp" // For key_path_t
#include "irods/irods_exception.hpp"
#include "irods/irods_logger.hpp"
#include "irods/irods_re_plugin.hpp"
#include "irods/irods_server_api_table.hpp"
#include "irods/irods_server_properties.hpp"
#include "irods/locks.hpp" // For removeMutex TODO remove eventually
#include "irods/miscServerFunct.hpp" // For get_catalog_service_role
#include "irods/rcConnect.h"
#include "irods/rcGlobalExtern.h" // For ProcessType
#include "irods/replica_access_table.hpp"
#include "irods/rodsErrorTable.h"
#include "irods/rsIcatOpr.hpp"
#include "irods/sharedmemory.hpp"

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

    volatile std::sig_atomic_t g_terminate = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    volatile std::sig_atomic_t g_reload_config = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    auto init_logger(const nlohmann::json& _config) -> void;
    auto setup_signal_handlers() -> int;
    auto createAndSetRECacheSalt() -> irods::error;
    auto init_shared_memory_for_plugin(const nlohmann::json& _plugin_object) -> bool;
    auto init_shared_memory_for_plugins() -> irods::error;
    auto deinit_shared_memory_for_plugin(const nlohmann::json& _plugin_object) -> bool;
    auto deinit_shared_memory_for_plugins() -> irods::error;

    // TODO Refactor these functions.
    auto initServer(RsComm& _comm) -> int;
    auto initServerMain(RsComm& _comm, const bool _enable_test_mode, const bool _write_to_stdout) -> int;
} // anonymous namespace

int main(int _argc, char* _argv[])
{
    ProcessType = AGENT_PT; // This process identifies itself as the agent factory or an agent.

    std::string config_dir_path;

    // TODO Boost.ProgramOptions isn't necessary.

    namespace po = boost::program_options;

    po::options_description opts_desc{""};

    // clang-format off
    opts_desc.add_options()
        ("config-directory,f", po::value<std::string>(), "")
        ("message-queue,q", po::value<std::string>(), "");
    // clang-format on

    po::positional_options_description pod;
    pod.add("config-directory", 1);
    pod.add("message-queue", 1);

    try {
        po::variables_map vm;
        po::store(po::command_line_parser(_argc, _argv).options(opts_desc).positional(pod).run(), vm);
        po::notify(vm);

        if (auto iter = vm.find("config-directory"); std::end(vm) != iter) {
            config_dir_path = std::move(iter->second.as<std::string>());
        }
        else {
            fmt::print(stderr, "Error: Missing [CONFIG_FILE_PATH] parameter.");
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
        config = json::parse(std::ifstream{fs::path{config_dir_path} / "server_config.json"});
        irods::server_properties::instance().capture(); // TODO This MUST NOT assume /etc/irods/server_config.json.

        // TODO Init base systems for parent process.
        // - logger
        // - shared memory for replica access table, dns cache, hostname cache?
        // - delay server salt

        // To see log messages from rsyslog, you must add irodsAgent5 to /etc/rsyslog.d/00-irods.conf.
        init_logger(config);

        log_af::info("{}: Initializing loggers for agent factory.", __func__);

        namespace logger = irods::experimental::log;

        logger::agent::set_level(logger::get_level_from_config(irods::KW_CFG_LOG_LEVEL_CATEGORY_AGENT));
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

        log_af::info("{}: Initializing client allowlist for agent factory.", __func__);
        irods::client_api_allowlist::init();

        // TODO
        //remove_leftover_rulebase_pid_files(*server_config);

        // TODO
        //create_stacktrace_directory();

        // TODO Initialize shared memory systems.
        log_af::info("{}: Initializing shared memory for agent factory.", __func__);

        namespace hnc = irods::experimental::net::hostname_cache;
        hnc::init("irods_hostname_cache5", irods::get_hostname_cache_shared_memory_size());
        irods::at_scope_exit deinit_hostname_cache{[] { hnc::deinit(); }};

        namespace dnsc = irods::experimental::net::dns_cache;
        dnsc::init("irods_dns_cache5", irods::get_dns_cache_shared_memory_size());
        irods::at_scope_exit deinit_dns_cache{[] { dnsc::deinit(); }};

        irods::experimental::replica_access_table::init();
        irods::at_scope_exit deinit_replica_access_table{[] { irods::experimental::replica_access_table::deinit(); }};

        // TODO Initialize zone information for request processing.
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

        // TODO
        if (const auto res = createAndSetRECacheSalt(); !res.ok()) {
            log_af::error("{}: createAndSetRECacheSalt error.\n{}", __func__, res.result());
            return 1;
        }

        if (const auto res = init_shared_memory_for_plugins(); !res.ok()) {
            log_af::error("{}: Failed to initialize shared memory for plugins. [error code={}]", __func__, res.code());
            return 1;
        }
        irods::at_scope_exit remove_shared_memory{[] { deinit_shared_memory_for_plugins(); }};

        // TODO Why is this necessary?
        irods::re_plugin_globals = std::make_unique<irods::global_re_plugin_mgr>();

        // TODO initServerMain can likely be simplified.
        RsComm svrComm; // RsComm contains a std::string, so never memset this type!
        if (const auto ec = initServerMain(svrComm, false, false); ec < 0) {
            log_af::error("{}: initServerMain error. [error code={}]", __func__, ec);
            return 1;
        }
#if 0
        // This message queue gives child processes a way to notify the parent process.
        // This will only be used by the agent factory because iRODS 5.0 won't have a control plane.
        // Or at least that's the plan.
        constexpr const auto* mq_name = "irodsd_mq"; // TODO Make this name unique.
        constexpr auto max_number_of_msg = 1; // Set to 1 to protect against duplicate/spamming of messages.
        constexpr auto max_msg_size = 512; 
        boost::interprocess::message_queue::remove(mq_name);
        boost::interprocess::message_queue pproc_mq{
            boost::interprocess::create_only, mq_name, max_number_of_msg, max_msg_size};
#endif

        // Setting up signal handlers here removes the need for reacting to shutdown signals
        // such as SIGINT and SIGTERM during the startup sequence.
        log_af::info("{}: Initializing signal handlers for agent factory.", __func__);
        if (setup_signal_handlers() == -1) {
            log_af::error("{}: Error setting up signal handlers for agent factory process.", __func__);
            return 1;
        }

        // Enter parent process main loop.
        // 
        // This process should never introduce threads. Everything it cares about must be handled
        // within the loop. This keeps things simple and straight forward.
        //
        // THE PARENT PROCESS IS THE ONLY PROCESS THAT SHOULD/CAN REACT TO SIGNALS!
        // EVERYTHING IS PROPAGATED THROUGH/FROM THE PARENT PROCESS!

#if 0
        std::array<char, max_msg_size> msg_buf{};
        boost::interprocess::message_queue::size_type recvd_size{};
        unsigned int priority{};
#endif

        log_af::info("{}: Waiting for client request.", __func__);
        while (true) {
            if (g_terminate) {
                log_af::info("{}: Received shutdown instruction. Exiting agent factory main loop.", __func__);
                // TODO Send shutdown message to main server process.
                break;
            }

            if (g_reload_config) {
                log_af::info("{}: Received configuration reload instruction. Reloading configuration.", __func__);
            }

            std::this_thread::sleep_for(std::chrono::seconds{1});
        }

        // Start shutting everything down.

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

    auto setup_signal_handlers() -> int
    {
        // DO NOT memset sigaction structures!

        // SIGINT
        struct sigaction sa_terminate; // NOLINT(cppcoreguidelines-pro-type-member-init)
        sigemptyset(&sa_terminate.sa_mask);
        sa_terminate.sa_flags = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
        sa_terminate.sa_handler = [](int) { g_terminate = 1; };
        if (sigaction(SIGINT, &sa_terminate, nullptr) == -1) {
            return -1;
        }

        // SIGTERM
        if (sigaction(SIGTERM, &sa_terminate, nullptr) == -1) {
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
#if 0
        // SIGCHLD
        // This signal is disabled by default.
        struct sigaction sa_sigchld; // NOLINT(cppcoreguidelines-pro-type-member-init)
        sigemptyset(&sa_sigchld.sa_mask);
        sa_sigchld.sa_flags = SA_NOCLDSTOP; // Do not trigger handler when child receives SIGSTOP.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access, cppcoreguidelines-pro-type-cstyle-cast)
        sa_sigchld.sa_handler = SIG_IGN;
        if (sigaction(SIGCHLD, &sa_sigchld, nullptr) == -1) {
            return -1;
        }
#endif
        // TODO Handle other signals.

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

        // TODO Re-enable eventually.
        //printZoneInfo();

        rodsServerHost_t* rodsServerHost{};
        if (const auto ec = getRcatHost(PRIMARY_RCAT, nullptr, &rodsServerHost); ec < 0 || !rodsServerHost) {
            return ec;
        }

        std::string svc_role;
        if (const auto res = get_catalog_service_role(svc_role); !res.ok()) {
            log_af::error("{}: Could not get server role. [error code={}]", __func__, res.code());
            return res.code(); // TODO Handle narrowing.
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
        //initAndClearProcLog();

        setRsCommFromRodsEnv(&_comm);

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

        int zone_port;
        try {
            zone_port = irods::get_server_property<const int>(irods::KW_CFG_ZONE_PORT);
        }
        catch (const irods::exception& e) {
            irods::log(irods::error(e));
            return e.code();
        }

#if 0
        _comm->sock = sockOpenForInConn(_comm, &zone_port, nullptr, SOCK_STREAM);
        if (_comm->sock < 0) {
            log_af::error("{}: sockOpenForInConn error. status = {}", __func__, _comm->sock);
            return _comm->sock;
        }

        if (listen(_comm->sock, MAX_LISTEN_QUE) < 0) {
            log_af::error("{}: listen failed, errno: {}", __func__, errno);
            return SYS_SOCK_LISTEN_ERR;
        }
#endif

        log_af::info("rodsServer Release version {} - API Version {} is up", RODS_REL_VERSION, RODS_API_VERSION);

        // TODO Likely unnecessary.
        // Record port, PID, and CWD into a well-known file.
        //recordServerProcess(_comm);

#if 0
        // Setup the delay server CRON task.
        // The delay server will launch just before we enter the server's main loop.
        ix::cron::cron_builder delay_server;
        const auto migrate_delay_server_sleep_time =
            get_advanced_setting(irods::KW_CFG_MIGRATE_DELAY_SERVER_SLEEP_TIME_IN_SECONDS, 5);
        delay_server.interval(migrate_delay_server_sleep_time).task([enable_test_mode, write_to_stdout] {
            migrate_delay_server(enable_test_mode, write_to_stdout);
        });
        ix::cron::cron::instance().add_task(delay_server.build());
#endif
        return 0;
    } // initServerMain
} // anonymous namespace
